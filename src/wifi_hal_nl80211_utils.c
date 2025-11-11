/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/


#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/handlers.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <sys/ioctl.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include <cjson/cJSON.h>

#ifdef CONFIG_WIFI_EMULATOR
#define MAX_CLIENTS 3
static wifi_interface_name_idex_map_t *interface_index_map = NULL;
#else
#define INTERFACE_MAP_JSON "/nvram/InterfaceMap.json"

static const wifi_interface_name_idex_map_t *interface_index_map;
static unsigned int interface_index_map_size;

static const wifi_interface_name_idex_map_t static_interface_index_map[] = {
#ifdef RASPBERRY_PI_PORT
#if defined(PLATFORM_LINUX)
    {0, 0,  "wlan0",   "",  "brlan0",    0,    0,      "private_ssid_2g"},
#else
    {0, 0,  "wlan0",   "",  "brlan0",    0,    0,      "private_ssid_2g"},
    {1, 1,  "wlan1",   "",  "brlan0",    0,    1,      "private_ssid_5g"},
    {0, 0,  "wlan2",   "",  "brlan1",    0,    2,      "iot_ssid_2g"},
    {1, 1,  "wlan3",   "",  "brlan1",    0,    3,      "iot_ssid_5g"},
    {0, 0,  "wlan4",   "",  "brlan2",    0,    4,      "hotspot_open_2g"},
    {1, 1,  "wlan5",   "",  "brlan3",    0,    5,      "hotspot_open_5g"},
    {0, 0,  "wlan6",   "",  "br1an4",    0,    6,      "lnf_psk_2g"},
    {1, 1,  "wlan7",   "",  "brlan3",    0,    7,      "lnf_psk_5g"},
    {0, 0,  "wlan8",   "",  "brlan4",    0,    8,      "hotspot_secure_2g"},
    {1, 1,  "wlan9",   "",  "brlan5",    0,    9,      "hotspot_secure_5g"},
    {0, 0,  "wlan10",  "",  "br1an6",    0,    10,     "lnf_radius_2g"},
    {1, 1,  "wlan11",  "",  "br1an6",    0,    11,     "lnf_radius_5g"},
    {0, 0,  "wlan12",  "",  "brlan2",    0,    12,     "mesh_backhaul_2g"},
    {1, 1,  "wlan13",  "",  "brlan3",    0,    13,     "mesh_backhaul_5g"},
    {0, 0,  "wlan14",  "",  "brlan2",    0,    14,     "mesh_sta_2g"},
    {1, 1,  "wlan15",  "",  "brlan2",    0,    15,     "mesh_sta_5g"},
#endif
#endif

#ifdef TCXB7_PORT // for Broadcom based platforms
    {0, 0,  "wl0.1",   "",  "brlan0",  100,    0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",   "",  "brlan0",  100,    1,      "private_ssid_5g"},
    {0, 0,  "wl0.2",   "",  "brlan1",  101,    2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",   "",  "brlan1",  101,    3,      "iot_ssid_5g"},
    {0, 0,  "wl0.3",   "",  "brlan2",  102,    4,      "hotspot_open_2g"},
    {1, 1,  "wl1.3",   "",  "brlan3",  103,    5,      "hotspot_open_5g"},
    {0, 0,  "wl0.4",   "",  "br106",   106,    6,      "lnf_psk_2g"},
    {1, 1,  "wl1.4",   "",  "br106",   106,    7,      "lnf_psk_5g"},
    {0, 0,  "wl0.5",   "",  "brlan4",  104,    8,      "hotspot_secure_2g"},
    {1, 1,  "wl1.5",   "",  "brlan5",  105,    9,      "hotspot_secure_5g"},
    {0, 0,  "wl0.6",   "",  "br106",   106,    10,     "lnf_radius_2g"},
    {1, 1,  "wl1.6",   "",  "br106",   106,    11,     "lnf_radius_5g"},
    {0, 0,  "wl0.7",   "",  "brlan112",  0,    12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",   "",  "brlan113",  0,    13,     "mesh_backhaul_5g"},
    {0, 0,  "wl0",     "",  "brlan1",    0,    14,     "mesh_sta_2g"},
    {1, 1,  "wl1",     "",  "brlan1",    0,    15,     "mesh_sta_5g"},
#endif

#ifdef TCHCBRV2_PORT // for Broadcom based platforms
    {0, 0,  "wl0.1",   "",  "brlan0",  100,    0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",   "",  "brlan0",  100,    1,      "private_ssid_5g"},
    {0, 0,  "wl0.2",   "",  "brlan1",  101,    2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",   "",  "brlan1",  101,    3,      "iot_ssid_5g"},
    {0, 0,  "wl0.3",   "",  "brlan2",  102,    4,      "hotspot_open_2g"},
    {1, 1,  "wl1.3",   "",  "brlan3",  103,    5,      "hotspot_open_5g"},
    {0, 0,  "wl0.4",   "",  "br106",   106,    6,      "lnf_psk_2g"},
    {1, 1,  "wl1.4",   "",  "br106",   106,    7,      "lnf_psk_5g"},
    {0, 0,  "wl0.5",   "",  "brlan4",  104,    8,      "hotspot_secure_2g"},
    {1, 1,  "wl1.5",   "",  "brlan5",  105,    9,      "hotspot_secure_5g"},
    {0, 0,  "wl0.6",   "",  "br106",   106,    10,     "lnf_radius_2g"},
    {1, 1,  "wl1.6",   "",  "br106",   106,    11,     "lnf_radius_5g"},
    {0, 0,  "wl0.7",   "",  "brlan112",  0,    12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",   "",  "brlan113",  0,    13,     "mesh_backhaul_5g"},
    {0, 0,  "wl0",     "",  "brlan1",    0,    14,     "mesh_sta_2g"},
    {1, 1,  "wl1",     "",  "brlan1",    0,    15,     "mesh_sta_5g"},
#endif

#ifdef VNTXER5_PORT // for Qualcomm based platforms
    {1, 0,  "ath0",    "",   "brlan0",  100,    0,     "private_ssid_2g"},
    {2, 1,  "ath1",    "",   "brlan0",  100,    1,     "private_ssid_5g"},
    {1, 0,  "ath2",    "",   "brlan1",  101,    2,     "iot_ssid_2g"},
    {2, 1,  "ath3",    "",   "brlan1",  101,    3,     "iot_ssid_5g"},
    {1, 0,  "ath4",    "",   "brlan2",  102,    4,     "hotspot_open_2g"},
    {2, 1,  "ath5",    "",   "brlan3",  103,    5,     "hotspot_open_5g"},
    {1, 0,  "ath6",    "",   "br106",   106,    6,     "lnf_psk_2g"},
    {2, 1,  "ath7",    "",   "br106",   106,    7,     "lnf_psk_5g"},
    {1, 0,  "ath8",    "",   "brlan4",  104,    8,     "hotspot_secure_2g"},
    {2, 1,  "ath9",    "",   "brlan5",  105,    9,     "hotspot_secure_5g"},
    {1, 0,  "ath10",   "",   "br106",   106,    10,    "lnf_radius_2g"},
    {2, 1,  "ath11",   "",   "br106",   106,    11,    "lnf_radius_5g"},
    {1, 0,  "ath12",   "",   "brlan112",  0,    12,    "mesh_backhaul_2g"},
    {2, 1,  "ath13",   "",   "brlan113",  0,    13,    "mesh_backhaul_5g"},
    {1, 0,  "ath14",   "",   "brlan1",    0,    14,    "mesh_sta_2g"},
    {2, 1,  "ath15",   "",   "brlan1",    0,    15,    "mesh_sta_5g"},
#endif

#ifdef TARGET_GEMINI7_2 // for Qualcomm based platforms
    {1, 0,  "home-ap-24",   "", "br-home",  100,   0,  "private_ssid_2g"},
    {2, 1,  "home-ap-50",   "", "br-home",  100,   1,  "private_ssid_5g"},
    {1, 0,  "bhaul-ap-24",  "", "",           0,  12,  "mesh_backhaul_2g"},
    {2, 1,  "bhaul-ap-50",  "", "",           0,  13,  "mesh_backhaul_5g"},
    {1, 0,  "bhaul-sta-24", "", "",           0,  14,  "mesh_sta_2g"},
    {2, 1,  "bhaul-sta-50", "", "",           0,  15,  "mesh_sta_5g"},
#endif

#ifdef CMXB7_PORT // for Intel based platforms
    {1, 0,  "wlan0.0", "",   "brlan0",  100, 0,      "private_ssid_2g"},
    {0, 1,  "wlan2.0", "",   "brlan0",  100, 1,      "private_ssid_5g"},
    {1, 0,  "wlan0.1", "",   "brlan1",  101, 2,      "iot_ssid_2g"},
    {0, 1,  "wlan2.1", "",   "brlan1",  101, 3,      "iot_ssid_5g"},
    {1, 0,  "wlan0.2", "",   "brlan2",  102, 4,      "hotspot_open_2g"},
    {0, 1,  "wlan2.2", "",   "brlan3",  103, 5,      "hotspot_open_5g"},
    {1, 0,  "wlan0.3", "",   "br106",   106, 6,      "lnf_psk_2g"},
    {0, 1,  "wlan2.3", "",   "br106",   106, 7,      "lnf_psk_5g"},
    {1, 0,  "wlan0.4", "",   "brlan4",  104, 8,      "hotspot_secure_2g"},
    {0, 1,  "wlan2.4", "",   "brlan5",  105, 9,      "hotspot_secure_5g"},
    {1, 0,  "wlan0.5", "",   "br106",   106, 10,     "lnf_radius_2g"},
    {0, 1,  "wlan2.5", "",   "br106",   106, 11,     "lnf_radius_5g"},
    {1, 0,  "wlan0.6", "",   "brlan112",112, 12,     "mesh_backhaul_2g"},
    {0, 1,  "wlan2.6", "",   "brlan113",113, 13,     "mesh_backhaul_5g"},
    {1, 0,  "wlan1",   "",   "brlan1",    0, 14,     "mesh_sta_2g"},
    {0, 1,  "wlan3",   "",   "brlan1",    0, 15,     "mesh_sta_5g"},   
#endif

#ifdef XLE_PORT // for Broadcom XLE

#if defined (XLE_3_RADIO_SUPPORT) && defined(XLE_BCM_SDK_504L04P3)
    {1, 0,  "wl0.1",   "",  "brlan0",  100,    0,      "private_ssid_2g"},
    {2, 1,  "wl1.1",   "",  "brlan0",  100,    1,      "private_ssid_5gl"},
    {1, 0,  "wl0.2",   "",  "brlan1",  101,    2,      "iot_ssid_2g"},
    {2, 1,  "wl1.2",   "",  "brlan1",  101,    3,      "iot_ssid_5gl"},
    {1, 0,  "wl0.3",   "",  "brlan2",  102,    4,      "hotspot_open_2g"},
    {2, 1,  "wl1.3",   "",  "brlan3",  103,    5,      "hotspot_open_5gl"},
    {1, 0,  "wl0.4",   "",  "br106",   106,    6,      "lnf_psk_2g"},
    {2, 1,  "wl1.4",   "",  "br106",   106,    7,      "lnf_psk_5gl"},
    {1, 0,  "wl0.5",   "",  "brlan4",  104,    8,      "hotspot_secure_2g"},
    {2, 1,  "wl1.5",   "",  "brlan5",  105,    9,      "hotspot_secure_5gl"},
    {1, 0,  "wl0.6",   "",  "br106",   106,    10,     "lnf_radius_2g"},
    {2, 1,  "wl1.6",   "",  "br106",   106,    11,     "lnf_radius_5gl"},
    {1, 0,  "wl0.7",   "",  "brlan112",112,    12,     "mesh_backhaul_2g"},
    {2, 1,  "wl1.7",   "",  "brlan113",113,    13,     "mesh_backhaul_5gl"},
    {1, 0,  "wl0",     "",  "",          0,    14,     "mesh_sta_2g"},
    {2, 1,  "wl1",     "",  "",          0,    15,     "mesh_sta_5gl"},
    {0, 2,  "wl2.1",   "",  "brlan0",  100,    16,     "private_ssid_5gh"},
    {0, 2,  "wl2.2",   "",  "brlan1",  101,    17,     "iot_ssid_5gh"},
    {0, 2,  "wl2.3",   "",  "brlan3",  103,    18,     "hotspot_open_5gh"},
    {0, 2,  "wl2.4",   "",  "br106",   106,    19,     "lnf_psk_5gh"},
    {0, 2,  "wl2.5",   "",  "brlan5",  105,    20,     "hotspot_secure_5gh"},
    {0, 2,  "wl2.6",   "",  "br106",   106,    21,     "lnf_radius_5gh"},
    {0, 2,  "wl2.7",   "",  "brlan113",114,    22,     "mesh_backhaul_5gh"},
    {0, 2,  "wl2",     "",  "",          0,    23,     "mesh_sta_5gh"},
#elif defined (XLE_3_RADIO_SUPPORT)
    {0, 0,  "wl0.1",   "",  "brlan0",  100,    0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",   "",  "brlan0",  100,    1,      "private_ssid_5gl"},
    {0, 0,  "wl0.2",   "",  "brlan1",  101,    2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",   "",  "brlan1",  101,    3,      "iot_ssid_5gl"},
    {0, 0,  "wl0.3",   "",  "brlan2",  102,    4,      "hotspot_open_2g"},
    {1, 1,  "wl1.3",   "",  "brlan3",  103,    5,      "hotspot_open_5gl"},
    {0, 0,  "wl0.4",   "",  "br106",   106,    6,      "lnf_psk_2g"},
    {1, 1,  "wl1.4",   "",  "br106",   106,    7,      "lnf_psk_5gl"},
    {0, 0,  "wl0.5",   "",  "brlan4",  104,    8,      "hotspot_secure_2g"},
    {1, 1,  "wl1.5",   "",  "brlan5",  105,    9,      "hotspot_secure_5gl"},
    {0, 0,  "wl0.6",   "",  "br106",   106,    10,     "lnf_radius_2g"},
    {1, 1,  "wl1.6",   "",  "br106",   106,    11,     "lnf_radius_5gl"},
    {0, 0,  "wl0.7",   "",  "brlan112",112,    12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",   "",  "brlan113",113,    13,     "mesh_backhaul_5gl"},
    {0, 0,  "wl0",     "",  "",          0,    14,     "mesh_sta_2g"},
    {1, 1,  "wl1",     "",  "",          0,    15,     "mesh_sta_5gl"},
    {2, 2,  "wl2.1",   "",  "brlan0",  100,    16,     "private_ssid_5gh"},
    {2, 2,  "wl2.2",   "",  "brlan1",  101,    17,     "iot_ssid_5gh"},
    {2, 2,  "wl2.3",   "",  "brlan3",  103,    18,     "hotspot_open_5gh"},
    {2, 2,  "wl2.4",   "",  "br106",   106,    19,     "lnf_psk_5gh"},
    {2, 2,  "wl2.5",   "",  "brlan5",  105,    20,     "hotspot_secure_5gh"},
    {2, 2,  "wl2.6",   "",  "br106",   106,    21,     "lnf_radius_5gh"},
    {2, 2,  "wl2.7",   "",  "brlan113",114,    22,     "mesh_backhaul_5gh"},
    {2, 2,  "wl2",     "",  "",          0,    23,     "mesh_sta_5gh"},

#else
    {0, 0,  "wl0.1",   "",  "brlan0",  100,    0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",   "",  "brlan0",  100,    1,      "private_ssid_5g"},
    {0, 0,  "wl0.2",   "",  "brlan1",  101,    2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",   "",  "brlan1",  101,    3,      "iot_ssid_5g"},
    {0, 0,  "wl0.3",   "",  "brlan2",  102,    4,      "hotspot_open_2g"},
    {1, 1,  "wl1.3",   "",  "brlan3",  103,    5,      "hotspot_open_5g"},
    {0, 0,  "wl0.4",   "",  "br106",   106,    6,      "lnf_psk_2g"},
    {1, 1,  "wl1.4",   "",  "br106",   106,    7,      "lnf_psk_5g"},
    {0, 0,  "wl0.5",   "",  "brlan4",  104,    8,      "hotspot_secure_2g"},
    {1, 1,  "wl1.5",   "",  "brlan5",  105,    9,      "hotspot_secure_5g"},
    {0, 0,  "wl0.6",   "",  "br106",   106,    10,     "lnf_radius_2g"},
    {1, 1,  "wl1.6",   "",  "br106",   106,    11,     "lnf_radius_5g"},
    {0, 0,  "wl0.7",   "",  "brlan112",112,    12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",   "",  "brlan113",113,    13,     "mesh_backhaul_5g"},
    {0, 0,  "wl0",     "",  "",          0,    14,     "mesh_sta_2g"},
    {1, 1,  "wl1",     "",  "",          0,    15,     "mesh_sta_5g"},
#endif
#endif

#ifdef TCXB8_PORT
    {1, 0,  "wl0.1",   "",  "brlan0",   100,   0,      "private_ssid_2g"},
    {0, 1,  "wl1.1",   "",  "brlan0",   100,   1,      "private_ssid_5g"},
    {1, 0,  "wl0.2",   "",  "brlan1",   101,   2,      "iot_ssid_2g"},
    {0, 1,  "wl1.2",   "",  "brlan1",   101,   3,      "iot_ssid_5g"},
    {1, 0,  "wl0.3",   "",  "brlan2",   102,   4,      "hotspot_open_2g"},
    {0, 1,  "wl1.3",   "",  "brlan3",   103,   5,      "hotspot_open_5g"},
    {1, 0,  "wl0.4",   "",  "br106",    106,   6,      "lnf_psk_2g"},
    {0, 1,  "wl1.4",   "",  "br106",    106,   7,      "lnf_psk_5g"},
    {1, 0,  "wl0.5",   "",  "brlan4",   104,   8,      "hotspot_secure_2g"},
    {0, 1,  "wl1.5",   "",  "brlan5",   105,   9,      "hotspot_secure_5g"},
    {1, 0,  "wl0.6",   "",  "br106",    106,   10,     "lnf_radius_2g"},
    {0, 1,  "wl1.6",   "",  "br106",    106,   11,     "lnf_radius_5g"},
    {1, 0,  "wl0.7",   "",  "brlan112", 112,   12,     "mesh_backhaul_2g"},
    {0, 1,  "wl1.7",   "",  "brlan113", 113,   13,     "mesh_backhaul_5g"},
    {1, 0,  "wl0",     "",  "",         0,     14,     "mesh_sta_2g"},
    {0, 1,  "wl1",     "",  "",         0,     15,     "mesh_sta_5g"},
    {2, 2,  "wl2.1",   "",  "brlan0",   100,   16,     "private_ssid_6g"},
    {2, 2,  "wl2.2",   "",  "brlan1",   101,   17,     "iot_ssid_6g"},
    {2, 2,  "wl2.3",   "",  "bropen6g", 2253,  18,     "hotspot_open_6g"},
    {2, 2,  "wl2.4",   "",  "br106",    106,   19,     "lnf_psk_6g"},
    {2, 2,  "wl2.5",   "",  "brsecure6g",2256, 20,     "hotspot_secure_6g"},
#if 0
    {2, 2,  "wl2.6",   "",  "br106",    106,   21,     "lnf_radius_6g"},
#endif
    {2, 2,  "wl2.7",   "",  "brlan114", 114,   22,     "mesh_backhaul_6g"},
    {2, 2,  "wl2",     "",  "",         0,     23,     "mesh_sta_6g"},
#endif

#ifdef XB10_PORT
    {2, 0,  "wl0.1",   "",  "brlan0",   100,   0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",   "",  "brlan0",   100,   1,      "private_ssid_5g"},
    {2, 0,  "wl0.2",   "",  "brlan1",   101,   2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",   "",  "brlan1",   101,   3,      "iot_ssid_5g"},
    {2, 0,  "wl0.3",   "",  "brlan2",   102,   4,      "hotspot_open_2g"},
    {1, 1,  "wl1.3",   "",  "brlan3",   103,   5,      "hotspot_open_5g"},
    {2, 0,  "wl0.4",   "",  "br106",    106,   6,      "lnf_psk_2g"},
    {1, 1,  "wl1.4",   "",  "br106",    106,   7,      "lnf_psk_5g"},
    {2, 0,  "wl0.5",   "",  "brlan4",   104,   8,      "hotspot_secure_2g"},
    {1, 1,  "wl1.5",   "",  "brlan5",   105,   9,      "hotspot_secure_5g"},
    {2, 0,  "wl0.6",   "",  "br106",    106,   10,     "lnf_radius_2g"},
    {1, 1,  "wl1.6",   "",  "br106",    106,   11,     "lnf_radius_5g"},
    {2, 0,  "wl0.7",   "",  "brlan112", 112,   12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",   "",  "brlan113", 113,   13,     "mesh_backhaul_5g"},
    {2, 0,  "wl0",     "",  "",         0,     14,     "mesh_sta_2g"},
    {1, 1,  "wl1",     "",  "",         0,     15,     "mesh_sta_5g"},
    {0, 2,  "wl2.1",   "",  "brlan0",   100,   16,     "private_ssid_6g"},
    {0, 2,  "wl2.2",   "",  "brlan1",   101,   17,     "iot_ssid_6g"},
    {0, 2,  "wl2.3",   "",  "bropen6g", 2253,  18,     "hotspot_open_6g"},
    {0, 2,  "wl2.4",   "",  "br106",    106,   19,     "lnf_psk_6g"},
    {0, 2,  "wl2.5",   "",  "brsecure6g",2256, 20,     "hotspot_secure_6g"},
#if 0
    {0, 2,  "wl2.6",   "",  "br106",    106,   21,     "lnf_radius_6g"},
#endif
    {0, 2,  "wl2.7",   "",  "brlan114", 114,   22,     "mesh_backhaul_6g"},
    {0, 2,  "wl2",     "",  "",         0,     23,     "mesh_sta_6g"},
#endif

#ifdef SCXER10_PORT
    {1, 0,  "wl0.1",   "",  "brlan0",   100,   0,      "private_ssid_2g"},
    {2, 1,  "wl1.1",   "",  "brlan0",   100,   1,      "private_ssid_5g"},
    {1, 0,  "wl0.2",   "",  "brlan1",   101,   2,      "iot_ssid_2g"},
    {2, 1,  "wl1.2",   "",  "brlan1",   101,   3,      "iot_ssid_5g"},
    {1, 0,  "wl0.3",   "",  "brlan2",   102,   4,      "hotspot_open_2g"},
    {2, 1,  "wl1.3",   "",  "brlan3",   103,   5,      "hotspot_open_5g"},
    {1, 0,  "wl0.4",   "",  "br106",    106,   6,      "lnf_psk_2g"},
    {2, 1,  "wl1.4",   "",  "br106",    106,   7,      "lnf_psk_5g"},
    {1, 0,  "wl0.5",   "",  "brlan4",   104,   8,      "hotspot_secure_2g"},
    {2, 1,  "wl1.5",   "",  "brlan5",   105,   9,      "hotspot_secure_5g"},
    {1, 0,  "wl0.6",   "",  "br106",    106,   10,     "lnf_radius_2g"},
    {2, 1,  "wl1.6",   "",  "br106",    106,   11,     "lnf_radius_5g"},
    {1, 0,  "wl0.7",   "",  "brlan112", 112,   12,     "mesh_backhaul_2g"},
    {2, 1,  "wl1.7",   "",  "brlan113", 113,   13,     "mesh_backhaul_5g"},
    {1, 0,  "wl0",     "",  "",         0,     14,     "mesh_sta_2g"},
    {2, 1,  "wl1",     "",  "",         0,     15,     "mesh_sta_5g"},
    {0, 2,  "wl2.1",   "",  "brlan0",   100,   16,     "private_ssid_6g"},
    {0, 2,  "wl2.2",   "",  "brlan1",   101,   17,     "iot_ssid_6g"},
    {0, 2,  "wl2.3",   "",  "bropen6g", 2253,  18,     "hotspot_open_6g"},
    {0, 2,  "wl2.4",   "",  "br106",    106,   19,     "lnf_psk_6g"},
    {0, 2,  "wl2.5",   "",  "brsecure6g",2256, 20,     "hotspot_secure_6g"},
#if 0
    {0, 2,  "wl2.6",   "",  "br106",    106,   21,     "lnf_radius_6g"},
#endif
    {0, 2,  "wl2.7",   "",  "brlan114", 114,   22,     "mesh_backhaul_6g"},
    {0, 2,  "wl2",     "",  "",         0,     23,     "mesh_sta_6g"},
#endif

#ifdef SKYSR213_PORT // for Broadcom based platforms
    {0, 0,  "wl0.1",   "",  "brlan0",  100,    0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",   "",  "brlan0",  100,    1,      "private_ssid_5g"},
    {0, 0,  "wl0.2",   "",  "brlan9",  101,    2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",   "",  "brlan10", 101,    3,      "iot_ssid_5g"},
    {0, 0,  "wl0.7",   "",  "brlan6",    0,    12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",   "",  "brlan7",    0,    13,     "mesh_backhaul_5g"},
    {0, 0,  "wl0",     "",  "",          0,    14,     "mesh_sta_2g"},
    {1, 1,  "wl1",     "",  "",          0,    15,     "mesh_sta_5g"},
#endif

#ifdef RDKB_ONE_WIFI_PROD
{0, 0,  "wl0.1",   "brlan0",   100,   0,      "private_ssid_2g"},
{2, 1,  "wl1.1",   "brlan0",   100,   1,      "private_ssid_5g"},
{0, 0,  "wl0.2",   "brlan1",   101,   2,      "iot_ssid_2g"},
{2, 1,  "wl1.2",   "brlan1",   101,   3,      "iot_ssid_5g"},
{0, 0,  "wl0.3",   "brlan2",   102,   4,      "hotspot_open_2g"},
{2, 1,  "wl1.3",   "brlan3",   103,   5,      "hotspot_open_5g"},
{0, 0,  "wl0.4",   "br106",    106,   6,      "lnf_psk_2g"},
{2, 1,  "wl1.4",   "br106",    106,   7,      "lnf_psk_5g"},
{0, 0,  "wl0.5",   "brlan4",   104,   8,      "hotspot_secure_2g"},
{2, 1,  "wl1.5",   "brlan5",   105,   9,      "hotspot_secure_5g"},
{0, 0,  "wl0.6",   "br106",    106,   10,     "lnf_radius_2g"},
{2, 1,  "wl1.6",   "br106",    106,   11,     "lnf_radius_5g"},
{0, 0,  "wl0.7",   "brlan112", 112,   12,     "mesh_backhaul_2g"},
{2, 1,  "wl1.7",   "brlan113", 113,   13,     "mesh_backhaul_5g"},
{0, 0,  "wl0",     "",         0,     14,     "mesh_sta_2g"},
{2, 1,  "wl1",     "",         0,     15,     "mesh_sta_5g"},
#ifdef RDKB_ONE_WIFI_3_RADIO_SUPPORT
{1, 2,  "wl2.1",   "brlan0",   100,   16,     "private_ssid_6g"},
{1, 2,  "wl2.2",   "brlan1",   101,   17,     "iot_ssid_6g"},
{1, 2,  "wl2.3",   "bropen6g", 2253,  18,     "hotspot_open_6g"},
{1, 2,  "wl2.5",   "brsecure6g",2256, 20,     "hotspot_secure_6g"},
{1, 2,  "wl2.7",   "brlan114", 114,   22,     "mesh_backhaul_6g"},
{1, 2,  "wl2",     "",         0,     23,     "mesh_sta_6g"},
#endif /* RDKB_ONE_WIFI_3_RADIO_SUPPORT */
#endif /* RDKB_ONE_WIFI_PROD */
  
#ifdef SCXF10_PORT
    {2, 0,  "wl0.1",  "", "brlan0",   100,   0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",  "", "brlan0",   100,   1,      "private_ssid_5g"},
    {2, 0,  "wl0.2",  "", "brlan1",   101,   2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",  "", "brlan1",   101,   3,      "iot_ssid_5g"},
    {2, 0,  "wl0.3",  "", "brlan2",   102,   4,      "hotspot_open_2g"},
    {1, 1,  "wl1.3",  "", "brlan3",   103,   5,      "hotspot_open_5g"},
    {2, 0,  "wl0.4",  "", "br106",    106,   6,      "lnf_psk_2g"},
    {1, 1,  "wl1.4",  "", "br106",    106,   7,      "lnf_psk_5g"},
    {2, 0,  "wl0.5",  "", "brlan4",   104,   8,      "hotspot_secure_2g"},
    {1, 1,  "wl1.5",  "", "brlan5",   105,   9,      "hotspot_secure_5g"},
    {2, 0,  "wl0.6",  "", "br106",    106,   10,     "lnf_radius_2g"},
    {1, 1,  "wl1.6",  "", "br106",    106,   11,     "lnf_radius_5g"},
    {2, 0,  "wl0.7",  "", "brlan112", 112,   12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",  "", "brlan113", 113,   13,     "mesh_backhaul_5g"},
    {2, 0,  "wl0",    "", "",         0,     14,     "mesh_sta_2g"},
    {1, 1,  "wl1",    "", "",         0,     15,     "mesh_sta_5g"},
    {0, 2,  "wl2.1",  "", "brlan0",   100,   16,     "private_ssid_6g"},
    {0, 2,  "wl2.2",  "", "brlan1",   101,   17,     "iot_ssid_6g"},
    {0, 2,  "wl2.3",  "", "bropen6g", 2253,  18,     "hotspot_open_6g"},
    {0, 2,  "wl2.4",  "", "br106",    106,   19,     "lnf_psk_6g"},
    {0, 2,  "wl2.5",  "", "brsecure6g",2256, 20,     "hotspot_secure_6g"},
#if 0
    {0, 2,  "wl2.6",  "", "br106",    106,   21,     "lnf_radius_6g"},
#endif
    {0, 2,  "wl2.7",  "", "brlan114", 114,   22,     "mesh_backhaul_6g"},
    {0, 2,  "wl2",    "", "",         0,     23,     "mesh_sta_6g"},
#endif /* SCXF10_PORT */
    // for Intel based platforms
};
#endif

#ifdef CONFIG_WIFI_EMULATOR
static radio_interface_mapping_t *l_radio_interface_map = NULL;
#else
static const radio_interface_mapping_t *l_radio_interface_map;
static unsigned int l_radio_interface_map_size;
static const radio_interface_mapping_t static_radio_interface_map[] = {
#if defined(TCXB7_PORT) || defined(SKYSR213_PORT) || defined(TCHCBRV2_PORT)
    { 0, 0, "radio1", "wl0"},
    { 1, 1, "radio2", "wl1"},
#endif

#if defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2) 
    { 1, 0, "radio1", "wifi0"},
    { 2, 1, "radio2", "wifi1"},
#endif

#if defined(XLE_PORT)
    { 0, 0, "radio1", "wl0"},
    { 1, 1, "radio2", "wl1"},
    { 2, 2, "radio3", "wl2"},
#endif

#if defined(TCXB8_PORT) 
    { 1, 0, "radio1", "wl0"},
    { 0, 1, "radio2", "wl1"},
    { 2, 2, "radio3", "wl2"},
#endif

#if defined(XB10_PORT) 
    { 2, 0, "radio1", "wl0"},
    { 1, 1, "radio2", "wl1"},
    { 0, 2, "radio3", "wl2"},
#endif

#if defined(SCXER10_PORT) 
    { 1, 0, "radio1", "wl0"},
    { 2, 1, "radio2", "wl1"},
    { 0, 2, "radio3", "wl2"},
#endif

#if defined(SCXF10_PORT) 
    { 2, 0, "radio1", "wl0"},
    { 1, 1, "radio2", "wl1"},
    { 0, 2, "radio3", "wl2"},
#endif
 
#ifdef CMXB7_PORT // for Intel based platforms
    { 1, 0, "radio1", "wlan0"},
    { 0, 1, "radio2", "wlan2"},
#endif

#ifdef RASPBERRY_PI_PORT
#if !defined(PLATFORM_LINUX)
    { 0, 0, "radio1", "wlan0"},
    { 1, 1, "radio2", "wlan1"},
#else
    { 0, 0, "radio1", "wlan0"},
#endif
#endif

#if defined(RDKB_ONE_WIFI_PROD)
    { 2, 0, "radio1", "wl0"},
    { 1, 1, "radio2", "wl1"},
#ifdef RDKB_ONE_WIFI_3_RADIO_SUPPORT
    { 0, 2, "radio3", "wl2"},
#endif
#endif
};
#endif

const wifi_driver_info_t  driver_info = {
#ifdef RASPBERRY_PI_PORT
    "pi4",
    "cfg80211",
    {"RaspBerry","RaspBerry","PI","PI","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef BANANA_PI_PORT // for reference device platforms
    "bpi4",
    "cfg80211",
    {"Banana Filogic Wireless Gateway","Banana","PI","PI","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef TCXB7_PORT // for Broadcom based platforms
    "tcxb7",
    "dhd",
    {"Xfinity Wireless Gateway","Technicolor","XB7","CGM4331COM","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef VNTXER5_PORT // for Qualcomm based platforms
    "vntxer5",
    "wifi_3_0",
    {"Xfinity Wireless Gateway","Vantiva","XER5","XER5","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef TARGET_GEMINI7_2
    "dt_gemini7_2",
    "wifi_3_0",
    {"Wireless Extender","DT","GEMINI7_2","GR-EXT02A-CTS","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    NULL,
    NULL,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    platform_get_reg_domain,
#endif 

#ifdef TCXB8_PORT // for Broadcom based platforms
    "tcxb8",
    "dhd",
    {"Xfinity Wireless Gateway","Technicolor","XB8","CGM4981COM","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif


#ifdef TCHCBRV2_PORT // for Broadcom based platforms
    "cbrv2",
    "dhd",
    {"Xfinity Wireless Gateway","Technicolor","CBRV2","CGA4332COM","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef XB10_PORT // for Broadcom based platforms
    "xb10",
    "dhd",
#if defined(WPS_VBVXB10_INFO) || defined(CONFIG_WIFI_EMULATOR)
    {"Xfinity Wireless Gateway","Technicolor","XB10","CGM601TCOM","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
#endif
#ifdef WPS_SERCOMMXB10_INFO
    {"Xfinity Wireless Gateway","Sercomm","XB10","SG417DBCT","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
#endif
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef SCXER10_PORT // for Broadcom based platforms
    "xer10",
    "dhd",
    {"Xfinity Wireless Gateway","Sercomm","XER10","SCER11BEL","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef SCXF10_PORT // for Broadcom based platforms
    "xf10",
    "dhd",
    {"Xfinity Wireless Gateway","Sercomm","XF10","SCXF11BFL","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif
 
#ifdef CMXB7_PORT
    "cmxb7",
    "mtlk",
    {"Xfinity Wireless Gateway","Commscope","XB7","TG4482PC2","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef XLE_PORT // for Broadcom XLE
    "xle",
    "cfg80211",
    {"Xfinity Wireless Gateway","SKY","XLE","WNXL11BWL","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif

#ifdef SKYSR213_PORT // for Broadcom HUB6
    "skysr213",
    "dhd",
    {"Sky Wireless Gateway","SKY","HUB6","SKYSR213","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_chanspec_list,
    platform_set_acs_exclusion_list,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif
#ifdef RDKB_ONE_WIFI_PROD // for Broadcom based platforms
    "rdkb",
    "dhd",
    {"rdkb","rdkb","cm","cm","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_pre_create_vap,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default,
    platform_wps_event,
    platform_flags_init,
    platform_get_aid,
    platform_free_aid,
    platform_sync_done,
    platform_update_radio_presence,
    platform_set_txpower,
    platform_set_offload_mode,
    platform_get_acl_num,
    platform_get_vendor_oui,
    platform_set_neighbor_report,
    platform_get_radio_phytemperature,
    platform_set_dfs,
    platform_get_radio_caps,
    NULL,
#endif
    
};

static struct wifiCountryEnumStrMap wifi_country_map[] =
{
    {wifi_countrycode_AC,"AC"}, /**< ASCENSION ISLAND */
    {wifi_countrycode_AD,"AD"}, /**< ANDORRA */
    {wifi_countrycode_AE,"AE"}, /**< UNITED ARAB EMIRATES */
    {wifi_countrycode_AF,"AF"}, /**< AFGHANISTAN */
    {wifi_countrycode_AG,"AG"}, /**< ANTIGUA AND BARBUDA */
    {wifi_countrycode_AI,"AI"}, /**< ANGUILLA */
    {wifi_countrycode_AL,"AL"}, /**< ALBANIA */
    {wifi_countrycode_AM,"AM"}, /**< ARMENIA */
    {wifi_countrycode_AN,"AN"}, /**< NETHERLANDS ANTILLES */
    {wifi_countrycode_AO,"AO"}, /**< ANGOLA */
    {wifi_countrycode_AQ,"AQ"}, /**< ANTARCTICA */
    {wifi_countrycode_AR,"AR"}, /**< ARGENTINA */
    {wifi_countrycode_AS,"AS"}, /**< AMERICAN SAMOA */
    {wifi_countrycode_AT,"AT"}, /**< AUSTRIA */
    {wifi_countrycode_AU,"AU"}, /**< AUSTRALIA */
    {wifi_countrycode_AW,"AW"}, /**< ARUBA */
    {wifi_countrycode_AZ,"AZ"}, /**< AZERBAIJAN */
    {wifi_countrycode_BA,"BA"}, /**< BOSNIA AND HERZEGOVINA */
    {wifi_countrycode_BB,"BB"}, /**< BARBADOS */
    {wifi_countrycode_BD,"BD"}, /**< BANGLADESH */
    {wifi_countrycode_BE,"BE"}, /**< BELGIUM */
    {wifi_countrycode_BF,"BF"}, /**< BURKINA FASO */
    {wifi_countrycode_BG,"BG"}, /**< BULGARIA */
    {wifi_countrycode_BH,"BH"}, /**< BAHRAIN */
    {wifi_countrycode_BI,"BI"}, /**< BURUNDI */
    {wifi_countrycode_BJ,"BJ"}, /**< BENIN */
    {wifi_countrycode_BM,"BM"}, /**< BERMUDA */
    {wifi_countrycode_BN,"BN"}, /**< BRUNEI DARUSSALAM */
    {wifi_countrycode_BO,"BO"}, /**< BOLIVIA */
    {wifi_countrycode_BR,"BR"}, /**< BRAZIL */
    {wifi_countrycode_BS,"BS"}, /**< BAHAMAS */
    {wifi_countrycode_BT,"BT"}, /**< BHUTAN */
    {wifi_countrycode_BV,"BV"}, /**< BOUVET ISLAND */
    {wifi_countrycode_BW,"BW"}, /**< BOTSWANA */
    {wifi_countrycode_BY,"BY"}, /**< BELARUS */
    {wifi_countrycode_BZ,"BZ"}, /**< BELIZE */
    {wifi_countrycode_CA,"CA"}, /**< CANADA */
    {wifi_countrycode_CC,"CC"}, /**< COCOS (KEELING) ISLANDS */
    {wifi_countrycode_CD,"CD"}, /**< CONGO,THE DEMOCRATIC REPUBLIC OF THE */
    {wifi_countrycode_CF,"CF"}, /**< CENTRAL AFRICAN REPUBLIC */
    {wifi_countrycode_CG,"CG"}, /**< CONGO */
    {wifi_countrycode_CH,"CH"}, /**< SWITZERLAND */
    {wifi_countrycode_CI,"CI"}, /**< COTE D'IVOIRE */
    {wifi_countrycode_CK,"CK"}, /**< COOK ISLANDS */
    {wifi_countrycode_CL,"CL"}, /**< CHILE */
    {wifi_countrycode_CM,"CM"}, /**< CAMEROON */
    {wifi_countrycode_CN,"CN"}, /**< CHINA */
    {wifi_countrycode_CO,"CO"}, /**< COLOMBIA */
    {wifi_countrycode_CP,"CP"}, /**< CLIPPERTON ISLAND */
    {wifi_countrycode_CR,"CR"}, /**< COSTA RICA */
    {wifi_countrycode_CU,"CU"}, /**< CUBA */
    {wifi_countrycode_CV,"CV"}, /**< CAPE VERDE */
    {wifi_countrycode_CY,"CY"}, /**< CYPRUS */
    {wifi_countrycode_CX,"CX"}, /**< CHRISTMAS ISLAND */
    {wifi_countrycode_CZ,"CZ"}, /**< CZECH REPUBLIC */
    {wifi_countrycode_DE,"DE"}, /**< GERMANY */
    {wifi_countrycode_DJ,"DJ"}, /**< DJIBOUTI */
    {wifi_countrycode_DK,"DK"}, /**< DENMARK */
    {wifi_countrycode_DM,"DM"}, /**< DOMINICA */
    {wifi_countrycode_DO,"DO"}, /**< DOMINICAN REPUBLIC */
    {wifi_countrycode_DZ,"DZ"}, /**< ALGERIA */
    {wifi_countrycode_EC,"EC"}, /**< ECUADOR */
    {wifi_countrycode_EE,"EE"}, /**< ESTONIA */
    {wifi_countrycode_EG,"EG"}, /**< EGYPT */
    {wifi_countrycode_EH,"EH"}, /**< WESTERN SAHARA */
    {wifi_countrycode_ER,"ER"}, /**< ERITREA */
    {wifi_countrycode_ES,"ES"}, /**< SPAIN */
    {wifi_countrycode_ET,"ET"}, /**< ETHIOPIA */
    {wifi_countrycode_FI,"FI"}, /**< FINLAND */
    {wifi_countrycode_FJ,"FJ"}, /**< FIJI */
    {wifi_countrycode_FK,"FK"}, /**< FALKLAND ISLANDS (MALVINAS) */
    {wifi_countrycode_FM,"FM"}, /**< MICRONESIA FEDERATED STATES OF */
    {wifi_countrycode_FO,"FO"}, /**< FAROE ISLANDS */
    {wifi_countrycode_FR,"FR"}, /**< FRANCE */
    {wifi_countrycode_GA,"GA"}, /**< GABON */
    {wifi_countrycode_GB,"GB"}, /**< UNITED KINGDOM */
    {wifi_countrycode_GD,"GD"}, /**< GRENADA */
    {wifi_countrycode_GE,"GE"}, /**< GEORGIA */
    {wifi_countrycode_GF,"GF"}, /**< FRENCH GUIANA */
    {wifi_countrycode_GG,"GG"}, /**< GUERNSEY */
    {wifi_countrycode_GH,"GH"}, /**< GHANA */
    {wifi_countrycode_GI,"GI"}, /**< GIBRALTAR */
    {wifi_countrycode_GL,"GL"}, /**< GREENLAND */
    {wifi_countrycode_GM,"GM"}, /**< GAMBIA */
    {wifi_countrycode_GN,"GN"}, /**< GUINEA */
    {wifi_countrycode_GP,"GP"}, /**< GUADELOUPE */
    {wifi_countrycode_GQ,"GQ"}, /**< EQUATORIAL GUINEA */
    {wifi_countrycode_GR,"GR"}, /**< GREECE */
    {wifi_countrycode_GS,"GS"}, /**< SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS */
    {wifi_countrycode_GT,"GT"}, /**< GUATEMALA */
    {wifi_countrycode_GU,"GU"}, /**< GUAM */
    {wifi_countrycode_GW,"GW"}, /**< GUINEA-BISSAU */
    {wifi_countrycode_GY,"GY"}, /**< GUYANA */
    {wifi_countrycode_HR,"HR"}, /**< CROATIA */
    {wifi_countrycode_HT,"HT"}, /**< HAITI */
    {wifi_countrycode_HM,"HM"}, /**< HEARD ISLAND AND MCDONALD ISLANDS */
    {wifi_countrycode_HN,"HN"}, /**< HONDURAS */
    {wifi_countrycode_HK,"HK"}, /**< HONG KONG */
    {wifi_countrycode_HU,"HU"}, /**< HUNGARY */
    {wifi_countrycode_IS,"IS"}, /**< ICELAND */
    {wifi_countrycode_IN,"IN"}, /**< INDIA */
    {wifi_countrycode_ID,"ID"}, /**< INDONESIA */
    {wifi_countrycode_IR,"IR"}, /**< IRAN, ISLAMIC REPUBLIC OF */
    {wifi_countrycode_IQ,"IQ"}, /**< IRAQ */
    {wifi_countrycode_IE,"IE"}, /**< IRELAND */
    {wifi_countrycode_IL,"IL"}, /**< ISRAEL */
    {wifi_countrycode_IM,"IM"}, /**< MAN, ISLE OF */
    {wifi_countrycode_IT,"IT"}, /**< ITALY */
    {wifi_countrycode_IO,"IO"}, /**< BRITISH INDIAN OCEAN TERRITORY */
    {wifi_countrycode_JM,"JM"}, /**< JAMAICA */
    {wifi_countrycode_JP,"JP"}, /**< JAPAN */
    {wifi_countrycode_JE,"JE"}, /**< JERSEY */
    {wifi_countrycode_JO,"jo"}, /**< JORDAN */
    {wifi_countrycode_KE,"KE"}, /**< KENYA */
    {wifi_countrycode_KG,"KG"}, /**< KYRGYZSTAN */
    {wifi_countrycode_KH,"KH"}, /**< CAMBODIA */
    {wifi_countrycode_KI,"KI"}, /**< KIRIBATI */
    {wifi_countrycode_KM,"KM"}, /**< COMOROS */
    {wifi_countrycode_KN,"KN"}, /**< SAINT KITTS AND NEVIS */
    {wifi_countrycode_KP,"KP"}, /**< KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF */
    {wifi_countrycode_KR,"KR"}, /**< KOREA, REPUBLIC OF */
    {wifi_countrycode_KW,"KW"}, /**< KUWAIT */
    {wifi_countrycode_KY,"KY"}, /**< CAYMAN ISLANDS */
    {wifi_countrycode_KZ,"KZ"}, /**< KAZAKHSTAN */
    {wifi_countrycode_LA,"LA"}, /**< LAO PEOPLE'S DEMOCRATIC REPUBLIC */
    {wifi_countrycode_LB,"LB"}, /**< LEBANON */
    {wifi_countrycode_LC,"LC"}, /**< SAINT LUCIA */
    {wifi_countrycode_LI,"LI"}, /**< LIECHTENSTEIN */
    {wifi_countrycode_LK,"LK"}, /**< SRI LANKA */
    {wifi_countrycode_LR,"LR"}, /**< LIBERIA */
    {wifi_countrycode_LS,"LS"}, /**< LESOTHO */
    {wifi_countrycode_LT,"LT"}, /**< LITHUANIA */
    {wifi_countrycode_LU,"LU"}, /**< LUXEMBOURG */
    {wifi_countrycode_LV,"LV"}, /**< LATVIA */
    {wifi_countrycode_LY,"LY"}, /**< LIBYAN ARAB JAMAHIRIYA */
    {wifi_countrycode_MA,"MA"}, /**< MOROCCO */
    {wifi_countrycode_MC,"MC"}, /**< MONACO */
    {wifi_countrycode_MD,"MD"}, /**< MOLDOVA, REPUBLIC OF */
    {wifi_countrycode_ME,"ME"}, /**< MONTENEGRO */
    {wifi_countrycode_MG,"MG"}, /**< MADAGASCAR */
    {wifi_countrycode_MH,"MH"}, /**< MARSHALL ISLANDS */
    {wifi_countrycode_MK,"MK"}, /**< MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF */
    {wifi_countrycode_ML,"ML"}, /**< MALI */
    {wifi_countrycode_MM,"MM"}, /**< MYANMAR */
    {wifi_countrycode_MN,"MN"}, /**< MONGOLIA */
    {wifi_countrycode_MO,"MO"}, /**< MACAO */
    {wifi_countrycode_MQ,"MQ"}, /**< MARTINIQUE */
    {wifi_countrycode_MR,"MR"}, /**< MAURITANIA */
    {wifi_countrycode_MS,"MS"}, /**< MONTSERRAT */
    {wifi_countrycode_MT,"MT"}, /**< MALTA */
    {wifi_countrycode_MU,"MU"}, /**< MAURITIUS */
    {wifi_countrycode_MV,"MV"}, /**< MALDIVES */
    {wifi_countrycode_MW,"MW"}, /**< MALAWI */
    {wifi_countrycode_MX,"MX"}, /**< MEXICO */
    {wifi_countrycode_MY,"MY"}, /**< MALAYSIA */
    {wifi_countrycode_MZ,"MZ"}, /**< MOZAMBIQUE */
    {wifi_countrycode_NA,"NA"}, /**< NAMIBIA */
    {wifi_countrycode_NC,"NC"}, /**< NEW CALEDONIA */
    {wifi_countrycode_NE,"NE"}, /**< NIGER */
    {wifi_countrycode_NF,"NF"}, /**< NORFOLK ISLAND */
    {wifi_countrycode_NG,"NG"}, /**< NIGERIA */
    {wifi_countrycode_NI,"NI"}, /**< NICARAGUA */
    {wifi_countrycode_NL,"NL"}, /**< NETHERLANDS */
    {wifi_countrycode_NO,"NO"}, /**< NORWAY */
    {wifi_countrycode_NP,"NP"}, /**< NEPAL */
    {wifi_countrycode_NR,"NR"}, /**< NAURU */
    {wifi_countrycode_NU,"NU"}, /**< NIUE */
    {wifi_countrycode_NZ,"NZ"}, /**< NEW ZEALAND */
    {wifi_countrycode_MP,"MP"}, /**< NORTHERN MARIANA ISLANDS */
    {wifi_countrycode_OM,"OM"}, /**< OMAN */
    {wifi_countrycode_PA,"PA"}, /**< PANAMA */
    {wifi_countrycode_PE,"PE"}, /**< PERU */
    {wifi_countrycode_PF,"PF"}, /**< FRENCH POLYNESIA */
    {wifi_countrycode_PG,"PG"}, /**< PAPUA NEW GUINEA */
    {wifi_countrycode_PH,"PH"}, /**< PHILIPPINES */
    {wifi_countrycode_PK,"PK"}, /**< PAKISTAN */
    {wifi_countrycode_PL,"PL"}, /**< POLAND */
    {wifi_countrycode_PM,"PM"}, /**< SAINT PIERRE AND MIQUELON */
    {wifi_countrycode_PN,"PN"}, /**< PITCAIRN */
    {wifi_countrycode_PR,"PR"}, /**< PUERTO RICO */
    {wifi_countrycode_PS,"PS"}, /**< PALESTINIAN TERRITORY,OCCUPIED */
    {wifi_countrycode_PT,"PT"}, /**< PORTUGAL */
    {wifi_countrycode_PW,"PW"}, /**< PALAU */
    {wifi_countrycode_PY,"PY"}, /**< PARAGUAY */
    {wifi_countrycode_QA,"QA"}, /**< QATAR */
    {wifi_countrycode_RE,"RE"}, /**< REUNION */
    {wifi_countrycode_RO,"RO"}, /**< ROMANIA */
    {wifi_countrycode_RS,"RS"}, /**< SERBIA */
    {wifi_countrycode_RU,"RU"}, /**< RUSSIAN FEDERATION */
    {wifi_countrycode_RW,"RW"}, /**< RWANDA */
    {wifi_countrycode_SA,"SA"}, /**< SAUDI ARABIA */
    {wifi_countrycode_SB,"SB"}, /**< SOLOMON ISLANDS */
    {wifi_countrycode_SD,"SD"}, /**< SUDAN */
    {wifi_countrycode_SE,"SE"}, /**< SWEDEN */
    {wifi_countrycode_SC,"SC"}, /**< SEYCHELLES */
    {wifi_countrycode_SG,"SG"}, /**< SINGAPORE */
    {wifi_countrycode_SH,"SH"}, /**< SAINT HELENA */
    {wifi_countrycode_SI,"SI"}, /**< SLOVENIA */
    {wifi_countrycode_SJ,"SJ"}, /**< SVALBARD AND JAN MAYEN */
    {wifi_countrycode_SK,"SK"}, /**< SLOVAKIA */
    {wifi_countrycode_SL,"SL"}, /**< SIERRA LEONE */
    {wifi_countrycode_SM,"SM"}, /**< SAN MARINO */
    {wifi_countrycode_SN,"SN"}, /**< SENEGAL */
    {wifi_countrycode_SO,"SO"}, /**< SOMALIA */
    {wifi_countrycode_SR,"SR"}, /**< SURINAME */
    {wifi_countrycode_ST,"ST"}, /**< SAO TOME AND PRINCIPE */
    {wifi_countrycode_SV,"SV"}, /**< EL SALVADOR */
    {wifi_countrycode_SY,"SY"}, /**< SYRIAN ARAB REPUBLIC */
    {wifi_countrycode_SZ,"SZ"}, /**< SWAZILAND */
    {wifi_countrycode_TA,"TA"}, /**< TRISTAN DA CUNHA */
    {wifi_countrycode_TC,"TC"}, /**< TURKS AND CAICOS ISLANDS */
    {wifi_countrycode_TD,"TD"}, /**< CHAD */
    {wifi_countrycode_TF,"TF"}, /**< FRENCH SOUTHERN TERRITORIES */
    {wifi_countrycode_TG,"TG"}, /**< TOGO */
    {wifi_countrycode_TH,"TH"}, /**< THAILAND */
    {wifi_countrycode_TJ,"TJ"}, /**< TAJIKISTAN */
    {wifi_countrycode_TK,"TK"}, /**< TOKELAU */
    {wifi_countrycode_TL,"TL"}, /**< TIMOR-LESTE (EAST TIMOR) */
    {wifi_countrycode_TM,"TM"}, /**< TURKMENISTAN */
    {wifi_countrycode_TN,"TN"}, /**< TUNISIA */
    {wifi_countrycode_TO,"TO"}, /**< TONGA */
    {wifi_countrycode_TR,"TR"}, /**< TURKEY */
    {wifi_countrycode_TT,"TT"}, /**< TRINIDAD AND TOBAGO */
    {wifi_countrycode_TV,"TV"}, /**< TUVALU */
    {wifi_countrycode_TW,"TW"}, /**< TAIWAN, PROVINCE OF CHINA */
    {wifi_countrycode_TZ,"TZ"}, /**< TANZANIA, UNITED REPUBLIC OF */
    {wifi_countrycode_UA,"UA"}, /**< UKRAINE */
    {wifi_countrycode_UG,"UG"}, /**< UGANDA */
    {wifi_countrycode_UM,"UM"}, /**< UNITED STATES MINOR OUTLYING ISLANDS */
    {wifi_countrycode_US,"US"}, /**< UNITED STATES */
    {wifi_countrycode_UY,"UY"}, /**< URUGUAY */
    {wifi_countrycode_UZ,"UZ"}, /**< UZBEKISTAN */
    {wifi_countrycode_VA,"VA"}, /**< HOLY SEE (VATICAN CITY STATE) */
    {wifi_countrycode_VC,"VC"}, /**< SAINT VINCENT AND THE GRENADINES */
    {wifi_countrycode_VE,"VE"}, /**< VENEZUELA */
    {wifi_countrycode_VG,"VG"}, /**< VIRGIN ISLANDS, BRITISH */
    {wifi_countrycode_VI,"VI"}, /**< VIRGIN ISLANDS, U.S. */
    {wifi_countrycode_VN,"VN"}, /**< VIET NAM */
    {wifi_countrycode_VU,"VU"}, /**< VANUATU */
    {wifi_countrycode_WF,"WF"}, /**< WALLIS AND FUTUNA */
    {wifi_countrycode_WS,"WS"}, /**< SAMOA */
    {wifi_countrycode_YE,"YE"}, /**< YEMEN */
    {wifi_countrycode_YT,"YT"}, /**< MAYOTTE */
    {wifi_countrycode_YU,"YU"}, /**< YUGOSLAVIA */
    {wifi_countrycode_ZA,"ZA"}, /**< SOUTH AFRICA */
    {wifi_countrycode_ZM,"ZM"}, /**< ZAMBIA */
    {wifi_countrycode_ZW,"ZW"} /**< ZIMBABWE */
};

const unsigned int wifi_2g_channels[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
const unsigned int wifi_2g_channels_count = sizeof(wifi_2g_channels) / sizeof(wifi_2g_channels[0]);

const unsigned int wifi_5g_channels[] = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116,
    120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165, 169, 173, 177 };
const unsigned int wifi_5g_channels_count = sizeof(wifi_5g_channels) / sizeof(wifi_5g_channels[0]);

const unsigned int wifi_6g_channels[] = { 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57,
    61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141,
    145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217,
    221, 225, 229, 233 };
const unsigned int wifi_6g_channels_count = sizeof(wifi_6g_channels) / sizeof(wifi_6g_channels[0]);

struct wifiEnvironmentEnumStrMap wifi_environment_map[] =
{
    {wifi_operating_env_all, " "},
    {wifi_operating_env_indoor, "I"},
    {wifi_operating_env_outdoor, "O"},
    {wifi_operating_env_non_country, "X"}
};

static const char *const us_op_class_cc[] = {
        "US", "CA", NULL
};

static const char *const eu_op_class_cc[] = {
        "AL", "AM", "AT", "AZ", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE",
        "DK", "EE", "EL", "ES", "FI", "FR", "GE", "HR", "HU", "IE", "IS", "IT",
        "LI", "LT", "LU", "LV", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT",
        "RO", "RS", "RU", "SE", "SI", "SK", "TR", "UA", "GB", "GR", NULL
};

static const char *const jp_op_class_cc[] = {
        "JP", NULL
};

static const char *const cn_op_class_cc[] = {
        "CN", NULL
};

wifi_country_radio_op_class_t us_op_class = {
    wifi_countrycode_US,
    {
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 2, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 4, 121, 12, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 0, 0, 0, 0} },
        { 5, 125, 5, {149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 12, 81, 11, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0, 0} }
    }
};

wifi_country_radio_op_class_t eu_op_class = {
    wifi_countrycode_AT,
    {
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 2, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 3, 121, 11, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 0, 0, 0, 0, 0} },
        { 4, 81, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} },
        { 5, 116, 2, {36, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 6, 119, 2, {52, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} }
    }
};

wifi_country_radio_op_class_t jp_op_class = {
    wifi_countrycode_JP,
    {
        { 30, 81, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} },
        { 31, 82, 1, {14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 32, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 34, 121, 11, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 0, 0, 0, 0, 0} },
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 58, 121, 11, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 0, 0, 0, 0, 0} }
    }
};

wifi_country_radio_op_class_t cn_op_class = {
    wifi_countrycode_CN,
    {
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 2, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 3, 125, 5, {149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 4, 116, 2, {36, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 5, 119, 2, {52, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 7, 81, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} }
    }
};

/* We need to update correct country global oprating class information */
wifi_country_radio_op_class_t other_op_class = {
    wifi_countrycode_IN,
    {
        { 81, 0, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} },
        { 82, 0, 1, {14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 115, 0, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 121, 0, 12, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 0, 0, 0, 0} },
        { 124, 0, 4, {149, 153, 157, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 125, 0, 6, {149, 153, 157, 161, 165, 169, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} }
    }
};

unsigned int get_sizeof_interfaces_index_map(void) {
#ifdef CONFIG_WIFI_EMULATOR
    unsigned int count = 0;
    const wifi_interface_name_idex_map_t *tmp_interface_index_map = interface_index_map;
    for(count = 0;(tmp_interface_index_map != NULL);) {
        if (strstr(tmp_interface_index_map->vap_name, "sta")) {
            tmp_interface_index_map++;
            count++;
        } else {
            break;
        }
    }
    return count;
#else
    return interface_index_map_size;
#endif
}

static unsigned int get_sizeof_radio_interfaces_map(void)
{
#ifdef CONFIG_WIFI_EMULATOR
    unsigned int count = 0;
    radio_interface_mapping_t *tmp_radio_interface_map = l_radio_interface_map;
    for(count = 0;(tmp_radio_interface_map != NULL);) {
        if (strstr(tmp_radio_interface_map->radio_name, "radio")) {
            tmp_radio_interface_map++;
            count++;
        } else {
            break;
        }
    }
    return count;
#else
    return l_radio_interface_map_size;
#endif
}

BOOL is_wifi_hal_vap_private(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "private_ssid", strlen("private_ssid")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_xhs(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "iot_ssid", strlen("iot_ssid")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot", strlen("hotspot")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot_from_interfacename(char *interface_name)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((strcmp(interface_index_map[index].interface_name, interface_name) == 0) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot", strlen("hotspot")) == 0)) {
            return true;
        }
    }
    return false;
}

wifi_vap_info_t* get_wifi_vap_info_from_interfacename(char *interface_name)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    if (!interface_name) {
        return NULL;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
#ifndef FEATURE_SINGLE_PHY
        radio = get_radio_by_rdk_index(i);
#else //FEATURE_SINGLE_PHY
        radio = &g_wifi_hal.radio_info[i];
#endif //FEATURE_SINGLE_PHY
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (strncmp(interface->name, interface_name, strlen(interface_name)) == 0) {
                return &interface->vap_info;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }
    return NULL;
}

BOOL is_wifi_hal_6g_radio_from_interfacename(char *interface_name)
{
    unsigned int index = 0;
    wifi_radio_info_t *radio;

    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if (strcmp(interface_index_map[index].interface_name, interface_name) == 0) {
            radio = get_radio_by_rdk_index(interface_index_map[index].rdk_radio_index);
            if (radio == NULL) {
                wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__,
                                        interface_index_map[index].rdk_radio_index);
            } else if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
                return true;
            } else {
                wifi_hal_info_print("%s:%d:radio index:%d interface_name:%s band:%d\n", __func__, __LINE__,
                                        interface_index_map[index].rdk_radio_index, interface_name, radio->oper_param.band);
            }
            break;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot_open(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot_open", strlen("hotspot_open")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_lnf(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "lnf", strlen("lnf")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_lnf_psk(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "lnf_psk", strlen("lnf_psk")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_mesh(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "mesh", strlen("mesh")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_mesh_backhaul(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "mesh_backhaul", strlen("mesh_backhaul")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot_secure(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot_secure", strlen("hotspot_secure")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_lnf_radius(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "lnf_radius", strlen("lnf_radius")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_mesh_sta(UINT ap_index)
{
    unsigned int index = 0;
    for (index = 0; index < get_sizeof_interfaces_index_map(); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "mesh_sta", strlen("mesh_sta")) == 0)) {
            return true;
        }
    }
    return false;
}

static const wifi_enum_to_str_map_t wifi_variant_Map[] =
{
    {WIFI_80211_VARIANT_A,  "a"},
    {WIFI_80211_VARIANT_B,  "b"},
    {WIFI_80211_VARIANT_G,  "g"},
    {WIFI_80211_VARIANT_N,  "n"},
    {WIFI_80211_VARIANT_AC, "ac"},
    {WIFI_80211_VARIANT_AD, "ad"},
    {WIFI_80211_VARIANT_AX, "ax"},
#ifdef CONFIG_IEEE80211BE
    {WIFI_80211_VARIANT_BE, "be"},
#endif /* CONFIG_IEEE80211BE */
};

static const wifi_enum_to_str_map_t wifi_bandwidth_Map[] =
{
    {WIFI_CHANNELBANDWIDTH_20MHZ,    "20MHz" },
    {WIFI_CHANNELBANDWIDTH_40MHZ,    "40MHz" },
    {WIFI_CHANNELBANDWIDTH_80MHZ,    "80MHz" },
    {WIFI_CHANNELBANDWIDTH_160MHZ,   "160MHz" },
    {WIFI_CHANNELBANDWIDTH_80_80MHZ, "80+80MHz" },
#ifdef CONFIG_IEEE80211BE
    {WIFI_CHANNELBANDWIDTH_320MHZ,   "320MHz" },
#endif /* CONFIG_IEEE80211BE */
};

static const wifi_enum_to_str_map_t wifi_bitrate_Map[] =
{
    {WIFI_BITRATE_DEFAULT, "default" },
    {WIFI_BITRATE_1MBPS,   "1.0"     },
    {WIFI_BITRATE_2MBPS,   "2.0"     },
    {WIFI_BITRATE_5_5MBPS, "5.5"     },
    {WIFI_BITRATE_6MBPS,   "6.0"     },
    {WIFI_BITRATE_9MBPS,   "9.0"     },
    {WIFI_BITRATE_11MBPS,  "11.0"    },
    {WIFI_BITRATE_12MBPS,  "12.0"    },
    {WIFI_BITRATE_18MBPS,  "18.0"    },
    {WIFI_BITRATE_24MBPS,  "24.0"    },
    {WIFI_BITRATE_36MBPS,  "36.0"    },
    {WIFI_BITRATE_48MBPS,  "48.0"    },
    {WIFI_BITRATE_54MBPS,  "54.0"    },
};

int get_interface_name_from_radio_index(uint8_t radio_index, char *interface_name)
{
    uint8_t i = 0;

    for (i = 0; i < get_sizeof_radio_interfaces_map(); i++) {
        if (l_radio_interface_map[i].radio_index == radio_index) {
            strncpy(interface_name, l_radio_interface_map[i].interface_name, strlen(l_radio_interface_map[i].interface_name));
            return RETURN_OK;
        }
    }

    return RETURN_ERR;
}

#ifndef FEATURE_SINGLE_PHY
/* Below two functions assumes that phy_index is unique for a radio index.
   These functions cannot be used in single phy architecture. */
int get_rdk_radio_index(unsigned int phy_index)
{
    const wifi_interface_name_idex_map_t *map;
    unsigned int i;
    for (i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        map = &interface_index_map[i];
        if ( phy_index == map->phy_index ) {
            return map->rdk_radio_index;
        }
    }
    return -1;
}

wifi_radio_info_t *get_radio_by_phy_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->index == index) {
            return radio;
        }
    }

    return NULL;
}
#else //FEATURE_SINGLE_PHY
/* Below two functions are used in case of Banana Pi platform
   These functions support single phy supporting multiple radios.*/
int get_rdk_radio_index_from_interface_name(char *interface_name)
{
    uint8_t i = 0;
    const wifi_interface_name_idex_map_t *map = NULL;
    for (i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        map = &interface_index_map[i];
        if ((strcmp(interface_name, map->interface_name) == 0)) {
            wifi_hal_dbg_print("%s:%d rdk_radio_index:%d for interface:%s\n", __func__, __LINE__,
                map->rdk_radio_index, interface_name);
            return map->rdk_radio_index;
        }
    }
    wifi_hal_dbg_print("%s:%d rdk_radio_index:%d for interface:%s\n", __func__, __LINE__, -1,
        interface_name);
    return -1;
}

int get_rdk_radio_indices(unsigned int phy_index, int *rdk_radio_indices, int *num_radios_mapped)
{
    uint8_t i = 0;
    int num_radios = 0;
    int max_radios;

    if (rdk_radio_indices == NULL || num_radios_mapped == NULL) {
        return RETURN_ERR;
    }
    max_radios = *num_radios_mapped;

    for (i = 0; i < get_sizeof_radio_interfaces_map(); i++) {
        if (l_radio_interface_map[i].phy_index == phy_index) {
            if (num_radios < max_radios) {
                rdk_radio_indices[num_radios] = l_radio_interface_map[i].radio_index;
                num_radios++;
            } else {
                wifi_hal_error_print("%s:%d: Not adding rdk radio%u, "
                                     "since exceeding max_radios:%d\n",
                    __func__, __LINE__, i, max_radios);
            }
        }
    }
    *num_radios_mapped = num_radios;
    if (num_radios == 0) {
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: Filled rdk_radio_indices, size:%d\n", __func__, __LINE__,
        *num_radios_mapped);
    for (i = 0; i < *num_radios_mapped; i++) {
        wifi_hal_dbg_print("%u ", rdk_radio_indices[i]);
    }
    wifi_hal_dbg_print("\n");
    return RETURN_OK;
}
#endif //FEATURE_SINGLE_PHY

int is_backhaul_interface(wifi_interface_info_t *interface)
{
    wifi_vap_info_t *vap;

    vap = &interface->vap_info;
    return (strncmp(vap->vap_name, "mesh_backhaul", strlen("mesh_backhaul")) == 0) ? true : false;
}

unsigned int get_band_info_from_rdk_radio_index(unsigned int rdk_radio_index)
{
    unsigned int i;
    const char *vap_name = NULL;

    for (i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        if (interface_index_map[i].rdk_radio_index == rdk_radio_index) {
            vap_name = interface_index_map[i].vap_name;
            if (!vap_name) {
                break;
            }
            if (strstr(vap_name, "2g") != NULL) {
                return WIFI_FREQUENCY_2_4_BAND;
            } else if (strstr(vap_name, "5gl") != NULL) {
                return  WIFI_FREQUENCY_5L_BAND;
            } else if (strstr(vap_name, "5gh") != NULL) {
                return  WIFI_FREQUENCY_5H_BAND;
            } else if (strstr(vap_name, "5g") != NULL) {
                return WIFI_FREQUENCY_5_BAND;
            } else if (strstr(vap_name, "6g") != NULL) {
                return WIFI_FREQUENCY_6_BAND;
            }

            wifi_hal_error_print("%s:%d: Unable to parse band from vap_name: %s\n",
                                 __func__, __LINE__, vap_name);
            break;
        }
    }

    wifi_hal_error_print("%s:%d: Failed to resolve band for rdk_radio_index: %u\n",
                         __func__, __LINE__, rdk_radio_index);
    return 0;
}

void update_vap_mode(wifi_interface_info_t *interface)
{
    wifi_vap_info_t *vap = &interface->vap_info;

    if (strncmp(vap->vap_name, "mesh_sta", strlen("mesh_sta")) == 0) {
        vap->vap_mode = wifi_vap_mode_sta;
    } else {
        vap->vap_mode = wifi_vap_mode_ap;
    }
}

void get_wifi_interface_info_map(wifi_interface_name_idex_map_t *interface_map)
{
    memcpy(interface_map, interface_index_map, get_sizeof_interfaces_index_map()*sizeof(wifi_interface_name_idex_map_t));
}

int get_ap_vlan_id(char *interface_name)
{
    unsigned int i = 0;
    const wifi_interface_name_idex_map_t *map = NULL;
    for (i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        map = &interface_index_map[i];
        if ((strcmp(interface_name, map->interface_name) == 0))  {
            wifi_hal_dbg_print("get_ap_vlan_id %d and returned val is %d\n",map->vlan_id, interface_index_map[i].vlan_id);
            return map->vlan_id;
        }
   }
   return -1;
}

void get_radio_interface_info_map(radio_interface_mapping_t *radio_interface_map)
{
    memcpy(radio_interface_map, l_radio_interface_map, get_sizeof_radio_interfaces_map()*sizeof(radio_interface_mapping_t));
}

wifi_interface_info_t* get_primary_interface(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    char interface_name[32] = { 0 };

    get_interface_name_from_radio_index(radio->rdk_radio_index, interface_name);
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        if(strcmp(interface_name, interface->name) == 0)
            return interface;

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    return NULL;
}

wifi_interface_info_t* get_private_vap_interface(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        vap = &interface->vap_info;
        if (!strncmp(vap->vap_name, "private_ssid_", sizeof("private_ssid_")-1)) {
            return interface;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }
    return NULL;
}

int wifi_hal_get_vap_interface_type(wifi_vap_name_t vap_name, wifi_vap_type_t vap_type)
{
    char *last_underscore;
    int len;

    if (vap_name == NULL) {
        return -1;
    }

    last_underscore = strrchr(vap_name, '_');
    if (last_underscore == NULL) {
        return -1;
    }

    len = last_underscore - vap_name + 1;
    strncpy(vap_type, vap_name, len);
    vap_type[len] = '\0';

    return 0;
}

wifi_interface_info_t *wifi_hal_get_vap_interface_by_type(wifi_radio_info_t *radio,
    wifi_vap_type_t vap_type)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    if (radio == NULL) {
        return NULL;
    }

    hash_map_foreach(radio->interface_map, interface) {
        vap = &interface->vap_info;
        if (strncmp(vap->vap_name, vap_type, strnlen(vap_type, sizeof(wifi_vap_type_t))) == 0) {
            return interface;
        }
    }

    return NULL;
}

#if !defined(PLATFORM_LINUX)
int getIpStringFromAdrress (char * ipString, ip_addr_t * ip)
{
    if (ip->family == wifi_ip_family_ipv4) {
        inet_ntop(AF_INET, &ip->u.IPv4addr, ipString, INET_ADDRSTRLEN);
    }
    else if (ip->family == wifi_ip_family_ipv6) {
        inet_ntop(AF_INET6, &ip->u.IPv6addr, ipString, INET_ADDRSTRLEN);
    }
    else {
        strcpy(ipString,"0.0.0.0");
        wifi_hal_error_print("%s IP not recognised\n", __func__);
        return 0;
    }

    return 1;
}
#endif

int get_mac_address (char *intf_name,  mac_address_t mac)
{
    int sock;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return RETURN_ERR;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, intf_name);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
        close(sock);
        return RETURN_ERR;
    }

    memcpy(mac, (unsigned char *)ifr.ifr_hwaddr.sa_data, sizeof(mac_address_t));
    close(sock);

    return RETURN_OK;
}

int set_interface_properties(unsigned int phy_index, wifi_interface_info_t *interface)
{
    const wifi_interface_name_idex_map_t *map;
    const radio_interface_mapping_t *radio_map;
    wifi_vap_info_t *vap;
    unsigned int i;

    vap = &interface->vap_info;

    vap->vap_index = 0;

    /* Set interface properties for VAP interfaces */
    for (i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        map = &interface_index_map[i];
        if ((strcmp(interface->name, map->interface_name) == 0) &&
            (phy_index == map->phy_index)) {
            vap->radio_index = map->rdk_radio_index;
            vap->vap_index = map->index;
            strcpy(vap->vap_name, map->vap_name);
            vap->vap_mode = is_wifi_hal_vap_mesh_sta(vap->vap_index) ? wifi_vap_mode_sta :
                                                                       wifi_vap_mode_ap;
            return 0;
        }
    }

    /* Set interface properties for radio interfaces */
    for (i = 0; i < get_sizeof_radio_interfaces_map(); i++) {
        radio_map = &l_radio_interface_map[i];
        if ((strcmp(interface->name, radio_map->interface_name) == 0) &&
            (phy_index == radio_map->phy_index)) {
            vap->radio_index = radio_map->radio_index;
            vap->vap_index = -1;
            return 0;
        }
    }
    wifi_hal_error_print("%s:%d phy_index %d interface%s not found\n", __func__, __LINE__,  phy_index, interface->name);

    return -1;
}

int get_interface_name_from_vap_index(unsigned int vap_index, char *interface_name)
{
    // OneWifi interafce mapping with vap_index
    unsigned char l_index = 0;
    unsigned char total_num_of_vaps = 0;
    const char *l_interface_name = NULL;
    wifi_radio_info_t *radio;

    for (l_index = 0; l_index < g_wifi_hal.num_radios; l_index++) {
#ifndef FEATURE_SINGLE_PHY
        radio = get_radio_by_rdk_index(l_index);
#else //FEATURE_SINGLE_PHY
        radio = &g_wifi_hal.radio_info[l_index];
#endif //FEATURE_SINGLE_PHY
        total_num_of_vaps += radio->capab.maxNumberVAPs;
    }

    if ((vap_index >= total_num_of_vaps) || (interface_name == NULL)) {
        wifi_hal_error_print("%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    for (l_index = 0; l_index < get_sizeof_interfaces_index_map(); l_index++) {
        if (interface_index_map[l_index].index == vap_index) {
            l_interface_name = interface_index_map[l_index].interface_name;
            strncpy(interface_name, l_interface_name, (strlen(l_interface_name) + 1));
            wifi_hal_dbg_print("%s:%d: VAP index %d: interface name %s\n", __func__, __LINE__, vap_index, interface_name);
            return RETURN_OK;
        }
    }

    wifi_hal_error_print("%s:%d: Interface name not found:%d \n",__func__, __LINE__, vap_index);

    return RETURN_ERR;
}

wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->rdk_radio_index == index) {
            return radio;
        }
    }
    return NULL;
}


wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    // wifi_hal_dbg_print("%s:%d:{ vap_index:[%d] } g_wifi_hal.num_radios:[%d]\r\n",__func__, __LINE__, vap_index, g_wifi_hal.num_radios);
    for (i = 0; i < g_wifi_hal.num_radios; i++) {

        radio = &g_wifi_hal.radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_info.vap_index == vap_index) {
                return interface;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    return NULL;
}

wifi_interface_info_t *get_interface_by_if_index(unsigned int if_index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->index == if_index) {
                return interface;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    return NULL;
}


BOOL get_ie_ext_by_eid(unsigned int eid, unsigned char *buff, unsigned int buff_len, unsigned char **ie_out, unsigned short *ie_out_len)
{
    ieee80211_tlv_t *ie = NULL;
    signed int len;

    ie = (ieee80211_tlv_t *)buff;
    len = buff_len;

    while ((ie != NULL) && (len > 0)) {
        if ((ie->type == WLAN_EID_EXTENSION) && (ie->length != 0) && ie->value[0] == eid) {
            //wifi_hal_dbg_print("%s:%d: Found ssid ie, ie length:%d\n", __func__, __LINE__,
            //    ie->length);
            *ie_out = (unsigned char *)ie;
            *ie_out_len = ie->length + sizeof(ieee80211_tlv_t);
            return true;
        }

        len = len - (ie->length + sizeof(ieee80211_tlv_t));
        ie = (ieee80211_tlv_t *)((unsigned char *)ie + (ie->length + sizeof(ieee80211_tlv_t)));
    }

    return false;
}

BOOL get_ie_by_eid(unsigned int eid, unsigned char *buff, unsigned int buff_len, unsigned char **ie_out, size_t *ie_out_len)
{
    ieee80211_tlv_t *ie = NULL;
    signed int len;

    ie = (ieee80211_tlv_t *)buff;
    len = buff_len;

    while ((ie != NULL) && (len > 0)) {
        if ((ie->type == eid) && (ie->length != 0)) {
            //wifi_hal_dbg_print("%s:%d: Found ssid ie, ie length:%d\n", __func__, __LINE__,
            //    ie->length);
            *ie_out = (unsigned char *)ie;
            *ie_out_len = ie->length + sizeof(ieee80211_tlv_t);
            return true;
        }

        len = len - (ie->length + sizeof(ieee80211_tlv_t));
        ie = (ieee80211_tlv_t *)((unsigned char *)ie + (ie->length + sizeof(ieee80211_tlv_t)));
    }

    return false;
}

const u8 * get_vendor_ie_by_type(const u8 *pos, size_t len, u32 vendor_type)
{
    const u8 *end;

    end = pos + len;

    while (end - pos > 1) {
        if (2 + pos[1] > end - pos) {
            break;
        }

        if (pos[0] == WLAN_EID_VENDOR_SPECIFIC && pos[1] >= 4 && vendor_type == WPA_GET_BE32(&pos[2])) {
            return pos;
        }

        pos += 2 + pos[1];
    }

    return NULL;
}

int get_radio_variant_str_from_int(unsigned int variant, char *variant_str)
{
    unsigned char index = 0;
    char temp_variant_str[24];
    memset(temp_variant_str, 0, sizeof(temp_variant_str));

    if ((variant == 0) || (variant_str == NULL)) {
        wifi_hal_error_print("%s:%d: variant value zero:%d\n", __func__, __LINE__, variant);
        return RETURN_ERR;
    }

    for (index = 0; index < ARRAY_SIZE(wifi_variant_Map); index++) {
        if ((variant & wifi_variant_Map[index].enum_val) && (strlen(temp_variant_str) == 0)) {
            strcpy(temp_variant_str, wifi_variant_Map[index].str_val);
        } else if (variant & wifi_variant_Map[index].enum_val) {
            strcat(temp_variant_str, ",");
            strcat(temp_variant_str, wifi_variant_Map[index].str_val);
        }
    }

    strncpy(variant_str, temp_variant_str, strlen(temp_variant_str));

    return RETURN_OK;
}

int get_vap_mode_str_from_int_mode(unsigned char vap_mode, char *vap_mode_str)
{
    switch (vap_mode) {
    case wifi_vap_mode_ap:
        strcpy(vap_mode_str, "ap");
        break;

    case wifi_vap_mode_sta:
        strcpy(vap_mode_str, "sta");
        break;

    case wifi_vap_mode_monitor:
        strcpy(vap_mode_str, "monitor");
        break;

    default:
        strcpy(vap_mode_str, "none");
        break;
    }

    return RETURN_OK;
}

int get_security_mode_support_radius(int mode)
{
    int sec_mode = 0;
    if ((mode == wifi_security_mode_wpa_enterprise) || (mode == wifi_security_mode_wpa2_enterprise ) || (mode == wifi_security_mode_wpa3_enterprise) || (mode == wifi_security_mode_wpa_wpa2_enterprise)){
        sec_mode = 1;
    } else {
        sec_mode = 0;
    }

    return sec_mode;
}

int get_security_mode_int_from_str(char *security_mode_str,char *mfp_str,wifi_security_modes_t *security_mode)
{

    if(strcmp(security_mode_str, "None") == 0) {
        *security_mode = wifi_security_mode_none;
    } else if (strcmp(security_mode_str, "owe") == 0) {
        *security_mode = wifi_security_mode_enhanced_open;
    } else if (strcmp(security_mode_str, "psk") == 0) {
        *security_mode = wifi_security_mode_wpa_personal;
    } else if (strcmp(security_mode_str, "psk2") == 0) {
        *security_mode = wifi_security_mode_wpa2_personal;
    } else if (strcmp(security_mode_str, "psk psk2") == 0) {
        *security_mode = wifi_security_mode_wpa_wpa2_personal;
    } else if ((strstr(security_mode_str, "sae") != NULL) && (strstr(security_mode_str, "psk2") == NULL)) {
        /* should also take care of "sae sae-ext" case regardless of order */
        *security_mode = wifi_security_mode_wpa3_personal;
    } else if (strstr(security_mode_str, "psk2") && strstr(security_mode_str, "sae")) {
        /* should also take care of "psk2 sae sae-ext" case regardless of order */
        *security_mode = wifi_security_mode_wpa3_transition;
    } else if (strcmp(security_mode_str, "wpa") == 0) {
        *security_mode = wifi_security_mode_wpa_enterprise;
    } else if ((strcmp(security_mode_str, "wpa2") == 0) && (strcmp(mfp_str, "2") != 0 )) {
        *security_mode = wifi_security_mode_wpa2_enterprise;
    } else if ((strcmp(security_mode_str, "wpa2") == 0) && (strcmp(mfp_str, "2") == 0 )){
        *security_mode = wifi_security_mode_wpa3_enterprise;
    } else if (strcmp(security_mode_str, "wpa wpa2") == 0) {
        *security_mode = wifi_security_mode_wpa_wpa2_enterprise;
    } else if (strstr(security_mode_str, "psk2") && strstr(security_mode_str, "sae") && !strcmp(mfp_str, "0")) {
        *security_mode = wifi_security_mode_wpa3_compatibility;
    } else {
        wifi_hal_error_print("%s:%d: wifi security mode not found:[%s:%s]\r\n",__func__, __LINE__, security_mode_str,mfp_str);
        return RETURN_ERR;
    }

    wifi_hal_dbg_print("%s:%d: security mode %d string %s and mfp is %s\r\n",__func__, __LINE__, *security_mode,security_mode_str,mfp_str);
    return RETURN_OK;
}

int get_security_mode_str_from_int(wifi_security_modes_t security_mode, unsigned int vap_index, char *security_mode_str)
{
    (void)vap_index;

    switch (security_mode) {
    case wifi_security_mode_none:
        strcpy(security_mode_str, "None");
        break;

    case wifi_security_mode_enhanced_open:
        strcpy(security_mode_str, "owe");
        break;

    case wifi_security_mode_wpa_personal:
        strcpy(security_mode_str, "psk");
        break;

    case wifi_security_mode_wpa2_personal:
        strcpy(security_mode_str, "psk2");
        break;

    case wifi_security_mode_wpa_wpa2_personal:
        strcpy(security_mode_str, "psk psk2");
        break;

    case wifi_security_mode_wpa3_personal:
#ifdef CONFIG_IEEE80211BE
        {
            const wifi_interface_info_t * const interface = get_interface_by_vap_index(vap_index);
            if (NULL == interface) {
                wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__);
                return RETURN_ERR;
            }
            if (wifi_vap_mode_ap == interface->vap_info.vap_mode &&
                !interface->u.ap.conf.disable_11be) {
                strcpy(security_mode_str, "sae sae-ext");
            } else {
                strcpy(security_mode_str, "sae");
            }
        }
#else
        strcpy(security_mode_str, "sae");
#endif /* CONFIG_IEEE80211BE */
        break;

    case wifi_security_mode_wpa3_transition:
#ifdef CONFIG_IEEE80211BE
        {
            const wifi_interface_info_t * const interface = get_interface_by_vap_index(vap_index);
            if (NULL == interface) {
                wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__);
                return RETURN_ERR;
            }
            if (wifi_vap_mode_ap == interface->vap_info.vap_mode &&
                !interface->u.ap.conf.disable_11be) {
                strcpy(security_mode_str, "sae sae-ext psk2");
            } else {
                strcpy(security_mode_str, "psk2 sae");
            }
        }
#else
        strcpy(security_mode_str, "psk2 sae");
#endif /* CONFIG_IEEE80211BE */
        break;

    case wifi_security_mode_wpa_enterprise:
        strcpy(security_mode_str, "wpa");
        break;

    case wifi_security_mode_wpa2_enterprise:
        strcpy(security_mode_str, "wpa2");
        break;

    case wifi_security_mode_wpa3_enterprise:
        strcpy(security_mode_str, "wpa2");
        break;

    case wifi_security_mode_wpa_wpa2_enterprise:
        strcpy(security_mode_str, "wpa wpa2");
        break;

    case wifi_security_mode_wpa3_compatibility:
        strcpy(security_mode_str, "psk2 sae");
        break;

    default:
        wifi_hal_error_print("%s:%d: wifi security mode not found:[%d]\r\n",__func__, __LINE__, security_mode);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_security_encryption_mode_str_from_int(wifi_encryption_method_t encryption_mode, unsigned int vap_index, char *encryption_mode_str)
{
    (void)vap_index;

    switch (encryption_mode) {
    case wifi_encryption_tkip:
        strcpy(encryption_mode_str, "tkip");
        break;

    case wifi_encryption_aes:
#ifdef CONFIG_IEEE80211BE
        {
            const wifi_interface_info_t * const interface = get_interface_by_vap_index(vap_index);
            if (NULL == interface) {
                wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__);
                return RETURN_ERR;
            }
            unsigned char has_gcmp256 = 0;
            if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
                const wifi_security_modes_t security_mode = interface->vap_info.u.bss_info.security.mode;
                switch (security_mode) {
                case wifi_security_mode_wpa3_personal:
                case wifi_security_mode_wpa3_transition:
                case wifi_security_mode_wpa3_enterprise:
                case wifi_security_mode_wpa3_compatibility:
                    has_gcmp256 = !interface->u.ap.conf.disable_11be;
                    break;
                default:
                    break;
                }
            }
            if (has_gcmp256) {
                strcpy(encryption_mode_str, "aes+gcmp256");
            } else {
                strcpy(encryption_mode_str, "aes");
            }
        }
#else
        strcpy(encryption_mode_str, "aes");
#endif /* CONFIG_IEEE80211BE */
        break;

    case wifi_encryption_aes_tkip:
        strcpy(encryption_mode_str, "tkip+aes");
        break;

    default:
        wifi_hal_error_print("%s:%d: wifi encryption method not found:[%d]\r\n",__func__, __LINE__, encryption_mode);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT get_coutry_str_from_oper_params(wifi_radio_operationParam_t *operParams, char *country)
{
    unsigned int index = 0;
    char tmp_countrycode_str[4];
    char tmp_environment_str[4];

    memset(tmp_countrycode_str, 0, sizeof(tmp_countrycode_str));
    memset(tmp_environment_str, 0, sizeof(tmp_environment_str));
   
    // Default country as "USI"
    strcpy(tmp_countrycode_str, "US");
    strcpy(tmp_environment_str, "I");

    for (index = 0; index < ARRAY_SZ(wifi_country_map); index++) {
        if (wifi_country_map[index].countryCode == operParams->countryCode) {
            strncpy(tmp_countrycode_str, wifi_country_map[index].countryStr, sizeof(wifi_country_map[index].countryStr)-1);
            break;
        }
    }

    for (index = 0; index < ARRAY_SZ(wifi_environment_map); index++) {
        if (wifi_environment_map[index].operatingEnvironment == operParams->operatingEnvironment) {
            strncpy(tmp_environment_str, wifi_environment_map[index].environment, sizeof(wifi_environment_map[index].environment)-1);
            break;
        }
    }

    snprintf(country, 4, "%s%s", tmp_countrycode_str, tmp_environment_str);

    return RETURN_OK;
}

// Based on wpa_supplicant_set_suites
int pick_akm_suite(int sel)
{
    if (0) {
#ifdef CONFIG_IEEE80211R
    } else if (sel & WPA_KEY_MGMT_FT_PSK) {
        wifi_hal_dbg_print("%s:%d: WPA: using KEY_MGMT FT/PSK\n", __func__, __LINE__);
        return  WPA_KEY_MGMT_FT_PSK;
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_SAE
#ifdef CONFIG_IEEE80211BE
    } else if (sel & WPA_KEY_MGMT_SAE_EXT_KEY) {
        wifi_hal_dbg_print("%s:%d: WPA: using KEY_MGMT SAE_EXT\n", __func__, __LINE__);
        return WPA_KEY_MGMT_SAE_EXT_KEY;
#endif /* CONFIG_IEEE80211BE */
    } else if (sel & WPA_KEY_MGMT_SAE) {
        wifi_hal_dbg_print("%s:%d: WPA: using KEY_MGMT SAE\n", __func__, __LINE__);
        return WPA_KEY_MGMT_SAE;
#endif
#ifdef CONFIG_IEEE80211W
    } else if (sel & WPA_KEY_MGMT_IEEE8021X_SHA256) {
        wifi_hal_dbg_print("%s:%d: WPA: using KEY_MGMT 802.1X with SHA256\n", __func__, __LINE__);
        return  WPA_KEY_MGMT_IEEE8021X_SHA256;
    } else if (sel & WPA_KEY_MGMT_PSK_SHA256) {
        wifi_hal_dbg_print("%s:%d: WPA: using KEY_MGMT PSK with SHA256\n", __func__, __LINE__);
        return  WPA_KEY_MGMT_PSK_SHA256;
#endif /* CONFIG_IEEE80211W */
    } else if (sel & WPA_KEY_MGMT_IEEE8021X) {
       wifi_hal_dbg_print("%s:%d: WPA: using KEY_MGMT 802.1X\n", __func__, __LINE__);
       return WPA_KEY_MGMT_IEEE8021X;
    } else if (sel & WPA_KEY_MGMT_PSK) {
        wifi_hal_dbg_print("%s:%d: WPA: using KEY_MGMT WPA-PSK\n", __func__, __LINE__);
        return WPA_KEY_MGMT_PSK;
    } else {
        wifi_hal_dbg_print("%s:%d: WPA: Failed to select authenticated key management type\n", __func__, __LINE__);
        return -1;
    }
}

INT get_coutry_str_from_code(wifi_countrycode_type_t code, char *country)
{
    unsigned int index = 0;
    bool value_updated = false;

    for (index = 0; index < ARRAY_SZ(wifi_country_map); index++) {
        if (wifi_country_map[index].countryCode == code) {
            strcpy(country, wifi_country_map[index].countryStr);
            value_updated = true;
            break;
        }
    }

    if (value_updated == false) {
        //Copy default value
        strcpy(country, "US");
    }
    return RETURN_OK;
}

static int find_country_code_match(const char *const cc[], const char *const country)
{
    int i;

    if (country == NULL) {
        return RETURN_ERR;
    }

    for (i = 0; cc[i]; i++) {
        if (cc[i][0] == country[0] && cc[i][1] == country[1]) {
            return RETURN_OK;
        }
    }

    return RETURN_ERR;
}
#ifdef RDKB_ONE_WIFI_PROD
#define NUM_RADIOS 3

static bool parse_wiphy_band_mapping(FILE *fp, int *pcie_index) {
    char line[LINE_MAX];
    int curr_phy_idx;
    bool in_wiphy = false;

    while (fgets(line, sizeof(line), fp)) {
        // Detect start of Wiphy
        char *wiphy_ptr = strstr(line, "Wiphy ");
        if (wiphy_ptr == line) {
            // Example: "Wiphy phy2"
            if (sscanf(line, "Wiphy phy%d", &curr_phy_idx) == 1) {
                in_wiphy = true;
            }
            continue;
        }
        // If in a Wiphy stanza, look for "Band N:"
        if (in_wiphy) {
            // Skip leading spaces
            char *trimmed = line;
            while (*trimmed == ' ' || *trimmed == '\t') ++trimmed;

            // Look for "Band N:"
            if (strncmp(trimmed, "Band ", 5) == 0) {
                int band_num;
                if (sscanf(trimmed, "Band %d:", &band_num) == 1) {
                    --band_num; /* The iw tool prints nl_band->nla_type + 1 */
                    if (curr_phy_idx < NUM_RADIOS &&
                        ((band_num < NUM_NL80211_BANDS) && (band_num >= 0)))
                        pcie_index[curr_phy_idx] = ((band_num == NL80211_BAND_6GHZ) ? 2 : band_num);
                    else {
                        wifi_hal_error_print("%s:%d: Recieved phy_index:%d Num Radios:%d \
                            band_num:%d NUM_NL80211_BANDS:%d\n", __func__, __LINE__, \
                            curr_phy_idx, NUM_RADIOS, band_num, NUM_NL80211_BANDS);
                        return false;
                    }
                } else {
                    wifi_hal_error_print("%s:%d: Unable to read the band num %s\n", __func__, __LINE__, trimmed);
                    return false;
                }
                in_wiphy = false;
            }
        }
    }
    return true;
}

static void remap_phy_index(wifi_interface_name_idex_map_t *map, int map_size, const int *pcie_index, int pcie_size)
{
    for (int i = 0; i < map_size; ++i) {
        if (!map[i].interface_name)
            continue;

        // Find the digit after "wl" (e.g., wl0.1, wl1, etc)
        char *p = map[i].interface_name;
        if (strncmp(p, "wl", 2) != 0)
            continue;

        p += 2;
        if (!isdigit((unsigned char)*p))
            continue;

        int idx = *p - '0';  // Get the integer
        if (idx < 0 || idx >= pcie_size)
            continue;
        if (pcie_index[idx] != -1) {
            map[i].phy_index = pcie_index[idx];
        } else {
            wifi_hal_error_print("%s:%d: idx:%d doesnt exist \n", __func__, __LINE__, idx);
        }
    }
}

void remap_wifi_interface_name_index_map() {
    FILE *fp;
    int pcie_index[NUM_RADIOS] = {-1, -1, -1};

    fp = popen("iw list", "r");
    if (parse_wiphy_band_mapping(fp, pcie_index)) {
        remap_phy_index(interface_index_map, sizeof(interface_index_map)/sizeof(interface_index_map[0]),
            pcie_index, NUM_RADIOS);
    }
    pclose(fp);
}

#endif /* RDKB_ONE_WIFI_PROD */

int get_wifi_op_class_info(wifi_countrycode_type_t country_code, wifi_country_radio_op_class_t *op_classes)
{
    if (country_code > wifi_countrycode_ZW) {
        wifi_hal_dbg_print("%s:%d: Wrong country code:%d\n", __func__, __LINE__, country_code);
        return RETURN_ERR;
    }

    char str_country[4];
    int ret;

    memset(str_country, 0, sizeof(str_country));
    get_coutry_str_from_code(country_code, str_country);

    ret = find_country_code_match(us_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &us_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }
    ret = find_country_code_match(eu_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &eu_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }
    ret = find_country_code_match(jp_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &jp_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }
    ret = find_country_code_match(cn_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &cn_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    } else {
        memcpy(op_classes, &other_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }

    return RETURN_OK;
}

int get_op_class_from_radio_params(wifi_radio_operationParam_t *param)
{
    unsigned int i, j;
    wifi_country_radio_op_class_t cc_op_class;
    wifi_radio_op_class_t   *op_class;

#if HOSTAPD_VERSION >= 210 //2.10
    if (param->band == WIFI_FREQUENCY_6_BAND) {
        if (param->channel == 2) {
            return 136;
        }

        switch (param->channelWidth) {
            case WIFI_CHANNELBANDWIDTH_20MHZ: return 131;
            case WIFI_CHANNELBANDWIDTH_40MHZ: return 132;
            case WIFI_CHANNELBANDWIDTH_80MHZ: return 133;
            case WIFI_CHANNELBANDWIDTH_160MHZ: return 134;
            case WIFI_CHANNELBANDWIDTH_80_80MHZ: return 135;
            case WIFI_CHANNELBANDWIDTH_320MHZ: return 137;
            default:
                wifi_hal_error_print("%s:%d: failed to convert bw %d to op class for 6GHZ band\n",
                    __func__, __LINE__, param->channelWidth);
                return RETURN_ERR;
        }
    }
#endif

    memset(&cc_op_class, 0, sizeof(cc_op_class));

    get_wifi_op_class_info(param->countryCode, &cc_op_class);

    // country code match
    if (cc_op_class.cc != param->countryCode) {
        wifi_hal_error_print("%s:%d:Could not find country code : %d\n", __func__, __LINE__, param->countryCode);
        return RETURN_ERR;
    }

    // channel match with country op class
    for (i = 0; i < ARRAY_SZ(cc_op_class.op_class); i++) {
        op_class = &cc_op_class.op_class[i];
        for (j = 0; j < op_class->num; j++) {
            if (op_class->ch_list[j] == param->channel) {
                return op_class->op_class;
            }
        }
    }

    // channel match with global op class
    for (i = 0; i < ARRAY_SZ(other_op_class.op_class); i++) {
        op_class = &other_op_class.op_class[i];
        for (j = 0; j < op_class->num; j++) {
            if (op_class->ch_list[j] == param->channel) {
                return op_class->op_class;
            }
        }
    }

    wifi_hal_error_print("%s:%d:Could not find channel is list for country op class / global op class : %d\n", __func__, __LINE__, param->countryCode);
    return RETURN_ERR;
}

int get_sec_channel_offset(wifi_radio_info_t *radio, int freq)
{
    int i;
    enum nl80211_band band;

    if ((freq >= MIN_FREQ_MHZ_2G) && (freq <= MAX_FREQ_MHZ_2G)) {
        band = NL80211_BAND_2GHZ;
    } else if ((freq >= MIN_FREQ_MHZ_5G) && (freq <= MAX_FREQ_MHZ_5G)) {
        band = NL80211_BAND_5GHZ;
#if HOSTAPD_VERSION >= 210
    } else if ((freq >= MIN_FREQ_MHZ_6G) && (freq <= MAX_FREQ_MHZ_6G)) {
#ifndef LINUX_VM_PORT
        band = NL80211_BAND_6GHZ;
#endif
#endif
    } else {
        wifi_hal_info_print("%s:%d: Unknown frequency: %d in attribute of phy index: %d\n", __func__, __LINE__, 
            freq, radio->index);
        return 0;
    }

    for (i = 0; i < radio->hw_modes[band].num_channels; i++) {
        if (freq == radio->channel_data[band][i].freq) {
            /* sec_chan_offset for 20MHz will be 0. For bandwidth 40MHz, 80MHz sec_chan_offset will be a non-zero value*/
	    if (radio->oper_param.channelWidth != WIFI_CHANNELBANDWIDTH_20MHZ) {
		if (radio->channel_data[band][i].allowed_bw & HOSTAPD_CHAN_WIDTH_40P)
		    return 1;
		if (radio->channel_data[band][i].allowed_bw & HOSTAPD_CHAN_WIDTH_40M)
		    return -1;
	    }
	    break;
        }
    }

    return 0;
}

int get_bw80_center_freq(wifi_radio_operationParam_t *param, const char *country)
{
    int i, freq = -1, num_channels;
    int *channels;
    unsigned int center_channels_5g[] = {42, 58, 106, 122, 138, 155};
    unsigned int center_channels_6g[] = {7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215};

    if (param->band == WIFI_FREQUENCY_6_BAND) {
        channels = &center_channels_6g[0];
        num_channels = ARRAY_SZ(center_channels_6g);
    } else {
        channels = &center_channels_5g[0];
        num_channels = ARRAY_SZ(center_channels_5g);
    }

    for (i = 0; i < num_channels; i++) {
        if (param->channel <= (channels[i]+6)) {
            freq = ieee80211_chan_to_freq(country, param->operatingClass, channels[i]);
            break;
        }
    }

    if (freq == -1) {
        wifi_hal_error_print("%s:%d - channel %d is not allowed at 80MHz bandwidth\n", __func__, __LINE__, param->channel);
    }

    return freq;
}

int get_bw160_center_freq(wifi_radio_operationParam_t *param, const char *country)
{
    int i, freq = -1, num_channels;
    int *channels;
    int center_channels_5g[] = {50, 114, 163};
    int center_channels_6g[] = {15, 47, 79, 111, 143, 175, 207};

    if (param->band == WIFI_FREQUENCY_6_BAND) {
        channels = &center_channels_6g[0];
        num_channels = ARRAY_SZ(center_channels_6g);
    } else {
        channels = &center_channels_5g[0];
        num_channels = ARRAY_SZ(center_channels_5g);
    }

    for (i = 0; i < num_channels; i++) {
        if (param->channel <= (channels[i]+14)) {
            freq = ieee80211_chan_to_freq(country, param->operatingClass, channels[i]);
            break;
        }
    }

    if (freq == -1) {
        wifi_hal_error_print("%s:%d - channel %d is not allowed at 160MHz bandwidth\n", __func__, __LINE__, param->channel);
    }

    return freq;
}

#ifdef CONFIG_IEEE80211BE
int get_bw320_center_freq(wifi_radio_operationParam_t *param, const char *country)
{
    int i, freq = -1;
    const unsigned char *channels;
    //center frequency index
    static const unsigned char center_channels_6g[] = {31, 63, 95, 127, 159, 191};
    static const unsigned int next_channel_start = 30;
    const unsigned int num_channels = ARRAY_SZ(center_channels_6g);
    channels = center_channels_6g;

    for (i = 0; i < num_channels; i++) {
        if (param->channel <= (channels[i] + next_channel_start)) {
            freq = ieee80211_chan_to_freq(country, param->operatingClass, channels[i]);
            break;
        }
    }

    if (freq == -1) {
        wifi_hal_error_print("%s:%d - channel %d is not allowed at 320MHz bandwidth\n", __func__, __LINE__, param->channel);
    }

    return freq;
}
#endif /* CONFIG_IEEE80211BE */

//wifi_halstats
void wifi_hal_stats_print(wifi_hal_stats_log_level_t level, const char *format, ...)
{
    char buff[256] = { 0 };
    FILE *fpg = NULL;
    get_formatted_time(buff);
    va_list list;
    if ((access("/nvram/wifiHalStatsDbg", R_OK)) == 0) {
        fpg = fopen("/tmp/wifiHalStats", "a+");
    } else {
        switch (level) {
        case WIFI_HAL_STATS_LOG_LVL_INFO:
        case WIFI_HAL_STATS_LOG_LVL_ERROR:
            fpg = fopen("/rdklogs/logs/wifiHalStats.txt", "a+");
            if (fpg == NULL) {
                return;
            }
            break;
        case WIFI_HAL_STATS_LOG_LVL_DEBUG:
        default:
            return;
        }
    }
    if (fpg == NULL) {
        return;
    }
    static const char *level_marker[WIFI_HAL_STATS_LOG_LVL_MAX] = {
        [WIFI_HAL_STATS_LOG_LVL_DEBUG] = "<D>",
        [WIFI_HAL_STATS_LOG_LVL_INFO] = "<I>",
        [WIFI_HAL_STATS_LOG_LVL_ERROR] = "<E>",
    };
    if (level < WIFI_HAL_STATS_LOG_LVL_MAX){
        snprintf(&buff[strlen(buff)], 256 - strlen(buff), " %s ", level_marker[level]);
    }
    fprintf(fpg, "%s ", buff);
    va_start(list, format);
    vfprintf(fpg, format, list);
    va_end(list);
    fflush(fpg);
    fclose(fpg);
    return;
}

void wifi_hal_print(wifi_hal_log_level_t level, const char *format, ...)
{
    char buff[256] = {0};
    va_list list;
    FILE *fpg = NULL;

    get_formatted_time(buff);

#ifdef LINUX_VM_PORT
    printf("%s ", buff);
    va_start(list, format);
    vprintf (format, list);
    va_end(list);
#else
#ifndef CONFIG_WIFI_EMULATOR
    if ((access("/nvram/wifiHalDbg", R_OK)) == 0) {

        fpg = fopen("/tmp/wifiHal", "a+");
        if (fpg == NULL) {
            return;
        }
    } else {
        switch (level) {
            case WIFI_HAL_LOG_LVL_INFO:
            case WIFI_HAL_LOG_LVL_ERROR:
                fpg = fopen("/rdklogs/logs/wifiHal.txt", "a+");
                if (fpg == NULL) {
                    return;
                }
            break;
            case WIFI_HAL_LOG_LVL_DEBUG:
            default:
                return;
        }
    }
#else
    if ((access("/nvram/wifiHalDbg", R_OK)) == 0) {

        fpg = fopen("/tmp/wifiEmulatorHal", "a+");
        if (fpg == NULL) {
            return;
        }
    } else {
        switch (level) {
            case WIFI_HAL_LOG_LVL_INFO:
            case WIFI_HAL_LOG_LVL_ERROR:
                fpg = fopen("/rdklogs/logs/wifiEmulatorHal.txt", "a+");
                if (fpg == NULL) {
                    return;
                }
            break;
            case WIFI_HAL_LOG_LVL_DEBUG:
            default:
                return;
        }
    }
#endif
    static const char *level_marker[WIFI_HAL_LOG_LVL_MAX] =
    {
        [WIFI_HAL_LOG_LVL_DEBUG] = "<D>",
        [WIFI_HAL_LOG_LVL_INFO] = "<I>",
        [WIFI_HAL_LOG_LVL_ERROR] = "<E>",
    };
    if (level < WIFI_HAL_LOG_LVL_MAX)
        snprintf(&buff[strlen(buff)], 256 - strlen(buff), " %s ", level_marker[level]);

    fprintf(fpg, "%s ", buff);
    va_start(list, format);
    vfprintf(fpg, format, list);
    va_end(list);
    fflush(fpg);
    fclose(fpg);
#endif
    return;
}

const char *wpa_alg_to_string(enum wpa_alg alg)
{
#define ALG2S(x) case x: return #x;
    switch (alg) {
    ALG2S(WPA_ALG_NONE)
    ALG2S(WPA_ALG_WEP)
    ALG2S(WPA_ALG_TKIP)
    ALG2S(WPA_ALG_CCMP)
#if HOSTAPD_VERSION >= 210 //2.10
    ALG2S(WPA_ALG_BIP_CMAC_128)
#else
    ALG2S(WPA_ALG_IGTK)
    ALG2S(WPA_ALG_PMK)
#endif
    ALG2S(WPA_ALG_GCMP)
    ALG2S(WPA_ALG_SMS4)
    ALG2S(WPA_ALG_KRK)
    ALG2S(WPA_ALG_GCMP_256)
    ALG2S(WPA_ALG_CCMP_256)
    ALG2S(WPA_ALG_BIP_GMAC_128)
    ALG2S(WPA_ALG_BIP_GMAC_256)
    ALG2S(WPA_ALG_BIP_CMAC_256)
    default:
    break;
    }

    return "WPA_ALG_UNKNOWN";
}

const char *nl80211_attribute_to_string(enum nl80211_attrs attrib)
{
#define A2S(x) case x: return #x;
    switch (attrib) {
    A2S(NL80211_ATTR_UNSPEC)

    A2S(NL80211_ATTR_WIPHY)
    A2S(NL80211_ATTR_WIPHY_NAME)

    A2S(NL80211_ATTR_IFINDEX)
    A2S(NL80211_ATTR_IFNAME)
    A2S(NL80211_ATTR_IFTYPE)

    A2S(NL80211_ATTR_MAC)

    A2S(NL80211_ATTR_KEY_DATA)
    A2S(NL80211_ATTR_KEY_IDX)
    A2S(NL80211_ATTR_KEY_CIPHER)
    A2S(NL80211_ATTR_KEY_SEQ)
    A2S(NL80211_ATTR_KEY_DEFAULT)

    A2S(NL80211_ATTR_BEACON_INTERVAL)
    A2S(NL80211_ATTR_DTIM_PERIOD)
    A2S(NL80211_ATTR_BEACON_HEAD)
    A2S(NL80211_ATTR_BEACON_TAIL)

    A2S(NL80211_ATTR_STA_AID)
    A2S(NL80211_ATTR_STA_FLAGS)
    A2S(NL80211_ATTR_STA_LISTEN_INTERVAL)
    A2S(NL80211_ATTR_STA_SUPPORTED_RATES)
    A2S(NL80211_ATTR_STA_VLAN)
    A2S(NL80211_ATTR_STA_INFO)

    A2S(NL80211_ATTR_WIPHY_BANDS)

    A2S(NL80211_ATTR_MNTR_FLAGS)

    A2S(NL80211_ATTR_MESH_ID)
    A2S(NL80211_ATTR_STA_PLINK_ACTION)
    A2S(NL80211_ATTR_MPATH_NEXT_HOP)
    A2S(NL80211_ATTR_MPATH_INFO)

    A2S(NL80211_ATTR_BSS_CTS_PROT)
    A2S(NL80211_ATTR_BSS_SHORT_PREAMBLE)
    A2S(NL80211_ATTR_BSS_SHORT_SLOT_TIME)

    A2S(NL80211_ATTR_HT_CAPABILITY)

    A2S(NL80211_ATTR_SUPPORTED_IFTYPES)

    A2S(NL80211_ATTR_REG_ALPHA2)
    A2S(NL80211_ATTR_REG_RULES)

    A2S(NL80211_ATTR_MESH_CONFIG)

    A2S(NL80211_ATTR_BSS_BASIC_RATES)

    A2S(NL80211_ATTR_WIPHY_TXQ_PARAMS)
    A2S(NL80211_ATTR_WIPHY_FREQ)
    A2S(NL80211_ATTR_WIPHY_CHANNEL_TYPE)

    A2S(NL80211_ATTR_KEY_DEFAULT_MGMT)

    A2S(NL80211_ATTR_MGMT_SUBTYPE)
    A2S(NL80211_ATTR_IE)

    A2S(NL80211_ATTR_MAX_NUM_SCAN_SSIDS)

    A2S(NL80211_ATTR_SCAN_FREQUENCIES)
    A2S(NL80211_ATTR_SCAN_SSIDS)
    A2S(NL80211_ATTR_GENERATION) /* replaces old SCAN_GENERATION */
    A2S(NL80211_ATTR_BSS)

    A2S(NL80211_ATTR_REG_INITIATOR)
    A2S(NL80211_ATTR_REG_TYPE)

    A2S(NL80211_ATTR_SUPPORTED_COMMANDS)

    A2S(NL80211_ATTR_FRAME)
    A2S(NL80211_ATTR_SSID)
    A2S(NL80211_ATTR_AUTH_TYPE)
    A2S(NL80211_ATTR_REASON_CODE)

    A2S(NL80211_ATTR_KEY_TYPE)
    A2S(NL80211_ATTR_MAX_SCAN_IE_LEN)
    A2S(NL80211_ATTR_CIPHER_SUITES)

    A2S(NL80211_ATTR_FREQ_BEFORE)
    A2S(NL80211_ATTR_FREQ_AFTER)

    A2S(NL80211_ATTR_FREQ_FIXED)


    A2S(NL80211_ATTR_WIPHY_RETRY_SHORT)
    A2S(NL80211_ATTR_WIPHY_RETRY_LONG)
    A2S(NL80211_ATTR_WIPHY_FRAG_THRESHOLD)
    A2S(NL80211_ATTR_WIPHY_RTS_THRESHOLD)

    A2S(NL80211_ATTR_TIMED_OUT)

    A2S(NL80211_ATTR_USE_MFP)

    A2S(NL80211_ATTR_STA_FLAGS2)

    A2S(NL80211_ATTR_CONTROL_PORT)

    A2S(NL80211_ATTR_TESTDATA)

    A2S(NL80211_ATTR_PRIVACY)

    A2S(NL80211_ATTR_DISCONNECTED_BY_AP)
    A2S(NL80211_ATTR_STATUS_CODE)

    A2S(NL80211_ATTR_CIPHER_SUITES_PAIRWISE)
    A2S(NL80211_ATTR_CIPHER_SUITE_GROUP)
    A2S(NL80211_ATTR_WPA_VERSIONS)
    A2S(NL80211_ATTR_AKM_SUITES)

    A2S(NL80211_ATTR_REQ_IE)
    A2S(NL80211_ATTR_RESP_IE)

    A2S(NL80211_ATTR_PREV_BSSID)
    A2S(NL80211_ATTR_KEY)
    A2S(NL80211_ATTR_KEYS)

    A2S(NL80211_ATTR_PID)

    A2S(NL80211_ATTR_4ADDR)

    A2S(NL80211_ATTR_SURVEY_INFO)

    A2S(NL80211_ATTR_PMKID)
    A2S(NL80211_ATTR_MAX_NUM_PMKIDS)

    A2S(NL80211_ATTR_DURATION)

    A2S(NL80211_ATTR_COOKIE)

    A2S(NL80211_ATTR_WIPHY_COVERAGE_CLASS)

    A2S(NL80211_ATTR_TX_RATES)

    A2S(NL80211_ATTR_FRAME_MATCH)

    A2S(NL80211_ATTR_ACK)

    A2S(NL80211_ATTR_PS_STATE)

    A2S(NL80211_ATTR_CQM)

    A2S(NL80211_ATTR_LOCAL_STATE_CHANGE)

    A2S(NL80211_ATTR_AP_ISOLATE)

    A2S(NL80211_ATTR_WIPHY_TX_POWER_SETTING)
    A2S(NL80211_ATTR_WIPHY_TX_POWER_LEVEL)

    A2S(NL80211_ATTR_TX_FRAME_TYPES)
    A2S(NL80211_ATTR_RX_FRAME_TYPES)
    A2S(NL80211_ATTR_FRAME_TYPE)

    A2S(NL80211_ATTR_CONTROL_PORT_ETHERTYPE)
    A2S(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT)

    A2S(NL80211_ATTR_SUPPORT_IBSS_RSN)

    A2S(NL80211_ATTR_WIPHY_ANTENNA_TX)
    A2S(NL80211_ATTR_WIPHY_ANTENNA_RX)

    A2S(NL80211_ATTR_MCAST_RATE)

    A2S(NL80211_ATTR_OFFCHANNEL_TX_OK)

    A2S(NL80211_ATTR_BSS_HT_OPMODE)

    A2S(NL80211_ATTR_KEY_DEFAULT_TYPES)

    A2S(NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION)

    A2S(NL80211_ATTR_MESH_SETUP)

    A2S(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX)
    A2S(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX)

    A2S(NL80211_ATTR_SUPPORT_MESH_AUTH)
    A2S(NL80211_ATTR_STA_PLINK_STATE)

    A2S(NL80211_ATTR_WOWLAN_TRIGGERS)
    A2S(NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED)

    A2S(NL80211_ATTR_SCHED_SCAN_INTERVAL)

    A2S(NL80211_ATTR_INTERFACE_COMBINATIONS)
    A2S(NL80211_ATTR_SOFTWARE_IFTYPES)

    A2S(NL80211_ATTR_REKEY_DATA)

    A2S(NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS)
    A2S(NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN)

    A2S(NL80211_ATTR_SCAN_SUPP_RATES)

    A2S(NL80211_ATTR_HIDDEN_SSID)

    A2S(NL80211_ATTR_IE_PROBE_RESP)
    A2S(NL80211_ATTR_IE_ASSOC_RESP)

    A2S(NL80211_ATTR_STA_WME)
    A2S(NL80211_ATTR_SUPPORT_AP_UAPSD)

    A2S(NL80211_ATTR_ROAM_SUPPORT)

    A2S(NL80211_ATTR_SCHED_SCAN_MATCH)
    A2S(NL80211_ATTR_MAX_MATCH_SETS)

    A2S(NL80211_ATTR_PMKSA_CANDIDATE)

    A2S(NL80211_ATTR_TX_NO_CCK_RATE)

    A2S(NL80211_ATTR_TDLS_ACTION)
    A2S(NL80211_ATTR_TDLS_DIALOG_TOKEN)
    A2S(NL80211_ATTR_TDLS_OPERATION)
    A2S(NL80211_ATTR_TDLS_SUPPORT)
    A2S(NL80211_ATTR_TDLS_EXTERNAL_SETUP)

    A2S(NL80211_ATTR_DEVICE_AP_SME)

    A2S(NL80211_ATTR_DONT_WAIT_FOR_ACK)

    A2S(NL80211_ATTR_FEATURE_FLAGS)

    A2S(NL80211_ATTR_PROBE_RESP_OFFLOAD)

    A2S(NL80211_ATTR_PROBE_RESP)

    A2S(NL80211_ATTR_DFS_REGION)

    A2S(NL80211_ATTR_DISABLE_HT)
    A2S(NL80211_ATTR_HT_CAPABILITY_MASK)

    A2S(NL80211_ATTR_NOACK_MAP)
    A2S(NL80211_ATTR_INACTIVITY_TIMEOUT)

    A2S(NL80211_ATTR_RX_SIGNAL_DBM)

    A2S(NL80211_ATTR_BG_SCAN_PERIOD)

    A2S(NL80211_ATTR_WDEV)

    A2S(NL80211_ATTR_USER_REG_HINT_TYPE)

    A2S(NL80211_ATTR_CONN_FAILED_REASON)

    A2S(NL80211_ATTR_AUTH_DATA)

    A2S(NL80211_ATTR_VHT_CAPABILITY)

    A2S(NL80211_ATTR_SCAN_FLAGS)

    A2S(NL80211_ATTR_CHANNEL_WIDTH)
    A2S(NL80211_ATTR_CENTER_FREQ1)
    A2S(NL80211_ATTR_CENTER_FREQ2)

    A2S(NL80211_ATTR_P2P_CTWINDOW)
    A2S(NL80211_ATTR_P2P_OPPPS)

    A2S(NL80211_ATTR_LOCAL_MESH_POWER_MODE)

    A2S(NL80211_ATTR_ACL_POLICY)

    A2S(NL80211_ATTR_MAC_ADDRS)

    A2S(NL80211_ATTR_MAC_ACL_MAX)

    A2S(NL80211_ATTR_RADAR_EVENT)

    A2S(NL80211_ATTR_EXT_CAPA)
    A2S(NL80211_ATTR_EXT_CAPA_MASK)

    A2S(NL80211_ATTR_STA_CAPABILITY)
    A2S(NL80211_ATTR_STA_EXT_CAPABILITY)
    A2S(NL80211_ATTR_PROTOCOL_FEATURES)
    A2S(NL80211_ATTR_SPLIT_WIPHY_DUMP)

    A2S(NL80211_ATTR_DISABLE_VHT)
    A2S(NL80211_ATTR_VHT_CAPABILITY_MASK)

    A2S(NL80211_ATTR_MDID)
    A2S(NL80211_ATTR_IE_RIC)

    A2S(NL80211_ATTR_CRIT_PROT_ID)
    A2S(NL80211_ATTR_MAX_CRIT_PROT_DURATION)

    A2S(NL80211_ATTR_PEER_AID)

    A2S(NL80211_ATTR_COALESCE_RULE)

    A2S(NL80211_ATTR_CH_SWITCH_COUNT)
    A2S(NL80211_ATTR_CH_SWITCH_BLOCK_TX)
    A2S(NL80211_ATTR_CSA_IES)
    A2S(NL80211_ATTR_CSA_C_OFF_BEACON)
    A2S(NL80211_ATTR_CSA_C_OFF_PRESP)

    A2S(NL80211_ATTR_RXMGMT_FLAGS)

    A2S(NL80211_ATTR_STA_SUPPORTED_CHANNELS)

    A2S(NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES)

    A2S(NL80211_ATTR_HANDLE_DFS)

    A2S(NL80211_ATTR_SUPPORT_5_MHZ)
    A2S(NL80211_ATTR_SUPPORT_10_MHZ)

    A2S(NL80211_ATTR_OPMODE_NOTIF)

    A2S(NL80211_ATTR_VENDOR_ID)
    A2S(NL80211_ATTR_VENDOR_SUBCMD)
    A2S(NL80211_ATTR_VENDOR_DATA)
    A2S(NL80211_ATTR_VENDOR_EVENTS)
    A2S(NL80211_ATTR_QOS_MAP)

    A2S(NL80211_ATTR_MAC_HINT)
    A2S(NL80211_ATTR_WIPHY_FREQ_HINT)

    A2S(NL80211_ATTR_MAX_AP_ASSOC_STA)

    A2S(NL80211_ATTR_TDLS_PEER_CAPABILITY)

    A2S(NL80211_ATTR_SOCKET_OWNER)

    A2S(NL80211_ATTR_CSA_C_OFFSETS_TX)
    A2S(NL80211_ATTR_MAX_CSA_COUNTERS)

    A2S(NL80211_ATTR_TDLS_INITIATOR)

    A2S(NL80211_ATTR_USE_RRM)

    A2S(NL80211_ATTR_WIPHY_DYN_ACK)

    A2S(NL80211_ATTR_TSID)
    A2S(NL80211_ATTR_USER_PRIO)
    A2S(NL80211_ATTR_ADMITTED_TIME)

    A2S(NL80211_ATTR_SMPS_MODE)

    A2S(NL80211_ATTR_OPER_CLASS)

    A2S(NL80211_ATTR_MAC_MASK)

    A2S(NL80211_ATTR_WIPHY_SELF_MANAGED_REG)

    A2S(NL80211_ATTR_EXT_FEATURES)

    A2S(NL80211_ATTR_SURVEY_RADIO_STATS)

    A2S(NL80211_ATTR_NETNS_FD)

    A2S(NL80211_ATTR_SCHED_SCAN_DELAY)
    A2S(NL80211_ATTR_REG_INDOOR)

    A2S(NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS)
    A2S(NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL)
    A2S(NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS)
    A2S(NL80211_ATTR_SCHED_SCAN_PLANS)

    A2S(NL80211_ATTR_PBSS)

    A2S(NL80211_ATTR_BSS_SELECT)

    A2S(NL80211_ATTR_STA_SUPPORT_P2P_PS)

    A2S(NL80211_ATTR_PAD)

    A2S(NL80211_ATTR_IFTYPE_EXT_CAPA)

    A2S(NL80211_ATTR_MU_MIMO_GROUP_DATA)
    A2S(NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR)

    A2S(NL80211_ATTR_SCAN_START_TIME_TSF)
    A2S(NL80211_ATTR_SCAN_START_TIME_TSF_BSSID)
    A2S(NL80211_ATTR_MEASUREMENT_DURATION)
    A2S(NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY)

    A2S(NL80211_ATTR_MESH_PEER_AID)

    A2S(NL80211_ATTR_NAN_MASTER_PREF)
    A2S(NL80211_ATTR_BANDS)
    A2S(NL80211_ATTR_NAN_FUNC)
    A2S(NL80211_ATTR_NAN_MATCH)

    A2S(NL80211_ATTR_FILS_KEK)
    A2S(NL80211_ATTR_FILS_NONCES)

    A2S(NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED)

    A2S(NL80211_ATTR_BSSID)

    A2S(NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI)
    A2S(NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST)

    A2S(NL80211_ATTR_TIMEOUT_REASON)

    A2S(NL80211_ATTR_FILS_ERP_USERNAME)
    A2S(NL80211_ATTR_FILS_ERP_REALM)
    A2S(NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM)
    A2S(NL80211_ATTR_FILS_ERP_RRK)
    A2S(NL80211_ATTR_FILS_CACHE_ID)

    A2S(NL80211_ATTR_PMK)

    A2S(NL80211_ATTR_SCHED_SCAN_MULTI)
    A2S(NL80211_ATTR_SCHED_SCAN_MAX_REQS)

    A2S(NL80211_ATTR_WANT_1X_4WAY_HS)
    A2S(NL80211_ATTR_PMKR0_NAME)
    A2S(NL80211_ATTR_PORT_AUTHORIZED)

    A2S(NL80211_ATTR_EXTERNAL_AUTH_ACTION)
    A2S(NL80211_ATTR_EXTERNAL_AUTH_SUPPORT)

    A2S(NL80211_ATTR_NSS)
    A2S(NL80211_ATTR_ACK_SIGNAL)

    A2S(NL80211_ATTR_CONTROL_PORT_OVER_NL80211)

    A2S(NL80211_ATTR_TXQ_STATS)
    A2S(NL80211_ATTR_TXQ_LIMIT)
    A2S(NL80211_ATTR_TXQ_MEMORY_LIMIT)
    A2S(NL80211_ATTR_TXQ_QUANTUM)

    default:
        return "NL80211_ATTRIB_UNKNOWN";

    }
#undef A2S
}

/*
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 * Licensed under the BSD-3 License
*/
const char *nl80211_command_to_string(enum nl80211_commands cmd)
{
#define C2S(x) case x: return #x;
    switch (cmd) {
    C2S(NL80211_CMD_UNSPEC)
    C2S(NL80211_CMD_GET_WIPHY)
    C2S(NL80211_CMD_SET_WIPHY)
    C2S(NL80211_CMD_NEW_WIPHY)
    C2S(NL80211_CMD_DEL_WIPHY)
    C2S(NL80211_CMD_GET_INTERFACE)
    C2S(NL80211_CMD_SET_INTERFACE)
    C2S(NL80211_CMD_NEW_INTERFACE)
    C2S(NL80211_CMD_DEL_INTERFACE)
    C2S(NL80211_CMD_GET_KEY)
    C2S(NL80211_CMD_SET_KEY)
    C2S(NL80211_CMD_NEW_KEY)
    C2S(NL80211_CMD_DEL_KEY)
    C2S(NL80211_CMD_GET_BEACON)
    C2S(NL80211_CMD_SET_BEACON)
    C2S(NL80211_CMD_START_AP)
    C2S(NL80211_CMD_STOP_AP)
    C2S(NL80211_CMD_GET_STATION)
    C2S(NL80211_CMD_SET_STATION)
    C2S(NL80211_CMD_NEW_STATION)
    C2S(NL80211_CMD_DEL_STATION)
    C2S(NL80211_CMD_GET_MPATH)
    C2S(NL80211_CMD_SET_MPATH)
    C2S(NL80211_CMD_NEW_MPATH)
    C2S(NL80211_CMD_DEL_MPATH)
    C2S(NL80211_CMD_SET_BSS)
    C2S(NL80211_CMD_SET_REG)
    C2S(NL80211_CMD_REQ_SET_REG)
    C2S(NL80211_CMD_GET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
    C2S(NL80211_CMD_GET_REG)
    C2S(NL80211_CMD_GET_SCAN)
    C2S(NL80211_CMD_TRIGGER_SCAN)
    C2S(NL80211_CMD_NEW_SCAN_RESULTS)
    C2S(NL80211_CMD_SCAN_ABORTED)
    C2S(NL80211_CMD_REG_CHANGE)
    C2S(NL80211_CMD_AUTHENTICATE)
    C2S(NL80211_CMD_ASSOCIATE)
    C2S(NL80211_CMD_DEAUTHENTICATE)
    C2S(NL80211_CMD_DISASSOCIATE)
    C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
    C2S(NL80211_CMD_REG_BEACON_HINT)
    C2S(NL80211_CMD_JOIN_IBSS)
    C2S(NL80211_CMD_LEAVE_IBSS)
    C2S(NL80211_CMD_TESTMODE)
    C2S(NL80211_CMD_CONNECT)
    C2S(NL80211_CMD_ROAM)
    C2S(NL80211_CMD_DISCONNECT)
    C2S(NL80211_CMD_SET_WIPHY_NETNS)
    C2S(NL80211_CMD_GET_SURVEY)
    C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
    C2S(NL80211_CMD_SET_PMKSA)
    C2S(NL80211_CMD_DEL_PMKSA)
    C2S(NL80211_CMD_FLUSH_PMKSA)
    C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
    C2S(NL80211_CMD_REGISTER_FRAME)
    C2S(NL80211_CMD_FRAME)
    C2S(NL80211_CMD_FRAME_TX_STATUS)
    C2S(NL80211_CMD_SET_POWER_SAVE)
    C2S(NL80211_CMD_GET_POWER_SAVE)
    C2S(NL80211_CMD_SET_CQM)
    C2S(NL80211_CMD_NOTIFY_CQM)
    C2S(NL80211_CMD_SET_CHANNEL)
    C2S(NL80211_CMD_SET_WDS_PEER)
    C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
    C2S(NL80211_CMD_JOIN_MESH)
    C2S(NL80211_CMD_LEAVE_MESH)
    C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
    C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
    C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
    C2S(NL80211_CMD_GET_WOWLAN)
    C2S(NL80211_CMD_SET_WOWLAN)
    C2S(NL80211_CMD_START_SCHED_SCAN)
    C2S(NL80211_CMD_STOP_SCHED_SCAN)
    C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
    C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
    C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
    C2S(NL80211_CMD_PMKSA_CANDIDATE)
    C2S(NL80211_CMD_TDLS_OPER)
    C2S(NL80211_CMD_TDLS_MGMT)
    C2S(NL80211_CMD_UNEXPECTED_FRAME)
    C2S(NL80211_CMD_PROBE_CLIENT)
    C2S(NL80211_CMD_REGISTER_BEACONS)
    C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
    C2S(NL80211_CMD_SET_NOACK_MAP)
    C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
    C2S(NL80211_CMD_START_P2P_DEVICE)
    C2S(NL80211_CMD_STOP_P2P_DEVICE)
    C2S(NL80211_CMD_CONN_FAILED)
    C2S(NL80211_CMD_SET_MCAST_RATE)
    C2S(NL80211_CMD_SET_MAC_ACL)
    C2S(NL80211_CMD_RADAR_DETECT)
    C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
    C2S(NL80211_CMD_UPDATE_FT_IES)
    C2S(NL80211_CMD_FT_EVENT)
    C2S(NL80211_CMD_CRIT_PROTOCOL_START)
    C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
    C2S(NL80211_CMD_GET_COALESCE)
    C2S(NL80211_CMD_SET_COALESCE)
    C2S(NL80211_CMD_CHANNEL_SWITCH)
    C2S(NL80211_CMD_VENDOR)
    C2S(NL80211_CMD_SET_QOS_MAP)
    C2S(NL80211_CMD_ADD_TX_TS)
    C2S(NL80211_CMD_DEL_TX_TS)
    C2S(NL80211_CMD_WIPHY_REG_CHANGE)
    C2S(NL80211_CMD_PORT_AUTHORIZED)
    C2S(NL80211_CMD_EXTERNAL_AUTH)
    C2S(NL80211_CMD_STA_OPMODE_CHANGED)
    C2S(NL80211_CMD_CONTROL_PORT_FRAME)
    default:
        return "NL80211_CMD_UNKNOWN";
    }
#undef C2S
}

void print_attributes(char *cmd, struct nlattr *tb[])
{
    unsigned int i;
    wifi_hal_dbg_print("\n%s attributes:\n", cmd);
    for (i = 0; i < NL80211_ATTR_MAX; i++) {
        if (tb[i] != NULL) {
            wifi_hal_dbg_print("%s\t", nl80211_attribute_to_string(nla_type(tb[i])));
        }
    }
    wifi_hal_dbg_print("\n\n");
}

void print_supported_commands(char *cmd, struct nlattr *tb)
{
    unsigned int i;
    struct nlattr *nl_cmd;

    if (tb != NULL) {
        wifi_hal_dbg_print("\n%s commands:\n", cmd);
        nla_for_each_nested(nl_cmd, tb, i) {
            wifi_hal_dbg_print("%s\t", nl80211_command_to_string(nla_get_u32(nl_cmd)));
        }
        wifi_hal_dbg_print("\n\n");
    }
}

char *get_wifi_drv_name()
{
    return driver_info.driver_name;
}

wifi_device_info_t get_device_info_details()
{
    return driver_info.device_info;
}
platform_pre_init_t	get_platform_pre_init_fn()
{
    return driver_info.platform_pre_init_fn;
}

platform_post_init_t 	get_platform_post_init_fn()
{
    return driver_info.platform_post_init_fn;
}

platform_ssid_default_t get_platform_ssid_default_fn()
{
   return driver_info.platform_ssid_default_fn;
}

platform_keypassphrase_default_t get_platform_keypassphrase_default_fn()
{
   return driver_info.platform_keypassphrase_default_fn;
}

platform_radius_key_default_t get_platform_radius_key_default_fn()
{
   return driver_info.platform_radius_key_default_fn;
}

platform_wps_pin_default_t get_platform_wps_pin_default_fn()
{
   return driver_info.platform_wps_pin_default_fn;
}

platform_wps_event_t get_platform_wps_event_fn()
{
   return driver_info.platform_wps_event_fn;
}

platform_country_code_default_t get_platform_country_code_default_fn()
{
    return driver_info.platform_country_code_default_fn;
}

platform_set_radio_params_t	get_platform_set_radio_fn()
{
    return driver_info.platform_set_radio_fn;
}

platform_pre_create_vap_t   get_platform_pre_create_vap_fn()
{
    return driver_info.platform_pre_create_vap_fn;
}

platform_create_vap_t	get_platform_create_vap_fn()
{
    return driver_info.platform_create_vap_fn;
}

platform_set_radio_pre_init_t get_platform_set_radio_pre_init_fn()
{
    return driver_info.platform_set_radio_pre_init_fn;
}

platform_flags_init_t   get_platform_flags_init_fn()
{
    return driver_info.platform_flags_init_fn;
}

platform_get_aid_t get_platform_get_aid_fn()
{
    return driver_info.platform_get_aid_fn;
}

platform_free_aid_t get_platform_free_aid_fn()
{
    return driver_info.platform_free_aid_fn;
}

platform_sync_done_t get_platform_sync_done_fn()
{
    return driver_info.platform_sync_done_fn;
}

platform_update_radio_presence_t get_platform_update_radio_presence_fn()
{
    return driver_info.platform_update_radio_presence_fn;
}

platform_set_txpower_t get_platform_set_txpower_fn()
{
    return driver_info.platform_set_txpower_fn;
}

platform_set_acs_exclusion_list_t get_platform_acs_exclusion_list_fn()
{
    return driver_info.platform_set_acs_exclusion_list_fn;
}

platform_get_chanspec_list_t get_platform_chanspec_list_fn()
{
    return driver_info.platform_get_chanspec_list_fn;
}

platform_get_ApAclDeviceNum_t get_platform_ApAclDeviceNum_fn()
{
    return driver_info.platform_get_ApAclDeviceNum_fn;
}
platform_set_neighbor_report_t get_platform_set_neighbor_report_fn()
{
    return driver_info.platform_set_neighbor_report_fn;
}

platform_get_vendor_oui_t get_platform_vendor_oui_fn()
{
    return driver_info.platform_get_vendor_oui_fn;
}

platform_get_radio_phytemperature_t get_platform_get_radio_phytemperature_fn()
{
    return driver_info.platform_get_radio_phytemperature_fn;
}

platform_set_offload_mode_t get_platform_set_offload_mode_fn()
{
    return driver_info.platform_set_offload_mode_fn;
}

platform_set_dfs_t get_platform_dfs_set_fn()
{
    return driver_info.platform_set_dfs_fn;
}

platform_get_radio_caps_t get_platform_get_radio_caps_fn()
{
    return driver_info.platform_get_radio_caps_fn;
}

platform_get_RegDomain_t get_platform_get_RegDomain_fn()
{
    return driver_info.platform_get_RegDomain_fn;
}

bool lsmod_by_name(const char *name)
{
    FILE *fp = NULL;
    char line[4096];

    if ((fp = fopen("/proc/modules", "r")) == NULL) {
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name) != NULL && strstr(line, "Live") != NULL) {
            fclose(fp);
            return true;
        }
    }

    fclose(fp);

    return false;
}

void update_ecomode_radio_capabilities(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned int channels_2_4g[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    unsigned int channels_5g[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 144, 149, 153, 157, 161, 165};
    unsigned int channels_6g[] = {5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229};

    if (radio == NULL) {
       wifi_hal_error_print("%s:%d: Failed in updating the eco mode radio capabilities\n", __func__, __LINE__);
       return;
    }

    radio->capab.index = radio->index;
    sprintf(radio->capab.ifaceName, "%s", radio->name);
    radio->capab.numSupportedFreqBand = 1;

    interface = hash_map_get_first(radio->interface_map);

    if (interface != NULL) {
        vap = &interface->vap_info;
        if (strstr(vap->vap_name, "2g") != NULL) {
            radio->oper_param.band = WIFI_FREQUENCY_2_4_BAND;
        } else if (strstr(vap->vap_name, "5g") != NULL) {
            radio->oper_param.band = WIFI_FREQUENCY_5_BAND;
        } else if (strstr(vap->vap_name, "6g") != NULL) {
            radio->oper_param.band = WIFI_FREQUENCY_6_BAND;
        } else {
            wifi_hal_error_print("%s:%d: Failed in updating frequency band for the eco mode radio\n", __func__, __LINE__);
            return;
        }
    }

    switch (radio->oper_param.band)
    {
        case WIFI_FREQUENCY_2_4_BAND:
            radio->capab.band[0] = WIFI_FREQUENCY_2_4_BAND;
            radio->capab.channel_list[0].num_channels = ARRAY_SZ(channels_2_4g);
            memcpy(radio->capab.channel_list[0].channels_list, channels_2_4g, sizeof(channels_2_4g));
            break;
        case WIFI_FREQUENCY_5_BAND:
            radio->capab.band[0] = WIFI_FREQUENCY_5_BAND;
            radio->capab.channel_list[0].num_channels = ARRAY_SZ(channels_5g);
            memcpy(radio->capab.channel_list[0].channels_list, channels_5g, sizeof(channels_5g));
            break;
        case WIFI_FREQUENCY_6_BAND:
            radio->capab.band[0] = WIFI_FREQUENCY_6_BAND;
            radio->capab.channel_list[0].num_channels = ARRAY_SZ(channels_6g);
            memcpy(radio->capab.channel_list[0].channels_list, channels_6g, sizeof(channels_6g));
            break;
        default:
            wifi_hal_error_print("%s:%d: Frequency band not defined\n", __func__, __LINE__);
            break;
    }
}

int create_ecomode_interfaces(void)
{
    uint8_t radioIndex;

    for (radioIndex = 0; radioIndex < get_sizeof_radio_interfaces_map(); radioIndex++)
    {
        int found = 0, j;
        wifi_radio_info_t *radio;
        for (j = 0; j < g_wifi_hal.num_radios; j++) {
           radio = &g_wifi_hal.radio_info[j];
           if (NULL == radio) {
               wifi_hal_error_print("%s:%d: Failed in creating eco mode interfaces\n", __func__, __LINE__);
               return -1;
           }
           if (radio->rdk_radio_index == l_radio_interface_map[radioIndex].radio_index) {
               //Radio interface not in ECO mode [Added already in g_wifi_hal.radio_info after notification from driver]
               found = 1;
               radio->radio_presence = true;
               wifi_hal_dbg_print("%s:%d: Found ECO Active mode radio , coming out\n", __func__, __LINE__);
               break;
           }
        }

        if (!found) {
          wifi_hal_dbg_print("%s:%d: Set up things for the ECO Sleeping mode radio\n", __func__, __LINE__);
          radio = &g_wifi_hal.radio_info[g_wifi_hal.num_radios];
          memset((unsigned char *)radio, 0, sizeof(wifi_radio_info_t));
          radio->radio_presence = false;
          radio->index =  l_radio_interface_map[radioIndex].phy_index;
          radio->rdk_radio_index = l_radio_interface_map[radioIndex].radio_index;
          radio->capab.index = radio->index;
          sprintf(radio->name, "%s", l_radio_interface_map[radioIndex].radio_name);
          g_wifi_hal.num_radios++;
          radio->capab.maxNumberVAPs = 0;
          radio->interface_map = hash_map_create();

          //Add interfaces to the Sleeping radio
          int vapIndex;
          wifi_vap_info_t *vap = NULL;

          for (vapIndex = 0; vapIndex < get_sizeof_interfaces_index_map(); vapIndex++)
          {
             wifi_interface_info_t *interface = NULL;
              wifi_hal_dbg_print("%s:%d: Process %s  vap interface to add to the radio\n", __func__, __LINE__, interface_index_map[vapIndex].interface_name);
              if (interface_index_map[vapIndex].rdk_radio_index != l_radio_interface_map[radioIndex].radio_index) {
                 continue;
              }

              interface = (wifi_interface_info_t *)malloc(sizeof(wifi_interface_info_t));
              if (interface == NULL) {
                  wifi_hal_dbg_print("%s:%d: malloc failed! Continue\n", __func__, __LINE__);
                  continue;
              }
              memset(interface, 0, sizeof(wifi_interface_info_t));
              interface->phy_index = radio->index;
              interface->index = interface_index_map[vapIndex].index;
              sprintf(interface->name, "%s", interface_index_map[vapIndex].interface_name);
              if (set_interface_properties(interface->phy_index , interface) != 0) {
                  wifi_hal_info_print("%s:%d: Could not map interface name to index:%d\n", __func__, __LINE__, interface->phy_index);
              }
              vap = &interface->vap_info;
              wifi_hal_dbg_print("%s:%d: phy index: %d\tradio index: %d\tinterface index: %d name: %s  type:%d, mac:%02x:%02x:%02x:%02x:%02x:%02x vap index: %d vap name: %s\n",
                                 __func__, __LINE__,radio->index, vap->radio_index, interface->index, interface->name, interface->type,interface->mac[0], interface->mac[1],
                                 interface->mac[2],interface->mac[3], interface->mac[4], interface->mac[5],vap->vap_index, vap->vap_name);
              hash_map_put(radio->interface_map, strdup(interface->name), interface);
              radio->capab.maxNumberVAPs++;

              wifi_hal_dbg_print("%s:%d: Fetch next interface after the radio interface hash map [%s]\n", __func__, __LINE__, interface->name);
           }
           // Build the sleeping radio capabilities manually based on the available info in the 'radio' to bringup webconfig,  Device.WiFi.**
           update_ecomode_radio_capabilities(radio);
       }
    }
    wifi_hal_dbg_print("\n%s:%d: Number of radios %d\n", __func__, __LINE__, g_wifi_hal.num_radios);
    return 0;
}

int uint_array_set(uint_array_t *array, uint num, const uint values[])
{
    int ret = 0;
    if (array == NULL) return -1;

    if (num == 0)
        goto cleanup_array;

    /* Reallocate array if needed */
    if (num != array->num) {
        free(array->values);
        array->values = (uint*)malloc(num * sizeof(uint));
        if (array->values == NULL) {
            wifi_hal_stats_error_print("%s:%d: memory allocation error!\n", __func__, __LINE__);
            ret = -1;
            goto cleanup_array;
        }
        array->num = num;
    }

    /* Copy freq data to the array entry */
    if (values) {
        memcpy(array->values, values, num * sizeof(uint));
    } else {
        memset(array->values, 0, num * sizeof(uint));
    }
    return 0;

cleanup_array:
    free(array->values);
    array->values = NULL;
    array->num = 0;
    return ret;
}

int wifi_freq_to_channel(int freq, uint *channel)
{
    uint8_t u8_channel;
    *channel = 0;
    if (NUM_HOSTAPD_MODES == ieee80211_freq_to_chan(freq, &u8_channel))
        return RETURN_ERR;
    *channel = u8_channel;
    return RETURN_OK;
}

int wifi_channel_to_freq(const char* country, UCHAR opclass, uint channel, uint *freq)
{
    int ifreq = ieee80211_chan_to_freq(country, opclass, channel);
    *freq = (uint)ifreq;
    return (ifreq < 0) ? RETURN_ERR : RETURN_OK;
}

enum nl80211_band wifi_freq_band_to_nl80211_band(wifi_freq_bands_t band)
{
    switch (band) {
        case WIFI_FREQUENCY_2_4_BAND:
            return NL80211_BAND_2GHZ;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
            return NL80211_BAND_5GHZ;
    #if HOSTAPD_VERSION >= 210
        case WIFI_FREQUENCY_6_BAND:
            return NL80211_BAND_6GHZ;
    #endif
        default:
            return NUM_NL80211_BANDS;
    }
}

enum nl80211_band get_nl80211_band_from_rdk_radio_index(unsigned int rdk_radio_index)
{
    unsigned int i;
    const char *vap_name = NULL;
    const char *suffix = NULL;
    const char *band_str = NULL;

    for (i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        if (interface_index_map[i].rdk_radio_index == rdk_radio_index) {
            vap_name = interface_index_map[i].vap_name;
            if (!vap_name) {
                break;
            }

            suffix = strrchr(vap_name, '_');
            if (suffix && strlen(suffix + 1) > 0) {
                band_str = suffix + 1;

                if (strncmp(band_str, "2g", 2) == 0) {
                    return NL80211_BAND_2GHZ;
                } else if (strncmp(band_str, "5g", 2) == 0 ||
                           strncmp(band_str, "5gl", 3) == 0 ||
                           strncmp(band_str, "5gh", 3) == 0) {
                    return NL80211_BAND_5GHZ;
#if HOSTAPD_VERSION >= 210 && !defined(XLE_PORT)
                } else if (strncmp(band_str, "6g", 2) == 0) {
                    return NL80211_BAND_6GHZ;
#endif
                }
            }

            wifi_hal_error_print("%s:%d: Unable to parse band from vap_name: %s\n",
                                 __func__, __LINE__, vap_name);
            break;
        }
    }

    wifi_hal_error_print("%s:%d: Failed to resolve band for rdk_radio_index: %u\n",
                         __func__, __LINE__, rdk_radio_index);
    return NUM_NL80211_BANDS;
}

const char* get_chan_dfs_state(struct hostapd_channel_data *chan)
{
    switch (chan->flag & HOSTAPD_CHAN_DFS_MASK) {
        case HOSTAPD_CHAN_DFS_UNKNOWN:
            return "unknown";
        case HOSTAPD_CHAN_DFS_USABLE:
            return "usable";
        case HOSTAPD_CHAN_DFS_UNAVAILABLE:
            return "unavailable";
        case HOSTAPD_CHAN_DFS_AVAILABLE:
            return "available";
        default:
            return "-";
    }
}

int get_total_num_of_vaps(void)
{
    unsigned char l_index = 0;
    int total_num_of_vaps = 0;
    wifi_radio_info_t *radio;

    for (l_index = 0; l_index < g_wifi_hal.num_radios; l_index++) {
#ifndef FEATURE_SINGLE_PHY
        radio = get_radio_by_rdk_index(l_index);
#else //FEATURE_SINGLE_PHY
        radio = &g_wifi_hal.radio_info[l_index];
#endif //FEATURE_SINGLE_PHY
        total_num_of_vaps += radio->capab.maxNumberVAPs;
    }

    return total_num_of_vaps;
}

/*
    int wifi_strcpy(char *dest, size_t dest_size, const char *src);
    lightweight replacement for strcpy_s()

    function checks input parameters for null pointers, buffer size, overlapped regions.

    Returns:
         0 - success
        -1 - on any error
*/
int wifi_strcpy(char *dest, size_t dest_size, const char *src)
{
    size_t srclen;

    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;

    dest[0] = '\0';
    srclen = strnlen(src, dest_size);
    if (srclen >= dest_size)
        return -1;

    // Check for overlap
    if ((src >= dest && src < dest + dest_size) ||
        (dest >= src && dest < src + srclen))
        return -1;

    memcpy(dest, src, srclen);
    dest[srclen] = '\0';
    return 0;
}

/*
    int wifi_strcat(char *dest, size_t dest_size, const char *src);
    lightweight replacement for strcat_s()

    function checks input parameters for null pointers, buffer size, overlapped regions.

    Returns:
         0 - success
        -1 - on any error
*/
int wifi_strcat(char *dest, size_t dest_size, const char *src)
{
    size_t destlen, srclen;

    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;

    destlen = strnlen(dest, dest_size);
    srclen = strnlen(src, dest_size);

    if (destlen + srclen >= dest_size)
        return -1;

    // Check for overlap
    if ((src >= dest && src < dest + dest_size) ||
        (dest >= src && dest < src + srclen))
        return -1;

    memcpy(dest + destlen, src, srclen);
    dest[destlen + srclen] = '\0';
    return 0;
}

/*
    int wifi_strncpy(char *dest, size_t dest_size, const char *src, size_t count)
    lightweight replacement for strncpy_s()

    function checks input parameters for null pointers, buffer size, overlapped regions.

    Returns:
         0 - success
        -1 - on any error
*/
int wifi_strncpy(char *dest, size_t dest_size, const char *src, size_t count)
{
    size_t srclen;

    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;

    dest[0] = '\0';
    if (count >= dest_size)
        return -1;

    srclen = strnlen(src, dest_size);
    count = (srclen < count) ? srclen : count;

    // Check for overlap
    if ((src >= dest && src < dest + dest_size) ||
        (dest >= src && dest < src + count))
        return -1;

    memcpy(dest, src, count);
    dest[count] = '\0';
    return 0;
}

/* Add a new string to the comma-separated list */
int str_list_append(char *dest, size_t dest_size, const char *src)
{
    if (dest_size == 0) return 0;
    if (dest[0] == '\0') {
        if (wifi_strcpy(dest, dest_size, src)) return -1;
    } else {
        if (wifi_strcat(dest, dest_size, ",")) return -1;
        if (wifi_strcat(dest, dest_size, src)) return -1;
    }
    return 0;
}

static int wifi_enum_bitmap_to_str(char *dest, size_t dest_size,
    const wifi_enum_to_str_map_t map[], size_t map_size, const char *prefix,
    int bitmap)
{
    size_t i;

    if ((dest == NULL) || (dest_size == 0)) {
        wifi_hal_error_print("%s:%d: NULL or zero-size buffer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    *dest = '\0';
    for (i = 0; i < map_size; ++i) {
        if (bitmap & map[i].enum_val) {
            if (str_list_append(dest, dest_size, prefix))
                goto fail;
            if (wifi_strcat(dest, dest_size, map[i].str_val))
                goto fail;
        }
    }
    return RETURN_OK;

fail:
    wifi_hal_error_print("%s:%d: cannot to append a new value to the string buffer\n", __func__, __LINE__);
    return RETURN_ERR;
}

int wifi_ieee80211Variant_to_str(char *dest, size_t dest_size, wifi_ieee80211Variant_t variant,
    const char *str)
{
    const char *mode;

    if (*str != '\0') {
        return wifi_enum_bitmap_to_str(dest, dest_size, wifi_variant_Map,
            ARRAY_SIZE(wifi_variant_Map), str, (int)variant);
    } else {
        if ((dest != NULL) && (dest_size != 0)) {
            *dest = '\0';

            if (variant & WIFI_80211_VARIANT_A) {
                mode = "a";
                str_list_append(dest, dest_size, mode);
            }
            if (variant & WIFI_80211_VARIANT_B) {
                mode = "b";
                str_list_append(dest, dest_size, mode);
            }
            if (variant & WIFI_80211_VARIANT_G) {
                mode = "g";
                str_list_append(dest, dest_size, mode);
            }
            if (variant &
                (WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX |
                    WIFI_80211_VARIANT_BE)) {
                if ((variant & WIFI_80211_VARIANT_BE) && (variant & WIFI_80211_VARIANT_AX)) {
                    // Wi-Fi 7 supports both AX (6E base) and BE (Wi-Fi 7)
                    str_list_append(dest, dest_size, "ax");
                    str_list_append(dest, dest_size, "be");
                } else {
                    if (variant & WIFI_80211_VARIANT_BE) {
                        mode = "be";
                    } else if (variant & WIFI_80211_VARIANT_AX) {
                        mode = "ax";
                    } else if (variant & WIFI_80211_VARIANT_AC) {
                        mode = "ac";
                    } else {
                        mode = "n";
                    }
                    str_list_append(dest, dest_size, mode);
                }
            }
        } else {
            wifi_hal_error_print("%s:%d: NULL or zero-size buffer\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

int wifi_channelBandwidth_to_str(char *dest, size_t dest_size, wifi_channelBandwidth_t bandwidth)
{
    return wifi_enum_bitmap_to_str(dest, dest_size,
        wifi_bandwidth_Map, ARRAY_SIZE(wifi_bandwidth_Map),
        "", (int)bandwidth);
}

int wifi_bitrate_to_str(char *dest, size_t dest_size, wifi_bitrate_t bitrate)
{
    return wifi_enum_bitmap_to_str(dest, dest_size,
        wifi_bitrate_Map, ARRAY_SIZE(wifi_bitrate_Map),
        "", (int)bitrate);
}

int wifi_channelBandwidth_from_str(const char *str, wifi_channelBandwidth_t *bandwidth)
{
    for (size_t i = 0; i < ARRAY_SIZE(wifi_bandwidth_Map); i++) {
        if (strcasecmp(str, wifi_bandwidth_Map[i].str_val) == 0) {
            *bandwidth = (wifi_channelBandwidth_t)wifi_bandwidth_Map[i].enum_val;
            return 0;
        }
    }
    return -1; 
}

/* return AP-config pointer as well as group index */
wifi_steering_apConfig_t* steering_find_ap_cfg(int vap_index, uint32_t *g_idx)
{
    int i, j;
    wifi_bm_steering_group_t      *g_ptr;
    wifi_bm_steering_group_info_t *g_info;

    for (i = 0; i < MAX_STEERING_GROUP_NUM; i++)
    {
        g_ptr = &g_wifi_hal.bm_steer_groups[i];

        if (!g_ptr->group_enable) {
            continue;
        }

        for (j = 0; j < MAX_NUM_RADIOS; j++) {
            g_info = &g_ptr->bm_group_info[j];

            if (g_info->config.apIndex == vap_index) {
                *g_idx = g_ptr->group_index;
                wifi_hal_dbg_print("%s:%d: found group index %d for ap_index:%d\n", __func__, __LINE__, g_ptr->group_index, vap_index);
                return &g_info->config;
            }
        }
    }
    return NULL;
}

int wifi_steering_add_mac_list(uint32_t vap_index, bm_sta_list_t *sta_info)
{
    mac_addr_str_t sta_mac_str;
    char *key;
    int ret;

    sta_info->is_acl_set = true;
    /* re-configure macmode etc. in case the run-time setting is cleared by ApplySetting */
    /* Macfilter deny mode set */
    ret = steering_set_acl_mode(vap_index, wifi_mac_filter_mode_black_list);
    if (ret != RETURN_OK)
    {
        return ret;
    }

    key = to_mac_str(sta_info->mac_addr, sta_mac_str);
    ret = wifi_hal_addApAclDevice(vap_index, key);

    wifi_hal_info_print("status:%d: add sta:%s to maclist on vap_index:%d\n", ret, key, vap_index);
    return ret;
}

int wifi_steering_del_mac_list(uint32_t vap_index, bm_sta_list_t *sta_info)
{
    int ret;
    mac_addr_str_t sta_mac_str;
    char *key;

    key = to_mac_str(sta_info->mac_addr, sta_mac_str);
    if (sta_info->is_acl_set != true) {
        wifi_hal_error_print("steering mac filter acl is not configured for sta:%s on vap_index:%d\n", key, vap_index);
        return RETURN_ERR;
    }

    ret = wifi_hal_delApAclDevice(vap_index, key);

    sta_info->is_acl_set = false;
    wifi_hal_info_print("status:%d del sta:%s from maclist on vap_index:%d\n", ret, key, vap_index);
    return ret;
}

void re_configure_steering_mac_list(wifi_interface_info_t *interface)
{
    wifi_vap_info_t *vap;
    bm_sta_list_t *ptr = NULL;
    mac_addr_str_t sta_mac_str;
    char *key;

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_info_print("%s:%d: sta vap:%d does not support this\n", __func__, __LINE__, vap->vap_index);
        return;
    } else if((vap->u.bss_info.mac_filter_enable == true) &&
                (vap->u.bss_info.mac_filter_mode != wifi_mac_filter_mode_black_list)) {
        wifi_hal_info_print("%s:%d: mac mode:%d for vap:%d\n", __func__, __LINE__, vap->u.bss_info.mac_filter_mode, vap->vap_index);
        return;
    }

    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    ptr = hash_map_get_first(interface->bm_sta_map);
    while (ptr != NULL) {
        if ((ptr->is_acl_set == true) && (ptr->vap_index == vap->vap_index)) {
            if (vap->u.bss_info.mac_filter_enable == false) {
                /* Inside this function, If mac filter is not enabled.
                 *  So, Forcefully we will enable mac filter and macmode */
                steering_set_acl_mode(vap->vap_index, wifi_mac_filter_mode_black_list);
            }
            key = to_mac_str(ptr->mac_addr, sta_mac_str);
            wifi_hal_addApAclDevice(ptr->vap_index, key);
        }
        ptr = hash_map_get_next(interface->bm_sta_map, ptr);
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
}

#ifdef CONFIG_WIFI_EMULATOR
void init_interface_map(void)
{
    interface_index_map = (wifi_interface_name_idex_map_t *)malloc(sizeof(wifi_interface_name_idex_map_t)*MAX_NUM_SIMULATED_CLIENT);
    if (interface_index_map != NULL) {
        memset(interface_index_map, 0, sizeof(wifi_interface_name_idex_map_t)*MAX_NUM_SIMULATED_CLIENT);
    }

    l_radio_interface_map = (radio_interface_mapping_t *)malloc(sizeof(radio_interface_mapping_t)*MAX_NUM_SIMULATED_CLIENT);
    if (l_radio_interface_map != NULL) {
        memset(l_radio_interface_map, 0, sizeof(radio_interface_mapping_t)*MAX_NUM_SIMULATED_CLIENT);
    }

    return;
}

void update_interface_names(unsigned int phy_index, char *interface_name)
{
    wifi_interface_name_idex_map_t *tmp_interface_index_map = interface_index_map;
    radio_interface_mapping_t *tmp_radio_interface_map = l_radio_interface_map;

    for (;(tmp_interface_index_map != NULL);) {
        if ((tmp_interface_index_map->phy_index == phy_index)) {
            strncpy(tmp_interface_index_map->interface_name, interface_name, sizeof(wifi_interface_name_t));
            tmp_interface_index_map++;
            break;
        }
        tmp_interface_index_map++;
    }

    for(;(tmp_radio_interface_map != NULL);) {
        if ((tmp_radio_interface_map->phy_index == phy_index)) {
            strncpy(tmp_radio_interface_map->interface_name, interface_name, sizeof(wifi_interface_name_t));
            tmp_radio_interface_map++;
            break;
        }
        tmp_radio_interface_map++;
    }

    return;
}

void update_interfaces_map(unsigned int phy_index, unsigned int interface_radio_index)
{
    static unsigned int index = 16;
    wifi_interface_name_idex_map_t *tmp_interface_index_map = interface_index_map;
    radio_interface_mapping_t *tmp_radio_interface_map = l_radio_interface_map;

    //Update interface Index map
    for (;(tmp_interface_index_map != NULL);) {
        if (!strstr(tmp_interface_index_map->vap_name, "sim_sta")) {

            tmp_interface_index_map->phy_index = phy_index;
            tmp_interface_index_map->rdk_radio_index = interface_radio_index;
            strncpy(tmp_interface_index_map->bridge_name, "hwsim0", sizeof(wifi_interface_name_t));
            tmp_interface_index_map->vlan_id = 100;
            tmp_interface_index_map->index = index;
            snprintf(tmp_interface_index_map->vap_name, sizeof(wifi_vap_name_t), "sim_sta_%d", interface_radio_index);
            break;
        }
        tmp_interface_index_map++;
    }

    //Update radio Interface map
    for(;(tmp_radio_interface_map != NULL);) {
        if (!strstr(tmp_radio_interface_map->radio_name, "radio")) {
            tmp_radio_interface_map->phy_index = phy_index;
            tmp_radio_interface_map->radio_index = interface_radio_index;
            snprintf(tmp_radio_interface_map->radio_name, sizeof(tmp_radio_interface_map->radio_name), "radio%d", tmp_radio_interface_map->radio_index+1);
            index++;
            break;
        }
        tmp_radio_interface_map++;
    }
    return;
}

void rearrange_interfaces_map()
{
    int interface_count = 0, radio_interface_count = 0;
    wifi_interface_name_idex_map_t *tmp_interface_index_map = interface_index_map;
    radio_interface_mapping_t *tmp_radio_interface_map = l_radio_interface_map;

    interface_count = get_sizeof_interfaces_index_map();
    radio_interface_count = get_sizeof_radio_interfaces_map();

    tmp_interface_index_map = (wifi_interface_name_idex_map_t *)malloc(interface_count*sizeof(wifi_interface_name_idex_map_t));
    if (tmp_interface_index_map != NULL) {
        memset(tmp_interface_index_map, 0, interface_count*sizeof(wifi_interface_name_idex_map_t));
    }

    tmp_radio_interface_map = (radio_interface_mapping_t *)malloc(radio_interface_count*sizeof(radio_interface_mapping_t));
    if (tmp_radio_interface_map != NULL) {
        memset(tmp_radio_interface_map, 0, radio_interface_count*sizeof(radio_interface_mapping_t));
    }

    memcpy(tmp_interface_index_map, interface_index_map, interface_count*sizeof(wifi_interface_name_idex_map_t));
    memcpy(tmp_radio_interface_map, l_radio_interface_map, radio_interface_count*sizeof(radio_interface_mapping_t));

    if (interface_index_map != NULL) {
        free(interface_index_map);
    }
    if(l_radio_interface_map != NULL) {
        free(l_radio_interface_map);
    }

    interface_index_map = tmp_interface_index_map;
    l_radio_interface_map = tmp_radio_interface_map;
    
    return;
}
#else
static inline cJSON *json_open_interface_map(FILE *fp, size_t len)
{
    cJSON *json;
    char *buff;

    buff = malloc(len);
    if (buff == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate %zu bytes for json file\n", __func__,
            __LINE__, len);
        return NULL;
    }

    len = fread(buff, 1, len, fp);

    json = cJSON_ParseWithLength(buff, len);
    if (json == NULL) {
        const char *const error_ptr = cJSON_GetErrorPtr();
        wifi_hal_error_print("%s:%d: Error json file parse: %s\n", __func__, __LINE__,
            (error_ptr ? error_ptr : "UNKNOWN"));
    }

    free(buff);

    return json;
}

static inline int json_parse_interface_map(cJSON *json)
{
    cJSON *phy_list;
    cJSON *phy_index;
    cJSON *phy_elm;
    cJSON *radio_list;
    cJSON *radio_elm;
    cJSON *radio_index;
    cJSON *radio_name;
    cJSON *inteface_list;
    cJSON *interface_elm;
    cJSON *interface_name;
    cJSON *mld_interface_name;
    cJSON *bridge;
    cJSON *vlan_id;
    cJSON *vap_index;
    cJSON *vap_name;
    wifi_interface_name_idex_map_t *tmp_intf_idx_map;
    radio_interface_mapping_t *tmp_radio_interface_map;
    unsigned int radio_interface_map_size;
    unsigned int interface_idx_map_size;
    unsigned int r_idx;
    unsigned int i_idx;
    cJSON_bool valid;

    phy_list = cJSON_GetObjectItem(json, "PhyList");
    if (!cJSON_IsArray(phy_list)) {
        wifi_hal_error_print("%s:%d: [PhyList] does not exist or is not an array\n", __func__,
            __LINE__);
        return -1;
    }

    radio_interface_map_size = 0;
    interface_idx_map_size = 0;

    cJSON_ArrayForEach(phy_elm, phy_list)
    {
        phy_index = cJSON_GetObjectItem(phy_elm, "Index");
        if (!(valid = cJSON_IsNumber(phy_index))) {
            wifi_hal_error_print("%s:%d: (Index) does not exist or is not a number\n", __func__,
                __LINE__);
            break;
        }

        radio_list = cJSON_GetObjectItem(phy_elm, "RadioList");
        if (!(valid = cJSON_IsArray(radio_list))) {
            wifi_hal_error_print("%s:%d: [RadioList] does not exist or is not an array\n", __func__,
                __LINE__);
            break;
        }

        cJSON_ArrayForEach(radio_elm, radio_list)
        {
            radio_index = cJSON_GetObjectItem(radio_elm, "Index");
            if (!(valid = cJSON_IsNumber(radio_index))) {
                wifi_hal_error_print("%s:%d: (Index) does not exist "
                                     "or is not a number\n",
                    __func__, __LINE__);
                break;
            }

            radio_name = cJSON_GetObjectItem(radio_elm, "RadioName");
            if (!(valid = cJSON_IsString(radio_name))) {
                wifi_hal_error_print("%s:%d: (RadioName) does not exist "
                                     "or is not a string\n",
                    __func__, __LINE__);
                break;
            }

            inteface_list = cJSON_GetObjectItem(radio_elm, "InterfaceList");
            if (!(valid = cJSON_IsArray(inteface_list))) {
                wifi_hal_error_print("%s:%d: [InterfaceList] does "
                                     "not exist or is not an array\n",
                    __func__, __LINE__);
                break;
            }

            cJSON_ArrayForEach(interface_elm, inteface_list)
            {
                interface_name = cJSON_GetObjectItem(interface_elm, "InterfaceName");
                if (!(valid = cJSON_IsString(interface_name))) {
                    wifi_hal_error_print("%s:%d: (InterfaceName) does "
                                         "not exist or is not a string\n",
                        __func__, __LINE__);
                    break;
                }

                bridge = cJSON_GetObjectItem(interface_elm, "Bridge");
                if (!(valid = cJSON_IsString(bridge))) {
                    wifi_hal_error_print("%s:%d: (Bridge) does "
                                         "not exist or is not a string\n",
                        __func__, __LINE__);
                    break;
                }

                vlan_id = cJSON_GetObjectItem(interface_elm, "vlanId");
                if (!(valid = cJSON_IsNumber(vlan_id))) {
                    wifi_hal_error_print("%s:%d: (vlanId) does "
                                         "not exist or is not a number\n",
                        __func__, __LINE__);
                    break;
                }

                vap_index = cJSON_GetObjectItem(interface_elm, "vapIndex");
                if (!(valid = cJSON_IsNumber(vap_index))) {
                    wifi_hal_error_print("%s:%d: (vapIndex) does "
                                         "not exist or is not a number\n",
                        __func__, __LINE__);
                    break;
                }

                vap_name = cJSON_GetObjectItem(interface_elm, "vapName");
                if (!(valid = cJSON_IsString(vap_name))) {
                    wifi_hal_error_print("%s:%d: (vapName) does "
                                         "not exist or is not a string\n",
                        __func__, __LINE__);
                    break;
                }
                interface_idx_map_size++;
            }
            if (!valid) {
                wifi_hal_error_print("%s:%d: Failed to [InterfaceList] validation\n", __func__,
                    __LINE__);
                break;
            }
            radio_interface_map_size++;
        }
        if (!valid) {
            wifi_hal_error_print("%s:%d: Failed to [RadioList] validation\n", __func__, __LINE__);
            break;
        }
    }
    if (!valid) {
        wifi_hal_error_print("%s:%d: Failed to [PhyList] validation\n", __func__, __LINE__);
        return -1;
    }

    tmp_intf_idx_map = NULL;
    tmp_radio_interface_map = NULL;

    if (!((tmp_intf_idx_map = calloc(1, sizeof(*tmp_intf_idx_map) * interface_idx_map_size)) &&
            (tmp_radio_interface_map = calloc(1,
                 sizeof(*tmp_radio_interface_map) * radio_interface_map_size)))) {
        wifi_hal_error_print("%s:%d: Failed to allocate interface_idx_map(%d - %u "
                             "bytes) or radio_interface_map_size(%d - %u bytes)\n",
            __func__, __LINE__, !!tmp_intf_idx_map, interface_idx_map_size,
            !!tmp_radio_interface_map, radio_interface_map_size);

        free(tmp_radio_interface_map);
        free(tmp_intf_idx_map);

        return -1;
    }

    // filling occurs from the end
    i_idx = interface_idx_map_size - 1;
    r_idx = radio_interface_map_size - 1;

    cJSON_ArrayForEach(phy_elm, phy_list)
    {
        phy_index = cJSON_GetObjectItem(phy_elm, "Index");
        radio_list = cJSON_GetObjectItem(phy_elm, "RadioList");

        cJSON_ArrayForEach(radio_elm, radio_list)
        {
            radio_index = cJSON_GetObjectItem(radio_elm, "Index");
            radio_name = cJSON_GetObjectItem(radio_elm, "RadioName");
            inteface_list = cJSON_GetObjectItem(radio_elm, "InterfaceList");

            tmp_radio_interface_map[r_idx].phy_index = (unsigned int)cJSON_GetNumberValue(
                phy_index);
            tmp_radio_interface_map[r_idx].radio_index = (unsigned int)cJSON_GetNumberValue(
                radio_index);

            snprintf(tmp_radio_interface_map[r_idx].radio_name,
                sizeof(tmp_radio_interface_map[r_idx].radio_name), "radio%u",
                tmp_radio_interface_map[r_idx].radio_index + 1);

            strncpy(tmp_radio_interface_map[r_idx].interface_name, cJSON_GetStringValue(radio_name),
                (sizeof(tmp_radio_interface_map[r_idx].interface_name) /
                    sizeof(*tmp_radio_interface_map[r_idx].interface_name)) -
                    1);
            tmp_radio_interface_map[r_idx]
                .interface_name[(sizeof(tmp_radio_interface_map[r_idx].interface_name) /
                                    sizeof(*tmp_radio_interface_map[r_idx].interface_name)) -
                    1] = '\0';

            cJSON_ArrayForEach(interface_elm, inteface_list)
            {
                interface_name = cJSON_GetObjectItem(interface_elm, "InterfaceName");
                mld_interface_name = cJSON_GetObjectItem(interface_elm, "MldName");
                bridge = cJSON_GetObjectItem(interface_elm, "Bridge");
                vlan_id = cJSON_GetObjectItem(interface_elm, "vlanId");
                vap_index = cJSON_GetObjectItem(interface_elm, "vapIndex");
                vap_name = cJSON_GetObjectItem(interface_elm, "vapName");

                tmp_intf_idx_map[i_idx].phy_index = tmp_radio_interface_map[r_idx].phy_index;

                tmp_intf_idx_map[i_idx].rdk_radio_index =
                    tmp_radio_interface_map[r_idx].radio_index;

                strncpy(tmp_intf_idx_map[i_idx].interface_name,
                    cJSON_GetStringValue(interface_name),
                    (sizeof(tmp_intf_idx_map[i_idx].interface_name) /
                        sizeof(*tmp_intf_idx_map[i_idx].interface_name)) -
                        1);
                tmp_intf_idx_map[i_idx]
                    .interface_name[(sizeof(tmp_intf_idx_map[i_idx].interface_name) /
                                        sizeof(*tmp_intf_idx_map[i_idx].interface_name)) -
                        1] = '\0';

                // MldName is optional
                if (mld_interface_name != NULL && cJSON_IsString(mld_interface_name)) {
                    strncpy(tmp_intf_idx_map[i_idx].mld_interface_name,
                        cJSON_GetStringValue(mld_interface_name),
                        sizeof(tmp_intf_idx_map[i_idx].mld_interface_name) - 1);
                }

                strncpy(tmp_intf_idx_map[i_idx].bridge_name, cJSON_GetStringValue(bridge),
                    (sizeof(tmp_intf_idx_map[i_idx].bridge_name) /
                        sizeof(*tmp_intf_idx_map[i_idx].bridge_name)) -
                        1);
                tmp_intf_idx_map[i_idx]
                    .bridge_name[(sizeof(tmp_intf_idx_map[i_idx].bridge_name) /
                                     sizeof(*tmp_intf_idx_map[i_idx].bridge_name)) -
                        1] = '\0';

                tmp_intf_idx_map[i_idx].vlan_id = (unsigned int)cJSON_GetNumberValue(vlan_id);

                tmp_intf_idx_map[i_idx].index = (unsigned int)cJSON_GetNumberValue(vap_index);

                strncpy(tmp_intf_idx_map[i_idx].vap_name, cJSON_GetStringValue(vap_name),
                    (sizeof(tmp_intf_idx_map[i_idx].vap_name) /
                        sizeof(*tmp_intf_idx_map[i_idx].vap_name)) -
                        1);
                tmp_intf_idx_map[i_idx].vap_name[(sizeof(tmp_intf_idx_map[i_idx].vap_name) /
                                                     sizeof(*tmp_intf_idx_map[i_idx].vap_name)) -
                    1] = '\0';
                i_idx--;
            }
            r_idx--;
        }
    }
    interface_index_map = tmp_intf_idx_map;
    interface_index_map_size = interface_idx_map_size;

    l_radio_interface_map = tmp_radio_interface_map;
    l_radio_interface_map_size = radio_interface_map_size;

    return 0;
}

static inline int init_json_interface_map(void)
{
    FILE *fp;
    cJSON *json;
    size_t len;
    int ret;

    fp = fopen(INTERFACE_MAP_JSON, "r");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d: Failed (err=%d, msg=%s) to opening interface map file:%s\n",
            __func__, __LINE__, errno, strerror(errno), INTERFACE_MAP_JSON);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    ret = -1;

    json = json_open_interface_map(fp, len);
    if (json) {
        ret = json_parse_interface_map(json);

        cJSON_Delete(json);
    }

    fclose(fp);

    return ret;
}

static inline void init_static_interface_map(void)
{
    interface_index_map = static_interface_index_map;
    interface_index_map_size = (sizeof(static_interface_index_map) /
        sizeof(*static_interface_index_map));

    l_radio_interface_map = static_radio_interface_map;
    l_radio_interface_map_size = (sizeof(static_radio_interface_map) /
        sizeof(*static_radio_interface_map));
}

void init_interface_map(void)
{
    unsigned int i;
    int json_ret;

    json_ret = init_json_interface_map();
    if (json_ret < 0) {
        init_static_interface_map();
    }

    wifi_hal_info_print("%s:%d: Using %s Interface Map\n", __func__, __LINE__,
        ((json_ret < 0) ? "STATIC" : "JSON"));

    wifi_hal_info_print("%s:%d: Interface Index Map(%u):\n", __func__, __LINE__,
        interface_index_map_size);
    for (i = 0; i < interface_index_map_size; i++) {
        wifi_hal_info_print(
            "\t[%u]={phy_index:%u, rdk_radio_index:%u, interface_name:%s, "
            "mld_interface_name:%s, bridge_name:%s, vlan_id:%d, index:%u, vap_name:%s}\n",
            i, interface_index_map[i].phy_index, interface_index_map[i].rdk_radio_index,
            interface_index_map[i].interface_name, interface_index_map[i].mld_interface_name,
            interface_index_map[i].bridge_name, interface_index_map[i].vlan_id,
            interface_index_map[i].index, interface_index_map[i].vap_name);
    }

    wifi_hal_info_print("%s:%d: Radio Interface Index Map(%u):\n", __func__, __LINE__,
        l_radio_interface_map_size);
    for (i = 0; i < l_radio_interface_map_size; i++) {
        wifi_hal_info_print("\t[%u]={phy_index:%u, radio_index:%u, radio_name:%s, "
                            "interface_name:%s}\n",
            i, l_radio_interface_map[i].phy_index, l_radio_interface_map[i].radio_index,
            l_radio_interface_map[i].radio_name, l_radio_interface_map[i].interface_name);
    }
}
#endif /* CONFIG_WIFI_EMULATOR */

void concat_band_to_vap_name(wifi_vap_name_t vap_name, unsigned int rdk_radio_index)
{
    switch (rdk_radio_index) {
    case 0:
        strncat((char *)vap_name, "2g", strlen("2g") + 1);
        break;
    case 1:
        strncat((char *)vap_name, "5g", strlen("5g") + 1);
        break;
    case 2:
        strncat((char *)vap_name, "6g", strlen("6g") + 1);
        break;
    default:
        wifi_hal_error_print("%s:%d: Invalid rdk_radio_index:%d for vap_name:%s\n", __func__,
            __LINE__, rdk_radio_index, vap_name);
    }
}

int configure_vap_name_basedon_colocated_mode(char *ifname, int colocated_mode)
{
    unsigned int index = 0, i = 0;
    wifi_interface_info_t *interface = NULL;
    int vap_count = 0;
    int index_map_size = get_sizeof_interfaces_index_map();
    for (index = 0; index < index_map_size; index++) {
        if (strncmp(interface_index_map[index].interface_name, ifname, strlen(ifname)) == 0) {
            switch (colocated_mode) {
            case 0:
                strcpy((char *)interface_index_map[index].vap_name, "mesh_sta_");
                concat_band_to_vap_name((char *)interface_index_map[index].vap_name,
                    interface_index_map[index].rdk_radio_index);
                break;
            case 1:
                for (i = 0; i < index_map_size; i++) {
                    if (interface_index_map[i].rdk_radio_index ==
                        interface_index_map[index].rdk_radio_index) {
                        vap_count++;
                    }
                }
                /* If only one VAP in collocated mode, configure it as mesh_back_haul */
                if (vap_count == 1) {
                    strcpy((char *)interface_index_map[index].vap_name, "mesh_backhaul_");
                    concat_band_to_vap_name((char *)interface_index_map[index].vap_name,
                        interface_index_map[index].rdk_radio_index);
                }
                /* Check the interface should be either fronthaul or backhaul */
                if (is_wifi_hal_vap_private(interface_index_map[index].index) == false &&
                    is_wifi_hal_vap_mesh_backhaul(interface_index_map[index].index) == false) {
                    /* Error case */
                    wifi_hal_error_print(
                        "%s:%d: Invalid vap_name:%s for ifname:%s for colocated_mode:%d\n",
                        __func__, __LINE__, interface_index_map[index].vap_name, ifname,
                        colocated_mode);
                    return -1;
                }
                break;
            default:
                /* Error case */
                wifi_hal_error_print("%s:%d: Invalid colocated_mode:%d for ifname:%s\n", __func__,
                    __LINE__, colocated_mode, ifname);
                return -1;
            }
            wifi_hal_dbg_print("%s:%d: vap_name:%s configured for ifname:%s vap_index:%d\n",
                __func__, __LINE__, interface_index_map[index].vap_name, ifname,
                interface_index_map[index].index);
            if (colocated_mode == 0) {
                interface = get_interface_by_vap_index(interface_index_map[index].index);
                if (interface != NULL && interface->vap_info.vap_mode == wifi_vap_mode_ap) {
                    memset(&interface->u, 0, sizeof(interface->u));
                }
            }
            return 0;
        }
    }
    wifi_hal_error_print("%s:%d: Interface:%s not present in interface_index_map\n", __func__,
        __LINE__, ifname);
    return -1;
}

char *wifi_hal_get_mld_name_by_interface_name(char *ifname)
{
    for (unsigned int i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        if (interface_index_map[i].mld_interface_name[0] == '\0') {
            continue;
        }
        if ((strncmp(ifname, interface_index_map[i].interface_name,
                 sizeof(interface_index_map[i].interface_name)) == 0)) {
            return interface_index_map[i].mld_interface_name;
        }
    }
    return NULL;
}

char *wifi_hal_get_interface_name(wifi_interface_info_t *interface)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return NULL;
    }

    if (interface->mld_name[0] == '\0') {
        return interface->name;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap &&
        interface->vap_info.u.bss_info.mld_info.common_info.mld_enable) {
        return interface->mld_name;
    }

    return interface->name;
}

bool wifi_hal_is_mld_enabled(wifi_interface_info_t *interface)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return false;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        return interface->vap_info.u.bss_info.mld_info.common_info.mld_enable;
    }

    return false;
}

int wifi_hal_set_mld_enabled(wifi_interface_info_t *interface, bool enabled)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return -1;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        interface->vap_info.u.bss_info.mld_info.common_info.mld_enable = enabled;
        return 0;
    }

    return -1;
}

#ifndef NL80211_DRV_LINK_ID_NA
#define NL80211_DRV_LINK_ID_NA (-1)
#endif

int wifi_hal_get_mld_link_id(wifi_interface_info_t *interface)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return NL80211_DRV_LINK_ID_NA;
    }

    if (!wifi_hal_is_mld_enabled(interface)) {
        return NL80211_DRV_LINK_ID_NA;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        return interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id;
    }

    return NL80211_DRV_LINK_ID_NA;
}

int wifi_hal_set_mld_link_id(wifi_interface_info_t *interface, int link_id)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return -1;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id = link_id;
        return 0;
    }

    return -1;
}

uint8_t *wifi_hal_get_mld_mac_address(wifi_interface_info_t *interface)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return NULL;
    }

    if (!wifi_hal_is_mld_enabled(interface)) {
        return NULL;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        return interface->vap_info.u.bss_info.mld_info.common_info.mld_addr;
    }

    return NULL;
}

int wifi_hal_set_mld_mac_address(wifi_interface_info_t *interface, mac_address_t mac)
{
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return -1;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
        memcpy(interface->vap_info.u.bss_info.mld_info.common_info.mld_addr, mac,
            sizeof(mac_address_t));
        return 0;
    }

    return -1;
}

wifi_interface_info_t *wifi_hal_get_mld_interface_by_link_id(wifi_interface_info_t *interface,
    int link_id)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface_iter;

    if (link_id < 0) {
        return interface;
    }

    if (!wifi_hal_is_mld_enabled(interface)) {
        return interface;
    }

    for (unsigned int i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
                i);
            return interface;
        }

        hash_map_foreach(radio->interface_map, interface_iter) {
            if (!wifi_hal_is_mld_enabled(interface_iter)) {
                continue;
            }

            // TODO: multiple mld support
            if (wifi_hal_get_mld_link_id(interface_iter) == link_id) {
                return interface_iter;
            }
        }
    }

    return interface;
}

wifi_interface_info_t *wifi_hal_get_mld_interface_by_freq(wifi_interface_info_t *interface,
    uint32_t freq)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface_iter;

    if (freq == 0) {
        return interface;
    }

    if (!wifi_hal_is_mld_enabled(interface)) {
        return interface;
    }

    for (unsigned int i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
                i);
            return interface;
        }

        hash_map_foreach(radio->interface_map, interface_iter) {
            if (!wifi_hal_is_mld_enabled(interface_iter)) {
                continue;
            }

            // TODO: multiple mld support
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            if (interface_iter->u.ap.iface.freq == freq) {
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
                return interface_iter;
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        }
    }

    return interface;
}

wifi_interface_info_t *wifi_hal_get_mld_link_interface_by_mac(wifi_interface_info_t *interface,
    mac_address_t mac)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface_iter;

    if (!wifi_hal_is_mld_enabled(interface)) {
        return memcmp(interface->mac, mac, sizeof(mac_address_t)) == 0 ? interface : NULL;
    }

    for (unsigned int i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
                i);
            return NULL;
        }

        hash_map_foreach(radio->interface_map, interface_iter) {
            if (!wifi_hal_is_mld_enabled(interface_iter)) {
                continue;
            }

            if (memcmp(interface_iter->mac, mac, sizeof(mac_address_t)) == 0) {
                return interface_iter;
            }
        }
    }

    return NULL;
}

int wifi_hal_get_mac_address(const char *ifname, mac_address_t mac)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        wifi_hal_error_print("%s:%d Failed to create socket, error: %s", __func__, __LINE__,
            strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        wifi_hal_error_print("%s:%d Failed to get MAC address, error: %s", __func__, __LINE__,
            strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, sizeof(mac_address_t));

    return 0;
}
