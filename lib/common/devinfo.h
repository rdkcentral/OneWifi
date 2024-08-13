/*
Copyright (c) 2017, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef DEVINFO_H_INCLUDED
#define DEVINFO_H_INCLUDED

#include <stdbool.h>

#define DEVINFO_MAX_LEN             32

#define DEVINFO_MODEL_NUM           "mo"
#define DEVINFO_SERIAL_NUM          "sn"
#define DEVINFO_SOFTWARE_VER        "fw"
#define DEVINFO_MESH_STATE          "ms"
#define DEVINFO_MESH_URL            "mu"
#define DEVINFO_CM_MAC              "cmac"
#define DEVINFO_CM_IP               "cip"
#define DEVINFO_CM_IPv6             "cipv6"
#define DEVINFO_WAN_MAC             "emac"
#define DEVINFO_WAN_IP              "eip"
#define DEVINFO_WAN_IPv6            "eipv6"
#define DEVINFO_HOME_MAC            "lmac"
#define DEVINFO_HOME_IP             "lip"
#define DEVINFO_HOME_IPv6           "lipv6"
#define DEVINFO_DEVICE_MODE         "mode"
#define DEVINFO_OFFCHAN_SCAN_ENABLE "off_chan"
#define DEVINFO_REBOOT_REASON       "rebootreason"
#define DEVINFO_MESH_OPT_MODE       "optimization"
#define DEVINFO_MESH_OPT_BROKER     "mwo_broker"
#define DEVINFO_MESH_OPT_PORT       "mwo_port"
#define DEVICEINFO_MESHRFC          "mesh_enable"
#define DEVICEINFO_OFFLINE_MQTT_BROKER "offline_mqtt_broker"
#define DEVICEINFO_OFFLINE_MQTT_PORT   "offline_mqtt_port"
#define DEVICEINFO_OFFLINE_MQTT_TOPIC_PREFIX "offline_mqtt_topic"
#define CONFIG_RDK_LAN_BRIDGE_NAME  "brlan0"
#define CONFIG_RDK_WAN_BRIDGE_NAME  "erouter0"

/**
 * The length of MAC address in ASCII string format.
 *  "AA:BB:CC:DD:EE:FF" -> 17 characters plus NULL terminator.
 */
#define MAC_ADDR_STR_LEN 18

/**
 * The maximum length of IP address in ASCII string format.
 *  "255.255.255.255" -> 15 characters plus NULL terminator.
 */
#define IP_ADDR_STR_LEN 16

/**
 * @brief Interface configuration.
 */
typedef struct {
    char inet_addr[IP_ADDR_STR_LEN];
    char mac_str[MAC_ADDR_STR_LEN];
} devinfo_inet_iface_config_t;

typedef enum
{
    MESH_OPT_DISABLE         = 0,
    MESH_OPT_MONITOR,
    MESH_OPT_ENABLE,
    MESH_MODE_COUNT,
} opt_mode_t;

typedef struct
{
  opt_mode_t   mMode;
  char         *mStr;
} mesh_wifi_optimization_mode_t;

bool devinfo_getv(const char *what, char *dest, size_t destsz);
bool devinfo_get_inet_iface_config(
        const char *if_name,
        devinfo_inet_iface_config_t *config);

#endif /* DEVINFO_H_INCLUDED */
