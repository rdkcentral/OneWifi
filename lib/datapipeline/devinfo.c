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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "util.h"
#include "log.h"
#include "devinfo.h"

/*****************************************************************************/

#define MODULE_ID LOG_MODULE_ID_OSA

/*****************************************************************************/

bool devinfo_getv(const char *what, char *dest, size_t destsz)
{
    char *buf;

    *dest = '\0';

    buf = strexa("/usr/sbin/deviceinfo.sh", strfmta("-%s", what));
    if (buf == NULL)
    {
        LOGE("devinfo_getv(%s)", strfmta("/usr/sbin/deviceinfo.sh -%s", what));
        return false;
    }

    strscpy(dest, buf, destsz);

    return true;
}

#define DEVINFO_CACHED_SIZE 64

bool devinfo_get_inet_iface_config(
        const char *if_name,
        devinfo_inet_iface_config_t *config)
{
    static char home_ip_cached[DEVINFO_CACHED_SIZE];
    static char home_mac_cached[DEVINFO_CACHED_SIZE];
    static char wan_ip_cached[DEVINFO_CACHED_SIZE];
    static char wan_mac_cached[DEVINFO_CACHED_SIZE];

    static bool once = true;

    /*
     * On RDK we only handle interfaces accessed via deviceinfo.sh.
     * Other interfaces are handled directly by NM via standard Linux
     * networking tools.
     * Calls to deviceinfo.sh may take significant amount of time,
     * so we cache IP and MAC for optimization purposes.
     * We also assume the WAN IP and MAC will not be changed without
     * restarting OpenSync.
     */
    if (once)
    {
        devinfo_getv(DEVINFO_HOME_IP,  home_ip_cached,  sizeof(home_ip_cached));
        devinfo_getv(DEVINFO_HOME_MAC, home_mac_cached, sizeof(home_mac_cached));
        devinfo_getv(DEVINFO_WAN_IP,   wan_ip_cached,   sizeof(wan_ip_cached));
        devinfo_getv(DEVINFO_WAN_MAC,  wan_mac_cached,  sizeof(wan_mac_cached));

        once = false;
    }

    if (!strcmp(if_name, CONFIG_RDK_LAN_BRIDGE_NAME))
    {
        STRSCPY(config->inet_addr, home_ip_cached);
        STRSCPY(config->mac_str, home_mac_cached);
    }
    else if (!strcmp(if_name, CONFIG_RDK_WAN_BRIDGE_NAME))
    {
        STRSCPY(config->inet_addr, wan_ip_cached);
        STRSCPY(config->mac_str, wan_mac_cached);
    }
    else
    {
        LOGD("Cannot get config for %s. Only %s and %s interfaces available",
             if_name, CONFIG_RDK_LAN_BRIDGE_NAME, CONFIG_RDK_WAN_BRIDGE_NAME);
        return false;
    }

    return true;
}
