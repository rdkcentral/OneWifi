/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


/**********************************************************************

    module:	cosa_apis_util.h

        This is base file for all parameters H files.

    ---------------------------------------------------------------

    description:

        This file contains all utility functions for COSA DML API development.

    ---------------------------------------------------------------

    environment:

        COSA independent

    ---------------------------------------------------------------

    author:

        Roger Hu

    ---------------------------------------------------------------

    revision:

        01/30/2011    initial revision.

**********************************************************************/


#ifndef  _COSA_APIS_UTIL_H
#define  _COSA_APIS_UTIL_H

#include "cosa_dml_api_common.h"

#ifndef WIFI_HAL_VERSION_3

#if defined(_HUB4_PRODUCT_REQ_)
#define RADIO_2G_MIN_CHANNEL           0
#define RADIO_2G_MAX_CHANNEL           13
#else
#define RADIO_2G_MIN_CHANNEL           0
#define RADIO_2G_MAX_CHANNEL           11
#endif /* * _HUB4_PRODUCT_REQ_ */

#endif //WIFI_HAL_VERSION_3

typedef struct StaticRoute 
{
    char         name[64];
    char         dest_lan_ip[16];
    char         netmask[16];
    char         gateway[16];
    int          metric;
    char         dest_intf[10];
    char         origin[16];
}StaticRoute;

#ifndef _BUILD_ANDROID
enum
{
    IPV6_ADDR_SCOPE_UNKNOWN,
    IPV6_ADDR_SCOPE_GLOBAL,
    IPV6_ADDR_SCOPE_LINKLOCAL,
    IPV6_ADDR_SCOPE_SITELOCAL,
    IPV6_ADDR_SCOPE_COMPATv4,
    IPV6_ADDR_SCOPE_LOOPBACK
};
#endif

typedef struct 
{
    int    scope;
    char   v6addr[64];
    char   v6pre[64];
}ipv6_addr_info_t;

ULONG
CosaUtilGetIfAddr
    (
        char*       netdev
    );


PUCHAR
CosaUtilGetLowerLayers
    (
        PUCHAR                      pTableName,
        PUCHAR                      pKeyword
    );

PUCHAR
CosaUtilGetFullPathNameByKeyword
    (
        PUCHAR                      pTableName,
        PUCHAR                      pParameterName,
        PUCHAR                      pKeyword
    );

ULONG
CosaUtilChannelValidate
    (
        UINT                        uiRadio, 
        ULONG                       Channel,
        char                        *channelList
    );

int CosaUtilGetIfStats(char * ifname, PCOSA_DML_IF_STATS  pStats);

ULONG CosaUtilIoctlXXX(char * if_name, char * method, void * input);
ULONG NetmaskToNumber(char *netmask);
ANSC_STATUS
CosaUtilGetStaticRouteTable
    (
        UINT                        *count,
        StaticRoute                 **out_route
    );

typedef struct v6sample {
           unsigned int bitsToMask;
           char intrName[20];
           unsigned char ipv6_addr[40];
           char address6[40];
           unsigned int devIndex;
           unsigned int flags;
           unsigned int scopeofipv6;
           char prefix_v6[40];
}ifv6Details;

int CosaUtilGetIpv6AddrInfo (char * ifname, ipv6_addr_info_t ** pp_info, int * num);
int getIpv6Scope(int scope_v6);
int parseProcfileParams(char* lineToParse,ifv6Details *detailsToParse,char* interface);
int safe_strcpy(char * dst, char * src, int dst_size);
int  __v6addr_mismatch(char * addr1, char * addr2, int pref_len);
int  __v6addr_mismatches_v6pre(char * v6addr,char * v6pre);
int  __v6pref_mismatches(char * v6pref1,char * v6pref2);
int CosaDmlV6AddrIsEqual(char * p_addr1, char * p_addr2);
int CosaDmlV6PrefIsEqual(char * p_pref1, char * p_pref2);
int _write_sysctl_file(char * fn, int val);
ANSC_STATUS CosaUtilStringToHex(char *str, unsigned char *hex_str, int hex_sz);
#endif
