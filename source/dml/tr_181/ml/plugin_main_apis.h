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

/**************************************************************************

    module: plugin_main_apis.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/


#ifndef  _PLUGIN_MAIN_APIS_H
#define  _PLUGIN_MAIN_APIS_H

#include "ansc_platform.h"
#include "cosa_apis.h"
#include "dslh_cpeco_interface.h"

// include files needed by diagnostic
/*
#include "dslh_definitions_diagnostics.h"
#include "bbhm_diag_lib.h"
*/
#include "dslh_dmagnt_interface.h"
#include "ccsp_ifo_ccd.h"

/*
#include "bbhm_diageo_interface.h"
#include "bbhm_diagip_interface.h"
#include "bbhm_diagit_interface.h"
#include "bbhm_diagns_interface.h"
#include "bbhm_download_interface.h"
#include "bbhm_upload_interface.h"
#include "bbhm_udpecho_interface.h"
*/

/*extern PCOSA_DIAG_PLUGIN_INFO             g_pCosaDiagPluginInfo;*/
extern COSAGetParamValueStringProc        g_GetParamValueString;
extern COSAGetParamValueUlongProc         g_GetParamValueUlong;
extern COSAGetParamValueBoolProc          g_GetParamValueBool;
extern COSAValidateHierarchyInterfaceProc g_ValidateInterface;
extern COSAGetHandleProc                  g_GetRegistryRootFolder;
extern COSAGetInstanceNumberByIndexProc   g_GetInstanceNumberByIndex;
extern COSAGetHandleProc                  g_GetMessageBusHandle;
extern COSAGetSubsystemPrefixProc         g_GetSubsystemPrefix;
extern COSAGetInterfaceByNameProc         g_GetInterfaceByName;
extern PCCSP_CCD_INTERFACE                g_pWifiCcdIf;
extern ANSC_HANDLE                        g_MessageBusHandle;
extern COSARegisterCallBackAfterInitDmlProc  g_RegisterCallBackAfterInitDml;

/* The OID for all objects s*/
#define COSA_DATAMODEL_BASE_OID                                 0
#define COSA_DATAMODEL_DEVICEINFO_OID                           1
#define COSA_DATAMODEL_DHCPV4_OID                               2
#define COSA_DATAMODEL_DNS_OID                                  3
#define COSA_DATAMODEL_ETHERNET_OID                             4
#define COSA_DATAMODEL_FIREWALL_OID                             5
#define COSA_DATAMODEL_GATEWAYINFO_OID                          6
#define COSA_DATAMODEL_HOSTS_OID                                7
#define COSA_DATAMODEL_INTERFACESTACK_OID                       8
#define COSA_DATAMODEL_IP_OID                                   9
#define COSA_DATAMODEL_MANAGEMENTSERVER_OID                     10
#define COSA_DATAMODEL_MOCA_OID                                 11
#define COSA_DATAMODEL_NAT_OID                                  12
#define COSA_DATAMODEL_ROUTING_OID                              13
#define COSA_DATAMODEL_SOFTWAREMODULES_OID                      14
#define COSA_DATAMODEL_TIME_OID                                 15
#define COSA_DATAMODEL_UPNP_OID                                 16
#define COSA_DATAMODEL_USERINTERFACE_OID                        17
#define COSA_DATAMODEL_USERS_OID                                18
#define COSA_DATAMODEL_WIFI_OID                                 19
#define COSA_DATAMODEL_DDNS_OID                                 20
#define COSA_DATAMODEL_SECURITY_OID                             21
#define COSA_DATAMODEL_DIAG_OID                                 22
#define COSA_DATAMODEL_BRIDGING_OID                             23
#define COSA_DATAMODEL_PPP_OID                                  24
#define COSA_DATAMODEL_DHCPV6_OID                               25
#define COSA_DATAMODEL_DEVICECONTROL_OID                        26
#define COSA_DATAMODEL_IGMP_OID                                 27
#define COSA_DATAMODEL_IPV6RD_OID                               28
#define COSA_DATAMODEL_RA_OID                                   29
#define COSA_DATAMODEL_NEIGHDISC_OID                            30
#define COSA_DATAMODEL_MLD_OID                                  31
#define COSA_DATAMODEL_LOGGING_OID								43

/*
 * This is the cosa datamodel backend manager which is used to manager all backend object
 */
#define  COSA_BACKEND_MANAGER_CLASS_CONTENT                                                 \
    /* duplication of the base object class content */                                      \
    COSA_BASE_CONTENT                                                                       \
    /* start of NAT object class content */                                                 \
	ANSC_HANDLE                  hWifi;                                                     \
	ANSC_HANDLE                  hLogging;                                                     \
    PCOSA_PLUGIN_INFO            hCosaPluginInfo;

typedef  struct
_COSA_BACKEND_MANAGER_OBJECT
{
    COSA_BACKEND_MANAGER_CLASS_CONTENT
#ifdef _COSA_SIM_                                                                           
            ULONG                        has_wifi_slap;                                             
            ULONG                        has_moca_slap;                                             
#endif                                                                                      
}
COSA_BACKEND_MANAGER_OBJECT,  *PCOSA_BACKEND_MANAGER_OBJECT;

extern PCOSA_BACKEND_MANAGER_OBJECT g_pCosaBEManager;



ANSC_HANDLE
CosaBackEndManagerCreate
    (
        VOID
    );

ANSC_STATUS
CosaBackEndManagerInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaBackEndManagerRemove
    (
        ANSC_HANDLE                 hThisObject
    );

#endif
