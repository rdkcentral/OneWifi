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

#ifndef  _COSA_WIFI_INTERNAL_H
#define  _COSA_WIFI_INTERNAL_H
#include "cosa_wifi_apis.h"
#include "poam_irepfo_interface.h"
#include "sys_definitions.h"


#include <telemetry_busmessage_sender.h>

/*
#include "poam_cosa_wifi_dm_interface.h"
#include "poam_cosa_wifi_dm_exported_api.h"
#include "slap_cosa_wifi_dm_interface.h"
#include "slap_cosa_wifi_dm_exported_api.h"
*/

#define  WECB_EXT_REFRESH_INTERVAL                       180

#define  COSA_IREP_FOLDER_NAME_WIFI                      "WIFI"

#define  COSA_IREP_FOLDER_NAME_WIFI_SSID                 "SSID"

#define  COSA_IREP_FOLDER_NAME_WIFI_AP                   "AccessPoint"

#define  COSA_IREP_FOLDER_NAME_MAC_FILT_TAB             "MacFilterTable"


/* Active Measurement macro's */
#define MIN_ACTIVE_MSMT_PKT_SIZE 64
#define MAX_ACTIVE_MSMT_PKT_SIZE 1470
#define MIN_ACTIVE_MSMT_SAMPLE_COUNT 1
#define MAX_ACTIVE_MSMT_SAMPLE_COUNT 100
#define MIN_ACTIVE_MSMT_SAMPLE_DURATION 1
#define MAX_ACTIVE_MSMT_SAMPLE_DURATION 10000

#define MIN_MAC_LEN     12

#define  COSA_DATAMODEL_WIFI_CLASS_CONTENT                                                  \
    /* duplication of the base object class content */                                      \
    COSA_BASE_CONTENT                                                                       \
    ANSC_HANDLE                     hIrepFolderCOSA;                                        \
    ANSC_HANDLE                     hIrepFolderWifi;                                        \
    ANSC_HANDLE                     hIrepFolderWifiSsid;                                    \
    ANSC_HANDLE                     hIrepFolderWifiAP;                                      \
    /*PPOAM_COSAWIFIDM_OBJECT*/ANSC_HANDLE         hPoamWiFiDm;                                            \
    /*PSLAP_COSAWIFIDM_OBJECT*/ANSC_HANDLE         hSlapWiFiDm;                                            \

	
typedef  struct
_COSA_DATAMODEL_WIFI                                               
{
	COSA_DATAMODEL_WIFI_CLASS_CONTENT

}
COSA_DATAMODEL_WIFI,  *PCOSA_DATAMODEL_WIFI;

/*
*  This struct is for creating entry context link in writable table when call GetEntry()
*/
#define  COSA_CONTEXT_RSL_LINK_CLASS_CONTENT                                      \
        COSA_CONTEXT_LINK_CLASS_CONTENT                                            \
        ULONG                            InterfaceIndex;                           \
        ULONG                            Index;                                    \

typedef  struct
_COSA_CONTEXT_RSL_LINK_OBJECT
{
    COSA_CONTEXT_RSL_LINK_CLASS_CONTENT
}
COSA_CONTEXT_RSL_LINK_OBJECT,  *PCOSA_CONTEXT_RSL_LINK_OBJECT;

/*
    Standard function declaration 
*/
ANSC_HANDLE
CosaWifiCreate
    (
        VOID
    );

ANSC_STATUS
CosaWifiInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaWifiRemove
    (
        ANSC_HANDLE                 hThisObject
    );
    
ANSC_STATUS
CosaWifiRegGetSsidInfo
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaWifiRegAddSsidInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    );
 
ANSC_STATUS
CosaWifiRegDelSsidInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    );
    
ANSC_STATUS
CosaWifiRegGetAPInfo
    (
        ANSC_HANDLE                 hThisObject
    );
    
ANSC_STATUS
CosaWifiRegAddAPInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    );
 
ANSC_STATUS
CosaWifiRegDelAPInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    );

ANSC_STATUS
CosaDmlWiFiApMfGetMacList
    (
        UCHAR       *mac,
        CHAR        *maclist,
        ULONG       numList
    );


ANSC_STATUS
CosaDmlWiFiApMfSetMacList
    (
        CHAR        *maclist,
        UCHAR       *mac,
        ULONG       *numList
    );

ANSC_STATUS
CosaWifiRegGetMacFiltInfo
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaWifiRegAddMacFiltInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    );
ANSC_STATUS
CosaWifiRegDelMacFiltInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    );

/* Prototype for Active Measurement SET/GET calls */
ANSC_STATUS
CosaDmlWiFiClient_SetActiveMsmtStepId
    (
        UINT StepId,
        ULONG StepIns
    );

ANSC_STATUS
CosaDmlActiveMsmt_Step_SetSrcMac
    (
        char *SrcMac,
        ULONG StepIns
    );

ANSC_STATUS
CosaDmlActiveMsmt_Step_SetDestMac
    (
        char *DestMac,
        ULONG StepIns
    );

ANSC_STATUS
ValidateActiveMsmtPlanID
   (
       UCHAR *pPlanId
   );
ANSC_STATUS
GetActiveMsmtStepInsNum
    (
        active_msmt_step_t *pStepCfg,
        ULONG *StepIns
    );


#endif 
