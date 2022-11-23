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

#ifndef  _SSP_INTERNAL_
#define  _SSP_INTERNAL_

#define  CCSP_COMMON_COMPONENT_HEALTH_Red                   1
#define  CCSP_COMMON_COMPONENT_HEALTH_Yellow                2
#define  CCSP_COMMON_COMPONENT_HEALTH_Green                 3

#define  CCSP_COMMON_COMPONENT_STATE_Initializing           1
#define  CCSP_COMMON_COMPONENT_STATE_Running                2
#define  CCSP_COMMON_COMPONENT_STATE_Blocked                3
#define  CCSP_COMMON_COMPONENT_STATE_Paused                 3

#define  CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_High  1
#define  CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_Low   2


extern   PCCSP_COMPONENT_CFG                        gpWifiStartCfg;

typedef  struct
_COMPONENT_COMMON_DM
{
    char*                           Name;
    ULONG                           Version;
    char*                           Author;
    ULONG                           Health;
    ULONG                           State;

    BOOL                            LogEnable;
    ULONG                           LogLevel;

    ULONG                           MemMaxUsage;
    ULONG                           MemMinUsage;
    ULONG                           MemConsumed;
}
COMPONENT_COMMON_DM,  *PCOMPONENT_COMMON_DM;

#define ComponentCommonDmInit(component_common_dm)                                          \
        {                                                                                   \
            AnscZeroMemory(component_common_dm, sizeof(COMPONENT_COMMON_DM));               \
            component_common_dm->Name        = NULL;                                        \
            component_common_dm->Version     = 1;                                           \
            component_common_dm->Author      = NULL;                                        \
            component_common_dm->Health      = CCSP_COMMON_COMPONENT_HEALTH_Red;            \
            component_common_dm->State       = CCSP_COMMON_COMPONENT_STATE_Running;         \
            if(g_iTraceLevel >= CCSP_TRACE_LEVEL_EMERGENCY)                                 \
                component_common_dm->LogLevel = (ULONG) g_iTraceLevel;                     \
            component_common_dm->LogEnable   = TRUE;                                        \
            component_common_dm->MemMaxUsage = 0;                                           \
            component_common_dm->MemMinUsage = 0;                                           \
            component_common_dm->MemConsumed = 0;                                           \
        }


#define  ComponentCommonDmClean(component_common_dm)                                        \
         {                                                                                  \
            if ( component_common_dm->Name )                                                \
            {                                                                               \
                AnscFreeMemory(component_common_dm->Name);                                  \
            }                                                                               \
                                                                                            \
            if ( component_common_dm->Author )                                              \
            {                                                                               \
                AnscFreeMemory(component_common_dm->Author);                                \
            }                                                                               \
         }


#define  ComponentCommonDmFree(component_common_dm)                                         \
         {                                                                                  \
            ComponentCommonDmClean(component_common_dm);                                    \
            AnscFreeMemory(component_common_dm);                                            \
         }

int  cmd_dispatch(int  command);

void load_data_model();


ANSC_STATUS
ssp_create_pnm
    (
        PCCSP_COMPONENT_CFG         pStartCfg
    );

ANSC_STATUS
ssp_engage_pnm
    (
        PCCSP_COMPONENT_CFG         pStartCfg
    );

ANSC_STATUS
ssp_cancel_pnm
    (
        PCCSP_COMPONENT_CFG         pStartCfg
    );


ANSC_STATUS 
ssp_LoadCosaPluginLibrary
(
);

ANSC_STATUS
MessageBusTaskSim
    (
        ANSC_HANDLE hThisObject
    );

char*
ssp_WifiCCDmGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_WifiCCDmGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    );

char*
ssp_WifiCCDmGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_WifiCCDmGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_WifiCCDmGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    );

BOOL
ssp_WifiCCDmGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_WifiCCDmSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    );

ULONG
ssp_WifiCCDmGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_WifiCCDmSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    );

ULONG
ssp_WifiCCDmGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_WifiCCDmGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_WifiCCDmGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_WifiCCDmApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    );

#endif
