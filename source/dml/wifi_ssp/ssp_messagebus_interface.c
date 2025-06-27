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

    module: ssp_messagebus_interface.c

        For CCSP Secure Software Download

    ---------------------------------------------------------------

    description:

        SSP implementation of the CCSP Message Bus Interface
        Service.

        *   ssp_WifiMbi_MessageBusEngage
        
    ---------------------------------------------------------------

    environment:

        Embedded Linux

    ---------------------------------------------------------------

    author:

        Tom Chang

    ---------------------------------------------------------------

    revision:

        06/23/2011  initial revision.

**********************************************************************/

#include "ssp_global.h"


ANSC_HANDLE                 bus_handle         = NULL;
extern  BOOL                g_bActive;
extern  char                g_Subsystem[32];
extern  PCOMPONENT_COMMON_DM g_pComponent_Common_Dm;

int ssp_WifiMbi_GetHealth ( )
{
    return g_pComponent_Common_Dm->Health;
}

#ifdef _ANSC_LINUX
ANSC_STATUS
ssp_WifiMbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    )
{
    ANSC_STATUS                 returnStatus       = ANSC_STATUS_SUCCESS;
    CCSP_Base_Func_CB           cb                 = {0};
    
    char PsmName[256];

    if ( ! component_id || ! path )
    {
        CcspTraceError((" !!! ssp_WifiMbi_MessageBusEngage: component_id or path is NULL !!!\n"));
        /*CID: 144415,55876  Dereference after null check*/
        return ANSC_STATUS_FAILURE;
    }

    /* Connect to message bus */
    returnStatus = 
        CCSP_Message_Bus_Init
            (
                component_id,
                config_file,
                &bus_handle,
                (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback,           /* mallocfc, use default */
                Ansc_FreeMemory_Callback            /* freefc,   use default */
            );

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        CcspTraceError((" !!! Wifi Message Bus Init ERROR !!!\n"));

        return returnStatus;
    }

    if ( g_Subsystem[0] != 0 )
    {
        _ansc_sprintf(PsmName, "%s%s", g_Subsystem, CCSP_DBUS_PSM);
    }
    else
    {
        AnscCopyString(PsmName, CCSP_DBUS_PSM);
    }

    /* Wait for PSM */
    waitConditionReady(bus_handle, PsmName, CCSP_DBUS_PATH_PSM, component_id);

    CcspTraceInfo(("!!! Connected to message bus... bus_handle: 0x%8p !!!\n", bus_handle));

    CCSP_Msg_SleepInMilliSeconds(1000);

    /* Base interface implementation that will be used cross components */
    cb.getParameterValues     = CcspCcMbi_GetParameterValues;
    cb.setParameterValues     = CcspCcMbi_SetParameterValues;
    cb.setCommit              = CcspCcMbi_SetCommit;
    cb.setParameterAttributes = CcspCcMbi_SetParameterAttributes;
    cb.getParameterAttributes = CcspCcMbi_GetParameterAttributes;
    cb.AddTblRow              = CcspCcMbi_AddTblRow;
    cb.DeleteTblRow           = CcspCcMbi_DeleteTblRow;
    cb.getParameterNames      = CcspCcMbi_GetParameterNames;
    cb.currentSessionIDSignal = CcspCcMbi_CurrentSessionIdSignal;

    /* Base interface implementation that will only be used by pnm */
    cb.initialize             = ssp_WifiMbi_Initialize;
    cb.finalize               = ssp_WifiMbi_Finalize;
    cb.freeResources          = ssp_WifiMbi_FreeResources;
    cb.busCheck               = ssp_WifiMbi_Buscheck;
    cb.getHealth              = ssp_WifiMbi_GetHealth;

    CcspBaseIf_SetCallback(bus_handle, &cb);

    /* Register event/signal */
    returnStatus = 
        CcspBaseIf_Register_Event
            (
                bus_handle,
                0,
                "currentSessionIDSignal"
            );

    if ( returnStatus != CCSP_Message_Bus_OK )
    {
        CcspTraceError((" !!! CCSP_Message_Bus_Register_Event: CurrentSessionIDSignal ERROR returnStatus: %ld!!!\n", returnStatus));

        return returnStatus;
    }

    return ANSC_STATUS_SUCCESS;
}

#endif

int
ssp_WifiMbi_Initialize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;
    
    printf("In %s()\n", __FUNCTION__);
    
    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}

int
ssp_WifiMbi_Finalize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    printf("In %s()\n", __FUNCTION__);

    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}


int
ssp_WifiMbi_Buscheck
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    printf("In %s()\n", __FUNCTION__);

    return 0;
}


int
ssp_WifiMbi_FreeResources
    (
        int priority,
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    UNREFERENCED_PARAMETER(priority);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    printf("In %s()\n", __FUNCTION__);

    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}

