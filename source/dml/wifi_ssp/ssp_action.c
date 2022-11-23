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

    module: ssp_action.c

        For CCSP Wifi

    ---------------------------------------------------------------

    description:

        SSP implementation of the General Bootloader Interface
        Service.

        *   ssp_create_wifi
        *   ssp_engage_wifi
        *   ssp_cancel_wifi
        *   ssp_WifiCCDmGetComponentName
        *   ssp_WifiCCDmGetComponentVersion
        *   ssp_WifiCCDmGetComponentAuthor
        *   ssp_WifiCCDmGetComponentHealth
        *   ssp_WifiCCDmGetComponentState
        *   ssp_WifiCCDmGetLoggingEnabled
        *   ssp_WifiCCDmSetLoggingEnabled
        *   ssp_WifiCCDmGetLoggingLevel
        *   ssp_WifiCCDmSetLoggingLevel
        *   ssp_WifiCCDmGetMemMaxUsage
        *   ssp_WifiCCDmGetMemMinUsage
        *   ssp_WifiCCDmGetMemConsumed
		*	ssp_WifiCCDmApplyChanges

    ---------------------------------------------------------------

    environment:

        Embedded Linux

    ---------------------------------------------------------------

    author:

        Venka Gade

    ---------------------------------------------------------------

    revision:

        06/04/2014  initial revision.

**********************************************************************/

#include "ssp_global.h"
#include "ccsp_trace.h"
#include "dm_pack_create_func.h"
extern ULONG                                       g_ulAllocatedSizePeak;

extern  PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController;
extern  PDSLH_DATAMODEL_AGENT_OBJECT    g_DslhDataModelAgent;
extern  PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm;
extern  PCCSP_FC_CONTEXT                pWifiFcContext;
extern  PCCSP_CCD_INTERFACE             pWifiCcdIf;
extern  ANSC_HANDLE                     bus_handle;
extern char                             g_Subsystem[32];

//static  COMPONENT_COMMON_DM             CommonDm = {0};

ANSC_STATUS
ssp_create_wifi
    (
        PCCSP_COMPONENT_CFG         pStartCfg
    )
{
    /* Create component common data model object */

    g_pComponent_Common_Dm = (PCOMPONENT_COMMON_DM)AnscAllocateMemory(sizeof(COMPONENT_COMMON_DM));

    if ( !g_pComponent_Common_Dm )
    {
        return ANSC_STATUS_RESOURCES;
    }

    ComponentCommonDmInit(g_pComponent_Common_Dm);

    g_pComponent_Common_Dm->Name     = AnscCloneString(pStartCfg->ComponentName);
    g_pComponent_Common_Dm->Version  = 1;
    g_pComponent_Common_Dm->Author   = AnscCloneString("CCSP");

    /* Create ComponentCommonDatamodel interface*/
    if ( !pWifiCcdIf )
    {
        pWifiCcdIf = (PCCSP_CCD_INTERFACE)AnscAllocateMemory(sizeof(CCSP_CCD_INTERFACE));

        if ( !pWifiCcdIf )
        {
            return ANSC_STATUS_RESOURCES;
        }
        else
        {
            AnscCopyString(pWifiCcdIf->Name, CCSP_CCD_INTERFACE_NAME);

            pWifiCcdIf->InterfaceId              = CCSP_CCD_INTERFACE_ID;
            pWifiCcdIf->hOwnerContext            = NULL;
            pWifiCcdIf->Size                     = sizeof(CCSP_CCD_INTERFACE);

            pWifiCcdIf->GetComponentName         = ssp_WifiCCDmGetComponentName;
            pWifiCcdIf->GetComponentVersion      = ssp_WifiCCDmGetComponentVersion;
            pWifiCcdIf->GetComponentAuthor       = ssp_WifiCCDmGetComponentAuthor;
            pWifiCcdIf->GetComponentHealth       = ssp_WifiCCDmGetComponentHealth;
            pWifiCcdIf->GetComponentState        = ssp_WifiCCDmGetComponentState;
            pWifiCcdIf->GetLoggingEnabled        = ssp_WifiCCDmGetLoggingEnabled;
            pWifiCcdIf->SetLoggingEnabled        = ssp_WifiCCDmSetLoggingEnabled;
            pWifiCcdIf->GetLoggingLevel          = ssp_WifiCCDmGetLoggingLevel;
            pWifiCcdIf->SetLoggingLevel          = ssp_WifiCCDmSetLoggingLevel;
            pWifiCcdIf->GetMemMaxUsage           = ssp_WifiCCDmGetMemMaxUsage;
            pWifiCcdIf->GetMemMinUsage           = ssp_WifiCCDmGetMemMinUsage;
            pWifiCcdIf->GetMemConsumed           = ssp_WifiCCDmGetMemConsumed;
            pWifiCcdIf->ApplyChanges             = ssp_WifiCCDmApplyChanges;
        }
    }

    /* Create context used by data model */
    pWifiFcContext = (PCCSP_FC_CONTEXT)AnscAllocateMemory(sizeof(CCSP_FC_CONTEXT));

    if ( !pWifiFcContext )
    {
        return ANSC_STATUS_RESOURCES;
    }
    else
    {
        AnscZeroMemory(pWifiFcContext, sizeof(CCSP_FC_CONTEXT));
    }

    pDslhCpeController = DslhCreateCpeController(NULL, NULL, NULL);

    if ( !pDslhCpeController )
    {
        CcspTraceWarning(("CANNOT Create pDslhCpeController... Exit!\n"));

        return ANSC_STATUS_RESOURCES;
    }

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
ssp_engage_wifi
    (
        PCCSP_COMPONENT_CFG         pStartCfg
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    char                            CrName[256]     = {0};
    PCCSP_DM_XML_CFG_LIST           pXmlCfgList     = NULL;

    g_pComponent_Common_Dm->Health = CCSP_COMMON_COMPONENT_HEALTH_Yellow;


    if ( pWifiCcdIf )
    {
        pWifiFcContext->hCcspCcdIf = (ANSC_HANDLE)pWifiCcdIf;
        pWifiFcContext->hMessageBus = bus_handle;
    }

    g_DslhDataModelAgent->SetFcContext((ANSC_HANDLE)g_DslhDataModelAgent, (ANSC_HANDLE)pWifiFcContext);

    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)MsgHelper_CreateCcdMbiIf((void*)bus_handle,g_Subsystem));
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pWifiCcdIf);
    pDslhCpeController->SetDbusHandle((ANSC_HANDLE)pDslhCpeController, bus_handle);
    pDslhCpeController->Engage((ANSC_HANDLE)pDslhCpeController);

    if ( g_Subsystem[0] != 0 )
    {
        _ansc_sprintf(CrName, "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
    }
    else
    {
        _ansc_sprintf(CrName, "%s", CCSP_DBUS_INTERFACE_CR);
    }

    returnStatus = CcspComponentLoadDmXmlList(pStartCfg->DmXmlCfgFileName, &pXmlCfgList);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
	CcspTraceWarning(("Failed while loading WiFi Data MOdel returnStatus = %ld\n",returnStatus));
        return  returnStatus;
    }

    returnStatus =
        pDslhCpeController->RegisterCcspDataModel2
            (
                (ANSC_HANDLE)pDslhCpeController,
                CrName,                             /* CCSP CR ID */
                DMPackCreateDataModelXML,           /* Comcast generated code to create XML. */
                pStartCfg->ComponentName,           /* Component Name    */
                pStartCfg->Version,                 /* Component Version */
                pStartCfg->DbusPath,                /* Component Path    */
                g_Subsystem                         /* Component Prefix  */
            );

    if ( returnStatus == ANSC_STATUS_SUCCESS || returnStatus == CCSP_SUCCESS )
    {
        /* System is fully initialized */
        g_pComponent_Common_Dm->Health = CCSP_COMMON_COMPONENT_HEALTH_Green;
    }
   else
    {
        CcspTraceWarning(("%s WiFi Failed to register with CR ret = %ld\n",__FUNCTION__,returnStatus));
    }

    AnscFreeMemory(pXmlCfgList);

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
ssp_cancel_wifi
    (
        PCCSP_COMPONENT_CFG         pStartCfg
    )
{
	int                             nRet  = 0;
    char                            CrName[256];
    char                            CpName[256];

    if( pDslhCpeController == NULL)
    {
        return ANSC_STATUS_SUCCESS;
    }

    if ( g_Subsystem[0] != 0 )
    {
        _ansc_sprintf(CrName, "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
        _ansc_sprintf(CpName, "%s%s", g_Subsystem, pStartCfg->ComponentName);
    }
    else
    {
        _ansc_sprintf(CrName, "%s", CCSP_DBUS_INTERFACE_CR);
        _ansc_sprintf(CpName, "%s", pStartCfg->ComponentName);
    }
    /* unregister component */
    nRet = CcspBaseIf_unregisterComponent(bus_handle, CrName, CpName );  
    AnscTrace("unregisterComponent returns %d\n", nRet);


    pDslhCpeController->Cancel((ANSC_HANDLE)pDslhCpeController);
    AnscFreeMemory(pDslhCpeController);
    pDslhCpeController = NULL;

    return ANSC_STATUS_SUCCESS;
}


char*
ssp_WifiCCDmGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Name;
}


ULONG
ssp_WifiCCDmGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Version;
}


char*
ssp_WifiCCDmGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Author;
}


ULONG
ssp_WifiCCDmGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Health;
}


ULONG
ssp_WifiCCDmGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->State;
}



BOOL
ssp_WifiCCDmGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->LogEnable;
}


ANSC_STATUS
ssp_WifiCCDmSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    /*CommonDm.LogEnable = bEnabled;*/
    if(g_pComponent_Common_Dm->LogEnable == bEnabled) return ANSC_STATUS_SUCCESS;
    g_pComponent_Common_Dm->LogEnable = bEnabled;

    if (!bEnabled)
        AnscSetTraceLevel(CCSP_TRACE_INVALID_LEVEL);
    else
        AnscSetTraceLevel(g_pComponent_Common_Dm->LogLevel);

    return ANSC_STATUS_SUCCESS;
}


ULONG
ssp_WifiCCDmGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->LogLevel;
}


ANSC_STATUS
ssp_WifiCCDmSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    /*CommonDm.LogLevel = LogLevel; */
    if(g_pComponent_Common_Dm->LogLevel == LogLevel) return ANSC_STATUS_SUCCESS;
    g_pComponent_Common_Dm->LogLevel = LogLevel;

    if (g_pComponent_Common_Dm->LogEnable)
        AnscSetTraceLevel(LogLevel);        

    return ANSC_STATUS_SUCCESS;
}


ULONG
ssp_WifiCCDmGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_ulAllocatedSizePeak;
}


ULONG
ssp_WifiCCDmGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->MemMinUsage;
}


ULONG
ssp_WifiCCDmGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    )
{
    LONG             size = 0;
    UNREFERENCED_PARAMETER(hThisObject);
    size = AnscGetComponentMemorySize(gpWifiStartCfg->ComponentName);
    if (size == -1 )
        size = 0;

    return size;
}


ANSC_STATUS
ssp_WifiCCDmApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                         returnStatus    = ANSC_STATUS_SUCCESS;
    /* Assume the parameter settings are committed immediately. */
    /*g_pComponent_Common_Dm->LogEnable = CommonDm.LogEnable;
    g_pComponent_Common_Dm->LogLevel  = CommonDm.LogLevel;

    AnscSetTraceLevel((INT)g_pComponent_Common_Dm->LogLevel);*/

    return returnStatus;
}

const char *rdk_logger_module_fetch(void)
{
    return "LOG.RDK.WIFI";
}
