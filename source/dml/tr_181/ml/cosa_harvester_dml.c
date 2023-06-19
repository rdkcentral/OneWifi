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

    module: cosa_wifi_dml.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/18/2011    initial revision.

**************************************************************************/
#include "ctype.h"
#include "ansc_platform.h"
#include "cosa_wifi_dml.h"
#include "cosa_wifi_internal.h"
#include "plugin_main_apis.h"
#include "ccsp_WifiLog_wrapper.h"
#include "ccsp_trace.h"
#include "ccsp_psm_helper.h"
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_monitor.h"
#include "dml_onewifi_api.h"
//#include "wifi_db.h"

extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];

extern void* g_pDslhDmlAgent;
extern int gChannelSwitchingCount;

extern BOOL g_wifidb_rfc;

char* GetInstAssocDevSchemaIdBuffer();
char *instSchemaIdBuffer = "8b27dafc-0c4d-40a1-b62c-f24a34074914/4388e585dd7c0d32ac47e71f634b579b";

#if 1
#define MIN_INSTANT_REPORT_TIME   1
#define MAX_INSTANT_REPORT_TIME   900

ANSC_STATUS CosaDmlHarvesterInit(ANSC_HANDLE hThisObject);

ANSC_STATUS
CosaDmlHarvesterInit
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;

    return returnStatus;
}

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_Report.WifiClient.

    *  WifiClient_GetParamBoolValue
    *  WifiClient_GetParamUlongValue
    *  WifiClient_GetParamStringValue
    *  WifiClient_SetParamBoolValue
    *  WifiClient_SetParamUlongValue
    *  WifiClient_SetParamStringValue
    *  WifiClient_Validate
    *  WifiClient_Commit
    *  WifiClient_Rollback

***********************************************************************/
BOOL
WifiClient_GetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL*                       pBool
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) get_dml_harvester();

    if(pcfg== NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if ( AnscEqualString(ParamName, "Enabled", TRUE))
    {
        *pBool = pcfg->b_inst_client_enabled;
        return TRUE;
    }
    return FALSE;
}

BOOL
WifiClient_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) get_dml_harvester();

    if(pcfg== NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if ( AnscEqualString(ParamName, "ReportingPeriod", TRUE))
    {
        *puLong = pcfg->u_inst_client_reporting_period;
        return TRUE;
    }

    return FALSE;
}

ULONG
WifiClient_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pUlSize);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) get_dml_harvester();
    if(pcfg== NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if( AnscEqualString(ParamName, "MacAddress", TRUE))
    {
        strncpy(pValue, pcfg->mac_address, *pUlSize);
        return 0;
    }

   if( AnscEqualString(ParamName, "Schema", TRUE))
    {
        AnscCopyString(pValue, "WifiSingleClient.avsc");
        return 0;
    }

    if( AnscEqualString(ParamName, "SchemaID", TRUE))
    {
        unsigned int bufsize = strlen(instSchemaIdBuffer);;
        if(!bufsize)
        {
            char result[1024] = "SchemaID Buffer is empty";
            AnscCopyString(pValue, (char*)&result);
            return -1;
        }
        else
        {
            CcspTraceWarning(("%s-%d : Buffer Size [%d] InputSize [%ld]\n" , __FUNCTION__, __LINE__, bufsize, *pUlSize));
            if (bufsize < *pUlSize)
            {
                strncpy(pValue, instSchemaIdBuffer, bufsize);
                CcspTraceWarning(("%s-%d : pValue Buffer Size [%d]\n" , __FUNCTION__, __LINE__, (int)strlen(pValue)));
                return 0;
            }
            else
            {
                *pUlSize = bufsize + 1;
                return 1;
            }
        }
        return 0;
    }

    return -1;
}

BOOL
WifiClient_SetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL                        bValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = NULL;
    pcfg = (instant_measurement_config_t*) get_dml_cache_harvester();
    if(pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and set the corresponding value */

    if ( AnscEqualString(ParamName, "Enabled", TRUE))
    {
        if((bValue == true) &&
               (pcfg->u_inst_client_reporting_period > pcfg->u_inst_client_def_override_ttl))
        {
             AnscTraceWarning(("Can not start report when PollingPeriod > TTL\n"));
             return FALSE;
        }

        pcfg->b_inst_client_enabled = bValue;
        return TRUE;
    }

    return FALSE;
}

BOOL
WifiClient_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = NULL;
    pcfg = (instant_measurement_config_t*) get_dml_cache_harvester();
    if(pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "ReportingPeriod", TRUE))
    {
        if (validate_def_reporting_period(uValue)) {
            pcfg->u_inst_client_reporting_period = uValue;
            return TRUE;
        } else {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Unsupported parameter value:'%d' for ReportingPeriod\n",__FUNCTION__, __LINE__,uValue);
            return FALSE;
        }
    }

    return FALSE;
}

BOOL
WifiClient_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = NULL;
    pcfg = (instant_measurement_config_t*) get_dml_cache_harvester();

    if(pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "MacAddress", TRUE))
    {
        if (validate_inst_client_mac(pValue)){
            strncpy(pcfg->mac_address, pValue, sizeof(pcfg->mac_address)-1);
            return TRUE;
        }else{
            return FALSE;
        }
	return TRUE;
    }

    return FALSE;
}

BOOL
WifiClient_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    instant_measurement_config_t *pcfg = NULL;
    pcfg = (instant_measurement_config_t*) get_dml_cache_harvester();

    if(pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (validate_def_reporting_period(pcfg->u_inst_client_reporting_period) != TRUE)
    {
        strncpy(pReturnParamName, "ReportingPeriod", *puLength);
        *puLength = AnscSizeOfString("ReportingPeriod");
        wifi_util_dbg_print(WIFI_DMCLI," %s:%dUnsupported parameter value '%s'\n",__FUNCTION__,__LINE__,pReturnParamName);
        return FALSE;
    }

    /*When instant reporting is enabled, TTL must not be less than poll time */
    if ((dml_wifi_is_instant_measurements_enable()) && (pcfg->u_inst_client_reporting_period != 0) &&
              (pcfg->u_inst_client_reporting_period > pcfg->u_inst_client_def_override_ttl))
    {
        strncpy(pReturnParamName, "OverrideTTL", *puLength);
        *puLength = AnscSizeOfString("OverrideTTL");
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unsupported parameter value '%s'\n",__FUNCTION__,__LINE__,pReturnParamName);
        return FALSE;
    }

    push_harvester_dml_cache_to_one_wifidb();
    return TRUE;
}

ULONG
WifiClient_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    return 0;
}

ULONG
WifiClient_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_Report.WifiClient.Default.

    *  WifiClient_Default_GetParamUlongValue
    *  WifiClient_Default_SetParamUlongValue
    *  WifiClient_Default_Validate
    *  WifiClient_Default_Commit
    *  WifiClient_Default_Rollback

***********************************************************************/

BOOL
WifiClient_Default_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) get_dml_harvester();

    if(pcfg== NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "OverrideTTL", TRUE))
    {
        //*puLong = get_inst_override_ttl();
        *puLong = pcfg->u_inst_client_def_override_ttl;
        return TRUE;
    }

    if ( AnscEqualString(ParamName, "ReportingPeriod", TRUE))
    {
        *puLong = pcfg->u_inst_client_def_reporting_period;
        return TRUE;
    }

    return FALSE;
}

BOOL
WifiClient_Default_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = NULL;
    pcfg = (instant_measurement_config_t*) get_dml_cache_harvester();

    if(pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "ReportingPeriod", TRUE))
    {
        pcfg->u_inst_client_def_reporting_period = uValue;
        return TRUE;
    }

    if ( AnscEqualString(ParamName, "OverrideTTL", TRUE))
    {
        pcfg->u_inst_client_def_override_ttl = uValue;
        return TRUE;
    }

    return FALSE;
}

BOOL
WifiClient_Default_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    instant_measurement_config_t *pcfg = NULL;
    pcfg = (instant_measurement_config_t*) get_dml_cache_harvester();

    if(pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (validate_def_reporting_period(pcfg->u_inst_client_def_reporting_period) != TRUE)
    {
        strncpy(pReturnParamName, "ReportingPeriod", *puLength);
        *puLength = AnscSizeOfString("ReportingPeriod");
        wifi_util_dbg_print(WIFI_DMCLI," %s:%dUnsupported parameter value '%s'\n",__FUNCTION__,__LINE__,pReturnParamName);
        return FALSE;
    }

    /*When instant reporting is enabled, TTL must not be less than poll time */
    if ((dml_wifi_is_instant_measurements_enable()) && (pcfg->u_inst_client_def_override_ttl != 0) &&
              (pcfg->u_inst_client_def_override_ttl > pcfg-> u_inst_client_reporting_period))
    {
        strncpy(pReturnParamName, "OverrideTTL", *puLength);
        *puLength = AnscSizeOfString("OverrideTTL");
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unsupported parameter value '%s'\n",__FUNCTION__,__LINE__,pReturnParamName);
        return FALSE;
    }
    if (pcfg->u_inst_client_def_override_ttl > 900)
    {
        strncpy(pReturnParamName, "OverrideTTL", *puLength);
        *puLength = AnscSizeOfString("OverrideTTL");
        AnscTraceWarning(("Unsupported parameter value '%s'\n", pReturnParamName));
        return FALSE;
    }
    push_harvester_dml_cache_to_one_wifidb();
    return TRUE;
}

ULONG
WifiClient_Default_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    return 0;
}

ULONG
WifiClient_Default_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_Report.WifiClient.ActiveMeasurements.
    *  WifiClient_ActiveMeasurements_GetParamBoolValue
    *  WifiClient_ActiveMeasurements_SetParamBoolValue
    *  WifiClient_ActiveMeasurements_GetParamUlongValue
    *  WifiClient_ActiveMeasurements_SetParamUlongValue
    *  WifiClient_ActiveMeasurements_Validate
    *  WifiClient_ActiveMeasurements_Commit
    *  WifiClient_ActiveMeasurements_Rollback

***********************************************************************/

BOOL
WifiClient_ActiveMeasurements_GetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL*                       pBool
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    active_msmt_t *pcfg = (active_msmt_t *) get_dml_blaster();
    if(pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "Enable", TRUE)) {
        *pBool = pcfg->ActiveMsmtEnable;
        return TRUE;
    }
    return FALSE;
}

BOOL
WifiClient_ActiveMeasurements_GetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG*                      puLong
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    active_msmt_t *pcfg = (active_msmt_t *) get_dml_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "PacketSize", TRUE)) {
        *puLong = pcfg->ActiveMsmtPktSize;
        return TRUE;
    }

    if ( AnscEqualString(ParamName, "SampleDuration", TRUE)) {
        *puLong = pcfg->ActiveMsmtSampleDuration;
        return TRUE;
    }

    if ( AnscEqualString(ParamName, "NumberOfSamples", TRUE)) {
        *puLong = pcfg->ActiveMsmtNumberOfSamples;
        return TRUE;
    }
    return FALSE;
}

BOOL
WifiClient_ActiveMeasurements_SetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL                        bValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);

    /* check the parameter name and set the corresponding value */
    active_msmt_t *pcfg = NULL;
    bool active_measurement_rfc =  false;
    pcfg = (active_msmt_t *) get_dml_cache_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    char *recName = "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WifiClient.ActiveMeasurements.Enable";
    char* strValue = NULL;

    if (PSM_Get_Record_Value2(bus_handle,g_Subsystem, recName, NULL, &strValue) != CCSP_SUCCESS) {
        AnscTraceWarning(("%s : fetching the PSM db failed for ActiveMsmt RFC\n", __func__));
    }
    else  {
        active_measurement_rfc = atoi(strValue);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        if(!active_measurement_rfc) {
            AnscTraceWarning(("%s : ActiveMsmt RFC is disabled \n", __func__));
            return FALSE;
        }
    }

    if ( AnscEqualString(ParamName, "Enable", TRUE)) {
        pcfg->ActiveMsmtEnable = bValue;
        push_blaster_config_dml_to_ctrl_queue();
        return TRUE;
    }

    return FALSE;
}

BOOL
WifiClient_ActiveMeasurements_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    active_msmt_t *pcfg = NULL;
    pcfg = (active_msmt_t *) get_dml_cache_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "PacketSize", TRUE)) {
        if((uValue < MIN_ACTIVE_MSMT_PKT_SIZE) ||(uValue > MAX_ACTIVE_MSMT_PKT_SIZE)) {
            return FALSE;
        }
        pcfg->ActiveMsmtPktSize = uValue;
        return TRUE;
    }

    if ( AnscEqualString(ParamName, "SampleDuration", TRUE)) {
        if((uValue < MIN_ACTIVE_MSMT_SAMPLE_DURATION) ||(uValue > MAX_ACTIVE_MSMT_SAMPLE_DURATION)) {
            return FALSE;
        }
	    pcfg->ActiveMsmtSampleDuration = uValue;
        return TRUE;
    }

    if ( AnscEqualString(ParamName, "NumberOfSamples", TRUE)) {
        if((uValue < MIN_ACTIVE_MSMT_SAMPLE_COUNT) ||(uValue > MAX_ACTIVE_MSMT_SAMPLE_COUNT)){
            return FALSE;
        }
		pcfg->ActiveMsmtNumberOfSamples = uValue;
        return TRUE;
    }
    return FALSE;
}

BOOL
WifiClient_ActiveMeasurements_Validate
(
    ANSC_HANDLE                 hInsContext,
    char*                       pReturnParamName,
    ULONG*                      puLength
)
{
    return TRUE;
}

ULONG
WifiClient_ActiveMeasurements_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    return 0;
}

ULONG
WifiClient_ActiveMeasurements_Rollback
(
    ANSC_HANDLE                 hInsContext
)
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_Report.WifiClient.ActiveMeasurements.Plan
    *  ActiveMeasurements_Plan_GetParamStringValue
    *  ActiveMeasurements_Plan_SetParamStringValue
    *  ActiveMeasurements_Plan_Validate
    *  ActiveMeasurements_Plan_Commit
    *  ActiveMeasurements_Plan_Rollback

***********************************************************************/
ULONG
ActiveMeasurements_Plan_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    active_msmt_t *pcfg = (active_msmt_t *) get_dml_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if ( AnscEqualString(ParamName, "PlanID", TRUE)){
        strcpy(pValue,(char*)pcfg->PlanId);
        return 0;
    }
    return -1;
}

BOOL
ActiveMeasurements_Plan_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    active_msmt_t *pcfg = NULL;
    pcfg = (active_msmt_t *) get_dml_cache_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if ( AnscEqualString(ParamName, "PlanID", TRUE)) {
         if (AnscEqualString(pValue, (char*)pcfg->PlanId, FALSE)) {
             AnscTraceWarning(("%s : Plan ID is same\n", __func__));
             return TRUE;
         }
         else {
            AnscTraceWarning(("%s : Plan ID is not same\n", __func__));
            strncpy((char*)pcfg->PlanId, pValue, strlen(pValue));
            /* Reset all the step information when plan id changes */
            if (ANSC_STATUS_SUCCESS != CosaDmlWiFiClient_ResetActiveMsmtStep(pcfg)) {
                AnscTraceWarning(("%s : resetting Active measurement Step Information failed\n", __FUNCTION__));
            }
             return TRUE;
         }

    }
    return FALSE;
}

BOOL
ActiveMeasurements_Plan_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return TRUE;
}

ULONG
ActiveMeasurements_Plan_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

ULONG
ActiveMeasurements_Plan_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_Report.WifiClient.ActiveMeasurements.Plan.Step{i}.
    *  ActiveMeasurement_Step_GetEntryCount
    *  ActiveMeasurement_Step_GetEntry
    *  ActiveMeasurement_Step_GetParamIntValue
    *  ActiveMeasurement_Step_GetParamStringValue
    *  ActiveMeasurement_Step_SetParamIntValue
    *  ActiveMeasurement_Step_SetParamStringValue
    *  ActiveMeasurement_Step_Validate
    *  ActiveMeasurement_Step_Commit
    *  ActiveMeasurement_Step_Rollback

***********************************************************************/
ULONG
ActiveMeasurement_Step_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return MAX_STEP_COUNT;
}

ANSC_HANDLE
ActiveMeasurement_Step_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    active_msmt_t *pcfg = (active_msmt_t *) get_dml_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if (nIndex >= MAX_STEP_COUNT)
        return (ANSC_HANDLE)NULL;

    *pInsNumber = nIndex + 1;
    return (ANSC_HANDLE)&pcfg->Step[nIndex];
}

BOOL
ActiveMeasurement_Step_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    ULONG    StepIns = 0;
    active_msmt_t *pcfg = (active_msmt_t *) get_dml_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    active_msmt_step_t *pStepCfg  = (active_msmt_step_t *)hInsContext;
    /* Get the instance number */
    if (ANSC_STATUS_SUCCESS != GetActiveMsmtStepInsNum(pStepCfg, &StepIns)) {
        AnscTraceWarning(("%s : GetActiveMsmtStepInsNum failed\n", __func__));
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if ( AnscEqualString(ParamName, "StepID", TRUE)) {
        /* collect value */
        *puLong = pcfg->Step[StepIns].StepId;
        return TRUE;
    }
    return FALSE;
}

ULONG
ActiveMeasurement_Step_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(pUlSize);
    ULONG    StepIns = 0;
    active_msmt_step_t *pStepCfg  = (active_msmt_step_t*)hInsContext;
    active_msmt_t *pcfg = (active_msmt_t *) get_dml_blaster();

    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* Get the instance number */
    if (ANSC_STATUS_SUCCESS != GetActiveMsmtStepInsNum(pStepCfg, &StepIns)) {
        AnscTraceWarning(("%s : GetActiveMsmtStepInsNum failed\n", __func__));
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "SourceMac", TRUE)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  \n",(char*)pcfg->Step[StepIns].SrcMac ,StepIns);
        strcpy(pValue, (char*)pcfg->Step[StepIns].SrcMac);
        return 0;
    }
    if ( AnscEqualString(ParamName, "DestMac", TRUE)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  \n",(char*)pcfg->Step[StepIns].DestMac ,StepIns);
        strcpy(pValue, (char*) pcfg->Step[StepIns].DestMac);
        return 0;
    }
    return -1;
}

BOOL
ActiveMeasurement_Step_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    ULONG    StepIns = 0;

    active_msmt_step_t *pStepCfg  = (active_msmt_step_t*)hInsContext;
    active_msmt_t *pcfg = NULL;
    pcfg = (active_msmt_t *) get_dml_cache_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if (ANSC_STATUS_SUCCESS != ValidateActiveMsmtPlanID(pcfg->PlanId)) {
        CcspTraceWarning(("%s-%d : NULL value for PlanId\n" , __FUNCTION__, __LINE__ ));
        return FALSE;
    }
    /* Get the instance number */
    if (ANSC_STATUS_SUCCESS != GetActiveMsmtStepInsNum(pStepCfg, &StepIns)) {
        AnscTraceWarning(("%s : GetActiveMsmtStepInsNum failed\n", __func__));
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if ( AnscEqualString(ParamName, "StepID", TRUE)) {
        pcfg->Step[StepIns].StepId = (unsigned int)uValue;
        return TRUE;
    }
    return FALSE;
}

BOOL
ActiveMeasurement_Step_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue
    )
{
    ULONG    StepIns = 0;
    active_msmt_step_t *pStepCfg  = (active_msmt_step_t*)hInsContext;
    active_msmt_t *pcfg = NULL;
    pcfg = (active_msmt_t *) get_dml_cache_blaster();

    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (ANSC_STATUS_SUCCESS != ValidateActiveMsmtPlanID(pcfg->PlanId)) {
        CcspTraceWarning(("%s-%d : NULL value for PlanId\n" , __FUNCTION__, __LINE__ ));
        return FALSE;
    }
    /* Get the instance number */
    if (ANSC_STATUS_SUCCESS != GetActiveMsmtStepInsNum(pStepCfg, &StepIns)) {
        AnscTraceWarning(("%s : GetActiveMsmtStepInsNum failed\n", __func__));
        return FALSE;
    }

    if (AnscEqualString(ParamName, "SourceMac", TRUE)) {
        strcpy( (char*)pcfg->Step[StepIns].SrcMac,pValue);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  \n",(char*)pcfg->Step[StepIns].SrcMac ,StepIns);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "DestMac", TRUE)) {
        strcpy((char*) pcfg->Step[StepIns].DestMac,pValue);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  \n",(char*)pcfg->Step[StepIns].DestMac ,StepIns);
        return TRUE;
    }
    return FALSE;
}
BOOL
ActiveMeasurement_Step_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

ULONG
ActiveMeasurement_Step_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    return ANSC_STATUS_SUCCESS;
}

ULONG
ActiveMeasurement_Step_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

#endif
