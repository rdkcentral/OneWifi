/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

        *  CosaWifiCreate
        *  CosaWifiInitialize
        *  CosaWifiRemove
    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        Richard Yang

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/

#include <telemetry_busmessage_sender.h>
#include "cosa_apis.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_internal.h"
#include "plugin_main_apis.h"
#include "ccsp_WifiLog_wrapper.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_dml.h"
#include "cosa_harvester_internal.h"
#include "wifi_hal.h"
#include "wifi_passpoint.h"
#include "wifi_data_plane.h"
#include "secure_wrapper.h"
#include <sys/un.h>

#include "wifi_util.h"
#include "dml_onewifi_api.h"

extern void* g_pDslhDmlAgent;
/**************************************************************************
*
*	Function Definitions
*
**************************************************************************/


/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        CosaWifiCreate
            (
            );

    description:

        This function constructs cosa wifi object and return handle.

    argument:  

    return:     newly created wifi object.

**********************************************************************/

ANSC_HANDLE
CosaWifiCreate
    (
        VOID
    )
{
	PCOSA_DATAMODEL_WIFI            pMyObject    = (PCOSA_DATAMODEL_WIFI)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PCOSA_DATAMODEL_WIFI)AnscAllocateMemory(sizeof(COSA_DATAMODEL_WIFI));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    pMyObject->Oid               = COSA_DATAMODEL_WIFI_OID;
    pMyObject->Create            = CosaWifiCreate;
    pMyObject->Remove            = CosaWifiRemove;
    pMyObject->Initialize        = CosaWifiInitialize;

    pMyObject->Initialize   ((ANSC_HANDLE)pMyObject);

    return  (ANSC_HANDLE)pMyObject;
}

void CosaDmlWiFiGetDataFromPSM(void)
{
    uint8_t index;
    int rssi = 0;
    bool bReconnectCountEnable = 0, bFeatureMFPConfig = 0;
    bool l_boolValue;
    int  l_intValue;
    char recName[256];
    char *strValue = NULL;
    int retPsmGet = CCSP_SUCCESS;
    int resetSSID[2] = {0,0};
    char *FactoryResetSSID           = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.FactoryResetSSID";
    char *FixedWmmParams             = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.FixedWmmParamsValues";
    char *WiFiForceDisableRadioStatus = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDK-CENTRAL_COM_ForceDisable_RadioStatus";
    char *FactoryReset       = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.FactoryReset";

    wifi_util_dbg_print(WIFI_CTRL, "%s set vap dml parameters\n", __FUNCTION__);

    if (CosaDmlWiFi_GetGoodRssiThresholdValue(&rssi) != ANSC_STATUS_SUCCESS) {
        /* Set default value */
	rssi = -65;   
    }
    set_vap_dml_parameters(RSSI_THRESHOLD, &rssi);
    
    for(index = 0; index < MAX_VAP; index++)
    {
        if(CosaDmlWiFi_GetRapidReconnectCountEnable(index , (BOOLEAN *) &bReconnectCountEnable, false) != ANSC_STATUS_SUCCESS)
	{
	    /* Set default value */
	    if((index == 0) || (index == 1))
	    {
	        bReconnectCountEnable = 1;
	    }
	    else
	    {
	        bReconnectCountEnable = 0;
	    }
	}
        set_multi_vap_dml_parameters(index, RECONNECT_COUNT_STATUS, &bReconnectCountEnable);
    }

    if(CosaDmlWiFi_GetFeatureMFPConfigValue((BOOLEAN *) &bFeatureMFPConfig) != ANSC_STATUS_SUCCESS)
    {
        /* Set Default value */
        bFeatureMFPConfig = 0;	
    }
    set_vap_dml_parameters(MFP_FEATURE_STATUS, &bFeatureMFPConfig);

    if(CosaDmlWiFiGetFactoryResetPsmData(&l_boolValue) != ANSC_STATUS_SUCCESS)
    {
        /* Set Default value */
	l_boolValue = 1;
    }
    set_vap_dml_parameters(WIFI_FACTORY_RESET, &l_boolValue);
    PSM_Set_Record_Value2(bus_handle,g_Subsystem, FactoryReset, ccsp_string, "0");

    /* Get factory reset ssid value from PSM and set to global cache */
    for(index = 1; index <= (UINT)get_num_radio_dml(); index++)
    {
        memset(recName, 0, sizeof(recName));
        sprintf(recName, FactoryResetSSID, index);
        wifi_util_dbg_print(WIFI_CTRL, "RDK_LOG_WARN,WIFI %s PSM GET for FactoryResetSSID \n",__FUNCTION__);
        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, recName, NULL, &strValue);
        if (retPsmGet == CCSP_SUCCESS)
        {
            resetSSID[index-1] = atoi(strValue);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }
	else
	{
	    /* Set Default value*/
	    resetSSID[index-1] = 0;
	}
        set_multi_radio_dml_parameters(index-1, FACTORY_RESET_SSID, &resetSSID[index-1]);
    }

    /* Get FixedWmmParams value from PSM and set into global cache */
    // if the value is FALSE or not present WmmNoAck values should be reset
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, FixedWmmParams, NULL, &strValue);
    if (retPsmGet == CCSP_SUCCESS) 
    {
        l_intValue = atoi(strValue);
	wifi_util_dbg_print(WIFI_CTRL, "RDK_LOG_WARN,WIFI %s PSM GET for FixedWmmParams \n",__FUNCTION__);
	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    } else 
    {
        /* Set default value */
	    //TBD -N
    }
    set_vap_dml_parameters(FIXED_WMM_PARAMS, &l_intValue);

    /* Get AssocCountThreshold value from PSM and set into global cache */
    if(CosaDmlWiFi_GetAssocCountThresholdValue(&l_intValue) != ANSC_STATUS_SUCCESS)
    {
        /* Set Default Value */
	l_intValue = 0;
    }
    set_vap_dml_parameters(ASSOC_COUNT_THRESHOLD, &l_intValue);

    /* Get AssocMonitorDuration value from PSM and set into global cache */
    if(CosaDmlWiFi_GetAssocMonitorDurationValue(&l_intValue) != ANSC_STATUS_SUCCESS)
    {
        /* Set Default Value */
	l_intValue = 0;
    }
    set_vap_dml_parameters(ASSOC_MONITOR_DURATION, &l_intValue);

    /* Get AssocGateTime value from PSM and set into global cache */
    if(CosaDmlWiFi_GetAssocGateTimeValue(&l_intValue) != ANSC_STATUS_SUCCESS)
    {
        /* Set Default Value */
	l_intValue = 0;
    }
    set_vap_dml_parameters(ASSOC_GATE_TIME, &l_intValue);

    /* Get WiFiTxOverflowSelfheal value from PSM and set into global cache */
    if(CosaDmlWiFiGetTxOverflowSelfheal((BOOLEAN *)&l_boolValue) != ANSC_STATUS_SUCCESS)
    {
        /* Set Default Value */
        l_boolValue = 0;
    }
    set_vap_dml_parameters(WIFI_TX_OVERFLOW_SELF_HEAL, &l_boolValue);

    /* Get WiFiForceDisableWiFiRadio value from PSM and set into global cache */
    if(CosaDmlWiFiGetForceDisableWiFiRadio((BOOLEAN *)&l_boolValue) != ANSC_STATUS_SUCCESS)
    {
        /* Set Default value */
	l_boolValue = FALSE;
    }
    set_vap_dml_parameters(WIFI_FORCE_DISABLE_RADIO, &l_boolValue);

    /* Get WiFiForceDisableRadioStatus value from PSM and set into global cache */
    if (CCSP_SUCCESS != PSM_Get_Record_Value2(bus_handle,g_Subsystem, WiFiForceDisableRadioStatus, NULL, &strValue))
    {
        /*Set Default value */
	l_intValue = 0;
    }
    else
    {
        l_intValue = _ansc_atoi(strValue);
    }
    ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc( strValue );
    set_vap_dml_parameters(WIFI_FORCE_DISABLE_RADIO_STATUS, &l_intValue);    

}

void CosaDmlWiFiGetExternalDataFromPSM(void)
{
    int logInterval = 0;
    int retPsmGet = CCSP_SUCCESS;
    char *strValue = NULL;

    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem,"dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WHIX.ChUtilityLogInterval",NULL,&strValue);

    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strValue && strlen(strValue))
        {
            logInterval=atoi(strValue);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }
    }
    else
    {
            wifi_util_dbg_print(WIFI_MON, "%s:%d The PSM_Get_Record_Value2  is failed with %d retval  \n",__FUNCTION__,__LINE__,retPsmGet);
	    logInterval = 900;//Default Value 15mins.
    }

    set_vap_dml_parameters(CH_UTILITY_LOG_INTERVAL, &logInterval);

    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem,"dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WHIX.LogInterval",NULL,&strValue);

    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strValue && strlen(strValue))
        {
            logInterval=atoi(strValue);
            wifi_util_dbg_print(WIFI_MON, "The LogInterval is %dsec or %dmin \n",logInterval,(int)logInterval/60);
            logInterval=(int)(logInterval/60);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }
    }
    else
    {
            wifi_util_dbg_print(WIFI_MON, "%s:%d The PSM_Get_Record_Value2  is failed with %d retval  \n",__FUNCTION__,__LINE__,retPsmGet);
	    logInterval=60;//Default Value 60mins.
    }

    set_vap_dml_parameters(DEVICE_LOG_INTERVAL, &logInterval);

}

void CosaDmlWiFiGetRFCDataFromPSM(void)
{
    int retPsmGet = CCSP_SUCCESS;
    char *strValue = NULL;
    UINT l_interworking_RFC, l_passpoint_RFC;
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
    bool wifi_radius_greylist_status;
#endif
    bool rfc;
    char recName[256] = {0x0};

    memset(recName, 0, sizeof(recName));

    //Fetch RFC values for Interworking and Passpoint
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-Interworking.Enable", NULL, &strValue);
    if ((retPsmGet == CCSP_SUCCESS) && (strValue)){
        l_interworking_RFC = _ansc_atoi(strValue);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }
    else
    {
        /* Set default value */
	l_interworking_RFC = 0;
    }
    set_wifi_rfc_parameters(RFC_WIFI_INTERWORKING_STATUS, &l_interworking_RFC);

    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-Passpoint.Enable", NULL, &strValue);
    if ((retPsmGet == CCSP_SUCCESS) && (strValue)){
        l_passpoint_RFC = _ansc_atoi(strValue);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }
    else
    {
        /* Set default value */
	l_passpoint_RFC = 0;
    }

    set_wifi_rfc_parameters(RFC_WIFI_PASSPOINT_STATUS, &l_passpoint_RFC);


#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
    CosaDmlWiFiGetEnableRadiusGreylist((BOOLEAN *)&wifi_radius_greylist_status);
    set_wifi_rfc_parameters(RFC_WIFI_RADIUS_GREYLIST_STATUS, &wifi_radius_greylist_status);
#endif

    memset(recName, 0, sizeof(recName));
    sprintf(recName, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WifiClient.ActiveMeasurements.Enable");
    if (PSM_Get_Record_Value2(bus_handle,g_Subsystem, recName, NULL, &strValue) != CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL,"%s : fetching the PSM db failed for ActiveMsmt RFC\n", __func__);
	/* Set default value */
        rfc = 0;
    }
    else
    {
        rfc = atoi(strValue); 
    }
    set_wifi_rfc_parameters(RFC_WIFI_CLIENT_ACTIVE_MEASUREMENTS, &rfc);

#if !defined(_HUB4_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_)
    memset(recName, 0, sizeof(recName));
    sprintf(recName, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EasyConnect.Enable");

    if(PSM_Get_Record_Value2(bus_handle,g_Subsystem, recName, NULL, &strValue) != CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL,"%s: fail to get PSM record for RFC EasyConnect\n",__func__);
	/* Set Deafult value */
        rfc = 1;
    }
    else
    {
        rfc = atoi(strValue);
    }
    set_wifi_rfc_parameters(RFC_WIFI_EASY_CONNECT, &rfc);
#endif
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaWifiInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa wifi object and return handle.

    argument:	ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaWifiInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_WIFI            pMyObject           = (PCOSA_DATAMODEL_WIFI)hThisObject;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoCOSA     = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoWifi     = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    /*PPOAM_COSAWIFIDM_OBJECT*/ANSC_HANDLE         pPoamWiFiDm         = (/*PPOAM_COSAWIFIDM_OBJECT*/ANSC_HANDLE  )NULL;
    /*PSLAP_COSAWIFIDM_OBJECT*/ANSC_HANDLE         pSlapWifiDm         = (/*PSLAP_COSAWIFIDM_OBJECT*/ANSC_HANDLE  )NULL;
    webconfig_dml_t *webconfig_dml;

    CcspWifiTrace(("RDK_LOG_WARN, RDKB_SYSTEM_BOOT_UP_LOG : CosaWifiInitialize - WiFi initialize. \n"));

    pMyObject->hPoamWiFiDm = (ANSC_HANDLE)pPoamWiFiDm;
    pMyObject->hSlapWiFiDm = (ANSC_HANDLE)pSlapWifiDm;

    /* Initiation all functions */
    
    /*Read configuration*/
    pMyObject->hIrepFolderCOSA = g_GetRegistryRootFolder(g_pDslhDmlAgent);
    pPoamIrepFoCOSA = (PPOAM_IREP_FOLDER_OBJECT)pMyObject->hIrepFolderCOSA;

    if ( !pPoamIrepFoCOSA )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        CcspTraceWarning(("CosaWifiInitialize - hIrepFolderCOSA failed\n"));

        goto  EXIT;
    }
    
    /*Get Wifi entry*/
    pPoamIrepFoWifi = 
        (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoCOSA->GetFolder
            (
                (ANSC_HANDLE)pPoamIrepFoCOSA,
                COSA_IREP_FOLDER_NAME_WIFI
            );

    if ( !pPoamIrepFoWifi )
    {
        pPoamIrepFoWifi =
            pPoamIrepFoCOSA->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoCOSA,
                    COSA_IREP_FOLDER_NAME_WIFI,
                    0
                );
    }

    if ( !pPoamIrepFoWifi )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        CcspTraceWarning(("CosaWifiInitialize - pPoamIrepFoWifi failed\n"));

        goto  EXIT;
    }
    else
    {
        pMyObject->hIrepFolderWifi = (ANSC_HANDLE)pPoamIrepFoWifi;
    }

    #if defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_)
    v_secure_system("touch /tmp/wifi_dml_complete");
    v_secure_system("uptime > /tmp/wifi_dml_complete");
    #endif

    webconfig_dml = (webconfig_dml_t *)get_webconfig_dml(); 
    if(webconfig_dml == NULL){
        wifi_util_dbg_print(WIFI_DMCLI, "%s: get_webconfig_dml return NULLL pointer\n", __FUNCTION__);
        return -1;
    }

    if (init(webconfig_dml) != 0) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s: Failed to init\n", __FUNCTION__);
        return -1;
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s: DML cahce %s\n", __FUNCTION__,webconfig_dml->radios[0].vaps.vap_map.vap_array[0].u.bss_info.ssid);
    CcspWifiTrace(("RDK_LOG_WARN, RDKB_SYSTEM_BOOT_UP_LOG : CosaWifiInitialize - WiFi initialization complete. \n"));
    t2_event_d("WIFI_INFO_CosaWifiinit",1);

#ifdef FEATURE_SUPPORT_WIFIDB
    CosaDmlWiFiGetDataFromPSM();
    CosaDmlWiFiGetExternalDataFromPSM();
    CosaDmlWiFiGetRFCDataFromPSM();
#endif//ONE_WIFI

EXIT:
        CcspTraceWarning(("CosaWifiInitialize - returnStatus %ld\n", returnStatus));

#ifdef FEATURE_SUPPORT_WIFIDB
        set_dml_init_status(true);
#endif//ONE_WIFI

	return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaWifiRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa wifi object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/
ANSC_STATUS
CosaWifiRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_WIFI            pMyObject    = (PCOSA_DATAMODEL_WIFI)hThisObject;

    /* Remove Poam or Slap resounce */
    if(!pMyObject)
        return returnStatus;

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

        return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        CosaWifiRegGetSsidInfo
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve Dslm policy parameters.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDdnsInfo
                Specifies the Dslm policy parameters to be filled.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
CosaWifiRegGetSsidInfo
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        CosaWifiRegAddSsidInfo
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hCosaContext
            );

    description:

        This function is called to configure Dslm policy parameters.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDdnsInfo
                Specifies the Dslm policy parameters to be filled.

    return:     status of operation.

**********************************************************************/
ANSC_STATUS
CosaWifiRegAddSsidInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    )
{
    ANSC_STATUS                     returnStatus         = ANSC_STATUS_SUCCESS;

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        CosaWifiRegDelSsidInfo
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hCosaContext
            );

    description:

        This function is called to configure Dslm policy parameters.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDdnsInfo
                Specifies the Dslm policy parameters to be filled.

    return:     status of operation.

**********************************************************************/
ANSC_STATUS
CosaWifiRegDelSsidInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                     returnStatus         = ANSC_STATUS_SUCCESS;
    
    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        CosaWifiRegGetAPInfo
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve Dslm policy parameters.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDdnsInfo
                Specifies the Dslm policy parameters to be filled.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
CosaWifiRegGetAPInfo
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        CosaWifiRegAddAPInfo
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hCosaContext
            );

    description:

        This function is called to configure Dslm policy parameters.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDdnsInfo
                Specifies the Dslm policy parameters to be filled.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
CosaWifiRegAddAPInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    )
{
    ANSC_STATUS                     returnStatus         = ANSC_STATUS_SUCCESS;

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        CosaWifiRegDelAPInfo
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hCosaContext
            );

    description:

        This function is called to configure Dslm policy parameters.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDdnsInfo
                Specifies the Dslm policy parameters to be filled.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
CosaWifiRegDelAPInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return TRUE;
}

ANSC_STATUS
CosaDmlWiFiApMfSetMacList
    (
        CHAR        *maclist,
        UCHAR       *mac,
        ULONG       *numList
    )
{
    int     i = 0;
    char *buf = NULL;
    unsigned char macAddr[COSA_DML_WIFI_MAX_MAC_FILTER_NUM][6];

    buf = strtok(maclist, ",");
    while(buf != NULL)
    {
        if(CosaUtilStringToHex(buf, macAddr[i], 6) != ANSC_STATUS_SUCCESS)
        {
            *numList = 0;
            return ANSC_STATUS_FAILURE;
        }
        i++;
        buf = strtok(NULL, ",");
    }
    *numList = i;
    memcpy(mac, macAddr, 6*i);
    
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlWiFiApMfGetMacList
    (
        UCHAR       *mac,
        CHAR        *maclist,
        ULONG       numList
    )
{
    unsigned int i = 0;
    int     j = 0;
    char macAddr[COSA_DML_WIFI_MAX_MAC_FILTER_NUM][18];

    for(i = 0; i<numList; i++) {
        if(i > 0)
            strcat(maclist, ",");
        sprintf(macAddr[i], "%02x:%02x:%02x:%02x:%02x:%02x", mac[j], mac[j+1], mac[j+2], mac[j+3], mac[j+4], mac[j+5]);
        strcat(maclist, macAddr[i]);
        j +=6;
    }
    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
CosaWifiRegGetMacFiltInfo
    (
        ANSC_HANDLE                 hThisObject
    )
{

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
CosaWifiRegDelMacFiltInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                     returnStatus         = ANSC_STATUS_SUCCESS;
    
    return returnStatus;
}
