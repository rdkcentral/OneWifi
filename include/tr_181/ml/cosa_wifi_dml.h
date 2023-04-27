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

    module: cosa_wifi_dml.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/18/2011    initial revision.

**************************************************************************/


#ifndef  _COSA_WIFI_DML_H
#define  _COSA_WIFI_DML_H

/***********************************************************************

 APIs for Object:

    WiFi.

    *  WiFi_GetParamBoolValue
    *  WiFi_GetParamIntValue
    *  WiFi_GetParamUlongValue
    *  WiFi_GetParamStringValue

***********************************************************************/
BOOL
WiFi_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
WiFi_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
WiFi_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
WiFi_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
WiFi_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

BOOL
WiFi_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    );

BOOL
WiFi_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

ANSC_STATUS CosaDmlWiFi_CheckAndConfigureMFPConfig( BOOLEAN bFeatureMFPConfig );

/***********************************************************************

 APIs for Object:

    WiFi.X_RDK_CSI.{i}.

    *  CSI_GetEntryCount
    *  CSI_GetEntry
    *  CSI_AddEntry
    *  CSI_DelEntry
    *  CSI_GetParamBoolValue
    *  CSI_GetParamStringValue
    *  CSI_SetParamBoolValue
    *  CSI_SetParamStringValue
    *  CSI_Validate
    *  CSI_Commit
    *  CSI_Rollback

***********************************************************************/
ULONG
CSI_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
CSI_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ANSC_HANDLE
CSI_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    );

ULONG
CSI_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    );

BOOL
CSI_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

ULONG
CSI_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
CSI_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
CSI_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
CSI_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
CSI_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
CSI_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.

    *  WiFiRegion_GetParamStringValue
    *  WiFiRegion_SetParamStringValue

***********************************************************************/

ULONG
WiFiRegion_GetParamStringValue

	(
		ANSC_HANDLE 				hInsContext,
		char*						ParamName,
		char*						pValue,
		ULONG*						pulSize
	);

BOOL
WiFiRegion_SetParamStringValue


    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );


/***********************************************************************

 APIs for Object:

    WiFi.Radio.{i}.

    *  Radio_GetEntryCount
    *  Radio_GetEntry
    *  Radio_GetParamBoolValue
    *  Radio_GetParamIntValue
    *  Radio_GetParamUlongValue
    *  Radio_GetParamStringValue
    *  Radio_SetParamBoolValue
    *  Radio_SetParamIntValue
    *  Radio_SetParamUlongValue
    *  Radio_SetParamStringValue
    *  Radio_Validate
    *  Radio_Commit
    *  Radio_Rollback

***********************************************************************/
ULONG
Radio_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
Radio_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

BOOL
Radio_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
Radio_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
Radio_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
Radio_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
Radio_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
Radio_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
Radio_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
Radio_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
Radio_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
Radio_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
Radio_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.Radio.{i}.Stats.

    *  Stats3_GetParamBoolValue
    *  Stats3_GetParamIntValue
    *  Stats3_GetParamUlongValue
    *  Stats3_GetParamStringValue

***********************************************************************/
BOOL
Stats3_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    );
/***********************************************************************

 APIs for Object:

    WiFi.Radio.{i}.Stats.

    *  Stats3_GetParamBoolValue
    *  Stats3_GetParamIntValue
    *  Stats3_GetParamUlongValue
    *  Stats3_GetParamStringValue

***********************************************************************/
BOOL
Stats3_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
Stats3_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
Stats3_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
Stats3_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

ULONG
ReceivedSignalLevel_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );
ANSC_HANDLE
ReceivedSignalLevel_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );
BOOL
ReceivedSignalLevel_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );
BOOL
ReceivedSignalLevel_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );
ULONG
ReceivedSignalLevel_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

 WiFi.X_RDKCENTRAL-COM_BandSteering.

    *  BandSteering_GetParamBoolValue
    *  BandSteering_SetParamBoolValue
    *  BandSteering_GetParamStringValue
    *  BandSteering_SetParamStringValue
    *  BandSteering_Validate
    *  BandSteering_Commit
    *  BandSteering_Rollback

***********************************************************************/
BOOL
BandSteering_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
BandSteering_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

ULONG
BandSteering_GetParamStringValue
	(
		ANSC_HANDLE 				hInsContext,
		char*						ParamName,
		char*						pValue,
		ULONG*						pUlSize
	);

BOOL
BandSteering_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
BandSteering_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
BandSteering_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
BandSteering_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

	WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.

	*  BandSetting_GetEntryCount
	*  BandSetting_GetEntry
	*  BandSetting_GetParamIntValue
	*  BandSetting_SetParamIntValue
	*  BandSteering_Validate
	*  BandSteering_Commit
	*  BandSteering_Rollback

***********************************************************************/
ULONG
BandSetting_GetEntryCount
	(
		ANSC_HANDLE 				hInsContext
	);

ANSC_HANDLE
BandSetting_GetEntry
	(
		ANSC_HANDLE 				hInsContext,
		ULONG						nIndex,
		ULONG*						pInsNumber
	);

BOOL
BandSetting_GetParamIntValue
	(
		ANSC_HANDLE 				hInsContext,
		char*						ParamName,
		int*						pInt
	);

BOOL
BandSetting_SetParamIntValue
	(
		ANSC_HANDLE 				hInsContext,
		char*						ParamName,
		int 						iValue
	);

BOOL
BandSetting_Validate
	(
		ANSC_HANDLE 				hInsContext,
		char*						pReturnParamName,
		ULONG*						puLength
	);

ULONG
BandSetting_Commit
	(
		ANSC_HANDLE 				hInsContext
	);

ULONG
BandSetting_Rollback
	(
		ANSC_HANDLE 				hInsContext
	);

/***********************************************************************

 APIs for Object:

    WiFi.SSID.{i}.

    *  SSID_GetEntryCount
    *  SSID_GetEntry
    *  SSID_AddEntry
    *  SSID_DelEntry
    *  SSID_GetParamBoolValue
    *  SSID_GetParamIntValue
    *  SSID_GetParamUlongValue
    *  SSID_GetParamStringValue
    *  SSID_SetParamBoolValue
    *  SSID_SetParamIntValue
    *  SSID_SetParamUlongValue
    *  SSID_SetParamStringValue
    *  SSID_Validate
    *  SSID_Commit
    *  SSID_Rollback

***********************************************************************/
ULONG
SSID_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
SSID_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ANSC_HANDLE
SSID_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    );

ULONG
SSID_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    );

BOOL
SSID_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
SSID_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
SSID_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
SSID_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
SSID_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
SSID_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
SSID_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
SSID_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
SSID_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
SSID_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
SSID_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.SSID.{i}.Stats.

    *  Stats4_GetParamBoolValue
    *  Stats4_GetParamIntValue
    *  Stats4_GetParamUlongValue
    *  Stats4_GetParamStringValue

***********************************************************************/
BOOL
Stats4_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
Stats4_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
Stats4_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
Stats4_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.

    *  AccessPoint_GetEntryCount
    *  AccessPoint_GetEntry
    *  AccessPoint_AddEntry
    *  AccessPoint_DelEntry
    *  AccessPoint_GetParamBoolValue
    *  AccessPoint_GetParamIntValue
    *  AccessPoint_GetParamUlongValue
    *  AccessPoint_GetParamStringValue
    *  AccessPoint_SetParamBoolValue
    *  AccessPoint_SetParamIntValue
    *  AccessPoint_SetParamUlongValue
    *  AccessPoint_SetParamStringValue
    *  AccessPoint_Validate
    *  AccessPoint_Commit
    *  AccessPoint_Rollback

***********************************************************************/
ULONG
AccessPoint_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
AccessPoint_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ANSC_HANDLE
AccessPoint_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    );

ULONG
AccessPoint_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    );

BOOL
AccessPoint_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
AccessPoint_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
AccessPoint_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
AccessPoint_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
AccessPoint_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
AccessPoint_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
AccessPoint_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
AccessPoint_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
AccessPoint_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
AccessPoint_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
AccessPoint_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.Security.

    *  Security_GetParamBoolValue
    *  Security_GetParamIntValue
    *  Security_GetParamUlongValue
    *  Security_GetParamStringValue
    *  Security_SetParamBoolValue
    *  Security_SetParamIntValue
    *  Security_SetParamUlongValue
    *  Security_SetParamStringValue
    *  Security_Validate
    *  Security_Commit
    *  Security_Rollback

***********************************************************************/
BOOL
Security_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
Security_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
Security_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
Security_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
Security_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
Security_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
Security_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
Security_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
Security_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
Security_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
Security_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.ConnectionControl.

    *  ConnectionControl_GetParamBoolValue
    *  ConnectionControl_GetParamIntValue
    *  ConnectionControl_GetParamUlongValue
    *  ConnectionControl_GetParamStringValue
    *  ConnectionControl_SetParamBoolValue
    *  ConnectionControl_SetParamIntValue
    *  ConnectionControl_SetParamUlongValue
    *  ConnectionControl_SetParamStringValue
    *  ConnectionControl_Validate
    *  ConnectionControl_Commit
    *  ConnectionControl_Rollback

***********************************************************************/
BOOL
ConnectionControl_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
ConnectionControl_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
ConnectionControl_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
ConnectionControl_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
ConnectionControl_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
ConnectionControl_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
ConnectionControl_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
ConnectionControl_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
ConnectionControl_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
ConnectionControl_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
ConnectionControl_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.ConnectionControl.PreAssocDeny

    *  PreAssocDeny_GetParamBoolValue
    *  PreAssocDeny_GetParamIntValue
    *  PreAssocDeny_GetParamUlongValue
    *  PreAssocDeny_GetParamStringValue
    *  PreAssocDeny_SetParamBoolValue
    *  PreAssocDeny_SetParamIntValue
    *  PreAssocDeny_SetParamUlongValue
    *  PreAssocDeny_SetParamStringValue
    *  PreAssocDeny_Validate
    *  PreAssocDeny_Commit
    *  PreAssocDeny_Rollback

***********************************************************************/
BOOL
PreAssocDeny_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
PreAssocDeny_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
PreAssocDeny_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
PreAssocDeny_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
PreAssocDeny_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
PreAssocDeny_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
PreAssocDeny_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
PreAssocDeny_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
PreAssocDeny_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
PreAssocDeny_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
PreAssocDeny_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.ConnectionControl.PostAssocDisc

    *  PostAssocDisc_GetParamBoolValue
    *  PostAssocDisc_GetParamIntValue
    *  PostAssocDisc_GetParamUlongValue
    *  PostAssocDisc_GetParamStringValue
    *  PostAssocDisc_SetParamBoolValue
    *  PostAssocDisc_SetParamIntValue
    *  PostAssocDisc_SetParamUlongValue
    *  PostAssocDisc_SetParamStringValue
    *  PostAssocDisc_Validate
    *  PostAssocDisc_Commit
    *  PostAssocDisc_Rollback

***********************************************************************/
BOOL
PostAssocDisc_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
PostAssocDisc_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
PostAssocDisc_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
PostAssocDisc_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
PostAssocDisc_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
PostAssocDisc_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
PostAssocDisc_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
PostAssocDisc_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
PostAssocDisc_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
PostAssocDisc_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
PostAssocDisc_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.WPS.

    *  WPS_GetParamBoolValue
    *  WPS_GetParamIntValue
    *  WPS_GetParamUlongValue
    *  WPS_GetParamStringValue
    *  WPS_SetParamBoolValue
    *  WPS_SetParamIntValue
    *  WPS_SetParamUlongValue
    *  WPS_SetParamStringValue
    *  WPS_Validate
    *  WPS_Commit
    *  WPS_Rollback

***********************************************************************/
BOOL
WPS_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
WPS_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
WPS_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
WPS_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
WPS_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
WPS_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
WPS_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
WPS_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
WPS_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
WPS_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
WPS_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );


/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.X_CISCO_COM_MACFilter.

    *  MacFilter_GetParamBoolValue
    *  MacFilter_GetParamIntValue
    *  MacFilter_GetParamUlongValue
    *  MacFilter_GetParamStringValue
    *  MacFilter_SetParamBoolValue
    *  MacFilter_SetParamIntValue
    *  MacFilter_SetParamUlongValue
    *  MacFilter_SetParamStringValue
    *  MacFilter_Validate
    *  MacFilter_Commit
    *  MacFilter_Rollback

***********************************************************************/
BOOL
MacFilter_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
MacFilter_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
MacFilter_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
MacFilter_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
MacFilter_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
MacFilter_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
MacFilter_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
MacFilter_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
MacFilter_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
MacFilter_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
MacFilter_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );



/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.Associated{i}.

    *  AssociatedDevice1_GetEntryCount
    *  AssociatedDevice1_GetEntry
    *  AssociatedDevice1_IsUpdated
    *  AssociatedDevice1_Synchronize
    *  AssociatedDevice1_GetParamBoolValue
    *  AssociatedDevice1_GetParamIntValue
    *  AssociatedDevice1_GetParamUlongValue
    *  AssociatedDevice1_GetParamStringValue

***********************************************************************/
ULONG
AssociatedDevice1_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
AssociatedDevice1_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

BOOL
AssociatedDevice1_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
AssociatedDevice1_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
AssociatedDevice1_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
AssociatedDevice1_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
AssociatedDevice1_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
AssociatedDevice1_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.

    *  Stats_GetParamUlongValue

***********************************************************************/

BOOL
Stats_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pULong
    );

BOOL
Stats_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

ULONG
WEPKey64Bit_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
WEPKey64Bit_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ULONG
WEPKey64Bit_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
WEPKey64Bit_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

BOOL
WEPKey64Bit_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
WEPKey64Bit_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
WEPKey64Bit_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
WEPKey128Bit_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
WEPKey128Bit_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ULONG
WEPKey128Bit_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
WEPKey128Bit_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

BOOL
WEPKey128Bit_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
WEPKey128Bit_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
WEPKey128Bit_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
RadiusSettings_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
RadiusSettings_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );
BOOL
RadiusSettings_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
RadiusSettings_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );
BOOL
RadiusSettings_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
RadiusSettings_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
Authenticator_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

BOOL
Authenticator_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );

BOOL
Authenticator_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
Authenticator_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
MacFiltTab_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
MacFiltTab_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ANSC_HANDLE
MacFiltTab_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    );

ULONG
MacFiltTab_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    );

ULONG
MacFiltTab_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
MacFiltTab_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

BOOL
MacFiltTab_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
MacFiltTab_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
MacFilterTab_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
NeighboringWiFiDiagnostic_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

ULONG
NeighboringWiFiDiagnostic_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
NeighboringWiFiDiagnostic_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
NeighboringWiFiDiagnostic_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );


BOOL
NeighboringWiFiDiagnostic_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );
ULONG
NeighboringWiFiDiagnostic_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
NeighboringWiFiDiagnostic_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
NeighboringScanResult_GetEntryCount
    (
        ANSC_HANDLE                 
    );

ANSC_HANDLE
NeighboringScanResult_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );
BOOL
NeighboringScanResult_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );


BOOL
NeighboringScanResult_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
NeighboringScanResult_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

ULONG
NeighboringScanResult_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

 /***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_ATM

    *  ATM_GetParamBoolValue
	*  ATM_SetParamBoolValue
	
***********************************************************************/
BOOL
ATM_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );
	

BOOL
ATM_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
ATM_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
ATM_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
ATM_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_ATM.APGroup.{i}.

    *  APGroup_GetEntryCount
    *  APGroup_GetEntry
    *  APGroup_GetParamUlongValue
    *  APGroup_GetParamStringValue
    *  APGroup_Validate
    *  APGroup_Commit
    *  APGroup_Rollback

***********************************************************************/
ULONG
APGroup_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );
	
ANSC_HANDLE
APGroup_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ULONG
APGroup_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
APGroup_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );
BOOL
APGroup_SetParamUlongValue (
	ANSC_HANDLE                 hInsContext,
	char*                       ParamName,
	ULONG                       uValue
);

BOOL
APGroup_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
APGroup_Commit
    (
        ANSC_HANDLE                 hInsContext
    );
	
ULONG
APGroup_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_ATM.APGroup.{i}.Sta.{j}.

    *  Sta_GetEntryCount
    *  Sta_GetEntry
    *  Sta_AddEntry
    *  Sta_DelEntry
    *  Sta_GetParamUlongValue
    *  Sta_GetParamStringValue
    *  Sta_SetParamUlongValue
    *  Sta_SetParamStringValue
    *  Sta_Validate
    *  Sta_Commit
    *  Sta_Rollback

***********************************************************************/

ULONG
Sta_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );
	
ANSC_HANDLE
Sta_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ANSC_HANDLE
Sta_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    );
	
ULONG
Sta_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    );

ULONG
Sta_GetParamStringValue
	(
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
Sta_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

BOOL
Sta_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

BOOL
Sta_SetParamUlongValue
	(
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );


BOOL
Sta_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );
	
ULONG
Sta_Commit
    (
        ANSC_HANDLE                 hInsContext
    );
	
ULONG
Sta_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL 
InterworkingElement_Validate
    (
        ANSC_HANDLE hInsContext, 
        char *pReturnParamName, 
        ULONG *puLength
    );


#endif
