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
#include "safec_lib_common.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_dml.h"
#include "cosa_wifi_internal.h"
#include "plugin_main_apis.h"
#include "ccsp_WifiLog_wrapper.h"
#include "ccsp_psm_helper.h"
#include "cosa_dbus_api.h"
#include "collection.h"
#include "wifi_hal.h"
#include "../../../stubs/wifi_stubs.h"
#include "wifi_monitor.h"

#if defined (FEATURE_SUPPORT_WEBCONFIG)
//#include "../sbapi/wifi_webconfig.h"
#include "wifi_webconfig_old.h"
#include "wifi_webconfig.h"//ONE_WIFI
#endif

#if defined(_COSA_BCM_MIPS_) || defined(_XB6_PRODUCT_REQ_) || defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_XER5_PRODUCT_REQ_)  || defined(_SCER11BEL_PRODUCT_REQ_)
#include "ccsp_base_api.h"
#include "messagebus_interface_helper.h"

extern ULONG g_currentBsUpdate;
#endif
# define INTEROP_MIN_STA 0
# define INTEROP_MAX_STA 32
extern bool is_radio_config_changed;
static int radio_reset_count;
ULONG last_vap_change;
ULONG last_radio_change;
extern bool g_update_wifi_region;

#include "wifi_passpoint.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "dml_onewifi_api.h"
extern unsigned int startTime[MAX_NUM_RADIOS];
# define WEPKEY_TYPE_SET 3
# define KEYPASSPHRASE_SET 2
# define MFPCONFIG_OPTIONS_SET 3
#define TCM_EXP_WEIGHTAGE "0.6"
#define TCM_GRADIENT_THRESHOLD "0.18"
uint8_t g_radio_instance_num = 0;
extern void* g_pDslhDmlAgent;
extern int gChannelSwitchingCount;
extern bool wifi_api_is_device_associated(int ap_index, char *mac);

/***********************************************************************
 IMPORTANT NOTE:

 According to TR69 spec:
 On successful receipt of a SetParameterValues RPC, the CPE MUST apply 
 the changes to all of the specified Parameters atomically. That is, either 
 all of the value changes are applied together, or none of the changes are 
 applied at all. In the latter case, the CPE MUST return a fault response 
 indicating the reason for the failure to apply the changes. 
 
 The CPE MUST NOT apply any of the specified changes without applying all 
 of them.

 In order to set parameter values correctly, the back-end is required to
 hold the updated values until "Validate" and "Commit" are called. Only after
 all the "Validate" passed in different objects, the "Commit" will be called.
 Otherwise, "Rollback" will be called instead.

 The sequence in COSA Data Model will be:

 SetParamBoolValue/SetParamIntValue/SetParamUlongValue/SetParamStringValue
 -- Backup the updated values;

 if( Validate_XXX())
 {
     Commit_XXX();    -- Commit the update all together in the same object
 }
 else
 {
     Rollback_XXX();  -- Remove the update at backup;
 }
 
***********************************************************************/

static BOOL isHotspotSSIDIpdated = FALSE;
BOOL IsValidMacAddress(char *mac);
ULONG InterworkingElement_Commit(ANSC_HANDLE hInsContext);
void *Wifi_Hosts_Sync_Func(void *pt, int index, wifi_associated_dev_t *associated_dev, BOOL bCallForFullSync, BOOL bCallFromDisConnCB);
int EVP_DecodeBlock(unsigned char*, unsigned char*, int);
int d2i_EC_PUBKEY(void **a, const unsigned char **key, long length);

static BOOL IsSsidHotspot(ULONG ins)
{
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(ins-1);
    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info \n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    return (BOOL) vapInfo->u.bss_info.bssHotspot;
}

static inline bool is_open_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_none ||
        mode == wifi_security_mode_enhanced_open;
}

static inline bool is_personal_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_wpa_personal ||
        mode == wifi_security_mode_wpa2_personal ||
        mode == wifi_security_mode_wpa_wpa2_personal ||
        mode == wifi_security_mode_wpa3_personal ||
        mode == wifi_security_mode_wpa3_transition ||
        mode == wifi_security_mode_wpa3_compatibility;
}

static inline bool is_enterprise_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_wpa_enterprise ||
        mode == wifi_security_mode_wpa2_enterprise ||
        mode == wifi_security_mode_wpa_wpa2_enterprise ||
        mode == wifi_security_mode_wpa3_enterprise;
}

/***********************************************************************

 APIs for Object:

    WiFi.

    *  WiFi_GetParamBoolValue
    *  WiFi_GetParamIntValue
    *  WiFi_GetParamUlongValue
    *  WiFi_GetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WiFi_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
 
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WiFi_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    FILE *fp;
    char path[32] = {0};
    int val =0 ;
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_dml_wifi_global_param();

    if(pcfg== NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    if (AnscEqualString(ParamName, "ApplyRadioSettings", TRUE))
    {
        /* always return false when get */
        *pBool = FALSE;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "ApplyAccessPointSettings", TRUE))
    {
        /* always return false when get */
        *pBool = FALSE;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_FactoryReset", TRUE))
    {
        /* always return false when get */
        *pBool = FALSE;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_EnableTelnet", TRUE))
    {
	    return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_ResetRadios", TRUE))
    {
        /* always return false when get */
        *pBool = FALSE;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_WiFiHost_Sync", TRUE))
    {
	
        *pBool = FALSE;
        return TRUE;
    }


    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_PreferPrivate", TRUE))
    {
        *pBool = pcfg->prefer_private;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_RapidReconnectIndicationEnable", TRUE))
    {
        *pBool = pcfg->rapid_reconnect_enable;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_vAPStatsEnable", TRUE))
    {
        *pBool = pcfg->vap_stats_feature;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "FeatureMFPConfig", TRUE))
    {
        *pBool = pcfg->mfp_config_feature;
         return TRUE;
    }

    if (AnscEqualString(ParamName, "TxOverflowSelfheal", TRUE))
    {
        *pBool = pcfg->tx_overflow_selfheal;
         return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDK-CENTRAL_COM_ForceDisable", TRUE))
    {
        *pBool = pcfg->force_disable_radio_feature;
         return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_EnableRadiusGreyList", TRUE))
    {
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
        *pBool = rfc_pcfg->radiusgreylist_rfc;
#else
        *pBool = FALSE;
#endif
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_EnableHostapdAuthenticator", TRUE))
    {
        return TRUE;
    }

    if (AnscEqualString(ParamName, "DFSatBootUp", TRUE))
    {
        *pBool = rfc_pcfg->dfsatbootup_rfc;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "2G80211axEnable", TRUE))
    {
        *pBool = rfc_pcfg->twoG80211axEnable_rfc;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Levl", TRUE))
    {
        *pBool = rfc_pcfg->levl_enabled_rfc;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "DFS", TRUE))
    {
        *pBool = rfc_pcfg->dfs_rfc;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WPA3_Personal_Transition", TRUE))
    {
        *pBool = rfc_pcfg->wpa3_rfc;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WiFi-Passpoint", TRUE))
    {
        *pBool = rfc_pcfg->wifipasspoint_rfc;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WiFi-OffChannelScan-APP", TRUE)) {
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
        *pBool = rfc_pcfg->wifi_offchannelscan_app_rfc;
#else //FEATURE_OFF_CHANNEL_SCAN_5G
        *pBool = FALSE;
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WiFi-OffChannelScan", TRUE))
    {
        *pBool = rfc_pcfg->wifi_offchannelscan_sm_rfc;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_MemwrapTool_RFC", TRUE))
    {
        *pBool = rfc_pcfg->memwraptool_app_rfc;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WiFi-Interworking", TRUE))
    {
        *pBool = rfc_pcfg->wifiinterworking_rfc;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Log_Upload", TRUE))
    {
        fp = popen("crontab -l | grep -c copy_wifi_logs.sh","r");
        while(fgets(path,sizeof(path) , fp) != NULL) {
            val = atoi(path);
            if(val == 1) {
                *pBool = TRUE;
            }
            else  {
                *pBool = FALSE;
            }
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload got %s and val=%d\n", __FUNCTION__,__LINE__,path,val);
        }
        pclose(fp);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "WiFiStuckDetect", TRUE))
    {
        if ((access(WIFI_STUCK_DETECT_FILE_NAME, R_OK)) != 0) {
            *pBool = FALSE;
        } else {
            *pBool = TRUE;
        }
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Tcm", TRUE))
    {
        *pBool = rfc_pcfg->tcm_enabled_rfc;
        return TRUE;
    }
 
    if(AnscEqualString(ParamName, "WPA3_Personal_Compatibility", TRUE))
    {
        *pBool = rfc_pcfg->wpa3_compatibility_enable;
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WiFi_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WiFi_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_dml_wifi_global_param();

    if (pcfg== NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_GoodRssiThreshold", TRUE))
    {
        /* collect value */
        *pInt = pcfg->good_rssi_threshold;
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AssocCountThreshold", TRUE))
    {
        /* collect value */
        *pInt = pcfg->assoc_count_threshold;
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AssocMonitorDuration", TRUE))
    {
        /* collect value */
        *pInt = pcfg->assoc_monitor_duration;
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AssocGateTime", TRUE))
    {
        /* collect value */
        *pInt = pcfg->assoc_gate_time;
        return TRUE;
    }
     /* check the parameter name and return the corresponding value */
    if (AnscEqualString(ParamName, "WHIX_LogInterval", TRUE))
    {
        /* collect value */
        *pInt = pcfg->whix_log_interval; //seconds
        return TRUE;
    }

    if (AnscEqualString(ParamName, "WHIX_ChUtility_LogInterval", TRUE))
    {
        /* collect value */
        *pInt = pcfg->whix_chutility_loginterval; //seconds
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WiFi_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WiFi_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        UINT numOfRadios = get_num_radio_dml();
        *puLong = numOfRadios;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        WiFi_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
WiFi_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    errno_t  rc  = -1;
    UNREFERENCED_PARAMETER(hInsContext);
    if (!ParamName || !pValue || !pUlSize || *pUlSize < 1)
        return -1;

    dml_global_default *gcfg = (dml_global_default *) get_global_default_obj();
    if(gcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_RadioPower", TRUE))
    {
        snprintf(pValue,*pUlSize,"%s",gcfg->RadioPower);
        return 0;
    }

    if( AnscEqualString(ParamName, "X_RDK_RadioData", TRUE))
    {
	CosaDmlWiFi_getWebConfig();
        return 0;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_ConfigFileBase64", TRUE))
    {
        return 0;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_GASConfiguration", TRUE))
    {
	WiFi_GetGasConfig(pValue);
        return 0;
    }
    if (AnscEqualString(ParamName, "Log_Enable", TRUE))
    {
        char dest[512] = {0};
        if(access("/nvram/wifiDbDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiDbDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiDbDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiMgrDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiMgrDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiMgrDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiCtrlDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiCtrlDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiCtrlDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiLib",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiLib");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiLib");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiWebConfigDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiWebConfigDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiWebConfigDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiPasspointDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiPasspointDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiPasspointDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiDppDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiDppDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiDppDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiMonDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiMonDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiMonDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiDMCLI",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiDMCLI");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiDMCLI");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiPsm",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiPsm");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiPsm");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiLibhostapDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiLibhostapDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiLibhostapDbg");
                ERR_CHK(rc);
           }
        }
        if(access("/nvram/wifiHalDbg",F_OK) == 0)
        {
            if (AnscSizeOfString(dest)!= 0) {
                rc = strcat_s(dest,sizeof(dest),",wifiHalDbg");
                ERR_CHK(rc);
            }
            else {
                rc = strcat_s(dest,sizeof(dest),"wifiHalDbg");
                ERR_CHK(rc);
           }
        }
        if ( AnscSizeOfString(dest) < *pUlSize) {
            AnscCopyString(pValue, dest);
            return 0;
        }
        else {
            *pUlSize = AnscSizeOfString(dest)+1;
            return 1;
        }
    }  
    return 0;
}

BOOL
WiFi_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    if ( rfc_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get RFC Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_radio_operationParam_t *wifiRadioOperParam = NULL;
    if (AnscEqualString(ParamName, "ApplyRadioSettings", TRUE ))
    {
        if (bValue == TRUE){
	    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings push to queue \n",__func__, __LINE__);
            if (push_radio_dml_cache_to_one_wifidb() == RETURN_ERR)
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings failed \n",__func__, __LINE__);
                return FALSE;
            }
            radio_reset_count++;
            last_radio_change = AnscGetTickInSeconds();
            if (g_update_wifi_region)
            {
                push_global_config_dml_cache_to_one_wifidb();
            }
            return TRUE;
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "ApplyAccessPointSettings", TRUE ))
    {
        if (bValue == TRUE){
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyAccessPointSettings push to queue \n",__func__, __LINE__);
            if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR)
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyAccessPointSettings failed \n",__func__, __LINE__);
                return FALSE;
            }
            last_vap_change = AnscGetTickInSeconds();
            return TRUE;
        }
        return TRUE;
    }
    if(AnscEqualString(ParamName, "X_CISCO_COM_FactoryReset", TRUE))
    {
        if (wifi_factory_reset(true) != TRUE)
            return FALSE;
        return TRUE;
	}

    if(AnscEqualString(ParamName, "X_CISCO_COM_EnableTelnet", TRUE))
    {
        if ( CosaDmlWiFi_EnableTelnet(bValue) == ANSC_STATUS_SUCCESS ) {
	}
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_ResetRadios", TRUE)) {
        wifi_util_info_print(WIFI_DMCLI, "%s:%d Restarting Radios & VAPs \n", __func__, __LINE__);
        is_radio_config_changed = TRUE; // Force apply all Radio configuration
        g_update_wifi_region = TRUE; // Force apply all Global configuration

        // Clear the stats, clients data, etc in cosaWifiRadioRestart()
        if (cosaWifiRadioRestart() != ANSC_STATUS_SUCCESS) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cosaWifiRadioRestart failed \n", __func__,
                __LINE__);
            return FALSE;
        }
        // Force apply radio configuration
        if (push_radio_dml_cache_to_one_wifidb() == RETURN_ERR) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d push_radio_dml_cache_to_one_wifidb failed \n",
                __func__, __LINE__);
            return FALSE;
        }
        last_radio_change = AnscGetTickInSeconds();
        // Force apply Global configuration
        if (g_update_wifi_region) {
            if (push_global_config_dml_cache_to_one_wifidb() == RETURN_ERR) {
                wifi_util_error_print(WIFI_DMCLI,
                    "%s:%d push_global_config_dml_cache_to_one_wifidb failed \n", __func__,
                    __LINE__);
                return FALSE;
            }
        }
        // Force apply VAP configuration
        if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d push_vap_dml_cache_to_one_wifidb failed \n",
                __func__, __LINE__);
            return FALSE;
        }
        last_vap_change = AnscGetTickInSeconds();
        wifi_util_info_print(WIFI_DMCLI, "%s:%d Restart Wi-Fi success \n", __func__, __LINE__);
        radio_reset_count++;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_WiFiHost_Sync", TRUE))
    {
        if (push_wifi_host_sync_to_ctrl_queue() == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Failed to push host sync to ctrl queue\n", __func__, __LINE__);
            return FALSE;
        }
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Managed_WiFi_Enabled", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d push_managed_wifi_disable_to_ctrl_queue to ctrl queue\n", __func__, __LINE__);
        if (!bValue) {
            if (push_managed_wifi_disable_to_ctrl_queue() == RETURN_ERR) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Failed to push_managed_wifi_disable_to_ctrl_queue to ctrl queue\n", __func__, __LINE__);
                return FALSE;
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI,"Managed-WIFI cannot be enabled through TR-181\n");
            return FALSE;
        }
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_PreferPrivate", TRUE))
    {
        if(global_wifi_config->global_parameters.prefer_private == bValue)
        {
            return TRUE;
        }
        if (bValue && rfc_pcfg->radiusgreylist_rfc) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RadiussGreyList enabled=%d hence cannot enable preferPrivate \n",__func__, __LINE__,rfc_pcfg->radiusgreylist_rfc);
            return FALSE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:prefer_private=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.prefer_private,bValue);
        global_wifi_config->global_parameters.prefer_private = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        push_prefer_private_ctrl_queue(bValue);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_RapidReconnectIndicationEnable", TRUE))
    {
        if(global_wifi_config->global_parameters.rapid_reconnect_enable == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:rapid_reconnect_enable=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.rapid_reconnect_enable,bValue);
        global_wifi_config->global_parameters.rapid_reconnect_enable = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }
    
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_vAPStatsEnable", TRUE))
    {
        if(global_wifi_config->global_parameters.vap_stats_feature == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:vap_stats_feature=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.vap_stats_feature,bValue);
        global_wifi_config->global_parameters.vap_stats_feature = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }
    if (AnscEqualString(ParamName, "FeatureMFPConfig", TRUE))
    {
        if(global_wifi_config->global_parameters.mfp_config_feature == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:mfp_config_feature=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.mfp_config_feature,bValue);
        global_wifi_config->global_parameters.mfp_config_feature = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }
    
    if (AnscEqualString(ParamName, "TxOverflowSelfheal", TRUE))
    {
        if(global_wifi_config->global_parameters.tx_overflow_selfheal == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:tx_overflow_selfheal=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.tx_overflow_selfheal,bValue);
        global_wifi_config->global_parameters.tx_overflow_selfheal = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDK-CENTRAL_COM_ForceDisable", TRUE))
    {
        if(global_wifi_config->global_parameters.force_disable_radio_feature == bValue)
        {
            return TRUE;
        }
        ULONG instance_number;
        for(instance_number = 0; instance_number < getNumberRadios(); instance_number++)
        {
            wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(instance_number);
            if (wifiRadioOperParam == NULL)
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
                return FALSE;
            }
            if(bValue)
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d WIFI_FORCE_DISABLE_CHANGED_TO_TRUE\n", __FUNCTION__,__LINE__);
                if(wifiRadioOperParam->enable)
                {
                    wifiRadioOperParam->enable = FALSE;
                    is_radio_config_changed = TRUE;
                    if(push_radio_dml_cache_to_one_wifidb() == RETURN_ERR)
                    {
                        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings failed\n", __FUNCTION__,__LINE__);
                        return FALSE;
                    }
                }
            }
            else
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d WIFI_FORCE_DISABLE_CHANGED_TO_FALSE\n", __FUNCTION__,__LINE__);
                wifiRadioOperParam->enable = TRUE;
                is_radio_config_changed = TRUE;
                if(push_radio_dml_cache_to_one_wifidb() == RETURN_ERR)
                {
                     wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings failed\n", __FUNCTION__,__LINE__);
                     return FALSE;
                }
             }
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:force_disable_radio_status=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.force_disable_radio_feature,bValue);
        global_wifi_config->global_parameters.force_disable_radio_feature = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        if(bValue) {
            CcspWifiTrace(("RDK_LOG_WARN, WIFI_FORCE_DISABLE_CHANGED_TO_TRUE\n"));
        }
        else {
            CcspWifiTrace(("RDK_LOG_WARN, WIFI_FORCE_DISABLE_CHANGED_TO_FALSE\n"));
        }
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_EnableRadiusGreyList", TRUE))
    {
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
        if(bValue != rfc_pcfg->radiusgreylist_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_radius_grey_list_rfc);
        }
        if(bValue && global_wifi_config->global_parameters.prefer_private) {
            wifi_util_dbg_print(WIFI_DMCLI,"prefer_private is set to false when radiusgreylist is enabled\n");
            global_wifi_config->global_parameters.prefer_private = false;
            push_global_config_dml_cache_to_one_wifidb();
            push_prefer_private_ctrl_queue(false);
        }
        if (ANSC_STATUS_SUCCESS == CosaDmlWiFiSetEnableRadiusGreylist( bValue ))
        {
            return TRUE;
        }
#endif
        return TRUE;
    }
    
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_EnableHostapdAuthenticator", TRUE))
    {
        return TRUE;
    }

    if (AnscEqualString(ParamName, "DFSatBootUp", TRUE))
    {
        if(bValue != rfc_pcfg->dfsatbootup_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_dfs_atbootup_rfc);
        }
		return TRUE;
    }

    if (AnscEqualString(ParamName, "DFS", TRUE))
    {
        if(bValue != rfc_pcfg->dfs_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_dfs_rfc);
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WPA3_Personal_Transition", TRUE))
    {
        if(bValue != rfc_pcfg->wpa3_rfc){
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_wpa3_rfc);
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WiFi-Passpoint", TRUE))
    {
        if(bValue != rfc_pcfg->wifipasspoint_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_wifi_passpoint_rfc);
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WiFi-OffChannelScan-APP", TRUE)) {
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
        if(bValue != rfc_pcfg->wifi_offchannelscan_app_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue, wifi_event_type_wifi_offchannelscan_app_rfc);
        }
        return TRUE;
#else //FEATURE_OFF_CHANNEL_SCAN_5G
        return FALSE;
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
    }
    if (AnscEqualString(ParamName, "WiFi-OffChannelScan", TRUE)) {
        if(bValue != rfc_pcfg->wifi_offchannelscan_sm_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_wifi_offchannelscan_sm_rfc);
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_MemwrapTool_RFC", TRUE)) {
        if (bValue != rfc_pcfg->memwraptool_app_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue, wifi_event_type_memwraptool_app_rfc);
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "WiFi-Interworking", TRUE))
    {
        if(bValue != rfc_pcfg->wifiinterworking_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_wifi_interworking_rfc);
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "2G80211axEnable", TRUE))
    {
#ifndef ALWAYS_ENABLE_AX_2G
        if(bValue != rfc_pcfg->twoG80211axEnable_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue,wifi_event_type_twoG80211axEnable_rfc);
        }
#endif
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Levl", TRUE))
    {
        if(bValue != rfc_pcfg->levl_enabled_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue, wifi_event_type_levl_rfc);
        }

        return TRUE;
    }

    if (AnscEqualString(ParamName, "Log_Upload", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload set\n", __FUNCTION__,__LINE__);
        if (bValue) {
            get_stubs_descriptor()->v_secure_system_fn("/usr/ccsp/wifi/wifi_logupload.sh start");
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload started\n", __FUNCTION__,__LINE__);
        } else {
            get_stubs_descriptor()->v_secure_system_fn("/usr/ccsp/wifi/wifi_logupload.sh stop");
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload stopped\n", __FUNCTION__,__LINE__);
        }
        return TRUE;
    }

    if (AnscEqualString(ParamName, "WiFiStuckDetect", TRUE))
    {
        if (bValue) {
            FILE *fp = fopen(WIFI_STUCK_DETECT_FILE_NAME, "a+");
            if (fp != NULL) {
                fclose(fp);
            }
        } else {
            remove(WIFI_STUCK_DETECT_FILE_NAME);
        }
        return TRUE;
    }
    
    if (AnscEqualString(ParamName, "Tcm", TRUE))
    {
        if(bValue != rfc_pcfg->tcm_enabled_rfc) {
            push_rfc_dml_cache_to_one_wifidb(bValue, wifi_event_type_tcm_rfc);
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Tcm rfc value set bvalue is %d \n", __FUNCTION__,__LINE__,bValue);
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Tcm started\n", __FUNCTION__,__LINE__);
        return TRUE;
    }

    if(AnscEqualString(ParamName, "WPA3_Personal_Compatibility", TRUE))
    {
        if(bValue != rfc_pcfg->wpa3_compatibility_enable) {
            push_rfc_dml_cache_to_one_wifidb(bValue, wifi_event_type_rsn_override_rfc);
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d setting WPA3_Personal_Compatibility RFC to %d \n", __FUNCTION__, __LINE__, bValue);
        }
        return TRUE;
    }

    return FALSE;
}
BOOL
WiFi_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    dml_global_default *gcfg = (dml_global_default *) get_global_default_obj();
    if(gcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

        errno_t rc = -1;
        int flag = 0;
        int ind = -1;

    if (!ParamName || !pString)
    {
        return FALSE;
    }

#ifdef USE_NOTIFY_COMPONENT
        char* p_write_id = NULL;
        char* p_new_val = NULL;
        char* p_old_val = NULL;
        char* p_notify_param_name = NULL;
        char* st;
        size_t len = 0;
        char *p_tok;
        int i = 0;
#endif

    rc = strcmp_s("X_RDKCENTRAL-COM_WiFi_Notification", strlen("X_RDKCENTRAL-COM_WiFi_Notification"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        return TRUE;
    }
    
    rc = strcmp_s("X_RDKCENTRAL-COM_Connected-Client", strlen("X_RDKCENTRAL-COM_Connected-Client"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
#ifdef USE_NOTIFY_COMPONENT
                        len = strlen(pString);
                        printf(" \n WIFI : Connected-Client Received \n");

                        for( p_tok = strtok_s(pString, &len, ",", &st) ; p_tok ; p_tok = strtok_s(NULL, &len, ",", &st) )
                        {
                                printf("Token p_tok - %s\n", p_tok);
                                switch(i)
                                {
                                       case 0:
                                                  p_notify_param_name = p_tok;
                                                  break;
                                       case 1:
                                                  p_write_id = p_tok;
                                                  break;
                                       case 2:
                                                  p_new_val = p_tok;
                                                  break;
                                       case 3:
                                                  p_old_val = p_tok;
                                                  break;
                                }
                                i++;

                                if((len == 0) || (i == 4))
                                    break;
                         }

                         if(i < 4)
                         {
                             CcspWifiTrace(("RDK_LOG_ERROR, Value p_val[%d] is NULL!!! (%s):(%d)!!!\n", i, __func__,  __LINE__));
                             return FALSE;
                         }

                        printf(" \n Notification : Parameter Name = %s \n", p_notify_param_name);
                        printf(" \n Notification : Interface = %s \n", p_write_id);
                        printf(" \n Notification : MAC = %s \n", p_new_val);
                        printf(" \n Notification : Status = %s \n", p_old_val);

#endif
            return TRUE;
    }
    
    rc = strcmp_s("X_CISCO_COM_FactoryResetRadioAndAp", strlen("X_CISCO_COM_FactoryResetRadioAndAp"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        fprintf(stderr, "-- %s X_CISCO_COM_FactoryResetRadioAndAp %s\n", __func__, pString);
        if (wifi_factory_reset(false) != TRUE)
            return FALSE;
        return TRUE;
    }

    rc = strcmp_s("X_CISCO_COM_RadioPower", strlen("X_CISCO_COM_RadioPower"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        strncpy(gcfg->RadioPower,pString,sizeof(gcfg->RadioPower)-1);
        return TRUE;
    }
	
    rc = strcmp_s("X_CISCO_COM_ConfigFileBase64", strlen("X_CISCO_COM_ConfigFileBase64"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        return TRUE;
    }
    rc = strcmp_s("X_RDKCENTRAL-COM_Br0_Sync", strlen("X_RDKCENTRAL-COM_Br0_Sync"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        return TRUE;
    }	
    rc = strcmp_s("X_RDKCENTRAL-COM_GASConfiguration", strlen("X_RDKCENTRAL-COM_GASConfiguration"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if(ANSC_STATUS_SUCCESS == WiFi_SetGasConfig(pString)){
            return TRUE;
        } else {
            CcspTraceWarning(("Failed to Set GAS Configuration\n"));
            return FALSE;
        }
    }
 
    rc = strcmp_s("X_RDK_RadioData", strlen("X_RDK_RadioData"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind)) {
#if defined (FEATURE_SUPPORT_WEBCONFIG)
    if (CosaDmlWiFi_setWebConfig(pString,strlen(pString), WIFI_RADIO_CONFIG) == ANSC_STATUS_SUCCESS) {
        CcspTraceWarning(("Success in parsing Radio Config\n"));
            return TRUE;
        } else {
            CcspTraceWarning(("Failed to parse Radio blob\n"));
            return FALSE;
        }
#else
        return FALSE;
#endif
    }
    rc = strcmp_s("Log_Enable", strlen("Log_Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind)) {
        char str[1024] = "";
        strcpy(str,pString);
        flag = CosaDmlWiFi_Logfiles_validation(str);
        if(flag == -1) {
            wifi_util_dbg_print(WIFI_DMCLI,"Log_Enable has invalid params in string\n");
            return FALSE;
        }
        remove("/nvram/wifiDbDbg");
        remove("/nvram/wifiMgrDbg");
        remove("/nvram/wifiWebConfigDbg");
        remove("/nvram/wifiCtrlDbg");
        remove("/nvram/wifiPasspointDbg");
        remove("/nvram/wifiDppDbg");
        remove("/nvram/wifiMonDbg");
        remove("/nvram/wifiDMCLI");
        remove("/nvram/wifiLib");
        remove("/nvram/wifiPsm");
        remove("/nvram/wifiLibhostapDbg");
        remove("/nvram/wifiHalDbg");
        FILE *fp = NULL;
        char * token = strtok(pString, ",");
        while( token != NULL ) {
            char dest[128]="/nvram/";
            strncat(dest,token,strlen(token));
            fp = fopen(dest,"w" );
            if (fp != NULL) {
                fclose(fp);
            }
            token = strtok(NULL, ",");
        }
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WiFi_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WiFi_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_GoodRssiThreshold", TRUE))
    {
        if(global_wifi_config->global_parameters.good_rssi_threshold == iValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:good_rssi_threshold=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.good_rssi_threshold,iValue);
        global_wifi_config->global_parameters.good_rssi_threshold = iValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AssocCountThreshold", TRUE))
    {
        if ( global_wifi_config->global_parameters.assoc_count_threshold == iValue )
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:assoc_count_threshold=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.assoc_count_threshold,iValue);
        global_wifi_config->global_parameters.assoc_count_threshold = iValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;

    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AssocMonitorDuration", TRUE))
    {
        if ( global_wifi_config->global_parameters.assoc_monitor_duration == iValue )
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:assoc_monitor_duration=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.assoc_monitor_duration,iValue);
        global_wifi_config->global_parameters.assoc_monitor_duration = iValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE; 
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AssocGateTime", TRUE))
    {
        if (global_wifi_config->global_parameters.assoc_gate_time == iValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:assoc_gate_time=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.assoc_gate_time,iValue);
        global_wifi_config->global_parameters.assoc_gate_time = iValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }

    if( AnscEqualString(ParamName, "WHIX_LogInterval", TRUE))
    {
        if (global_wifi_config->global_parameters.whix_log_interval == iValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: WHIX_LogInterval = %d Value = %d  \n",__func__, __LINE__, global_wifi_config->global_parameters.whix_log_interval, iValue);
        global_wifi_config->global_parameters.whix_log_interval = iValue; //update global structure
        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Failed to push WHIX_LogInterval to onewifi db\n",__func__, __LINE__);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "WHIX_ChUtility_LogInterval", TRUE))
    {
        if (global_wifi_config->global_parameters.whix_chutility_loginterval == iValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: WHIX_chutility_LogInterval = %d Value = %d  \n",__func__, __LINE__, global_wifi_config->global_parameters.whix_chutility_loginterval, iValue);
        global_wifi_config->global_parameters.whix_chutility_loginterval = iValue; //update global structure
        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Failed to push WHIX_LogInterval to onewifi db\n",__func__, __LINE__);
        }
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WiFi_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WiFi_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    /* check the parameter name and set the corresponding value */
    if(AnscEqualString(ParamName, "Status", TRUE))
    {
        return TRUE;
    }

    return FALSE;
}


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
	)
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_dml_wifi_global_param();

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Code", TRUE))
    {
        AnscCopyString(pValue,pcfg->wifi_region_code);
        return 0;
    }

    return -1;
}

#define BS_SOURCE_WEBPA_STR "webpa"
#define BS_SOURCE_RFC_STR "rfc"

char * getRequestorString()
{
   switch(g_currentWriteEntity)
   {
      case 0x0A: //CCSP_COMPONENT_ID_WebPA from webpa_internal.h(parodus2ccsp)
      case 0x0B: //CCSP_COMPONENT_ID_XPC
         return BS_SOURCE_WEBPA_STR;

      case 0x08: //DSLH_MPA_ACCESS_CONTROL_CLI
      case 0x10: //DSLH_MPA_ACCESS_CONTROL_CLIENTTOOL
         return BS_SOURCE_RFC_STR;

      default:
         return "unknown";
   }
}

char * getTime()
{
    time_t timer;
    static char buffer[50];
    struct tm* tm_info;
    time(&timer);
    tm_info = localtime(&timer);
    strftime(buffer, 50, "%Y-%m-%d %H:%M:%S ", tm_info);
    return buffer;
}

BOOL
WiFiRegion_SetParamStringValue


	(
		ANSC_HANDLE 				hInsContext,
		char*						ParamName,
		char*						pString
	)

{
    UNREFERENCED_PARAMETER(hInsContext);
    UINT r_itr = 0;
    char PartnerID[PARTNER_ID_LEN] = {0};
    char * currentTime = getTime();
    char * requestorStr = getRequestorString();
    wifi_radio_operationParam_t *wifiRadioOperParam;
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Code", TRUE))
    {
        if (strcmp(requestorStr, BS_SOURCE_RFC_STR) == 0 && strcmp(wifiRegionUpdateSource, BS_SOURCE_WEBPA_STR) == 0)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Do NOT allow override\n", __func__, __LINE__);
            return FALSE;
        }

        for (r_itr = 0; r_itr < get_num_radio_dml(); r_itr++) {
            wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(r_itr);
            if (wifiRadioOperParam == NULL)
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to fetch Operating params for radio index %d\n", __func__, __LINE__, r_itr);
                continue;
            }
            if (regDomainStrToEnums(pString, &wifiRadioOperParam->countryCode, &wifiRadioOperParam->operatingEnvironment) == ANSC_STATUS_SUCCESS)
            {
                is_radio_config_changed = TRUE;
            } else {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to convert country code for radio_index %d\n", __func__, __LINE__, r_itr);
                return FALSE;
            }
        }

        AnscCopyString( global_wifi_config->global_parameters.wifi_region_code, pString );
        push_global_config_dml_cache_to_one_wifidb();
        push_radio_dml_cache_to_one_wifidb();
        last_radio_change = AnscGetTickInSeconds();

        if((CCSP_SUCCESS == getPartnerId(PartnerID) ) && (PartnerID[ 0 ] != '\0') )
        {
            if (UpdateJsonParam("Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code",PartnerID, pString, requestorStr, currentTime) != ANSC_STATUS_SUCCESS)
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to update WifiRegion to Json file\n", __func__, __LINE__);
            }
        }
        snprintf(wifiRegionUpdateSource, 16, "%s", requestorStr);

        return TRUE;
    }

    return FALSE;
}

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
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Radio_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
Radio_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: Number of radio:%d\n",__func__, __LINE__, get_num_radio_dml());
    return get_num_radio_dml();
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        Radio_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
Radio_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_radio_operationParam_t *wifiRadioOperParam = NULL; 

    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: nIndex:%ld\n",__func__, __LINE__, nIndex);
    if ( nIndex < (UINT)get_num_radio_dml() )
    {
	wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_radio_operation_param(nIndex);
        if (wifiRadioOperParam == NULL)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %ld not found for wifiRadioOperParam\n", __FUNCTION__, nIndex));
            return NULL;
        }
        *pInsNumber = nIndex + 1;
	g_radio_instance_num = nIndex + 1;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: g_radio_instance_num:%d\n",__func__, __LINE__, g_radio_instance_num); 
        last_radio_change = AnscGetTickInSeconds();
        return (ANSC_HANDLE)wifiRadioOperParam;
    }
    return NULL; /* return the handle */
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Radio_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Radio_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{

    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, pcfg->band);
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);
    wifi_radio_capabilities_t radio_capab = ((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop.radiocap[instance_number];

    if(rcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->enable;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Upstream", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "AutoChannelSupported", TRUE))
    {
        *pBool = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "AutoChannelEnable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->autoChannelEnabled;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_EcoPowerDown", TRUE))
    {
        /* collect value */
#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        *pBool = pcfg->EcoPowerDown;
#else
        *pBool = false;
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        return TRUE;
    }

    if( AnscEqualString(ParamName, "IEEE80211hSupported", TRUE))
    {
        *pBool = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "IEEE80211hEnabled", TRUE))
    {
        *pBool = rcfg->IEEE80211hEnabled;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_COMCAST_COM_DFSSupport", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d X_COMCAST_COM_DFSSupport band %d num_channels %d\n", __FUNCTION__,__LINE__, pcfg->band, radio_capab.channel_list[0].num_channels);
        for (int i=0; i<radio_capab.channel_list[0].num_channels; i++) {
            if ( (pcfg->band == WIFI_FREQUENCY_5_BAND || pcfg->band == WIFI_FREQUENCY_5L_BAND || pcfg->band == WIFI_FREQUENCY_5H_BAND) && (radio_capab.channel_list[0].channels_list[i] >=52 && radio_capab.channel_list[0].channels_list[i] <=144) )
            {
                *pBool = TRUE;
                return TRUE;
            }
        }
        *pBool = FALSE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST_COM_DFSEnable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->DfsEnabled;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_COMCAST-COM_DCSSupported", TRUE))
    {
        *pBool = rcfg->DCSSupported;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_DCSEnable", TRUE))
    {
        *pBool = pcfg->DCSEnabled;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST_COM_IGMPSnoopingEnable", TRUE))
    {
        *pBool = rcfg->IGMPSnoopingEnabled;
        return TRUE;
    }
    
    if( AnscEqualString(ParamName, "X_COMCAST-COM_AutoChannelRefreshPeriodSupported", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_IEEE80211hSupported", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_ReverseDirectionGrantSupported", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_RtsThresholdSupported", TRUE))
    {
          *pBool = FALSE;
          return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_APIsolation", TRUE))
    {
        /* collect value */
        *pBool = rcfg->APIsolation;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_FrameBurst", TRUE))
    {
        /* collect value */
        *pBool = rcfg->FrameBurst;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_ApplySetting", TRUE))
    {
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AutoChannelRefreshPeriodSupported", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_RtsThresholdSupported", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_ReverseDirectionGrantSupported", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_ReverseDirectionGrant", TRUE))
    {
        *pBool = rcfg->ReverseDirectionGrant;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_AggregationMSDU", TRUE))
    {
        *pBool = rcfg->AggregationMSDU;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_AutoBlockAck", TRUE))
    {
        *pBool = rcfg->AutoBlockAck;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_DeclineBARequest", TRUE))
    {
        *pBool = rcfg->DeclineBARequest;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_STBCEnable", TRUE))
    {
        *pBool = pcfg->stbcEnable;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_11nGreenfieldEnabled", TRUE))
    {
        *pBool = pcfg->greenFieldEnable;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_WirelessOnOffButton", TRUE))
    {
        *pBool = rcfg->WirelessOnOffButton;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Radio_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Radio_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{

    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)hInsContext;
    INT instance_number = 0;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if (convert_freq_band_to_radio_index(pcfg->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, pcfg->band);
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);

    if(rcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "MCS", TRUE))
    {
        /* collect value */
        *pInt = rcfg->MCS; 
        return TRUE;
    }

    if( AnscEqualString(ParamName, "TransmitPower", TRUE))
    {
        /* collect value */
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: tx_power:%d\n",__func__, __LINE__, pcfg->transmitPower);
    	*pInt = pcfg->transmitPower;
        
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_MbssUserControl", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: userControl:%d\n",__func__, __LINE__, pcfg->userControl);
        *pInt = pcfg->userControl;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_AdminControl", TRUE))
    {
        *pInt = pcfg->adminControl;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_OnOffPushButtonTime", TRUE))
    {
        *pInt = rcfg->OnOffPushButtonTime;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_ObssCoex", TRUE))
    {
        *pInt = pcfg->obssCoex;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_MulticastRate", TRUE))
    {
        *pInt = rcfg->MulticastRate;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_COMCAST-COM_CarrierSenseThresholdRange", TRUE))
    {
         *pInt = rcfg->ThresholdRange;
         return TRUE;
    }
    if (AnscEqualString(ParamName, "X_COMCAST-COM_CarrierSenseThresholdInUse", TRUE))
    {
        *pInt = rcfg->ThresholdInUse; 
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_COMCAST-COM_ChannelSwitchingCount", TRUE))
    {
	*pInt = gChannelSwitchingCount;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_DCSDwelltime", TRUE))
    {
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_clientInactivityTimeout", TRUE) )
    {
        *pInt = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST_COM_DFSTimer", TRUE) ) {
        *pInt = pcfg->DFSTimer;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Radio_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Radio_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{

    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)hInsContext;    
    unsigned int upSecs;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, pcfg->band);
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);

    if(rcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
    wifi_radio_feature_param_t *fcfg = (wifi_radio_feature_param_t *) get_dml_cache_radio_feat_map(instance_number);
    if(fcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    if (monitor_param == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
#else //FEATURE_OFF_CHANNEL_SCAN_5G
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Offchannel distro not present\n", __FUNCTION__,__LINE__);
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "X_COMCAST_COM_RadioUpTime", TRUE))
    {
        /* collect value */
        upSecs = get_Uptime();
        *puLong = upSecs - startTime[instance_number];
        return TRUE;
    }
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        if (global_wifi_config->global_parameters.force_disable_radio_feature == TRUE )
        {
            *puLong = 2;
            return TRUE;
        }
        if (get_radio_presence(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, instance_number) == false) {
            *puLong = 8;
            return TRUE;
        }
        if (pcfg->enable == TRUE) {
            *puLong = 1;
        }
        else {
            *puLong = 2;
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "LastChange", TRUE))
    {
        /* collect value */
        *puLong = AnscGetTimeIntervalInSeconds(last_radio_change,AnscGetTickInSeconds());
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MaxBitRate", TRUE))
    {
        /* collect value */
        *puLong = rcfg->MaxBitRate; 
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SupportedFrequencyBands", TRUE))
    {
        /* collect value */
        *puLong = rcfg->SupportedFrequencyBands; 
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Channel", TRUE))
    {
        /* collect value */
	*puLong = pcfg->channel;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "AutoChannelRefreshPeriod", TRUE))
    {
        *puLong = rcfg->AutoChannelRefreshPeriod; 
        return TRUE;
    }

    if( AnscEqualString(ParamName, "OperatingChannelBandwidth", TRUE))
    {
        /* collect value */
        UINT bw = 0;
        if(operChanBandwidthHalEnumtoDmlEnum(pcfg->channelWidth,&bw) == RETURN_OK)
        {
            *puLong = bw;
            return TRUE;
        }
        return FALSE;
    }

    if( AnscEqualString(ParamName, "ExtensionChannel", TRUE))
    {
        *puLong = rcfg->ExtensionChannel;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "GuardInterval", TRUE))
    {
        /* collect value */
        COSA_DML_WIFI_GUARD_INTVL tmpGuardInterval = 0;

        if (guardIntervalHalEnumtoDmlEnum(pcfg->guardInterval, &tmpGuardInterval) != ANSC_STATUS_SUCCESS) {
            return FALSE;
        }
        *puLong = tmpGuardInterval;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_RTSThreshold", TRUE))
    {
        /* collect value */
	*puLong = pcfg->rtsThreshold;
        
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_FragmentationThreshold", TRUE))
    {
        /* collect value */
	*puLong = pcfg->fragmentationThreshold;
        
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_DTIMInterval", TRUE))
    {
        /* collect value */
        *puLong = pcfg->dtimPeriod;
        
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_BeaconInterval", TRUE) || AnscEqualString(ParamName, "BeaconPeriod", TRUE))
    {
        /* collect value */
        *puLong = pcfg->beaconInterval;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_TxRate", TRUE))
    {
        /* collect value */
        *puLong = pcfg->transmitPower;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_BasicRate", TRUE))
    {
        /* collect value */
        *puLong = rcfg->BasicRate;
        return TRUE;
    }
    
    if( AnscEqualString(ParamName, "X_CISCO_COM_CTSProtectionMode", TRUE))
    {
        /* collect value */
        *puLong = (FALSE == pcfg->ctsProtection) ? 0 : 1;

        return TRUE;
    }
#if 0
    if (AnscEqualString(ParamName, "X_CISCO_COM_HTTxStream", TRUE))
    {
        *puLong = pWifiRadioFull->Cfg.X_CISCO_COM_HTTxStream; 
        return TRUE;
    }
  
    if (AnscEqualString(ParamName, "X_CISCO_COM_HTRxStream", TRUE))
    {
        *puLong = pWifiRadioFull->Cfg.X_CISCO_COM_HTRxStream; 
        return TRUE;
    }
 #endif   
    if( AnscEqualString(ParamName, "RadioResetCount", TRUE) )
    {
        *puLong = radio_reset_count;
        return TRUE;
    }
    
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_ChanUtilSelfHealEnable", TRUE))
    {
        *puLong = pcfg->chanUtilSelfHealEnable;
       	return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_ChannelUtilThreshold", TRUE))
    {

        *puLong = pcfg->chanUtilThreshold;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_OffChannelTscan", TRUE))
    {
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
        *puLong = fcfg->OffChanTscanInMsec;
#else
        *puLong = 0;
#endif
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_OffChannelNscan", TRUE))
    {
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
        if (fcfg->OffChanNscanInSec != 0)
        {
            *puLong = (fcfg->OffChanNscanInSec == 0) ? 0 : (24*3600)/(fcfg->OffChanNscanInSec); //Converting to number from sec
            return TRUE;
        }
        *puLong = 0;
#else
        *puLong = 0;
#endif
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_OffChannelTidle", TRUE))
    {
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
        *puLong = fcfg->OffChanTidleInSec;
#else
        *puLong = 0;
#endif
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_OffChannelNchannel", TRUE))
    {
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
        if (is_radio_band_5G(pcfg->band))
        {
            wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
            *puLong = wifi_mgr->radio_config[instance_number].feature.Nchannel;
            return TRUE;
        }
        *puLong = 0;
#else
        *puLong = 0;
#endif
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Radio_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
Radio_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)hInsContext;
    
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, pcfg->band);
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);

    if(rcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        snprintf(pValue, *pUlSize, "%s", rcfg->Alias);
        return 0;
    }

    if( AnscEqualString(ParamName, "Name", TRUE))
    {
        /* collect value */
        INT instance_number = 0;
        if (convert_freq_band_to_radio_index(pcfg->band, &instance_number) == RETURN_ERR) {
            AnscCopyString(pValue, "Invalid_Radio");
        } else {
            if (convert_radio_index_to_ifname(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, instance_number, pValue, *pUlSize) != RETURN_OK) {
                AnscCopyString(pValue, "Invalid_Radio");
            }
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        /*TR-181: Since Radio is a layer 1 interface, 
          it is expected that LowerLayers will not be used
         */
         /* collect value */
        AnscCopyString(pValue, "Not Applicable");
        return 0;
    }

    if( AnscEqualString(ParamName, "OperatingFrequencyBand", TRUE))
    {
        /* collect value */
        if(10 < *pUlSize)
        {
            if ( pcfg->band == WIFI_FREQUENCY_2_4_BAND )
            {
                AnscCopyString(pValue, "2.4GHz");
            }
            else if ( pcfg->band == WIFI_FREQUENCY_5_BAND )
            {
                AnscCopyString(pValue, "5GHz");
            }
            else if ( pcfg->band == WIFI_FREQUENCY_5L_BAND )
            {
                AnscCopyString(pValue, "5GHz Low");
            }
            else if ( pcfg->band == WIFI_FREQUENCY_5H_BAND )
            {
                AnscCopyString(pValue, "5GHz High");
            }
            else if ( pcfg->band == WIFI_FREQUENCY_6_BAND )
            {
                AnscCopyString(pValue, "6GHz");
            }
        }
        else
        {
            *pUlSize = 6;
            return 1;
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "OperatingStandards", TRUE))
    {
        /* collect value */
        char buf[512] = {0};
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:wifi variant=%d\n",__func__, __LINE__, pcfg->variant);
        if ( pcfg->variant & WIFI_80211_VARIANT_A )
        {
            strcat(buf, "a");
        }

        if ( pcfg->variant & WIFI_80211_VARIANT_B )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",b");
            }
            else
            {
                strcat(buf, "b");
            }
        }

        if ( pcfg->variant & WIFI_80211_VARIANT_G )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",g");
            }
            else
            {
                strcat(buf, "g");
            }
        }

        if ( pcfg->variant & WIFI_80211_VARIANT_N )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",n");
            }
            else
            {
                strcat(buf, "n");
            }
        }

        if ( pcfg->variant & WIFI_80211_VARIANT_AC )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",ac");
            }
            else
            {
                strcat(buf, "ac");
            }
        }
        if ( pcfg->variant & WIFI_80211_VARIANT_AX )
        {

            if ((instance_number) || (rfc_pcfg && rfc_pcfg->twoG80211axEnable_rfc)) {
                if (AnscSizeOfString(buf) != 0)
                {
                    strcat(buf, ",ax");
                }
                else
                {
                    strcat(buf, "ax");
                }
            }
        }

#ifdef CONFIG_IEEE80211BE
        if ( pcfg->variant & WIFI_80211_VARIANT_BE )
        {
                if (AnscSizeOfString(buf) != 0)
                {
                    strcat(buf, ",be");
                }
                else
                {
                    strcat(buf, "be");
                }
        }
#endif /* CONFIG_IEEE80211BE */
        if ( AnscSizeOfString(buf) < *pUlSize)
        {
            AnscCopyString(pValue, buf);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(buf)+1;

            return 1;
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "PossibleChannels", TRUE))
    {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

        if( rfc_params == NULL )
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer RFC Params\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        return get_allowed_channels_str(pcfg->band,
            &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop.radiocap[instance_number],
            pValue, *pUlSize, rfc_params->dfs_rfc) == RETURN_OK ? 0 : -1;
    }

    if( AnscEqualString(ParamName, "ChannelsInUse", TRUE))
    {
        snprintf(pValue, *pUlSize, "%d", pcfg->channel);
        return 0;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_ApChannelScan", TRUE))
    {
        return 0;
    }

    if( AnscEqualString(ParamName, "TransmitPowerSupported", TRUE))
    {
        /* collect value */
        snprintf(pValue, *pUlSize, "%s", rcfg->TransmitPowerSupported);
        return 0;
    }

    if( AnscEqualString(ParamName, "RegulatoryDomain", TRUE))
    {
        /* collect value */
        char regulatoryDomain[4];
        memset(regulatoryDomain, 0, sizeof(regulatoryDomain));
        getRegulatoryDomainFromEnums(pcfg->countryCode, pcfg->operatingEnvironment, regulatoryDomain);
        if ( AnscSizeOfString(regulatoryDomain ) < *pUlSize)
        {
            AnscCopyString(pValue, regulatoryDomain);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(regulatoryDomain)+1;
            return 1;
        }
        return 0;
    }


    if( AnscEqualString(ParamName, "SupportedStandards", TRUE))
    {
        snprintf(pValue, *pUlSize, "%s", rcfg->SupportedStandards);
        return 0;
    }

    if (AnscEqualString(ParamName, "BasicDataTransmitRates", TRUE)) {
        char buf[512] = { 0 };
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d:pcfg->basicDataTransmitRates=%d\n", __func__,
            __LINE__, pcfg->basicDataTransmitRates);
        if (pcfg->basicDataTransmitRates & WIFI_BITRATE_6MBPS) {
            strcat(buf, "6");
        }

        if (pcfg->basicDataTransmitRates & WIFI_BITRATE_12MBPS) {
            if (AnscSizeOfString(buf) != 0) {
                strcat(buf, ",12");
            } else {
                strcat(buf, "12");
            }
        }

        if (pcfg->basicDataTransmitRates & WIFI_BITRATE_1MBPS) {
            if (AnscSizeOfString(buf) != 0) {
                strcat(buf, ",1");
            } else {
                strcat(buf, "1");
            }
        }

        if (pcfg->basicDataTransmitRates & WIFI_BITRATE_2MBPS) {
            if (AnscSizeOfString(buf) != 0) {
                strcat(buf, ",2");
            } else {
                strcat(buf, "2");
            }
        }

        if (pcfg->basicDataTransmitRates & WIFI_BITRATE_5_5MBPS) {
            if (AnscSizeOfString(buf) != 0) {
                strcat(buf, ",5.5");
            } else {
                strcat(buf, "5.5");
            }
        }

        if (pcfg->basicDataTransmitRates & WIFI_BITRATE_11MBPS) {
            if (AnscSizeOfString(buf) != 0) {
                strcat(buf, ",11");
            } else {
                strcat(buf, "11");
            }
        }

        if (pcfg->basicDataTransmitRates & WIFI_BITRATE_24MBPS) {
            if (AnscSizeOfString(buf) != 0) {
                strcat(buf, ",24");
            } else {
                strcat(buf, "24");
            }
        }

        if (AnscSizeOfString(buf) < *pUlSize) {
            AnscCopyString(pValue, buf);
            return 0;
        } else {
            *pUlSize = AnscSizeOfString(buf) + 1;
            return 1;
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "SupportedDataTransmitRates", TRUE))
    {
        /* collect value */
        snprintf(pValue, *pUlSize, "%s", "6,9,12,18,24,36,48,54");
        return 0;
    }
    
    if( AnscEqualString(ParamName, "OperationalDataTransmitRates", TRUE))
    {
        char buf[512] = {0};
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:pcfg->operationalDataTransmitRates=%d\n",__func__, __LINE__, pcfg->operationalDataTransmitRates);
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_6MBPS )
        {
            strcat(buf, "6");
        }
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_9MBPS )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",9");
            }
            else
            {
                strcat(buf, "9");
            }
        }
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_12MBPS )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",12");
            }
            else
            {
                strcat(buf, "12");
            }
        }
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_18MBPS )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",18");
            }
            else
            {
                strcat(buf, "18");
            }
        }
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_24MBPS )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",24");
            }
            else
            {
                strcat(buf, "24");
            }
        }
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_36MBPS )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",36");
            }
            else
            {
                strcat(buf, "36");
            }
        }
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_48MBPS )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",48");
            }
            else
            {
                strcat(buf, "48");
            }
        }
        if ( pcfg->operationalDataTransmitRates & WIFI_BITRATE_54MBPS )
        {
            if (AnscSizeOfString(buf) != 0)
            {
                strcat(buf, ",54");
            }
            else
            {
                strcat(buf, "54");
            }
        }
        if ( AnscSizeOfString(buf) < *pUlSize)
        {
            AnscCopyString(pValue, buf);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(buf)+1;
            return 1;
        }
        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Radio_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Radio_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    wifi_radio_operationParam_t *wifi_radio = (wifi_radio_operationParam_t *)hInsContext;

    if (wifi_radio == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(wifi_radio->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, wifi_radio->band);
        return FALSE;
    }
    wifi_radio_operationParam_t *wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(instance_number);
    UINT wlanIndex = 0;

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if ((instance_number < 0) || (instance_number > (INT)get_num_radio_dml()))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, Radio instanceNumber:%d out of range\n", instance_number));
        return FALSE;
    }

    wlanIndex = instance_number;
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s wlanIndex : %d\n", __FUNCTION__, wlanIndex);

    if (wifiRadioOperParam == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d not found for wifiRadioOperParam\n", __FUNCTION__, wlanIndex));
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);

    if(rcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
	wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:enable=%d bValue = %d instanceNumber=%d true=%d false=%d  \n",__func__, __LINE__,wifiRadioOperParam->enable,bValue,instance_number,TRUE,FALSE);
        if(global_wifi_config->global_parameters.force_disable_radio_feature)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n" ));
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n",__func__, __LINE__);
            return FALSE;
        }
        if (get_radio_presence(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, instance_number) == false) {
            CcspWifiTrace(("RDK_LOG_ERROR, %s:%d: Not allowed to change config when radio is not present in CPE \n", __func__, __LINE__));
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: Not allowed to change config when radio is not present in CPE \n", __func__, __LINE__);
            return FALSE;
        }
        if (wifiRadioOperParam->enable == bValue)
        {
             return  TRUE;
        }
        /* save update to backup */
        wifiRadioOperParam->enable = bValue;
	is_radio_config_changed = TRUE;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: RadioEnable : %d\n",__func__, __LINE__,wifiRadioOperParam->enable);
        return TRUE;
     }

    if( AnscEqualString(ParamName, "AutoChannelEnable", TRUE))
    {
	wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:autoChannelEnabled=%d bValue = %d  \n",__func__, __LINE__,wifiRadioOperParam->autoChannelEnabled,bValue);
        if (wifiRadioOperParam->autoChannelEnabled == bValue)
        {
            return  TRUE;
        }
        /* save update to backup */
        wifiRadioOperParam->autoChannelEnabled = bValue;
	is_radio_config_changed = TRUE;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s autoChannelEnabled : %d\n", __FUNCTION__, wifiRadioOperParam->autoChannelEnabled);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "IEEE80211hEnabled", TRUE))
    {
        rcfg->IEEE80211hEnabled = bValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST_COM_DFSEnable", TRUE))
    {
        wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        if (!(rfc_pcfg->dfs_rfc)) {
            CcspWifiTrace(("RDK_LOG_ERROR, DFS RFC DISABLED\n" ));
            return FALSE;
        }
        wifiRadioOperParam->DfsEnabled = bValue;
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_DCSEnable", TRUE))
    {
        if (wifiRadioOperParam->DCSEnabled == bValue)
        {
            return  TRUE;
        }

        wifiRadioOperParam->DCSEnabled = bValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s DCSEnabled : %d\n", __FUNCTION__, wifiRadioOperParam->DCSEnabled);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:DCSEnabled=%d  = %d  \n",__func__, __LINE__,wifiRadioOperParam->DCSEnabled,bValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST_COM_IGMPSnoopingEnable", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Cannot set IGMPSnoopingEnable \n",__func__,__LINE__);
        return FALSE;
    }


    if( AnscEqualString(ParamName, "X_CISCO_COM_APIsolation", TRUE))
    {
        rcfg->APIsolation = bValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_FrameBurst", TRUE))
    {
        rcfg->FrameBurst = bValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_ApplySetting", TRUE))
    {
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_ReverseDirectionGrant", TRUE))
    {
        if (rcfg->ReverseDirectionGrant == bValue)
        {
            return TRUE;
        }
        rcfg->ReverseDirectionGrant = bValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:ReverseDirectionGrant=%d  = %d  \n",__func__, __LINE__,rcfg->ReverseDirectionGrant,bValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_AggregationMSDU", TRUE))
    {
        if (rcfg->AggregationMSDU == bValue) {
            return TRUE;
        }
        rcfg->AggregationMSDU = bValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:AggregationMSDU=%d  = %d  \n",__func__, __LINE__,rcfg->AggregationMSDU,bValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_AutoBlockAck", TRUE))
    {
	if (rcfg->AutoBlockAck == bValue)
        {
            return TRUE;
        }
        rcfg->AutoBlockAck = bValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:AutoBlockAck=%d  = %d  \n",__func__, __LINE__,rcfg->AutoBlockAck,bValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_DeclineBARequest", TRUE))
    {
	if (rcfg->DeclineBARequest == bValue)
        {
            return TRUE;
        }
        rcfg->DeclineBARequest = bValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:DeclineBARequest=%d  = %d  \n",__func__, __LINE__,rcfg->DeclineBARequest,bValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_STBCEnable", TRUE))
    {
        wifiRadioOperParam->stbcEnable = bValue;
        is_radio_config_changed = TRUE;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s STBCEnableEnabled : %d\n", __FUNCTION__, wifiRadioOperParam->stbcEnable);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_11nGreenfieldEnabled", TRUE))
    {
        wifiRadioOperParam->greenFieldEnable = bValue;
        is_radio_config_changed = TRUE;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s GreenfiledEnabled : %d\n", __FUNCTION__, wifiRadioOperParam->greenFieldEnable);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_WirelessOnOffButton", TRUE))
    {
	if (rcfg->WirelessOnOffButton == bValue)
        {
            return TRUE;
        }
        rcfg->WirelessOnOffButton = bValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:WirelessOnOffButton=%d  = %d  \n",__func__, __LINE__,rcfg->WirelessOnOffButton,bValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_EcoPowerDown", TRUE))
    {
#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: EcoPowerDown = %d bValue = %d  \n", __func__, __LINE__, wifiRadioOperParam->EcoPowerDown, bValue);
        if (wifiRadioOperParam->EcoPowerDown == bValue)
        {
            return  TRUE;
        }
        /* save update to backup */
        wifiRadioOperParam->EcoPowerDown = bValue;
#ifdef FEATURE_SUPPORT_ECOPOWERDOWN
        wifiRadioOperParam->enable = ( (wifiRadioOperParam->EcoPowerDown) ? false : true);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: Updated radio enable status based on EcoPowerDown, EcoPowerDown = %d, Enable = %d  \n", __func__, __LINE__,wifiRadioOperParam->EcoPowerDown, wifiRadioOperParam->enable);
#endif // FEATURE_SUPPORT_ECOPOWERDOWN
        is_radio_config_changed = TRUE;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s EcoPowerDown : %d\n", __FUNCTION__, wifiRadioOperParam->EcoPowerDown);
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        static BOOL
        isValidTransmitPower
            (
                char*                       supportedPowerList,
                int                         transmitPower
            );

    description:

        This function can be used to validate against the supported transmit power;

    argument:   char*  supportedPowerList
                The supportedPowerList

                int transmitPower
                The transmitPower value that need validation before setting

    return:     TRUE if transmitPower is supported ;
                        FALSE if not supported
**********************************************************************/

static BOOL isValidTransmitPower(char* supportedPowerList, int transmitPower)
{
    char powerList[64] = {0} , *tok, *next_tok;
    size_t powerListSize = strlen(supportedPowerList);

    if ((powerListSize == 0) || (powerListSize >= sizeof(powerList)))
    {
        wifi_util_error_print(WIFI_DMCLI,"%s: failed to get supported Transmit power list\n", __func__);
        return FALSE;
    }
    strncpy(powerList, supportedPowerList, sizeof(powerList) - 1);
    powerList[sizeof(powerList) - 1] = '\0'; // Ensure null-termination
    tok = strtok_s(powerList, &powerListSize, ",", &next_tok);
    while (tok) {
        if (atoi(tok) == transmitPower) {
            return TRUE;
        }
        tok = strtok_s(NULL, &powerListSize, ",", &next_tok);
    }
    wifi_util_error_print(WIFI_DMCLI,"%s:%d Given Transmit power value %d is not supported and the supported values are %s\n",__func__, __LINE__, transmitPower, supportedPowerList);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Radio_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Radio_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    wifi_radio_operationParam_t *wifi_radio = (wifi_radio_operationParam_t *)hInsContext;
    if (wifi_radio == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(wifi_radio->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, wifi_radio->band);
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);

    if(rcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_radio_operationParam_t *wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(instance_number);
    UINT wlanIndex = 0;

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if ((instance_number < 0) || (instance_number > (INT)get_num_radio_dml()))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, Radio instanceNumber:%d out of range\n", instance_number));
        return FALSE;
    }

    wlanIndex = instance_number;
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s wlanIndex : %d\n", __FUNCTION__, wlanIndex);

    if (wifiRadioOperParam == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d not found for wifiRadioOperParam\n", __FUNCTION__, wlanIndex));
        return FALSE;
    }
 
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "MCS", TRUE))
    {
        rcfg->MCS = iValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "TransmitPower", TRUE))
    {
        if (wifiRadioOperParam->transmitPower == (UINT)iValue)
        {
            return  TRUE;
        }

        if (isValidTransmitPower(rcfg->TransmitPowerSupported,iValue) != TRUE)
        {
            return FALSE;
        }
        wifiRadioOperParam->transmitPower = iValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s transmitPower : %d\n", __FUNCTION__, wifiRadioOperParam->transmitPower);
        is_radio_config_changed = TRUE;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:transmitPower=%d bValue = %d RadioIndex=%d \n",__func__, __LINE__,wifiRadioOperParam->transmitPower,iValue, instance_number );
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_MbssUserControl", TRUE))
    {
        if (wifiRadioOperParam->userControl == (UINT)iValue)
        {
            return  TRUE;
        }

        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:userControl=%d bValue = %d  \n",__func__, __LINE__,wifiRadioOperParam->userControl,iValue);
        wifiRadioOperParam->userControl = iValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s transmitPower : %d\n", __FUNCTION__, wifiRadioOperParam->userControl);
        is_radio_config_changed = TRUE;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_AdminControl", TRUE))
    {
        wifiRadioOperParam->adminControl = iValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s adminControl: %d\n", __FUNCTION__, wifiRadioOperParam->adminControl);
        is_radio_config_changed = TRUE;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:adminControl=%d bValue = %d  \n",__func__, __LINE__,wifiRadioOperParam->adminControl,iValue);
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_OnOffPushButtonTime", TRUE))
    {
        rcfg->OnOffPushButtonTime = iValue;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_ObssCoex", TRUE))
    {
        if((iValue != 0) && (iValue != 1)) 
        {
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s Invalid value obssCoex: %d\n", __FUNCTION__,iValue);
            return FALSE;
        }
        wifiRadioOperParam->obssCoex = iValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s obssCoex: %d\n", __FUNCTION__, wifiRadioOperParam->obssCoex);
        is_radio_config_changed = TRUE;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:obssCoex=%d bValue = %d  \n",__func__, __LINE__,wifiRadioOperParam->obssCoex,iValue);
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_MulticastRate", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Cannot set MulticastRate \n",__func__,__LINE__);
        return FALSE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_CarrierSenseThresholdInUse", TRUE))
    {         
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Cannot set CarrierSenseThresholdInUse \n",__func__,__LINE__);
        return FALSE;
    }
    
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_DCSDwelltime", TRUE))
    {

	return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST_COM_DFSTimer", TRUE) ) {
        if(iValue < 30) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d: Invalid Timer value %d for the country code : %d\n", __func__, __LINE__, iValue, wifiRadioOperParam->countryCode);
            return FALSE;
        }

        wifiRadioOperParam->DFSTimer = iValue;
        is_radio_config_changed = TRUE;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: DFSTimer:%d iValue:%d \n",__func__, __LINE__, wifiRadioOperParam->DFSTimer,iValue);

        return TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        static BOOL
        isValidFragmentThreshold
            (
                int                         fragmentationThreshold
            );

    description:

        This function can be used to validate against the supported fragmentationThreshold;

    argument:   int fragmentationThreshold
                The fragmentationThreshold value that need validation before setting

    return:     TRUE if fragmentationThreshold is supported ;
                FALSE if not supported
**********************************************************************/

static BOOL isValidFragmentThreshold(int fragmentationThreshold)
{

    if ((fragmentationThreshold < 256) || (fragmentationThreshold > 2346))
    {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Given fragmentationThreshold value %d is not supported\n", __func__, __LINE__,fragmentationThreshold);
        return FALSE;
    }

    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Radio_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Radio_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    wifi_radio_operationParam_t *wifi_radio = (wifi_radio_operationParam_t *)hInsContext;

    if (wifi_radio == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(wifi_radio->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, wifi_radio->band);
        return FALSE;
    }
    wifi_radio_operationParam_t *wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(instance_number);
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    UINT wlanIndex = 0;
    wifi_channelBandwidth_t tmpChanWidth = 0;

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if ((instance_number < 0) || (instance_number > (INT)get_num_radio_dml()))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, Radio instanceNumber:%d out of range\n", instance_number));
        return FALSE;
    }

    wlanIndex = instance_number;
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s wlanIndex : %d\n", __FUNCTION__, wlanIndex);

    if (wifiRadioOperParam == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d not found for wifiRadioOperParam\n", __FUNCTION__, wlanIndex));
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);

    if(rcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
    wifi_radio_feature_param_t *fcfg = (wifi_radio_feature_param_t *) get_dml_cache_radio_feat_map(instance_number);
    if(fcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
#else //FEATURE_OFF_CHANNEL_SCAN_5G
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Offchannel distro not present\n", __FUNCTION__,__LINE__);
#endif //FEATURE_OFF_CHANNEL_SCAN_5G

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Channel", TRUE))
    {
        if (wifiRadioChannelIsValid(wlanIndex, uValue) != ANSC_STATUS_SUCCESS)
        {
            return FALSE;
        }
        if (wifiRadioOperParam->channel == uValue)
        {
            return  TRUE;
        }
        else if ((wifiRadioOperParam->band == WIFI_FREQUENCY_5_BAND) ||
                 (wifiRadioOperParam->band == WIFI_FREQUENCY_5L_BAND) ||
                 (wifiRadioOperParam->band == WIFI_FREQUENCY_5H_BAND))
        {
            if (is_dfs_channel_allowed(uValue) == false)
            {
                return FALSE;
            }
        }

        wifiRadioOperParam->channel = uValue;
        wifiRadioOperParam->autoChannelEnabled = FALSE;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s Channel : %d\n", __FUNCTION__, wifiRadioOperParam->channel);
        gChannelSwitchingCount++;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:channel=%d uValue = %d  \n",__func__, __LINE__,wifiRadioOperParam->channel,uValue);
        is_radio_config_changed = TRUE;

        return TRUE;
    }

    if( AnscEqualString(ParamName, "AutoChannelRefreshPeriod", TRUE))
    {
        rcfg->AutoChannelRefreshPeriod = uValue;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "OperatingChannelBandwidth", TRUE)) {
        if (operChanBandwidthDmlEnumtoHalEnum(uValue, &tmpChanWidth) != ANSC_STATUS_SUCCESS) {
            return FALSE;
        }

        if (wifiRadioOperParam->channelWidth == tmpChanWidth) {
            return TRUE;
        }

        if ((tmpChanWidth == WIFI_CHANNELBANDWIDTH_320MHZ) &&
            (wifiRadioOperParam->band != WIFI_FREQUENCY_6_BAND)) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d: 320MHZ bandwidth supported only for 6GHZ band\n",
                __func__, __LINE__);
            return FALSE;
        }

        if ((tmpChanWidth == WIFI_CHANNELBANDWIDTH_160MHZ) &&
            (wifiRadioOperParam->band == WIFI_FREQUENCY_5_BAND) && (rfc_pcfg->dfs_rfc != true)) {
            wifi_util_dbg_print(WIFI_DMCLI,
                "%s:%d: DFS Disabled!! Cannot set to tmpChanWidth = %d\n", __func__, __LINE__,
                tmpChanWidth);
            return FALSE;
        }

        if (wifiRadioOperParam->band == WIFI_FREQUENCY_2_4_BAND) {
            if ((tmpChanWidth != WIFI_CHANNELBANDWIDTH_20MHZ) &&
                (tmpChanWidth != WIFI_CHANNELBANDWIDTH_40MHZ)) {
                wifi_util_error_print(WIFI_DMCLI,
                    "%s:%d: Cannot set tmpChanWidth = %d for band %d\n", __func__, __LINE__,
                    tmpChanWidth, wifiRadioOperParam->band);
                return FALSE;
            }
        }

        if (is_bandwidth_and_hw_variant_compatible(wifiRadioOperParam->variant, tmpChanWidth) !=
            true) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d:tmpChanWidth = %d variant:%d\n", __func__,
                __LINE__, tmpChanWidth, wifiRadioOperParam->variant);
            return FALSE;
        }

        wifiRadioOperParam->channelWidth = tmpChanWidth;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s OperatingChannelBandwidth : %d\n", __FUNCTION__,
            wifiRadioOperParam->channelWidth);
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: New channelWidth=%d\n", __func__, __LINE__,
            wifiRadioOperParam->channelWidth);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "ExtensionChannel", TRUE))
    {
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s Extension Channel : %d\n", __FUNCTION__, uValue);
        if (rcfg->ExtensionChannel == uValue) {
            return TRUE;
        }
        rcfg->ExtensionChannel = uValue; 
        return TRUE;
    }

    if( AnscEqualString(ParamName, "GuardInterval", TRUE))
    {
        wifi_guard_interval_t tmpGuardInterval = 0;

        if (guardIntervalDmlEnumtoHalEnum(uValue, &tmpGuardInterval) != ANSC_STATUS_SUCCESS)
        {
            return FALSE;
        }

        if(wifiRadioOperParam->guardInterval == tmpGuardInterval)
        {
            return TRUE;
        }

        wifiRadioOperParam->guardInterval = tmpGuardInterval;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s guardInterval : %d\n", __FUNCTION__, wifiRadioOperParam->guardInterval);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:guardInterval=%d tmpChanWidth = %d  \n",__func__, __LINE__,wifiRadioOperParam->guardInterval,tmpGuardInterval);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_RTSThreshold", TRUE))
    {
        if (uValue > 2347)
        {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid RTSThreshold value:%d\n",__func__, __LINE__,uValue);
            return FALSE;
        }

        if (wifiRadioOperParam->rtsThreshold == uValue)
        {
            return  TRUE;
        }
        wifiRadioOperParam->rtsThreshold = uValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s RTSThreshold : %d\n", __FUNCTION__, wifiRadioOperParam->rtsThreshold);
	wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:rtsThreshold=%d tmpChanWidth = %d  \n",__func__, __LINE__,wifiRadioOperParam->rtsThreshold,uValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_FragmentationThreshold", TRUE))
    {
        if (wifiRadioOperParam->fragmentationThreshold  == uValue)
        {
            return  TRUE;
        }

        if (isValidFragmentThreshold(uValue) != TRUE)
        {
            return FALSE;
        }

        wifiRadioOperParam->fragmentationThreshold = uValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s fragmentationThreshold : %d\n", __FUNCTION__, wifiRadioOperParam->fragmentationThreshold);
	wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:fragmentationThreshold=%d  = %d  \n",__func__, __LINE__,wifiRadioOperParam->fragmentationThreshold,uValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_DTIMInterval", TRUE))
    {
        if (wifiRadioOperParam->dtimPeriod == uValue)
        {
            return  TRUE;
        }
        if (uValue > 255)
        {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid DTIM Interval value:%u\n",__func__, __LINE__,uValue);
            return FALSE;
        }

        /* save update to backup */
        wifiRadioOperParam->dtimPeriod = uValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s dtimPeriod : %d\n", __FUNCTION__, wifiRadioOperParam->dtimPeriod);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:dtimPeriod=%d  = %d  \n",__func__, __LINE__,wifiRadioOperParam->dtimPeriod,uValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_BeaconInterval", TRUE) || AnscEqualString(ParamName,"BeaconPeriod", TRUE))
    {
        if(wifiRadioOperParam->beaconInterval == uValue)
	{
            return  TRUE;
        }

        if (uValue < 100 || uValue > 3500)
        {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid Beacon Interval value:%lu\n",__func__, __LINE__, uValue);
            return FALSE;
        }

        wifiRadioOperParam->beaconInterval = uValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s beaconInterval : %d\n", __FUNCTION__, wifiRadioOperParam->beaconInterval);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:beaconInterval=%d  = %d  \n",__func__, __LINE__,wifiRadioOperParam->beaconInterval,uValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_TxRate", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Cannot set TxRate \n",__func__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_BasicRate", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Cannot set BasicRate \n",__func__,__LINE__);
        return FALSE;
    }
	
    if( AnscEqualString(ParamName, "X_CISCO_COM_CTSProtectionMode", TRUE))
    {
        if(wifiRadioOperParam->ctsProtection == uValue)
        {
            return  TRUE;
        }

        wifiRadioOperParam->ctsProtection = uValue;
        ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s ctsProtection : %d\n", __FUNCTION__, wifiRadioOperParam->ctsProtection);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:ctsProtection=%d  = %d  \n",__func__, __LINE__,wifiRadioOperParam->ctsProtection,uValue);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_ChanUtilSelfHealEnable", TRUE))
    {
        if(wifiRadioOperParam->chanUtilSelfHealEnable == uValue)
        {
            return  TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d cannot set ChanUtilSelfHealEnable \n",__func__, __LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_ChannelUtilThreshold", TRUE))
    {
        if(wifiRadioOperParam->chanUtilThreshold == uValue)
        {
            return  TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Cannot set ChannelUtilThreshold \n",__func__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "X_RDK_OffChannelTscan", TRUE))
    {
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
        if(!(is_radio_band_5G(wifiRadioOperParam->band)))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Not set for 5GHz radio\n", __func__, __LINE__);
            return TRUE;
        }

        if(fcfg->OffChanTscanInMsec != uValue)
        {
            fcfg->OffChanTscanInMsec = uValue;
            is_radio_config_changed = TRUE;
        }
        return TRUE;
#else //FEATURE_OFF_CHANNEL_SCAN_5G
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d OffChannel distro absent\n", __func__, __LINE__);
        return FALSE;
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
    }

    if( AnscEqualString(ParamName, "X_RDK_OffChannelNscan", TRUE))
    {
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
        if(!(is_radio_band_5G(wifiRadioOperParam->band)))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Not set for 5GHz radio\n", __func__, __LINE__);
            return TRUE;
        }
        //Converting from number to sec
        if (uValue != 0)
        {
            ULONG Nscan_sec = 24*3600/(uValue);
            if (fcfg->OffChanNscanInSec != Nscan_sec)
            {
                fcfg->OffChanNscanInSec = Nscan_sec;
                is_radio_config_changed = TRUE;
            }
            return TRUE;
        }
        else
        {
            if (fcfg->OffChanNscanInSec != 0)
            {
                fcfg->OffChanNscanInSec = 0;
                is_radio_config_changed = TRUE;
            }
            return TRUE;
        }
#else //FEATURE_OFF_CHANNEL_SCAN_5G
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d OffChannel distro absent\n", __func__, __LINE__);
        return FALSE;
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
    }

    if( AnscEqualString(ParamName, "X_RDK_OffChannelTidle", TRUE))
    {
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
        if(!(is_radio_band_5G(wifiRadioOperParam->band)))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Not set for 5GHz radio\n", __func__, __LINE__);
            return TRUE;
        }

        if(fcfg->OffChanTidleInSec != uValue)
        {
            fcfg->OffChanTidleInSec = uValue;
            is_radio_config_changed = TRUE;
        }
        return TRUE;
#else //FEATURE_OFF_CHANNEL_SCAN_5G
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d OffChannel distro absent\n", __func__, __LINE__);
        return FALSE;
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
    }

    return FALSE;
}

BOOL isValidTransmitRate(char *Btr)
{
    BOOL isValid=false;
    if (!Btr)
    {
        return isValid;
    }
    else
    {
        int i=0;
        int len;
        len=strlen(Btr);
        for(i=0;i<len;i++)
        {
           if(isdigit(Btr[i]) || Btr[i]==',' || Btr[i]=='.')
           {
              isValid=true;
           }
           else
           {
              isValid=false;
              break;
           }
         }
     }
     return isValid;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Radio_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Radio_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_radio_operationParam_t *wifi_radio = (wifi_radio_operationParam_t *)hInsContext;

    if (wifi_radio == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    INT instance_number = 0;
    wifi_global_config_t *global_wifi_config;
    if (convert_freq_band_to_radio_index(wifi_radio->band, &instance_number) ==  RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, wifi_radio->band);
        return FALSE;
    }
    wifi_radio_operationParam_t *wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(instance_number);
    UINT wlanIndex = 0;
    UINT txRate = 0;

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if ((instance_number < 0) || (instance_number > (INT)get_num_radio_dml()))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, Radio instanceNumber:%d out of range\n", instance_number));
        return FALSE;
    }

    wlanIndex = instance_number;
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s wlanIndex : %d\n", __FUNCTION__, wlanIndex);

    if (wifiRadioOperParam == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d not found for wifiRadioOperParam\n", __FUNCTION__, wlanIndex));
        return FALSE;
    }
    dml_radio_default *rcfg = (dml_radio_default *) get_radio_default_obj(instance_number);

    if(rcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        if ( AnscEqualString(pString, rcfg->Alias, TRUE)) {
                return TRUE;
        }
        strncpy(rcfg->Alias,pString,sizeof(rcfg->Alias)-1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        /*TR-181: Since Radio is a layer 1 interface, 
          it is expected that LowerLayers will not be used
         */
        /* User shouldnt be able to set a value for this */
        return FALSE;
    }

    if( AnscEqualString(ParamName, "RegulatoryDomain", TRUE))
    {
        char regulatoryDomainStr[4];
        size_t reg_len;
        size_t p_len;
        char PartnerID[PARTNER_ID_LEN] = {0};
        char * currentTime = getTime();
        char * requestorStr = getRequestorString();

        memset(regulatoryDomainStr, 0, sizeof(regulatoryDomainStr));
        getRegulatoryDomainFromEnums(wifiRadioOperParam->countryCode, wifiRadioOperParam->operatingEnvironment, regulatoryDomainStr);
        reg_len = strlen(regulatoryDomainStr);
        p_len = strlen(pString);

        if (p_len == reg_len)
        {
            if (!strncmp(pString, regulatoryDomainStr, strlen(regulatoryDomainStr)))
            {
                return TRUE;
            }
        }

        if (regDomainStrToEnums(pString, &wifiRadioOperParam->countryCode, &wifiRadioOperParam->operatingEnvironment) != ANSC_STATUS_SUCCESS)
        {
            return FALSE;
        }
        
        if (instance_number == 1) 
        {
            global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();
            snprintf(global_wifi_config->global_parameters.wifi_region_code, sizeof(global_wifi_config->global_parameters.wifi_region_code), "%s", pString);
            g_update_wifi_region = TRUE;
            if((CCSP_SUCCESS == getPartnerId(PartnerID) ) && (PartnerID[ 0 ] != '\0') )
            {
                if (UpdateJsonParam("Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code",PartnerID, pString, requestorStr, currentTime) != ANSC_STATUS_SUCCESS)
                {
                    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to update WifiRegion to Json file\n", __func__, __LINE__);
                }
            }
            snprintf(wifiRegionUpdateSource, 16, "%s", requestorStr);

        }

        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: country code=%d  environment=%d  pString=%s\n",__func__, __LINE__,wifiRadioOperParam->countryCode, wifiRadioOperParam->operatingEnvironment, pString);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    if(AnscEqualString(ParamName, "BasicDataTransmitRates", TRUE))
    {
        if(isValidTransmitRate(pString))
        {
            if (txRateStrToUint(pString, &txRate) != ANSC_STATUS_SUCCESS)
            {
                return FALSE;
            }

            if( wifiRadioOperParam->basicDataTransmitRates == txRate)
            {
                return TRUE;
            }
            wifiRadioOperParam->basicDataTransmitRates = txRate;
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:BasicDataTransmitRates=%d =%d\n",__func__,__LINE__,wifiRadioOperParam->basicDataTransmitRates,txRate);
            is_radio_config_changed = TRUE;
            return TRUE;
        }

    }
    if(AnscEqualString(ParamName, "OperationalDataTransmitRates", TRUE))
    {
        if(isValidTransmitRate(pString))
        {
            if (txRateStrToUint(pString, &txRate) != ANSC_STATUS_SUCCESS)
            {
                return FALSE;
            }

            if( wifiRadioOperParam->operationalDataTransmitRates == txRate)
            {
                return TRUE;
            }

            wifiRadioOperParam->operationalDataTransmitRates = txRate;
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:OperationalDataTransmitRates=%d =%d\n",__func__,__LINE__,wifiRadioOperParam->operationalDataTransmitRates,txRate);
            is_radio_config_changed = TRUE;
            return TRUE;

        }
    }

    if(AnscEqualString(ParamName, "OperatingStandards", TRUE)) {
        wifi_ieee80211Variant_t wifi_variant;
        wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

        if ((wifi_radio->band == WIFI_FREQUENCY_2_4_BAND) &&
                (rfc_pcfg->twoG80211axEnable_rfc == false) &&
                (strstr(pString, "ax") != NULL)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: wifi hw variant:%s radio_band:%d 80211axEnable rfc:%d\n",
                    __func__, __LINE__, pString, wifi_radio->band, rfc_pcfg->twoG80211axEnable_rfc);
            return FALSE;
        }

        if (wifiStdStrToEnum(pString, &wifi_variant,instance_number) != ANSC_STATUS_SUCCESS) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: wrong wifi std String=%s\n",__func__, __LINE__,pString);
            return FALSE;
        }

        // TODO: for debug purpouses only
        static const char * const wifi_mode_strings[] =
        {
            "WIFI_80211_VARIANT_A",
            "WIFI_80211_VARIANT_B",
            "WIFI_80211_VARIANT_G",
            "WIFI_80211_VARIANT_N",
            "WIFI_80211_VARIANT_H",
            "WIFI_80211_VARIANT_AC",
            "WIFI_80211_VARIANT_AD",
            "WIFI_80211_VARIANT_AX",
#ifdef CONFIG_IEEE80211BE
            "WIFI_80211_VARIANT_BE",
#endif /* CONFIG_IEEE80211BE */
        };

        for (size_t i = 0; i < (sizeof(wifi_mode_strings) / sizeof(wifi_mode_strings[0])); i++) {
            if (wifi_variant & (1ul << i))
                wifi_util_dbg_print(WIFI_DMCLI, "WIFI MODE SET[%d]: %s\n", i, wifi_mode_strings[i]);
        }
        if (validate_wifi_hw_variant(wifi_radio->band, wifi_variant) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: wifi hw mode std validation failure string=%s hw variant:%d\n",__func__, __LINE__,pString, wifi_variant);
            return FALSE;
        }

        uint32_t temp_channel_width = sync_bandwidth_and_hw_variant(wifi_variant, wifiRadioOperParam->channelWidth);
        if (temp_channel_width != 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d:change bandwidth from %d to %d\r\n",__func__, __LINE__, wifiRadioOperParam->channelWidth, temp_channel_width);
            wifiRadioOperParam->channelWidth = temp_channel_width;
        }

        wifiRadioOperParam->variant = wifi_variant;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:variant=%d  pString=%s\n",__func__, __LINE__,wifi_variant, pString);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Radio_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
Radio_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Radio_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Radio_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    //Need to add handlers for Bansteer
    return TRUE; 
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Radio_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Radio_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

ULONG
ReceivedSignalLevel_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

ANSC_HANDLE
ReceivedSignalLevel_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    return NULL; 
}


BOOL
ReceivedSignalLevel_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
	
    if(!hInsContext)
        return FALSE;
	
    if( AnscEqualString(ParamName, "ReceivedSignalLevel", TRUE))   {
        return TRUE;
    }
    return FALSE;		
}

/***********************************************************************

 APIs for Object:

    WiFi.Radio.{i}.Stats.

    *  Stats3_SetParamBoolValue
    *  Stats3_GetParamIntValue
    *  Stats3_GetParamUlongValue
    *  Stats3_GetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats3_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats3_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
	return TRUE;
}

ULONG
Stats3_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

BOOL
Stats3_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        *pBool
    )
{

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "X_COMCAST-COM_RadioStatisticsEnable", TRUE))    {
         return TRUE;
    }	
    return FALSE;
}

BOOL
Stats3_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    if( AnscEqualString(ParamName, "X_COMCAST-COM_RadioStatisticsEnable", TRUE))   {
        return TRUE;
    }
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats3_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats3_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)hInsContext;
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    INT instance_number = 0;
    bool is_aftx;
    if (convert_freq_band_to_radio_index(pcfg->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, pcfg->band);
        return FALSE;
    }
    dml_stats_default *stats = (dml_stats_default *)get_stats_default_obj(instance_number);

    if(stats == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if(monitor_param == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "X_COMCAST-COM_NoiseFloor", TRUE))    {
        *pInt = monitor_param->radio_data[instance_number].NoiseFloor; 
        return TRUE;
    }
    if( AnscEqualString(ParamName, "Noise", TRUE))    {
	*pInt = monitor_param->radio_data[instance_number].NoiseFloor;
	return TRUE;
    }
    if ((is_aftx = AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AFTX", TRUE)) ||
        AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AFRX", TRUE)) {
        unsigned long long utilization_rx = 0;
        unsigned long long utilization_tx = 0;
        unsigned long long utilization_total;
        int i = 0;
        unsigned int radio_activity_factor;
        pthread_mutex_lock(&monitor_param->data_lock);
        radio_activity_factor =
            monitor_param->radio_data[instance_number].RadioActivityFactor;
        while ((i++) < monitor_param->radio_chan_stats_data[instance_number]
                           .num_channels) {
            utilization_rx +=
                monitor_param->radio_chan_stats_data[instance_number]
                    .chan_data[i]
                    .ch_utilization_busy_self;
            utilization_tx +=
                monitor_param->radio_chan_stats_data[instance_number]
                    .chan_data[i]
                    .ch_utilization_busy_tx;
        }
        pthread_mutex_unlock(&monitor_param->data_lock);
        utilization_total = utilization_rx + utilization_tx;
        if (0 != utilization_total) {
            *pInt = (int)round((1.0 * (is_aftx ? utilization_tx : utilization_rx)) / utilization_total * radio_activity_factor);
        } else {
            *pInt = (is_aftx ? stats->ActivityFactor_TX : stats->ActivityFactor_RX);
        }
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_ActivityFactor", TRUE) || AnscEqualString(ParamName, "X_RDKCENTRAL-COM_AF", TRUE))    {
        *pInt = monitor_param->radio_data[instance_number].RadioActivityFactor;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_CarrierSenseThreshold_Exceeded", TRUE) || AnscEqualString(ParamName, "X_RDKCENTRAL-COM_CSTE", TRUE))    {
        *pInt = monitor_param->radio_data[instance_number].CarrierSenseThreshold_Exceeded;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_RetransmissionMetric", TRUE))     {
         *pInt = stats->RetransmissionMetric;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_MaximumNoiseFloorOnChannel", TRUE))    {
        *pInt = stats->MaximumNoiseFloorOnChannel;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_MinimumNoiseFloorOnChannel", TRUE))   {
        *pInt = stats->MinimumNoiseFloorOnChannel;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_MedianNoiseFloorOnChannel", TRUE))    {
        *pInt = stats->MedianNoiseFloorOnChannel;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_RadioStatisticsMeasuringRate", TRUE)) {
        *pInt = stats->RadioStatisticsMeasuringRate;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_RadioStatisticsMeasuringInterval", TRUE))    {
        *pInt = stats->RadioStatisticsMeasuringInterval;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats3_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats3_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)hInsContext;
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, pcfg->band);
        return FALSE;
    }
    dml_stats_default *stats = (dml_stats_default *)get_stats_default_obj(instance_number);

    if(stats == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if(monitor_param == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "BytesSent", TRUE))   {
        *puLong = monitor_param->radio_data[instance_number].radio_BytesSent;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "BytesReceived", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].radio_BytesReceived;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "PacketsSent", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].radio_PacketsSent;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "PacketsReceived", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].radio_PacketsReceived;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "ErrorsSent", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].radio_ErrorsSent;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "ErrorsReceived", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].radio_ErrorsReceived;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "DiscardPacketsSent", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].radio_DiscardPacketsSent;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "DiscardPacketsReceived", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].radio_DiscardPacketsReceived;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "PLCPErrorCount", TRUE))    {
        *puLong = stats->PLCPErrorCount;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "FCSErrorCount", TRUE))    {
        *puLong = stats->FCSErrorCount;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "InvalidMACCount", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number-1].radio_InvalidMACCount;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "PacketsOtherReceived", TRUE))    {
        *puLong = stats->PacketsOtherReceived;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_ChannelUtilization", TRUE))    {
        *puLong = monitor_param->radio_data[instance_number].channelUtil;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_StatisticsStartTime", TRUE))    {
        *puLong = stats->StatisticsStartTime;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats3_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                        iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                        iValue
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats3_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{

    wifi_radio_operationParam_t *wifi_radio = (wifi_radio_operationParam_t *)hInsContext;

    if (wifi_radio == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    INT instance_number = 0;
    if (convert_freq_band_to_radio_index(wifi_radio->band, &instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __FUNCTION__, __LINE__, wifi_radio->band);
        return FALSE;
    }
    wifi_radio_operationParam_t *wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(instance_number);

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
 
    if( AnscEqualString(ParamName, "X_COMCAST-COM_RadioStatisticsMeasuringRate", TRUE))   {
        if( wifi_radio->radioStatsMeasuringRate == (UINT)iValue)
        {
            return TRUE;
        }

        wifi_radio->radioStatsMeasuringRate = iValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:value=%d\n",__func__, __LINE__,wifi_radio->radioStatsMeasuringRate);
        is_radio_config_changed = TRUE;
        return TRUE;
    }
   if( AnscEqualString(ParamName, "X_COMCAST-COM_RadioStatisticsMeasuringInterval", TRUE))    {
        if( wifi_radio->radioStatsMeasuringInterval == (UINT)iValue)
        {
            return TRUE;
        }

        wifi_radio->radioStatsMeasuringInterval = iValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:value=%d\n",__func__, __LINE__,wifi_radio->radioStatsMeasuringInterval);
        is_radio_config_changed = TRUE;
        return TRUE;
    }
    return FALSE;
}

BOOL
Stats3_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    	
    return TRUE;
}

ULONG
Stats3_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS; 
}

/***********************************************************************

  APIs for Object:

 WiFi.Radio.{i}.AMSDU_TID.{i}.Enabled

   *  AMSDU_TID_GetEntryCount
   *  AMSDU_TID_GetEntry
   *  AMSDU_TID_GetParamBoolValue
   *  AMSDU_TID_SetParamBoolValue

 ***********************************************************************/
/**********************************************************************

        caller:	 owner of this object

  prototype:

    ULONG
    AMSDU_TID_GetEntryCount
      (
        ANSC_HANDLE         hInsContext
      );

  description:

    This function is called to retrieve the count of the table.

  argument:   ANSC_HANDLE         hInsContext,
        The instance handle;

  return:   The count of the table

**********************************************************************/
ULONG
AMSDU_TID_GetEntryCount(ANSC_HANDLE hInsContext)
{
    UNREFERENCED_PARAMETER(hInsContext);
    return MAX_AMSDU_TID;
}

/**********************************************************************

  caller:   owner of this object

  prototype:

    ANSC_HANDLE
    AMSDU_TID_GetEntry
      (
        ANSC_HANDLE         hInsContext,
        ULONG            nIndex,
        ULONG*            pInsNumber
      );

  description:

    This function is called to retrieve the entry specified by the index.

  argument:  ANSC_HANDLE         hInsContext,
        The instance handle;

        ULONG            nIndex,
        The index of this entry;

        ULONG*            pInsNumber
        The output instance number;

  return:   The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
AMSDU_TID_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG *pInsNumber)
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: nIndex:%ld\n", __func__, __LINE__, nIndex);
    wifi_radio_operationParam_t *wifiRadioOperParam = (wifi_radio_operationParam_t *)hInsContext;

    INT radio_instance_number = 0;

    if (nIndex >= MAX_AMSDU_TID) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Bad AMSDU TID idx specified: %ld\n", __func__,__LINE__, nIndex);
        return NULL;
    }

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Failed to get wifiRadioOperParam\n", __func__,__LINE__);
        return FALSE;
    }

    if (convert_freq_band_to_radio_index(wifiRadioOperParam->band, &radio_instance_number) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid frequency band - can't decode radio idx %X\n", __func__, __LINE__, wifiRadioOperParam->band);
        return FALSE;
    }

    if ((radio_instance_number < 0) || (radio_instance_number > (INT)get_num_radio_dml()))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Radio instanceNumber:%d out of range\n", __func__,__LINE__, radio_instance_number);
        return FALSE;
    }

    *pInsNumber = nIndex + 1;
    return (ANSC_HANDLE) ((radio_instance_number << 8) + *pInsNumber);
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AMSDU_TID_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL AMSDU_TID_SetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL bValue)
{
#if !defined(_XB8_PRODUCT_REQ_) && !defined(_XB10_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_)
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d AMSDU not supported on the device\n", __func__,
        __LINE__);
    return FALSE;
#else


    unsigned long amsdu_mask = (unsigned long)hInsContext;
    uint8_t radio_instance_number = amsdu_mask >> 8;
    uint8_t tid_idx = (amsdu_mask & 0xf) - 1;

    wifi_radio_operationParam_t *wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(radio_instance_number);

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __func__, __LINE__, radio_instance_number);
        return FALSE;
    }

    if ((radio_instance_number < 0) || (radio_instance_number > (INT)get_num_radio_dml()))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Radio instanceNumber:%d out of range\n", __func__, __LINE__, radio_instance_number);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Enable", TRUE)) {
        BOOL *is_enabled = (BOOL *)&wifiRadioOperParam->amsduTid[tid_idx];
        if (!is_enabled) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Invalid TID for AMSDU - param was %s\n",
                __func__, __LINE__, ParamName);
            return FALSE;
        }

        if (*is_enabled == bValue) {
            return TRUE;
        }

        *is_enabled = bValue;
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d:value=%d\n", __func__, __LINE__, *is_enabled);
        is_radio_config_changed = TRUE;
        return TRUE;
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d AMSDU param is malformed - param was %s \n", __func__,
        __LINE__, ParamName);
    return FALSE;

#endif
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AMSDU_TID_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve bool parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned bool value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL AMSDU_TID_GetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL *pBool)
{
#if !defined(_XB8_PRODUCT_REQ_) && !defined(_XB10_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_)
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d AMSDU not supported on the device\n", __func__,
        __LINE__);
    return FALSE;
#else

    unsigned long amsdu_mask = (unsigned long)hInsContext;
    uint8_t radio_instance_number = amsdu_mask >> 8;
    uint8_t tid_idx = (amsdu_mask & 0xf) - 1;

    wifi_radio_operationParam_t *wifiRadioOperParam = get_dml_radio_operation_param(radio_instance_number);

    if (wifiRadioOperParam == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __func__, __LINE__, radio_instance_number);
        return FALSE;
    }

    if ((radio_instance_number < 0) || (radio_instance_number > (INT)get_num_radio_dml()))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Radio instanceNumber:%d out of range\n", __func__, __LINE__, radio_instance_number);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Enable", TRUE)) {
        *pBool = wifiRadioOperParam->amsduTid[tid_idx];
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d:value=%d\n", __func__, __LINE__, *pBool);
        return TRUE;
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d AMSDU GET param is malformed - param was %s \n",
        __func__, __LINE__, ParamName);
    return FALSE;
#endif
}

BOOL AMSDU_TID_Validate(ANSC_HANDLE hInsContext, char *pReturnParamName, ULONG *puLength)
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

ULONG
AMSDU_TID_Commit(ANSC_HANDLE hInsContext)
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

ULONG
AMSDU_TID_Rollback(ANSC_HANDLE hInsContext)
{
    return ANSC_STATUS_SUCCESS;
}

/***********************************************************************

 APIs for Object:

    WiFi.SSID.{i}.

    *  SSID_GetEntryCount
    *  SSID_GetEntry
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
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SSID_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
SSID_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: total number of vaps:%d get_total_num_vap_dml():%d\n",__func__, __LINE__, get_num_radio_dml() * MAX_NUM_VAP_PER_RADIO, get_total_num_vap_dml());
    return get_total_num_vap_dml();
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        SSID_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
SSID_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_vap_info_t *vapInfo = NULL;

    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: get_total_num_vap_dml():%d nIndex:%d\n",__func__, __LINE__, get_total_num_vap_dml(), nIndex);
    if (nIndex >= 0 && nIndex <= (UINT)get_total_num_vap_dml())
    {
        UINT vapIndex = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, nIndex);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: nIndex:%d -> vapIndex:%d\n", __func__, __LINE__, nIndex, vapIndex);
        vapInfo = (wifi_vap_info_t *) get_dml_vap_parameters(vapIndex);
        if(vapInfo == NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: get_dml_vap_parameters == NULL nIndex:%d vapIndex:%d\n",__func__, __LINE__, nIndex, vapIndex);
        }
        *pInsNumber = vapIndex + 1;
    }
    last_vap_change = AnscGetTickInSeconds(); 
    return (ANSC_HANDLE) vapInfo; /* return the handle */
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SSID_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    ULONG vap_index = 0;
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);

    if(cfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
            return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if (global_wifi_config->global_parameters.force_disable_radio_feature == TRUE)
        {
            *pBool = FALSE;
            return TRUE;
        }

        if (isVapSTAMesh(pcfg->vap_index)) {
            *pBool = pcfg->u.sta_info.enabled;
            return TRUE;
        }
        *pBool = pcfg->u.bss_info.enabled;
        return TRUE;
    }
    
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "X_CISCO_COM_EnableOnline", TRUE))
    {
        if (isVapSTAMesh(pcfg->vap_index)) {
            *pBool = pcfg->u.sta_info.enabled;
            return TRUE;
        }
        *pBool = pcfg->u.bss_info.enabled;
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "X_CISCO_COM_RouterEnabled", TRUE))
    {
        *pBool = cfg->router_enabled;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SSID_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SSID_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        if (global_wifi_config->global_parameters.force_disable_radio_feature == TRUE ||
            ((webconfig_dml_t *)get_webconfig_dml())->radios[pcfg->radio_index].oper.enable == false)
        {
            *puLong = 2;
            return TRUE;
        }

        if (isVapSTAMesh(pcfg->vap_index)) {
            if( pcfg->u.sta_info.enabled == TRUE )
            {
                *puLong = 1;
            }
            else
            {
                *puLong = 2;
            }
            return TRUE;
        }

        /* collect value */
        if( pcfg->u.bss_info.enabled == TRUE )
        {
            *puLong = 1;
        }
        else
        {
            *puLong = 2;
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "LastChange", TRUE))
    {
        /* collect value */
        *puLong  = AnscGetTimeIntervalInSeconds(last_vap_change, AnscGetTickInSeconds());
        return TRUE;
    }


    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SSID_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
SSID_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    CHAR str[32] = {0};
    uint8_t instance_number = (uint8_t)convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name) +1;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    memset(str,0,sizeof(str));
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* collect value */
        if(instance_number>(MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO) || instance_number<0)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d invalid vap instance %d\n", __FUNCTION__,__LINE__,instance_number);
            return FALSE;
        }
        convert_apindex_to_ifname(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, instance_number-1,str,sizeof(str)-1);
        AnscCopyString(pValue,str);
        return 0;
    }

    if( AnscEqualString(ParamName, "Name", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pcfg->vap_name);
        return 0;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        int radioIndex = convert_vap_name_to_radio_array_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);

        /* collect value */
        _ansc_sprintf(str, "Device.WiFi.Radio.%d.", radioIndex+1);
        AnscCopyString(pValue, str);
        return 0;
    }

    if( AnscEqualString(ParamName, "BSSID", TRUE))
    {
	char buff[24] = {0};

        if (isVapSTAMesh(pcfg->vap_index)) {
            _ansc_sprintf
            (
                buff,
                "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.sta_info.bssid[0],
                pcfg->u.sta_info.bssid[1],
                pcfg->u.sta_info.bssid[2],
                pcfg->u.sta_info.bssid[3],
                pcfg->u.sta_info.bssid[4],
                pcfg->u.sta_info.bssid[5]
            );
        } else {
            _ansc_sprintf
            (
                buff,
                "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.bss_info.bssid[0],
                pcfg->u.bss_info.bssid[1],
                pcfg->u.bss_info.bssid[2],
                pcfg->u.bss_info.bssid[3],
                pcfg->u.bss_info.bssid[4],
                pcfg->u.bss_info.bssid[5]
            );
        }
	memcpy(pValue, buff, strlen(buff)+1);
        return 0;
    }

    if( AnscEqualString(ParamName, "MACAddress", TRUE))
    {
        char buff[24] = {0};
        if (isVapSTAMesh(pcfg->vap_index)) {
            _ansc_sprintf
            (
                buff,
                "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.sta_info.mac[0],
                pcfg->u.sta_info.mac[1],
                pcfg->u.sta_info.mac[2],
                pcfg->u.sta_info.mac[3],
                pcfg->u.sta_info.mac[4],
                pcfg->u.sta_info.mac[5]
            );
        } else {
            _ansc_sprintf
            (
                buff,
                "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.bss_info.bssid[0],
                pcfg->u.bss_info.bssid[1],
                pcfg->u.bss_info.bssid[2],
                pcfg->u.bss_info.bssid[3],
                pcfg->u.bss_info.bssid[4],
                pcfg->u.bss_info.bssid[5]
            );
        }
        memcpy(pValue, buff, strlen(buff)+1);
        return 0;
  }

    if( AnscEqualString(ParamName, "SSID", TRUE))
    {
        /* collect value */
        if(isVapSTAMesh(pcfg->vap_index)){
            AnscCopyString(pValue, pcfg->u.sta_info.ssid);
            return 0;
        } else {
            AnscCopyString(pValue, pcfg->u.bss_info.ssid);
            return 0;
        }
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_DefaultSSID", TRUE))
    {
        /* collect value */
        char ssid[128] = {0};
        if (wifi_hal_get_default_ssid(ssid, pcfg->vap_index) == RETURN_OK) {
            AnscCopyString(pValue, ssid);
            return 0;
        }

    }

    if( AnscEqualString(ParamName, "Repurposed_VapName", TRUE))
    {
        /* collect value */
        if (strlen(pcfg->repurposed_vap_name) != 0) {
            AnscCopyString(pValue, pcfg->repurposed_vap_name);
        }
        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SSID_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = (uint8_t)convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name) +1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    ULONG vap_index = 0;
    vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);

    if(cfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
            return FALSE;
    }
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        rdk_wifi_vap_info_t *rdk_vap_info;
        rdk_vap_info = (rdk_wifi_vap_info_t *)get_dml_cache_rdk_vap_info(vapInfo->vap_index);

        if (bValue == true) {
            rdk_vap_info->exists = bValue;
        }

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
        if (bValue == false) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d User is Trying to disable SSID for vap_index=%d\n",__FUNCTION__,__LINE__,vapInfo->vap_index);
        }
#endif
        set_dml_cache_vap_config_changed(instance_number - 1);

        if (isVapSTAMesh(pcfg->vap_index)) {
            if (vapInfo->u.sta_info.enabled == bValue)
            {
                return  TRUE;
            }

            vapInfo->u.sta_info.enabled = bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }

        /* SSID Enable object can be modified only when ForceDisableRadio feature is disabled */
        if(!(global_wifi_config->global_parameters.force_disable_radio_feature)) {
            if (vapInfo->u.bss_info.enabled == bValue)
            {
                return  TRUE;
            }

            vapInfo->u.bss_info.enabled = bValue;
	    set_dml_cache_vap_config_changed(instance_number - 1);
        } else {
            CcspWifiTrace(("RDK_LOG_ERROR, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n" ));
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n",__FUNCTION__,__LINE__,pcfg->vap_name);
            return FALSE;
        }
        return TRUE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_CISCO_COM_EnableOnline", TRUE))
    {
        if (isVapSTAMesh(pcfg->vap_index)) {
            if (vapInfo->u.sta_info.enabled == bValue)
            {
                return  TRUE;
            }

            vapInfo->u.sta_info.enabled = bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }

        /* SSID Enable object can be modified only when ForceDisableRadio feature is disabled */
        if(!(global_wifi_config->global_parameters.force_disable_radio_feature)){
            if (vapInfo->u.bss_info.enabled == bValue) {
                return  TRUE;
            }

            vapInfo->u.bss_info.enabled = bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        } else {
            CcspWifiTrace(("RDK_LOG_ERROR, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n" ));
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n",__FUNCTION__,__LINE__,pcfg->vap_name);
            return FALSE;
        }
        return TRUE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_CISCO_COM_RouterEnabled", TRUE))
    {
        /* SSID Enable object can be modified only when ForceDisableRadio feature is disabled */
        if(!(global_wifi_config->global_parameters.force_disable_radio_feature)) {
            if (cfg->router_enabled == bValue) {
                return  TRUE;
            }
            cfg->router_enabled = bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
        else {
            CcspWifiTrace(("RDK_LOG_ERROR, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n" ));
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n",__FUNCTION__,__LINE__,pcfg->vap_name);
            return FALSE;
        }
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SSID_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SSID_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SSID_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name) +1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* save update to backup */
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Does not support modification\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Does not support modification\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ( AnscEqualString(ParamName, "SSID", TRUE) )
    {
        if(global_wifi_config->global_parameters.force_disable_radio_feature)
        {
             CcspWifiTrace(("RDK_LOG_ERROR, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n" ));
             wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n",__FUNCTION__,__LINE__,pcfg->vap_name);
             return FALSE;
        }
        if (isVapSTAMesh(vapInfo->vap_index)) {
            if ( AnscEqualString(vapInfo->u.sta_info.ssid, pString, TRUE) ) {
                return  TRUE;
            }
            snprintf(vapInfo->u.sta_info.ssid,sizeof(vapInfo->u.sta_info.ssid),"%s",pString);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }

        if ( AnscEqualString(vapInfo->u.bss_info.ssid, pString, TRUE) )
        {
            return  TRUE;
        }

        if (IsSsidHotspot(instance_number) )
	{
	    if(AnscEqualString(pString, "OutOfService", FALSE)) /* case insensitive */
	    {
                vapInfo->u.bss_info.enabled = FALSE;
	        fprintf(stderr, "%s: Disable HHS SSID since it's set to OutOfService\n", __FUNCTION__);
	    }
	    else
	    {
                isHotspotSSIDIpdated = TRUE;
	    }
	}
	snprintf(vapInfo->u.bss_info.ssid,sizeof(vapInfo->u.bss_info.ssid),"%s",pString);
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SSID_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
SSID_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SSID_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SSID_Commit
    (
        ANSC_HANDLE                 hInsContext
    )

{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SSID_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SSID_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/***********************************************************************

 APIs for Object:

    WiFi.SSID.{i}.Stats.

    *  Stats4_GetParamBoolValue
    *  Stats4_GetParamIntValue
    *  Stats4_GetParamUlongValue
    *  Stats4_GetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats4_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats4_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pBool);
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats4_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats4_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats4_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats4_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "BytesSent", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "BytesReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PacketsSent", TRUE))
    {
        *puLong = 0; 
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PacketsReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "ErrorsSent", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "ErrorsReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UnicastPacketsSent", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UnicastPacketsReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "DiscardPacketsSent", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "DiscardPacketsReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MulticastPacketsSent", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MulticastPacketsReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "BroadcastPacketsSent", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "BroadcastPacketsReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UnknownProtoPacketsReceived", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RetransCount", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "FailedRetransCount", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RetryCount", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MultipleRetryCount", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }
    

    if( AnscEqualString(ParamName, "ACKFailureCount", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "AggregatedPacketCount", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }
	/* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Stats4_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
Stats4_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pValue);
    UNREFERENCED_PARAMETER(pUlSize);
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.

    *  AccessPoint_GetEntryCount
    *  AccessPoint_GetEntry
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
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AccessPoint_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
AccessPoint_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);    

    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: total number of vaps:%d get_total_num_vap_dml():::%d\n",__func__, __LINE__, get_num_radio_dml() * MAX_NUM_VAP_PER_RADIO, get_total_num_vap_dml());    
    return get_total_num_vap_dml();
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        AccessPoint_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
AccessPoint_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_vap_info_t * vapInfo = NULL;

    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: total number of vaps:%d nIndex:%d\n",__func__, __LINE__, get_total_num_vap_dml(), nIndex);
    if ( nIndex >= 0 && nIndex <= (UINT)get_total_num_vap_dml() )
    {
        UINT vapIndex = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, nIndex);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: nIndex:%d -> vapIndex:%d\n", __func__, __LINE__, nIndex, vapIndex);
        vapInfo = (wifi_vap_info_t *) get_dml_vap_parameters(vapIndex);
        if(vapInfo == NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: vap parameter is NULL nIndex:%d vapIndex:%d\n",__func__, __LINE__, nIndex, vapIndex);
        }
        *pInsNumber = vapIndex + 1;
    }

    return (ANSC_HANDLE)vapInfo; /* return the handle */
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AccessPoint_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    ULONG vap_index = 0;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);

    if(cfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* collect value */
        if (isVapSTAMesh(pcfg->vap_index)) {
            *pBool = pcfg->u.sta_info.enabled;
            return TRUE;
        }
        *pBool = pcfg->u.bss_info.enabled;
        return TRUE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        *pBool = TRUE;
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "IsolationEnable", TRUE))
    {
        *pBool = pcfg->u.bss_info.isolation;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SSIDAdvertisementEnabled", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.showSsid;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "WMMCapability", TRUE))
    {
        /* collect value */
	*pBool = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UAPSDCapability", TRUE))
    {
        /* collect value */
	*pBool = TRUE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "WMMEnable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.wmm_enabled;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UAPSDEnable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.UAPSDEnabled;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_BssCountStaAsCpe", TRUE))
    {
        /* collect value */
        *pBool = cfg->bss_count_sta_as_cpe;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_BssHotSpot", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.bssHotspot;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_KickAssocDevices", TRUE))
    {
        /* collect value */
        *pBool = cfg->kick_assoc_devices;
        return TRUE;
    }

#if defined (FEATURE_SUPPORT_INTERWORKING)

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_InterworkingServiceCapability", TRUE))
    {
        /* collect value */
        //*pBool = pWifiAp->AP.Cfg.InterworkingCapability;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_InterworkingServiceEnable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.interworking.interworking.interworkingEnabled;
        return TRUE;
    }
#else
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_InterworkingServiceCapability", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_InterworkingServiceEnable", TRUE))
    {
        /* collect value */
        *pBool = FALSE;
        return TRUE;
    }
#endif

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_rapidReconnectCountEnable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.rapidReconnectEnable;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_StatsEnable", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.vapStatsEnable;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_BSSTransitionImplemented", TRUE))
    {
        /* collect value */
        if(isVapHotspot(vap_index) || isVapSTAMesh(vap_index) || (vap_index == 3))
        {
           *pBool = FALSE;
        }
        else
        {
           *pBool = TRUE;
        }
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_BSSTransitionActivated", TRUE))
    {
        /* collect value */
        *pBool = pcfg->u.bss_info.bssTransitionActivated;
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_NeighborReportActivated", TRUE))
    {
        *pBool = pcfg->u.bss_info.nbrReportActivated;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_WirelessManagementImplemented", TRUE))
    {
        *pBool = 1;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_InterworkingApplySettings", TRUE))
    {
        /* always return true when get */
        *pBool = TRUE;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "Connected_Building_Enabled", TRUE)) {
        if(isVapHotspot(vap_index)) {
            *pBool = pcfg->u.bss_info.connected_building_enabled;
        } else {
            *pBool = FALSE;
        }
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_HostapMgtFrameCtrl", TRUE)) {
        *pBool = pcfg->u.bss_info.hostap_mgt_frame_ctrl;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "InteropTelemetryCtrl", TRUE)) {
        *pBool = pcfg->u.bss_info.interop_ctrl;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AccessPoint_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    ULONG vap_index = 0;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);

    if(cfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "X_CISCO_COM_WmmNoAck", TRUE))
    {
        if (isVapSTAMesh(pcfg->vap_index)) {
           *pInt = 0;
           return TRUE;
        }
        *pInt = pcfg->u.bss_info.wmmNoAck;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_MulticastRate", TRUE))
    {
        *pInt = cfg->multicast_rate;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_BssMaxNumSta", TRUE))
    {
        *pInt = pcfg->u.bss_info.bssMaxSta;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_BssUserStatus", TRUE))
    {
        if (isVapSTAMesh(pcfg->vap_index)) {
           *pInt = (pcfg->u.sta_info.enabled == TRUE)? 1 : 2;
           return TRUE;
        }
        *pInt = (pcfg->u.bss_info.enabled == TRUE)? 1 : 2;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_ManagementFramePowerControl", TRUE))
    {
        if (isVapSTAMesh(pcfg->vap_index)) {
           *pInt = 0;
           return TRUE;
        }

        *pInt = pcfg->u.bss_info.mgmtPowerControl;
        CcspWifiTrace(("RDK_LOG_INFO,X_RDKCENTRAL-COM_ManagementFramePowerControl:%d\n",pcfg->u.bss_info.mgmtPowerControl));
        CcspTraceWarning(("X_RDKCENTRAL-COM_ManagementFramePowerControl_Get:<%d>\n", pcfg->u.bss_info.mgmtPowerControl));
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_rapidReconnectMaxTime", TRUE) )
    {
        if (isVapSTAMesh(pcfg->vap_index)) {
           *pInt = 180;
           return TRUE;
        }
        *pInt = pcfg->u.bss_info.rapidReconnThreshold;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "InteropNumSta", TRUE))
    {
        *pInt = pcfg->u.bss_info.inum_sta;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d inumsta:%d \n", __FUNCTION__,__LINE__,pcfg->u.bss_info.inum_sta);
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AccessPoint_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext; 
    ULONG vap_index = 0;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);

    if(cfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        /* collect value */
        if (isVapSTAMesh(pcfg->vap_index)) {
            if( pcfg->u.sta_info.enabled == TRUE )
            {
                *puLong = 2;
            }
            else
            {
                *puLong = 1;
            }
           return TRUE;
        }
        
        if( pcfg->u.bss_info.enabled == TRUE )
        {
            *puLong = 2;
        }
        else
        {
            *puLong = 1;
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RetryLimit", TRUE))
    {
        *puLong = cfg->retry_limit;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MLD_ID", TRUE))
    {
        *puLong = pcfg->u.bss_info.mld_info.common_info.mld_id;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MLD_Link_ID", TRUE))
    {
        *puLong = pcfg->u.bss_info.mld_info.common_info.mld_link_id;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_LongRetryLimit", TRUE))
    {
        *puLong = cfg->long_retry_limit;
        return TRUE;
    }
  
    if (AnscEqualString(ParamName, "MaxAssociatedDevices", TRUE))
    {
        *puLong =  pcfg->u.bss_info.bssMaxSta;
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold", TRUE))
    {
        *puLong = cfg->associated_devices_highwatermark_threshold; 
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_COMCAST-COM_AssociatedDevicesHighWatermarkThresholdReached", TRUE))
    {
        *puLong = 3; 
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_COMCAST-COM_AssociatedDevicesHighWatermark", TRUE))
    {
        *puLong = 3; 
        return TRUE;
    }
	
	//zqiu
    if( AnscEqualString(ParamName, "X_COMCAST-COM_AssociatedDevicesHighWatermarkDate", TRUE))
    {
	//TODO: need cacultion for the time
	*puLong = AnscGetTickInSeconds();
        return TRUE;
    }
	
    if (AnscEqualString(ParamName, "X_COMCAST-COM_TXOverflow", TRUE))
    {
        *puLong = cfg->txoverflow;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AccessPoint_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
AccessPoint_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    char beacon_str[32] = {0};
    uint8_t instance_number = 0;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        snprintf(pValue,*pUlSize,"AccessPoint%d",instance_number);
        return 0;
    }

    if( AnscEqualString(ParamName, "SSIDReference", TRUE))
    {
        snprintf(pValue,*pUlSize,"Device.WiFi.SSID.%d.",instance_number);
        return 0;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_BeaconRate", TRUE))
    {
        if (isVapSTAMesh(pcfg->vap_index)) {
           AnscCopyString(pValue, "6Mbps");
           return TRUE;
        }
	getBeaconRateStringFromEnum(beacon_str,sizeof(beacon_str),pcfg->u.bss_info.beaconRate);
	AnscCopyString(pValue, beacon_str);
	return 0;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_MAC_FilteringMode", TRUE))
    {
        if (isVapHotspot(pcfg->vap_index)) {
           snprintf(pValue, *pUlSize, "%s", "Deny");
           return 0;
        }
        if (pcfg->u.bss_info.mac_filter_enable == TRUE) {
            if (pcfg->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                snprintf(pValue, *pUlSize, "%s", "Deny");
            } else {
                snprintf(pValue, *pUlSize, "%s", "Allow");
            }
        } else {
            snprintf(pValue, *pUlSize, "%s", "Allow-ALL");
        }
        return 0;

    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AccessPoint_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue

    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    ULONG vap_index = 0;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);

    if(cfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if (global_wifi_config->global_parameters.force_disable_radio_feature)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n" ));
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __FUNCTION__,__LINE__);
            return FALSE;
        }
        if (isVapSTAMesh(pcfg->vap_index)) {
            vapInfo->u.sta_info.enabled = bValue;
        } else {
            vapInfo->u.bss_info.enabled = bValue;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }


    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    //Following parameters are nots supported in Mesh STA Mode
    if( AnscEqualString(ParamName, "IsolationEnable", TRUE))
    {
        if ( vapInfo->u.bss_info.isolation == bValue )
        {
            return  TRUE;
        }
        
        /* save update to backup */
        vapInfo->u.bss_info.isolation = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SSIDAdvertisementEnabled", TRUE))
    {
        if ( vapInfo->u.bss_info.showSsid == bValue )
        {
            return TRUE;
        }
        
        /* save update to backup */
        vapInfo->u.bss_info.showSsid = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "WMMEnable", TRUE))
    {
        if ( vapInfo->u.bss_info.wmm_enabled == bValue )
        {
            return  TRUE;
        }
        
        /* save update to backup */
        vapInfo->u.bss_info.wmm_enabled = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UAPSDEnable", TRUE))
    {
        if ( vapInfo->u.bss_info.UAPSDEnabled == bValue )
        {
            return  TRUE;
        }
        /* save update to backup */
        vapInfo->u.bss_info.UAPSDEnabled = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_BssCountStaAsCpe", TRUE))
    {
        cfg->bss_count_sta_as_cpe = bValue;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_BssHotSpot", TRUE))
    {
        if ( vapInfo->u.bss_info.bssHotspot == bValue )
        {
            return  TRUE;
        }
        /* save update to backup */
        vapInfo->u.bss_info.bssHotspot = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);

        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_KickAssocDevices", TRUE))
    {
        cfg->kick_assoc_devices = bValue;
        return TRUE;
    }


    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_BSSTransitionActivated", TRUE))
    {
        if ( vapInfo->u.bss_info.bssTransitionActivated == bValue )
        {
            return  TRUE;
        }
        vapInfo->u.bss_info.bssTransitionActivated = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Apply BSSTransitionActivated failed \n",__func__, __LINE__);
            return FALSE;
        }
        return  TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_rapidReconnectCountEnable", TRUE))
    {
        if ( vapInfo->u.bss_info.rapidReconnectEnable == bValue )
        {
            return  TRUE;
        }
        vapInfo->u.bss_info.rapidReconnectEnable = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
	return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_StatsEnable", TRUE))
    {

        if ( vapInfo->u.bss_info.vapStatsEnable == bValue )
        {
            return  TRUE;
        }
        vapInfo->u.bss_info.vapStatsEnable = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_NeighborReportActivated", TRUE))
    {

        if ( vapInfo->u.bss_info.nbrReportActivated == bValue )
        {
            return  TRUE;
        }
        vapInfo->u.bss_info.nbrReportActivated = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Apply NeighborReportActivated failed \n",__func__, __LINE__);
            return FALSE;
        }
        return TRUE;
    }
    
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_InterworkingServiceEnable", TRUE))
    {

        if ( vapInfo->u.bss_info.interworking.interworking.interworkingEnabled == bValue )
        {
            return  TRUE;
        }
        vapInfo->u.bss_info.interworking.interworking.interworkingEnabled = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);

        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_InterworkingApplySettings", TRUE ))
    {
        if (bValue == TRUE){
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d X_RDKCENTRAL-COM_InterworkingApplySettings push to queue \n",__func__, __LINE__);
            if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR)
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d X_RDKCENTRAL-COM_InterworkingApplySettings failed \n",__func__, __LINE__);
                return FALSE;
            }
            last_vap_change = AnscGetTickInSeconds();
            return TRUE;
        }
        return TRUE;
    }

    if (AnscEqualString(ParamName, "connected_building_enabled", TRUE))
    {
        if (!isVapHotspot(instance_number-1))
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s connected_building_enabled  not supported for vaps other than public vaps\n", __FUNCTION__));
            return FALSE;
        }
        vapInfo->u.bss_info.connected_building_enabled = bValue;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: connected_building_enabled Value = %d  \n",__func__, __LINE__, vapInfo->u.bss_info.connected_building_enabled);
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_HostapMgtFrameCtrl", TRUE))
    {
        vapInfo->u.bss_info.hostap_mgt_frame_ctrl = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);

        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: hostap_mgt_frame_ctrl value = %d\n", __func__,
            __LINE__, vapInfo->u.bss_info.hostap_mgt_frame_ctrl);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "InteropTelemetryCtrl", TRUE))
    {
        vapInfo->u.bss_info.interop_ctrl = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);

        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: interop_ctrl value = %d\n", __func__,
            __LINE__, vapInfo->u.bss_info.interop_ctrl);
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AccessPoint_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(instance_number-1);

    if(cfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_CISCO_COM_WmmNoAck", TRUE))
    {
        if (vapInfo->u.bss_info.wmmNoAck == (UINT) iValue )
        {
            return  TRUE;
        }
        /* save update to backup */
        vapInfo->u.bss_info.wmmNoAck = iValue;
        set_dml_cache_vap_config_changed(instance_number - 1);

        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_MulticastRate", TRUE))
    {
        cfg->multicast_rate = iValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_BssMaxNumSta", TRUE))
    {
        if (vapInfo->u.bss_info.bssMaxSta == (UINT) iValue)
        {
            /* Same value in VAPs private data, no change needed. Just return */
            return  TRUE;
        }

        /* Allow users to set max station for given VAP */
        vapInfo->u.bss_info.bssMaxSta = iValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return (TRUE);
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_ManagementFramePowerControl", TRUE))
    {
        if((iValue < -20) || (iValue > 0))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unsupported Value for ManagementFramePowerControl :Supports in the Range [-20,0] \n", __FUNCTION__,__LINE__);
            return FALSE;
        }
        if ( vapInfo->u.bss_info.mgmtPowerControl == iValue )
        {
            return  TRUE;
        }
        /* save update to backup */
        vapInfo->u.bss_info.mgmtPowerControl = iValue;
        CcspWifiTrace(("RDK_LOG_INFO,X_RDKCENTRAL-COM_ManagementFramePowerControl:%d\n", iValue));
        CcspTraceWarning(("X_RDKCENTRAL-COM_ManagementFramePowerControl_Get:<%d>\n", iValue));
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_rapidReconnectMaxTime", TRUE))
    {
        if ( vapInfo->u.bss_info.rapidReconnThreshold == (unsigned int)iValue )
        {
            return  TRUE;
        }
        /* save update to backup */
        vapInfo->u.bss_info.rapidReconnThreshold = iValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "InteropNumSta", TRUE))
    {
        if (vapInfo->u.bss_info.inum_sta == (UINT)iValue)
        {
            return  TRUE;
        }

        if (iValue < INTEROP_MIN_STA || iValue > INTEROP_MAX_STA) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid value for vap index:%d\n",__func__, __LINE__,pcfg->vap_index);
            return FALSE;
        }
        /* Allow users to set max station for given VAP */
        vapInfo->u.bss_info.inum_sta = iValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return (TRUE);
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AccessPoint_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(instance_number-1);

    if(cfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
 
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "RetryLimit", TRUE))
    {
        cfg->retry_limit = uValue;   
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_LongRetryLimit", TRUE))
    {
        cfg->long_retry_limit = uValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MaxAssociatedDevices", TRUE))
    {

        if (isVapSTAMesh(vapInfo->vap_index)) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vapInfo->vap_name);
            return TRUE;
        }

        if ( vapInfo->u.bss_info.bssMaxSta == uValue )
        {
            return  TRUE;
        }

        /* save update to backup */
        vapInfo->u.bss_info.bssMaxSta = uValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold", TRUE))
    {
        cfg->associated_devices_highwatermark_threshold = uValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MLD_ID", TRUE))
    {
        if ( vapInfo->u.bss_info.mld_info.common_info.mld_id == (unsigned int)uValue )
        {
            return  TRUE;
        }
        /* save update to backup */
        vapInfo->u.bss_info.mld_info.common_info.mld_id = uValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MLD_Link_ID", TRUE))
    {
        if ( vapInfo->u.bss_info.mld_info.common_info.mld_link_id == (unsigned int)uValue )
        {
            return  TRUE;
        }
        /* save update to backup */
        vapInfo->u.bss_info.mld_info.common_info.mld_link_id = uValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AccessPoint_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);
    UINT beaconIndex = 0;
    errno_t                         rc           =  -1;
    int                             ind          =  -1;

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if((pString == NULL) || (ParamName == NULL))
    {
       CcspTraceInfo(("RDK_LOG_WARN, %s %s:%d\n",__FILE__, __FUNCTION__,__LINE__));
       return FALSE;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }
    
    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("Alias", strlen("Alias"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d does not support configuration\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    rc = strcmp_s("SSIDReference", strlen("SSIDReference"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d does not support configuration\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
	
    rc = strcmp_s("X_RDKCENTRAL-COM_BeaconRate", strlen("X_RDKCENTRAL-COM_BeaconRate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if (!getBeaconRateFromString(pString, &beaconIndex))
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s BeaconRate Parameter Invalid :%s\n", __FUNCTION__, pString));
            return FALSE;
        }
        vapInfo->u.bss_info.beaconRate = beaconIndex;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }
	
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AccessPoint_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
AccessPoint_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AccessPoint_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
AccessPoint_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    int  vap_index = 0;

    vap_index = pcfg->vap_index;
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);
    if (cfg->kick_assoc_devices) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Pushing Kick assoc to control queue\n", __func__, __LINE__);
        push_kick_assoc_to_ctrl_queue(vap_index);
        cfg->kick_assoc_devices = FALSE;
    }
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 
        ULONG
        AccessPoint_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
AccessPoint_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}


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
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Security_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_vap_security_t *l_security_cfg= NULL;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);
    wifi_radio_operationParam_t *radioOperation = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(pcfg->radio_index);

    if ((vapInfo == NULL) || (radioOperation ==NULL))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(instance_number-1)) {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_TransitionDisable", TRUE))
    {
        *pBool = l_security_cfg->wpa3_transition_disable;
    }

    if( AnscEqualString(ParamName, "Reset", TRUE)) {
        *pBool = FALSE;
    }

    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Security_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    if( AnscEqualString(ParamName, "X_CISCO_COM_RadiusReAuthInterval", TRUE))
    {
        /* collect value */
        *pInt = 0;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_DefaultKey", TRUE))
    {
        /* collect value */
        *pInt = 0;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */

    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Security_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    /* check the parameter name and return the corresponding value */
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;
    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_vap_security_t *pcfg = NULL;

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        pcfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(vap_pcfg->vap_index);
        if(pcfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter \n",__func__, __LINE__,vap_pcfg->vap_name);
            return FALSE;
        }
    } else {
        pcfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(vap_pcfg->vap_index);
        if(pcfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vap_pcfg->vap_name);
            return FALSE;
        }
    }


    if( AnscEqualString(ParamName, "RekeyingInterval", TRUE))
    {
        /* collect value */
        *puLong = pcfg->rekey_interval;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_EncryptionMethod", TRUE))
    {
        /* collect value */
        *puLong = pcfg->encr;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RadiusServerPort", TRUE))
    {
        /* collect value */
        *puLong = pcfg->u.radius.port;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RepurposedRadiusServerPort", TRUE))
    {
        /* collect value */
        *puLong = pcfg->repurposed_radius.port;
        return TRUE;
    }
	
	if( AnscEqualString(ParamName, "SecondaryRadiusServerPort", TRUE))
    {
        /* collect value */
        *puLong = pcfg->u.radius.s_port;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RepurposedSecondaryRadiusServerPort", TRUE))
    {
        /* collect value */
        *puLong = pcfg->repurposed_radius.s_port;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RadiusDASPort", TRUE))
    {
        /* collect value */
        *puLong = pcfg->u.radius.dasport;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

void get_security_modes_supported(int vap_index, int *mode)
{
    int band;
    unsigned int radio_index;
    wifi_vap_info_t *vap_info;
    BOOL passpoint_enabled;

    radio_index = getRadioIndexFromAp((unsigned int)vap_index);
    if (convert_radio_index_to_freq_band(&get_webconfig_dml()->hal_cap.wifi_prop, radio_index,
        &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d failed to convert radio index %u to band\n",
            __func__, __LINE__, radio_index);
        return;
    }

    vap_info = get_dml_cache_vap_info(vap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d failed to get vap info for index %d\n",
            __func__, __LINE__, vap_index);
        return;
    }
    passpoint_enabled = vap_info->u.bss_info.interworking.passpoint.enable;

    if (band == WIFI_FREQUENCY_6_BAND) {
        *mode = passpoint_enabled ? COSA_DML_WIFI_SECURITY_WPA3_Enterprise :
            COSA_DML_WIFI_SECURITY_WPA3_Personal | COSA_DML_WIFI_SECURITY_WPA3_Enterprise |
            COSA_DML_WIFI_SECURITY_Enhanced_Open;
        return;
    }

    if (passpoint_enabled) {
        *mode = COSA_DML_WIFI_SECURITY_WPA_Enterprise | COSA_DML_WIFI_SECURITY_WPA2_Enterprise |
            COSA_DML_WIFI_SECURITY_WPA_WPA2_Enterprise | COSA_DML_WIFI_SECURITY_WPA3_Enterprise;
        return;
    }

    *mode = COSA_DML_WIFI_SECURITY_None | COSA_DML_WIFI_SECURITY_Enhanced_Open |
        COSA_DML_WIFI_SECURITY_WPA_Personal | COSA_DML_WIFI_SECURITY_WPA_Enterprise |
        COSA_DML_WIFI_SECURITY_WPA2_Personal | COSA_DML_WIFI_SECURITY_WPA2_Enterprise |
        COSA_DML_WIFI_SECURITY_WPA_WPA2_Personal | COSA_DML_WIFI_SECURITY_WPA_WPA2_Enterprise |
        COSA_DML_WIFI_SECURITY_WPA3_Personal | COSA_DML_WIFI_SECURITY_WPA3_Personal_Transition |
        COSA_DML_WIFI_SECURITY_WPA3_Enterprise | COSA_DML_WIFI_SECURITY_WPA3_Personal_Compatibility;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Security_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
Security_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_vap_security_t *pcfg = NULL;

    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, vap_pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        pcfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(vap_pcfg->vap_index);
        if(pcfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter \n",__func__, __LINE__,vap_pcfg->vap_name);
            return FALSE;
        }
    } else {
        pcfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(vap_pcfg->vap_index);
        if(pcfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vap_pcfg->vap_name);
            return FALSE;
        }
    }


    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "ModesSupported", TRUE))
    {
        /* collect value */
        char buf[512] = {0};
        int mode = 0;
        get_security_modes_supported(vap_index, &mode);

        if (wifiSecSupportedDmlToStr(mode, buf, sizeof(buf)) == ANSC_STATUS_SUCCESS)
        {
            if ( AnscSizeOfString(buf) < *pUlSize)
            {
                AnscCopyString(pValue, buf);
                return 0;
            }
            else
            {
                *pUlSize = AnscSizeOfString(buf)+1;
                return 1;
            }
        }
        else
        {
            return -1;
        }
    }
 
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "ModeEnabled", TRUE))
    {
        /* collect value */
        char buf[32] = {0};
        if ( AnscSizeOfString(buf) < *pUlSize) {
            getSecurityStringFromInt(pcfg->mode, buf);
            AnscCopyString(pValue, buf);
        } else {
            *pUlSize = AnscSizeOfString(buf) + 1;
            return 1;
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "WEPKey", TRUE))
    {
        /* WEP Key should always return empty string when read */
        AnscCopyString(pValue, "");
        /* collect value */
        return 0;
    }

    if( AnscEqualString(ParamName, "PreSharedKey", TRUE))
    {
        /* PresharedKey should always return empty string when read */
        AnscCopyString(pValue, "");
        return 0;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_DefaultKeyPassphrase", TRUE))
    {
        char password[128] = {0};

        if (wifi_hal_get_default_keypassphrase(password, vap_index) == RETURN_OK)
        {
            if ( AnscSizeOfString(password) > 0 )
            {
                if  ( AnscSizeOfString(password) < *pUlSize)
                {
                    AnscCopyString(pValue, password);
                    return 0;
                }
                else
                {
                    *pUlSize = AnscSizeOfString(password)+1;
                    return 1;
                }
            }
        }
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_WEPKey", TRUE) || AnscEqualString(ParamName, "X_COMCAST-COM_WEPKey", TRUE))
    {
        /* collect value */
        return 0;
    }

    if(AnscEqualString(ParamName, "KeyPassphrase", TRUE) || AnscEqualString(ParamName, "X_COMCAST-COM_KeyPassphrase", TRUE))
    {
        /* collect value */
        if ( AnscSizeOfString(pcfg->u.key.key) > 0 )
        {
            if  ( AnscSizeOfString(pcfg->u.key.key) < *pUlSize)
            {
                AnscCopyString(pValue, pcfg->u.key.key);
                return 0;
            }
           else
            {
                *pUlSize = AnscSizeOfString(pcfg->u.key.key)+1;
                return 1;
            }
        } else  {
            // if both PreSharedKey and KeyPassphrase are NULL, set to NULL string
            AnscCopyString(pValue, "");
            return 0;
        }
    }

    if( AnscEqualString(ParamName, "SAEPassphrase", TRUE))
    {
        if (AnscSizeOfString(pcfg->u.key.key) > 0)
        {
            if  ( AnscSizeOfString(pcfg->u.key.key) < *pUlSize)
            {
                AnscCopyString(pValue, pcfg->u.key.key);
                return 0;
            }
            else
            {
                *pUlSize = AnscSizeOfString(pcfg->u.key.key)+1;
                return 1;
            }
        }
    }

    if( AnscEqualString(ParamName, "RadiusSecret", TRUE))
    {
        /* Radius Secret should always return empty string when read */
        AnscCopyString(pValue, "");
        return 0;
    }

    if( AnscEqualString(ParamName, "RepurposedRadiusSecret", TRUE))
    {
        /* Radius Secret should always return empty string when read */
        AnscCopyString(pValue, "");
        return 0;
    }    

    if( AnscEqualString(ParamName, "SecondaryRadiusSecret", TRUE))
    {
        /* Radius Secret should always return empty string when read */
        AnscCopyString(pValue, "");
        return 0;
    }

    if( AnscEqualString(ParamName, "RepurposedSecondaryRadiusSecret", TRUE))
    {
        /* Radius Secret should always return empty string when read */
        AnscCopyString(pValue, "");
        return 0;
    }

    if( AnscEqualString(ParamName, "RadiusServerIPAddr", TRUE))
    {
        int result;
        result=strcmp((char *)&pcfg->u.radius.ip,"");
        if(result)
        {
            AnscCopyString(pValue, (char *)&pcfg->u.radius.ip);
        }
        else
        {
            AnscCopyString(pValue,"0.0.0.0");
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "RepurposedRadiusServerIPAddr", TRUE))
    {
        int result;
        result=strcmp((char *)&pcfg->repurposed_radius.ip,"");
        if(result)
        {
            AnscCopyString(pValue, (char *)&pcfg->repurposed_radius.ip);
        }
        else
        {
            AnscCopyString(pValue,"0.0.0.0");
        }
        return 0;
    }
    
    if( AnscEqualString(ParamName, "SecondaryRadiusServerIPAddr", TRUE))
    {
        int result;
        result=strcmp((char *)&pcfg->u.radius.s_ip,"");
        if(result)
        {
            AnscCopyString(pValue, (char *)&pcfg->u.radius.s_ip);
        }
        else
        {
            AnscCopyString(pValue,"0.0.0.0");
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "RepurposedSecondaryRadiusServerIPAddr", TRUE))
    {
        int result;
        result=strcmp((char *)&pcfg->repurposed_radius.s_ip,"");
        if(result)
        {
            AnscCopyString(pValue, (char *)&pcfg->repurposed_radius.s_ip);
        }
        else
        {
            AnscCopyString(pValue,"0.0.0.0");
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "MFPConfig", TRUE))
    {
	convert_security_mode_integer_to_string(pcfg->mfp,pValue);
        return 0;
    }
    
    if( AnscEqualString(ParamName, "RadiusDASIPAddr", TRUE))
    {
        getIpStringFromAdrress(pValue,&pcfg->u.radius.dasip);
        return 0;
    }
    if( AnscEqualString(ParamName, "RadiusDASSecret", TRUE))
    {
        /* Radius Secret should always return empty string when read */
        AnscCopyString(pValue, "");
        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Security_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{

    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_vap_security_t *l_security_cfg= NULL;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);
    wifi_radio_operationParam_t *radioOperation = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(pcfg->radio_index);

    if ((vapInfo == NULL) || (radioOperation ==NULL))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(instance_number-1)) {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }
    /* check the parameter name and set the corresponding value */
    if (AnscEqualString(ParamName, "X_RDKCENTRAL-COM_TransitionDisable", TRUE))
    {
        if (l_security_cfg->wpa3_transition_disable != bValue) {
            l_security_cfg->wpa3_transition_disable = bValue;
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:wpa3_transition_disable=%d Value=%d\n",
                __func__, __LINE__, l_security_cfg->wpa3_transition_disable, bValue);
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Reset", TRUE))
    {
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Security_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "X_CISCO_COM_RadiusReAuthInterval", TRUE))
    {
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_CISCO_COM_DefaultKey", TRUE))
    {
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Security_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_vap_security_t *l_security_cfg = NULL;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if (isVapSTAMesh(instance_number-1)) {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(instance_number-1);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(instance_number-1);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "RekeyingInterval", TRUE))
    {
        if ( l_security_cfg->rekey_interval != uValue )
        {
	    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RekeyingInterval=%d Value = %d  \n",__func__, __LINE__,l_security_cfg->rekey_interval,uValue);
            /* save update to backup */
            l_security_cfg->rekey_interval = uValue;
	    set_dml_cache_vap_config_changed(instance_number - 1);
        }

        return TRUE;
    }
  
    if( AnscEqualString(ParamName, "X_CISCO_COM_EncryptionMethod", TRUE))
    {
        if ( l_security_cfg->encr != uValue )
        {
	    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:X_CISCO_COM_EncryptionMethod=%d Value = %d  \n",__func__, __LINE__,l_security_cfg->encr,uValue);
            /* collect value */
            l_security_cfg->encr = uValue;
	    set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RadiusServerPort", TRUE))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        if ( l_security_cfg->u.radius.port != uValue )
        {
	    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RadiusServerPort=%d Value = %d  \n",__func__, __LINE__,l_security_cfg->u.radius.port,uValue);
            /* save update to backup */
            l_security_cfg->u.radius.port = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SecondaryRadiusServerPort", TRUE))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        if ( l_security_cfg->u.radius.s_port != uValue )
        {
	    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:SecondaryRadiusServerPort=%d Value = %d  \n",__func__, __LINE__,l_security_cfg->u.radius.s_port,uValue);
            /* save update to backup */
            l_security_cfg->u.radius.s_port = uValue;
	    set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RadiusDASPort", TRUE))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        if ( l_security_cfg->u.radius.dasport != uValue )
        {
	    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RadiusDASPort=%d Value = %d  \n",__func__, __LINE__,l_security_cfg->u.radius.dasport,uValue);
            /* save update to backup */
            l_security_cfg->u.radius.dasport   = uValue;
	    set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }


    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Security_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_vap_security_t *l_security_cfg= NULL;


    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);
    wifi_radio_operationParam_t *radioOperation = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(pcfg->radio_index);
    errno_t                         rc           = -1;
    int                             ind          = -1;
    BOOL WPA3_RFC = FALSE;

    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if ((vapInfo == NULL) || (radioOperation == NULL))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if (isVapSTAMesh(instance_number-1)) {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(instance_number-1);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(instance_number-1);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }

    if (!ParamName || !pString)
        return FALSE;

    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("ModeEnabled", strlen("ModeEnabled"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        wifi_security_modes_t TmpMode;
        COSA_DML_WIFI_SECURITY cosaTmpMode;
        wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

        if (!getSecurityTypeFromString(pString, &TmpMode, &cosaTmpMode))
        {
             wifi_util_error_print(WIFI_DMCLI, "%s:%d failed to parse mode: %s\n", __func__,
                 __LINE__, pString);
             return FALSE;
        }

        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d old mode: %d new mode: %d\n", __func__, __LINE__,
            l_security_cfg->mode, TmpMode);

        if (TmpMode == l_security_cfg->mode)
        {
            return TRUE;
        }

        if (radioOperation->band == WIFI_FREQUENCY_6_BAND &&
            TmpMode != wifi_security_mode_wpa3_personal &&
            TmpMode != wifi_security_mode_wpa3_enterprise &&
            TmpMode != wifi_security_mode_enhanced_open)
        {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d invalid mode %d for 6GHz\n", __func__,
                __LINE__, TmpMode);
            return FALSE;
        }

        /* GET the WPA3 Transition RFC value */
        CosaWiFiDmlGetWPA3TransitionRFC(&WPA3_RFC);
        if (radioOperation->band != WIFI_FREQUENCY_6_BAND && WPA3_RFC == FALSE &&
            (TmpMode == wifi_security_mode_wpa3_transition ||
            TmpMode == wifi_security_mode_wpa3_personal))
        {
             wifi_util_error_print(WIFI_DMCLI, "%s:%d WPA3 mode is not supported when "
                 "TransitionDisable RFC is false\n", __func__, __LINE__);
             return FALSE;
        }

        // cleanup key/radius for personal-enterprise-open mode change
        if ((is_personal_sec(TmpMode) && !is_personal_sec(l_security_cfg->mode)) ||
            (is_enterprise_sec(TmpMode) && !is_enterprise_sec(l_security_cfg->mode)) ||
            (is_open_sec(TmpMode) && !is_open_sec(l_security_cfg->mode)))
        {
            memset(&l_security_cfg->u, 0, sizeof(l_security_cfg->u));
        }
        
        if(TmpMode == wifi_security_mode_wpa3_compatibility && !rfc_pcfg->wpa3_compatibility_enable) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d WPA3 Compatibility mode is not supported when  RFC is disabled \n", __func__, __LINE__);
            return FALSE;
        }

        l_security_cfg->mode = TmpMode;
        switch (l_security_cfg->mode)
        {
            case wifi_security_mode_none:
                l_security_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wep_64:
            case wifi_security_mode_wep_128:
                l_security_cfg->u.key.type = wifi_security_key_type_pass;
                l_security_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wpa_personal:
            case wifi_security_mode_wpa2_personal:
            case wifi_security_mode_wpa_wpa2_personal:
                l_security_cfg->u.key.type = wifi_security_key_type_psk;
                l_security_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wpa_enterprise:
            case wifi_security_mode_wpa2_enterprise:
            case wifi_security_mode_wpa_wpa2_enterprise:
                l_security_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wpa3_personal:
                l_security_cfg->u.key.type = wifi_security_key_type_sae;
                l_security_cfg->mfp = wifi_mfp_cfg_required;
                break;
            case wifi_security_mode_wpa3_enterprise:
                l_security_cfg->mfp = wifi_mfp_cfg_required;
                break;
            case wifi_security_mode_wpa3_transition:
                l_security_cfg->u.key.type = wifi_security_key_type_psk_sae;
                l_security_cfg->mfp = wifi_mfp_cfg_optional;
                break;
            case wifi_security_mode_enhanced_open:
                l_security_cfg->mfp = wifi_mfp_cfg_required;
                break;
            case wifi_security_mode_wpa3_compatibility:
                l_security_cfg->u.key.type = wifi_security_key_type_psk_sae;
                l_security_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            default:
                break;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Set Value=%d success  \n",__func__, __LINE__,TmpMode);
        CcspWifiTrace(("RDK_LOG_WARN,RDKB_WIFI_CONFIG_CHANGED : Wifi security mode %s is Enabled\n",pString));
        return TRUE;
    }

    const char *WepKeyType[WEPKEY_TYPE_SET] = {"WEPKey", "X_CISCO_COM_WEPKey", "X_COMCAST-COM_WEPKey"};
    int i = 0;

    for(i = 0; i < WEPKEY_TYPE_SET; i++)
    {
        rc = strcmp_s(WepKeyType[i], strlen(WepKeyType[i]), ParamName, &ind);
        ERR_CHK(rc);
	if((rc == EOK) && (!ind))
        {
            if((l_security_cfg->mode == wifi_security_mode_wep_64) ||
              (l_security_cfg->mode == wifi_security_mode_wep_128))
	          return FALSE; /* Return an error only if the security mode enabled is WEP - For UI */
            return TRUE;
        }
    }

    const char *KeyPassphraseType[KEYPASSPHRASE_SET] = {"KeyPassphrase", "X_COMCAST-COM_KeyPassphrase"};
    for(i = 0; i < KEYPASSPHRASE_SET; i++)
    {
        rc = strcmp_s(KeyPassphraseType[i], strlen(KeyPassphraseType[i]), ParamName, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (!ind))
        {
            if(global_wifi_config->global_parameters.force_disable_radio_feature)
            {
                CcspWifiTrace(("RDK_LOG_ERROR, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n" ));
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n",__FUNCTION__,__LINE__);
                return FALSE;
            }
            if ((AnscSizeOfString(pString) < 8 ) || (AnscSizeOfString(pString) > 63))
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Size is too large value=%s\n",__func__, __LINE__,pString);
                return FALSE;
            }
            rc = strcmp_s((char*)l_security_cfg->u.key.key, sizeof(l_security_cfg->u.key.key), pString, &ind);
            ERR_CHK(rc);
            if((rc == EOK) && (!ind))
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value remains unchanged\n",__func__, __LINE__);
                return TRUE;
            }
             /* save update to backup */
            if (security_mode_support_radius(l_security_cfg->mode))
            {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support passphrase configuration \n",__func__, __LINE__,l_security_cfg->mode);
                return FALSE;
            }

             rc = strcpy_s((char*)l_security_cfg->u.key.key, sizeof(l_security_cfg->u.key.key), pString);
             if(rc != EOK)
             {
                 ERR_CHK(rc);
                 return FALSE;
             }
             set_dml_cache_vap_config_changed(instance_number - 1);
             return TRUE;
         }
    }

    rc = strcmp_s("PreSharedKey", strlen("PreSharedKey"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if((pString == NULL) || (strlen(pString) >= sizeof(l_security_cfg->u.key.key)))
             return FALSE;

        if (security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support passphrase configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }

        rc = strcpy_s((char*)l_security_cfg->u.key.key, sizeof(l_security_cfg->u.key.key), pString);
        if(rc != EOK)
        {
             ERR_CHK(rc);
             return FALSE;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);

        return TRUE;
    }

    rc = strcmp_s("SAEPassphrase", strlen("SAEPassphrase"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( (l_security_cfg->mode != wifi_security_mode_wpa3_transition) &&
             (l_security_cfg->mode != wifi_security_mode_wpa3_personal) )
        {
            CcspWifiTrace(("RDK_LOG_INFO, WPA3 security mode is not enabled in VAP %d\n", instance_number));
            return FALSE;
        }
        if(security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support passphrase configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        rc = strcmp_s((char*)l_security_cfg->u.key.key, sizeof(l_security_cfg->u.key.key), pString, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (!ind))
            return TRUE;

        if ((strlen(pString) < SAE_PASSPHRASE_MIN_LENGTH) ||
            (strlen(pString) >= SAE_PASSPHRASE_MAX_LENGTH))
        {
            return FALSE;
        }
        rc = strcpy_s((char*)l_security_cfg->u.key.key, sizeof(l_security_cfg->u.key.key), pString);
        if(rc != EOK)
        {
           ERR_CHK(rc);
           return FALSE;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    rc = strcmp_s("RadiusSecret", strlen("RadiusSecret"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        rc = strcmp_s(l_security_cfg->u.radius.key, sizeof(l_security_cfg->u.radius.key), pString, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (!ind))
            return TRUE;

		/* save update to backup */
        if((pString == NULL) || (strlen(pString) >= sizeof(l_security_cfg->u.radius.key)))
            return FALSE;

        rc = strcpy_s(l_security_cfg->u.radius.key, sizeof(l_security_cfg->u.radius.key), pString);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            return FALSE;
        }
	set_dml_cache_vap_config_changed(instance_number - 1);

        return TRUE;
    }
	
    rc = strcmp_s("SecondaryRadiusSecret", strlen("SecondaryRadiusSecret"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        rc = strcmp_s(l_security_cfg->u.radius.s_key, sizeof(l_security_cfg->u.radius.s_key), pString, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (!ind))
           return TRUE;
    
	/* save update to backup */
        if((pString == NULL) || (strlen(pString) >= sizeof(l_security_cfg->u.radius.s_key)))
             return FALSE;
        rc = strcpy_s(l_security_cfg->u.radius.s_key, sizeof(l_security_cfg->u.radius.s_key), pString);
        if(rc != EOK)
        {
              ERR_CHK(rc);
              return FALSE;
        }
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    rc = strcmp_s("RadiusServerIPAddr", strlen("RadiusServerIPAddr"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        rc = strcmp_s((char*)l_security_cfg->u.radius.ip, sizeof( l_security_cfg->u.radius.ip), pString, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (!ind))
	    return TRUE;

	/* save update to backup */
        if((pString == NULL) || (strlen(pString) >= sizeof(l_security_cfg->u.radius.ip)))
             return FALSE;
        rc = strcpy_s( (char*)l_security_cfg->u.radius.ip, sizeof(l_security_cfg->u.radius.ip), pString);
        if(rc != EOK)
        {
              ERR_CHK(rc);
              return FALSE;
        }
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    rc = strcmp_s("SecondaryRadiusServerIPAddr", strlen("SecondaryRadiusServerIPAddr"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        rc = strcmp_s((char*)l_security_cfg->u.radius.s_ip, sizeof(l_security_cfg->u.radius.s_ip), pString, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (!ind))
            return TRUE;
        
	/* save update to backup */
        if((pString == NULL) || (strlen(pString) >= sizeof(l_security_cfg->u.radius.s_ip)))
             return FALSE;
        rc = strcpy_s((char*)l_security_cfg->u.radius.s_ip, sizeof(l_security_cfg->u.radius.s_ip), pString);
        if(rc != EOK)
        {
              ERR_CHK(rc);
              return FALSE;
        }
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    rc = strcmp_s("MFPConfig", strlen("MFPConfig"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        wifi_mfp_cfg_t mfp;
        if (getMFPTypeFromString(pString, &mfp) != ANSC_STATUS_SUCCESS)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s invalide mfp string %s\n",__FUNCTION__,pString));
            return FALSE;
        }
        if (l_security_cfg->mfp == mfp)
            return TRUE;
        const char *MFPConfigOptions[MFPCONFIG_OPTIONS_SET] = {"Disabled", "Optional", "Required"};
        int mfpOptions_match = 0;
        for(i = 0; i < MFPCONFIG_OPTIONS_SET; i++)
        {
            rc = strcmp_s(MFPConfigOptions[i], strlen(MFPConfigOptions[i]), pString, &ind);
            ERR_CHK(rc);
            if((rc == EOK) && (!ind))
            {
                mfpOptions_match = 1;
                break;
            }
        }
        if(mfpOptions_match == 1)
        {

            l_security_cfg->mfp = mfp;
	    set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
        else
        {
            CcspTraceWarning(("MFPConfig : Unsupported Value'%s'\n", ParamName));
            return FALSE;
        }
    }

    rc = strcmp_s("RadiusDASIPAddr", strlen("RadiusDASIPAddr"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        ip_addr_t parameterIp;
        if (getIpAddressFromString(pString, &parameterIp) != 1)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d getIpAddressFromString failed \n",__func__, __LINE__);
            return FALSE;
        }
        if ((parameterIp.family == wifi_ip_family_ipv4) && (parameterIp.u.IPv4addr == l_security_cfg->u.radius.dasip.u.IPv4addr))
        {
            return TRUE;
        }

        if ((parameterIp.family == wifi_ip_family_ipv6) && (!memcmp(l_security_cfg->u.radius.dasip.u.IPv6addr,parameterIp.u.IPv6addr, 16)))
        {
            return TRUE;
        }

        memcpy(&l_security_cfg->u.radius.dasip, &parameterIp, sizeof(ip_addr_t));
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }
    rc = strcmp_s("RadiusDASSecret", strlen("RadiusDASSecret"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        rc = strcmp_s(l_security_cfg->u.radius.daskey, sizeof(l_security_cfg->u.radius.daskey), pString, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (!ind))
              return TRUE;

        /* save update to backup */
        if((pString == NULL) || (strlen(pString) >= sizeof(l_security_cfg->u.radius.daskey)))
              return FALSE;
        rc = strcpy_s(l_security_cfg->u.radius.daskey, sizeof(l_security_cfg->u.radius.daskey), pString);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            return FALSE;
        }
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Security_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
Security_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Security_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Security_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Security_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Security_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}


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
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        ConnectionControl_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ConnectionControl_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ConnectionControl_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ConnectionControl_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ConnectionControl_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ConnectionControl_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        ConnectionControl_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
ConnectionControl_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "ClientForceDisassociation", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.postassoc.client_force_disassoc_info);
        return 0;
    }

    if( AnscEqualString(ParamName, "ClientDenyAssociation", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.client_deny_assoc_info);
        return 0;
    }

    if( AnscEqualString(ParamName, "TcmClientDenyAssociation", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.tcm_client_deny_assoc_info);
        return 0;
    }

    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ConnectionControl_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ConnectionControl_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ConnectionControl_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ConnectionControl_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ConnectionControl_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ConnectionControl_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ConnectionControl_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ConnectionControl_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ConnectionControl_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
ConnectionControl_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        ConnectionControl_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
ConnectionControl_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        ConnectionControl_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
ConnectionControl_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.ConnectionControl.PreAssocDeny.

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
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PreAssocDeny_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PreAssocDeny_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "TcmWaitTime", TRUE))
    {
        *pInt = pcfg->u.bss_info.preassoc.time_ms;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "TcmMinMgmtFrames", TRUE))
    {
        *pInt = pcfg->u.bss_info.preassoc.min_num_mgmt_frames;
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PreAssocDeny_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        PreAssocDeny_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
PreAssocDeny_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "RssiUpThresholdSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"disabled, 10 to 100");
        return 0;
    }

    if( AnscEqualString(ParamName, "SnrThresholdSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"disabled, 1 to 100");
        return 0;
    }

    if( AnscEqualString(ParamName, "RssiUpThreshold", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.rssi_up_threshold);
        return 0;
    }

    if( AnscEqualString(ParamName, "SnrThreshold", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.snr_threshold);
        return 0;
    }

    if( AnscEqualString(ParamName, "CuThresholdSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"disabled, 0 to 100 (%% in integer)");
        return 0;
    }

    if( AnscEqualString(ParamName, "CuThreshold", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.cu_threshold);
        return 0;
    }
    if( AnscEqualString(ParamName, "BasicDataTransmitRates", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.basic_data_transmit_rates);
        return 0;
    }
    if( AnscEqualString(ParamName, "OperationalDataTransmitRates", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.operational_data_transmit_rates);
        return 0;
    }
    if( AnscEqualString(ParamName, "SupportedDataTransmitRates", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.supported_data_transmit_rates);
        return 0;
    }
    if( AnscEqualString(ParamName, "MinimumAdvertisedMCS", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.minimum_advertised_mcs);
        return 0;
    }
    if( AnscEqualString(ParamName, "6GOpInfoMinRate", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.sixGOpInfoMinRate);
        return 0;
    }
    
    if( AnscEqualString(ParamName, "TcmExpWeightage", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.tcm_exp_weightage);
        return 0;
    }

    if( AnscEqualString(ParamName, "TcmGradientThreshold", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.preassoc.tcm_gradient_threshold);
        return 0;
    }

    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PreAssocDeny_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PreAssocDeny_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{

    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (!isVapHotspot(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "TcmWaitTime", TRUE))
    {
        if (vapInfo->u.bss_info.preassoc.time_ms == iValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: DMCLI value set :%d \n",__func__, __LINE__,iValue);
        vapInfo->u.bss_info.preassoc.time_ms = iValue;
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "TcmMinMgmtFrames", TRUE))
    {
        if (vapInfo->u.bss_info.preassoc.min_num_mgmt_frames == iValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: DMCLI value set :%d \n",__func__, __LINE__,iValue);
        vapInfo->u.bss_info.preassoc.min_num_mgmt_frames = iValue;
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;

    }
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PreAssocDeny_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PreAssocDeny_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    int val;
    int ret;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (!isVapHotspot(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "RssiUpThreshold", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.rssi_up_threshold) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.preassoc.rssi_up_threshold, "disabled", sizeof(vapInfo->u.bss_info.preassoc.rssi_up_threshold));
            set_cac_cache_changed(instance_number - 1);
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: -90 to -50\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val > -50 || val < -95) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.preassoc.rssi_up_threshold, pString, sizeof(vapInfo->u.bss_info.preassoc.rssi_up_threshold));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SnrThreshold", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.snr_threshold) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.preassoc.snr_threshold, "disabled", sizeof(vapInfo->u.bss_info.preassoc.snr_threshold));
            set_cac_cache_changed(instance_number - 1);
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val < 1 || val > 100) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.preassoc.snr_threshold, pString, sizeof(vapInfo->u.bss_info.preassoc.snr_threshold));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "CuThreshold", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.cu_threshold) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.preassoc.cu_threshold, "disabled", sizeof(vapInfo->u.bss_info.preassoc.cu_threshold));
            set_cac_cache_changed(instance_number - 1);
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val < 0 || val > 100) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.preassoc.cu_threshold, pString, sizeof(vapInfo->u.bss_info.preassoc.cu_threshold));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "BasicDataTransmitRates", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Rate to set for preassoc\n", __FUNCTION__,__LINE__,pString);
          
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.basic_data_transmit_rates) == 0) {
          return TRUE;
        }
          
        if (strcmp(pString, "disabled") == 0) {
          strncpy(vapInfo->u.bss_info.preassoc.basic_data_transmit_rates, "disabled", sizeof(vapInfo->u.bss_info.preassoc.basic_data_transmit_rates));
          set_cac_cache_changed(instance_number - 1);
          set_dml_cache_vap_config_changed(instance_number - 1);
          return TRUE;
        }
          
        if(isValidTransmitRate(pString)) { 
          if(isSupportedRate(pString) != ANSC_STATUS_SUCCESS) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Invalid value\n", __FUNCTION__,__LINE__,pString);
            return FALSE;
          }
          strncpy(vapInfo->u.bss_info.preassoc.basic_data_transmit_rates, pString, sizeof(vapInfo->u.bss_info.preassoc.basic_data_transmit_rates));
          set_cac_cache_changed(instance_number - 1);
          set_dml_cache_vap_config_changed(instance_number - 1);
          return TRUE;
      }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Not a valid format\n", __FUNCTION__,__LINE__,pString);
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "OperationalDataTransmitRates", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s operational Rate to set for preassoc\n", __FUNCTION__,__LINE__,pString);
          
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.operational_data_transmit_rates) == 0) {
          return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.preassoc.operational_data_transmit_rates, "disabled", sizeof(vapInfo->u.bss_info.preassoc.operational_data_transmit_rates));
            set_cac_cache_changed(instance_number - 1);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }

        if(isValidTransmitRate(pString)) {
          if(isSupportedRate(pString) != ANSC_STATUS_SUCCESS) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Invalid value\n", __FUNCTION__,__LINE__,pString);
            return FALSE;
          }

          strncpy(vapInfo->u.bss_info.preassoc.operational_data_transmit_rates, pString, sizeof(vapInfo->u.bss_info.preassoc.operational_data_transmit_rates));
          set_cac_cache_changed(instance_number - 1);
          set_dml_cache_vap_config_changed(instance_number - 1);
          return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Not a valid format\n", __FUNCTION__,__LINE__,pString);
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "SupportedDataTransmitRates", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Supported Rate to set for preassoc\n", __FUNCTION__,__LINE__,pString);
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.supported_data_transmit_rates) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.preassoc.supported_data_transmit_rates, "disabled", sizeof(vapInfo->u.bss_info.preassoc.supported_data_transmit_rates));
            set_cac_cache_changed(instance_number - 1);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }

        if(isValidTransmitRate(pString)) {
          if(isSupportedRate(pString) != ANSC_STATUS_SUCCESS) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Invalid value\n", __FUNCTION__,__LINE__,pString);
            return FALSE;
          }

          strncpy(vapInfo->u.bss_info.preassoc.supported_data_transmit_rates, pString, sizeof(vapInfo->u.bss_info.preassoc.supported_data_transmit_rates));
          set_cac_cache_changed(instance_number - 1);
          set_dml_cache_vap_config_changed(instance_number - 1);
          return TRUE;
      }
      wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Not a valid format\n", __FUNCTION__,__LINE__,pString);
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "MinimumAdvertisedMCS", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.minimum_advertised_mcs) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.preassoc.minimum_advertised_mcs, "disabled", sizeof(vapInfo->u.bss_info.preassoc.minimum_advertised_mcs));
            set_cac_cache_changed(instance_number - 1);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format: value should be single integer number between 0 to 7\n", __FUNCTION__,__LINE__);
            return FALSE;
        }
        if (val < 0 || val > 7) {
          wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect value, value should be within 0 to 7\n", __FUNCTION__,__LINE__);
          return FALSE;
        }

        strncpy(vapInfo->u.bss_info.preassoc.minimum_advertised_mcs, pString, sizeof(vapInfo->u.bss_info.preassoc.minimum_advertised_mcs));
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "6GOpInfoMinRate", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.sixGOpInfoMinRate) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.preassoc.sixGOpInfoMinRate, "disabled", sizeof(vapInfo->u.bss_info.preassoc.sixGOpInfoMinRate));
            set_cac_cache_changed(instance_number - 1);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
        strncpy(vapInfo->u.bss_info.preassoc.sixGOpInfoMinRate, pString, sizeof(vapInfo->u.bss_info.preassoc.sixGOpInfoMinRate));
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }
    
    if( AnscEqualString(ParamName, "TcmExpWeightage", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.tcm_exp_weightage) == 0) {
            return TRUE;
        }

        if (strcmp(pString, TCM_EXP_WEIGHTAGE) == 0) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Trying to set default value \n", __FUNCTION__,__LINE__);
            strncpy(vapInfo->u.bss_info.preassoc.tcm_exp_weightage, TCM_EXP_WEIGHTAGE, sizeof(vapInfo->u.bss_info.preassoc.tcm_exp_weightage));
            set_cac_cache_changed(instance_number - 1);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
        strncpy(vapInfo->u.bss_info.preassoc.tcm_exp_weightage, pString, sizeof(vapInfo->u.bss_info.preassoc.tcm_exp_weightage));
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "TcmGradientThreshold", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.preassoc.tcm_gradient_threshold) == 0) {
            return TRUE;
        }

        if (strcmp(pString, TCM_GRADIENT_THRESHOLD) == 0) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d trying to set default value \n", __FUNCTION__,__LINE__);
            strncpy(vapInfo->u.bss_info.preassoc.tcm_gradient_threshold, TCM_GRADIENT_THRESHOLD, sizeof(vapInfo->u.bss_info.preassoc.tcm_gradient_threshold));
            set_cac_cache_changed(instance_number - 1);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
        strncpy(vapInfo->u.bss_info.preassoc.tcm_gradient_threshold, pString, sizeof(vapInfo->u.bss_info.preassoc.tcm_gradient_threshold));
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PreAssocDeny_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
PreAssocDeny_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        PreAssocDeny_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PreAssocDeny_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        PreAssocDeny_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PreAssocDeny_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.ConnectionControl.PostAssocDisc.

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
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PostAssocDisc_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PostAssocDisc_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PostAssocDisc_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        PostAssocDisc_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
PostAssocDisc_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "RssiUpThresholdSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"disabled, -50 to -95");
        return 0;
    }

    if( AnscEqualString(ParamName, "RssiUpThreshold", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.postassoc.rssi_up_threshold);
        return 0;
    }

    if( AnscEqualString(ParamName, "SamplingIntervalSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"1 to 10");
        return 0;
    }

    if( AnscEqualString(ParamName, "SamplingInterval", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.postassoc.sampling_interval);
        return 0;
    }

    if( AnscEqualString(ParamName, "SnrThresholdSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"disabled, 1 to 100");
        return 0;
    }

    if( AnscEqualString(ParamName, "SnrThreshold", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.postassoc.snr_threshold);
        return 0;
    }

    if( AnscEqualString(ParamName, "SamplingCountSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"1 to 10");
        return 0;
    }

    if( AnscEqualString(ParamName, "SamplingCount", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.postassoc.sampling_count);
        return 0;
    }

    if( AnscEqualString(ParamName, "CuThresholdSupported", TRUE))
    {
        snprintf(pValue,*pUlSize,"disabled, 0 to 100");
        return 0;
    }

    if( AnscEqualString(ParamName, "CuThreshold", TRUE))
    {
        snprintf(pValue,*pUlSize,pcfg->u.bss_info.postassoc.cu_threshold);
        return 0;
    }

    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PostAssocDisc_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PostAssocDisc_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PostAssocDisc_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PostAssocDisc_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    int val, ret;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (!isVapHotspot(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RssiUpThreshold", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.postassoc.rssi_up_threshold) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.postassoc.rssi_up_threshold, "disabled", sizeof(vapInfo->u.bss_info.postassoc.rssi_up_threshold));
            set_cac_cache_changed(instance_number - 1);
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val > -50 || val < -95) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.postassoc.rssi_up_threshold, pString, sizeof(vapInfo->u.bss_info.postassoc.rssi_up_threshold));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SamplingInterval", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.postassoc.sampling_interval) == 0) {
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val < 1 || val > 10) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.postassoc.sampling_interval, pString, sizeof(vapInfo->u.bss_info.postassoc.sampling_interval));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SnrThreshold", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.postassoc.snr_threshold) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.postassoc.snr_threshold, "disabled", sizeof(vapInfo->u.bss_info.postassoc.snr_threshold));
            set_cac_cache_changed(instance_number - 1);
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val < 1 || val > 100) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.postassoc.snr_threshold, pString, sizeof(vapInfo->u.bss_info.postassoc.snr_threshold));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "SamplingCount", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.postassoc.sampling_count) == 0) {
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val < 1 || val > 10) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.postassoc.sampling_count, pString, sizeof(vapInfo->u.bss_info.postassoc.sampling_count));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "CuThreshold", TRUE))
    {
        if(strcmp(pString, vapInfo->u.bss_info.postassoc.cu_threshold) == 0) {
            return TRUE;
        }

        if (strcmp(pString, "disabled") == 0) {
            strncpy(vapInfo->u.bss_info.postassoc.cu_threshold, "disabled", sizeof(vapInfo->u.bss_info.postassoc.cu_threshold));
            set_cac_cache_changed(instance_number - 1);
            return TRUE;
        }

        ret = sscanf(pString, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        if (val < 10 || val > 100) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __FUNCTION__,__LINE__);
            return FALSE;
        }

        strncpy(vapInfo->u.bss_info.postassoc.cu_threshold, pString, sizeof(vapInfo->u.bss_info.postassoc.cu_threshold));
        set_cac_cache_changed(instance_number - 1);
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PostAssocDisc_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
PostAssocDisc_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        PostAssocDisc_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PostAssocDisc_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        PostAssocDisc_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PostAssocDisc_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

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
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WPS_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WPS_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = pcfg->u.bss_info.wps.enable;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WPS_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WPS_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if (AnscEqualString(ParamName, "X_CISCO_COM_WpsPushButton", TRUE))
    {
        *pInt = pcfg->u.bss_info.wpsPushButton;
        return TRUE;
    }
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WPS_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WPS_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(puLong);
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        WPS_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
WPS_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    ULONG vap_index = 0;
    errno_t  rc           = -1;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    dml_vap_default *cfg = (dml_vap_default *) get_vap_default(vap_index);
    if(cfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "ConfigMethodsSupported", TRUE)) {
        char buf[512] = {0};
        if (cfg->wps_methods & WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE )
        {
            rc = strcat_s(buf, sizeof(buf), "USBFlashDrive");
            ERR_CHK(rc);
        }
        if (cfg->wps_methods & WIFI_ONBOARDINGMETHODS_ETHERNET )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",Ethernet");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "Ethernet");
               ERR_CHK(rc);
            }

        }
        if (cfg->wps_methods & WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",ExternalNFCToken");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "ExternalNFCToken");
               ERR_CHK(rc);
            }
        }
        if (cfg->wps_methods & WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",IntegratedNFCToken");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "IntegratedNFCToken");
               ERR_CHK(rc);
            }
        }
        if (cfg->wps_methods & WIFI_ONBOARDINGMETHODS_NFCINTERFACE )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",NFCInterface");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "NFCInterface");
               ERR_CHK(rc);
            }
        }
        if (cfg->wps_methods & WIFI_ONBOARDINGMETHODS_PUSHBUTTON )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",PushButton");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "PushButton");
               ERR_CHK(rc);
            }
         }
         if (cfg->wps_methods & WIFI_ONBOARDINGMETHODS_PIN )
         {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",PIN");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "PIN");
               ERR_CHK(rc);
            }
        }
        if ( AnscSizeOfString(buf) < *pUlSize)
        {
            rc = strcpy_s(pValue, *pUlSize, buf);
            ERR_CHK(rc);
            return 0;
        }
        else
        {
           *pUlSize = AnscSizeOfString(buf)+1;
           return 1;
        }
    }

    if( AnscEqualString(ParamName, "ConfigMethodsEnabled", TRUE))
    {
        /* collect value */
        char buf[512] = {0};

        if (pcfg->u.bss_info.wps.methods & WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE )
        {
            rc = strcat_s(buf, sizeof(buf), "USBFlashDrive");
            ERR_CHK(rc);
        }
        if (pcfg->u.bss_info.wps.methods & WIFI_ONBOARDINGMETHODS_ETHERNET )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",Ethernet");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "Ethernet");
               ERR_CHK(rc);
            }

        }
        if (pcfg->u.bss_info.wps.methods & WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",ExternalNFCToken");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "ExternalNFCToken");
               ERR_CHK(rc);
            }
        }
        if (pcfg->u.bss_info.wps.methods & WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",IntegratedNFCToken");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "IntegratedNFCToken");
               ERR_CHK(rc);
            }
        }
        if (pcfg->u.bss_info.wps.methods & WIFI_ONBOARDINGMETHODS_NFCINTERFACE )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",NFCInterface");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "NFCInterface");
               ERR_CHK(rc);
            }
        }
        if (pcfg->u.bss_info.wps.methods & WIFI_ONBOARDINGMETHODS_PUSHBUTTON )
        {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",PushButton");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "PushButton");
               ERR_CHK(rc);
            }
         }
         if (pcfg->u.bss_info.wps.methods & WIFI_ONBOARDINGMETHODS_PIN )
         {
            if (AnscSizeOfString(buf) != 0)
            {
               rc = strcat_s(buf, sizeof(buf), ",PIN");
               ERR_CHK(rc);
            }
            else
            {
               rc = strcat_s(buf, sizeof(buf), "PIN");
               ERR_CHK(rc);
            }
        }
        if ( AnscSizeOfString(buf) < *pUlSize)
        {
            rc = strcpy_s(pValue, *pUlSize, buf);
            ERR_CHK(rc);
            return 0;
        }
        else
        {
           *pUlSize = AnscSizeOfString(buf)+1;
           return 1;
        }
    }

    if (AnscEqualString(ParamName, "X_CISCO_COM_Pin", TRUE)) {
        if ( AnscSizeOfString(cfg->wps_pin) > 0 )
        {
            if  ( AnscSizeOfString(cfg->wps_pin) < *pUlSize) {
                AnscCopyString(pValue, cfg->wps_pin);
                return 0;
            } else {
                *pUlSize = AnscSizeOfString(cfg->wps_pin)+1;
                return 1;
            }
        } else  {
            AnscCopyString(pValue, "");
            return 0;
        }
        return 0;
    }
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WPS_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WPS_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
#ifdef FEATURE_SUPPORT_WPS
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);
   
    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }
    /* check the parameter name and set the corresponding value */
    if (AnscEqualString(ParamName, "Enable", TRUE)) {
        if (vapInfo->u.bss_info.wps.enable != bValue) {
            vapInfo->u.bss_info.wps.enable = bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }
    if (AnscEqualString(ParamName, "X_CISCO_COM_ActivatePushButton", TRUE)) {
        if (vapInfo->u.bss_info.wpsPushButton != bValue) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d:key=%d bValue=%d\n", __func__, __LINE__,
                vapInfo->u.bss_info.wpsPushButton, bValue);
            vapInfo->u.bss_info.wpsPushButton = bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_CISCO_COM_CancelSession", TRUE))
    {
        instance_number -= 1;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: WPS cancel for vap %d\n",__func__, __LINE__, instance_number);
        push_event_to_ctrl_queue(&instance_number, sizeof(instance_number), wifi_event_type_command, wifi_event_type_command_wps_cancel, NULL);
        return TRUE;
    }
#else
    wifi_util_info_print(WIFI_DMCLI, "%s:%d: WPS not supported\n", __func__, __LINE__);
#endif
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        WPS_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WPS_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
 
    /* check the parameter name and set the corresponding value */
#ifdef FEATURE_SUPPORT_WPS
    if (AnscEqualString(ParamName, "X_CISCO_COM_WpsPushButton", TRUE)) {
        return TRUE;
    }
#else
    wifi_util_info_print(WIFI_DMCLI, "%s:%d: WPS not supported\n", __func__, __LINE__);
#endif
    return FALSE;
}


    /**********************************************************************

        caller:     owner of this object

        prototype:

            BOOL
            WPS_SetParamUlongValue
                (
                    ANSC_HANDLE                 hInsContext,
                    char*                       ParamName,
                    ULONG                       uValue
                );

        description:

            This function is called to set ULONG parameter value;

        argument:   ANSC_HANDLE                 hInsContext,
                    The instance handle;

                    char*                       ParamName,
                    The parameter name;

                    ULONG                       uValue
                    The updated ULONG value;

        return:     TRUE if succeeded.

    **********************************************************************/
    BOOL WPS_SetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG uValue)
    {
        UNREFERENCED_PARAMETER(hInsContext);
        UNREFERENCED_PARAMETER(ParamName);
        UNREFERENCED_PARAMETER(uValue);
        /* check the parameter name and set the corresponding value */

        /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
        return FALSE;
    }

    /**********************************************************************

        caller:     owner of this object

        prototype:

            BOOL
            WPS_SetParamStringValue
                (
                    ANSC_HANDLE                 hInsContext,
                    char*                       ParamName,
                    char*                       pString
                );

        description:

            This function is called to set string parameter value;

        argument:   ANSC_HANDLE                 hInsContext,
                    The instance handle;

                    char*                       ParamName,
                    The parameter name;

                    char*                       pString
                    The updated string value;

        return:     TRUE if succeeded.

    **********************************************************************/
    BOOL WPS_SetParamStringValue(ANSC_HANDLE hInsContext, char *ParamName, char *pString)
    {
#ifdef FEATURE_SUPPORT_WPS
        wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
        if (pcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Null pointer get fail\n", __FUNCTION__,
                __LINE__);
            return FALSE;
        }
        uint8_t instance_number = convert_vap_name_to_index(
                                      &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop,
                                      pcfg->vap_name) +
            1;
        wifi_vap_info_t *vapInfo = (wifi_vap_info_t *)get_dml_cache_vap_info(instance_number - 1);

        if (vapInfo == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Unable to get VAP info for instance_number:%d\n",
                __FUNCTION__, __LINE__, instance_number);
            return FALSE;
        }
        /* check the parameter name and set the corresponding value */
        if (AnscEqualString(ParamName, "ConfigMethodsEnabled", TRUE)) {
            int match = 0;

            if (isVapSTAMesh(pcfg->vap_index)) {
                wifi_util_dbg_print(WIFI_DMCLI, "%s:%d %s does not support configuration\n",
                    __FUNCTION__, __LINE__, pcfg->vap_name);
                return TRUE;
            }
            // Needs to initialize by 0 before setting
            vapInfo->u.bss_info.wps.methods = 0;
            /* save update to backup */
            if (_ansc_strstr(pString, "USBFlashDrive")) {
                match++;
                vapInfo->u.bss_info.wps.methods = (vapInfo->u.bss_info.wps.methods |
                    WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE);
            }
            if (_ansc_strstr(pString, "Ethernet")) {
                match++;
                vapInfo->u.bss_info.wps.methods = (vapInfo->u.bss_info.wps.methods |
                    WIFI_ONBOARDINGMETHODS_ETHERNET);
            }
            if (_ansc_strstr(pString, "ExternalNFCToken")) {
                match++;
                vapInfo->u.bss_info.wps.methods = (vapInfo->u.bss_info.wps.methods |
                    WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN);
            }
            if (_ansc_strstr(pString, "IntegratedNFCToken")) {
                match++;
                vapInfo->u.bss_info.wps.methods = (vapInfo->u.bss_info.wps.methods |
                    WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN);
            }
            if (_ansc_strstr(pString, "NFCInterface")) {
                match++;
                vapInfo->u.bss_info.wps.methods = (vapInfo->u.bss_info.wps.methods |
                    WIFI_ONBOARDINGMETHODS_NFCINTERFACE);
            }
            if (_ansc_strstr(pString, "PushButton")) {
                match++;
                vapInfo->u.bss_info.wps.methods = (vapInfo->u.bss_info.wps.methods |
                    WIFI_ONBOARDINGMETHODS_PUSHBUTTON);
            }
            if (_ansc_strstr(pString, "PIN")) {
                match++;
                vapInfo->u.bss_info.wps.methods = (vapInfo->u.bss_info.wps.methods |
                    WIFI_ONBOARDINGMETHODS_PIN);
            }
            if (_ansc_strstr(pString, "NONE")) {
                match++;
                vapInfo->u.bss_info.wps.methods = 0;
                set_dml_cache_vap_config_changed(instance_number - 1);
            }

            // If match is not there then return error
            if (match == 0) { // Might have passed value that is invalid
                return FALSE;
            }
            if (vapInfo->u.bss_info.wps.methods != 0) {
                set_dml_cache_vap_config_changed(instance_number - 1);
            }
            return TRUE;
        }

        if (AnscEqualString(ParamName, "X_CISCO_COM_ClientPin", TRUE)) {
            if ((strlen(pString) >= 4) && (strlen(pString) <= 8)) {
                push_wps_pin_dml_to_ctrl_queue((instance_number - 1), pString);
            } else {
                return FALSE;
            }
            return TRUE;
        }
#else
        wifi_util_info_print(WIFI_DMCLI, "%s:%d WPS is not supported\n", __FUNCTION__, __LINE__);
#endif
        return FALSE;
    }

    /**********************************************************************

        caller:     owner of this object

        prototype:

            BOOL
            WPS_Validate
                (
                    ANSC_HANDLE                 hInsContext,
                    char*                       pReturnParamName,
                    ULONG*                      puLength
                );

        description:

            This function is called to finally commit all the update.

        argument:   ANSC_HANDLE                 hInsContext,
                    The instance handle;

                    char*                       pReturnParamName,
                    The buffer (128 bytes) of parameter name if there's a validation.

                    ULONG*                      puLength
                    The output length of the param name.

        return:     TRUE if there's no validation.

    **********************************************************************/
    BOOL WPS_Validate(ANSC_HANDLE hInsContext, char *pReturnParamName, ULONG *puLength)
    {
#ifdef FEATURE_SUPPORT_WPS
        wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
        if (pcfg == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Null pointer get fail\n", __FUNCTION__,
                __LINE__);
            return FALSE;
        }
        uint8_t instance_number = convert_vap_name_to_index(
                                      &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop,
                                      pcfg->vap_name) +
            1;
        INT wlanIndex = -1;
        wlanIndex = instance_number - 1;
        dml_vap_default *cfg = (dml_vap_default *)get_vap_default(wlanIndex);
        wifi_vap_info_t *vapInfo = (wifi_vap_info_t *)get_dml_cache_vap_info(instance_number - 1);

        if (wifiApIsSecmodeOpenForPrivateAP(wlanIndex) != ANSC_STATUS_SUCCESS) {
            return FALSE;
        }
        if (vapInfo->u.bss_info.wpsPushButton == true) {
            if (vapInfo->u.bss_info.wps.enable == false) {
                CcspWifiTrace(
                    ("RDK_LOG_ERROR,(%s) WPS is not enabled for vap %d\n", __func__, wlanIndex));

                vapInfo->u.bss_info.wpsPushButton = false;
                return FALSE;
            }

            if ((cfg->wps_methods & WIFI_ONBOARDINGMETHODS_PUSHBUTTON) == 0) {
                CcspWifiTrace(("RDK_LOG_ERROR,(%s) WPS PBC is not configured for vap %d\n",
                    __func__, wlanIndex));

                vapInfo->u.bss_info.wpsPushButton = false;
                return FALSE;
            }
        }
        return TRUE;
#endif
        return FALSE;
    }

    /**********************************************************************

        caller:     owner of this object

        prototype:

            ULONG
            WPS_Commit
                (
                    ANSC_HANDLE                 hInsContext
                );

        description:

            This function is called to finally commit all the update.

        argument:   ANSC_HANDLE                 hInsContext,
                    The instance handle;

        return:     The status of the operation.

    **********************************************************************/
    ULONG
    WPS_Commit(ANSC_HANDLE hInsContext)
    {
#ifdef FEATURE_SUPPORT_WPS
        wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
        uint8_t instance_number = convert_vap_name_to_index(
                                      &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop,
                                      pcfg->vap_name) +
            1;
        INT wlanIndex = instance_number - 1;
        wifi_vap_info_t *vapInfo = (wifi_vap_info_t *)get_dml_cache_vap_info(instance_number - 1);
        if (vapInfo->u.bss_info.wpsPushButton == true) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d:Activate push button for vap %d\n", __func__,
                __LINE__, wlanIndex);
            push_event_to_ctrl_queue(&wlanIndex, sizeof(wlanIndex), wifi_event_type_command,
                wifi_event_type_command_wps, NULL);
            vapInfo->u.bss_info.wpsPushButton = false;
        }
        return TRUE;
#endif
        return FALSE;
    }

    /**********************************************************************

        caller:     owner of this object

        prototype:

            ULONG
            WPS_Rollback
                (
                    ANSC_HANDLE                 hInsContext
                );

        description:

            This function is called to roll back the update whenever there's a
            validation found.

        argument:   ANSC_HANDLE                 hInsContext,
                    The instance handle;

        return:     The status of the operation.

    **********************************************************************/
    ULONG
    WPS_Rollback(ANSC_HANDLE hInsContext)
    {
        UNREFERENCED_PARAMETER(hInsContext);
        return ANSC_STATUS_SUCCESS;
    }

/**********************************************************************

        BOOL
        IsValidMacAddress
            (
                char*                       mac
            );

    description:

        This function is called to check for valid MAC Address.

    argument:   char*                       mac,
                string mac address buffer.

    return:     TRUE if it's valid mac address.
        FALSE if it's invalid 

**********************************************************************/
#if defined(MAC_ADDR_LEN)
    #undef MAC_ADDR_LEN
#endif
#define MAC_ADDR_LEN 17

BOOL
IsValidMacAddress(char *mac)
{
    int iter = 0, len = 0;
    len = strlen(mac);
    if(len != MAC_ADDR_LEN) {
	CcspWifiTrace(("RDK_LOG_ERROR, (%s) MACAddress is not valid!!!\n", __func__));
	return FALSE;
    }
    if(mac[2] == ':' && mac[5] == ':' && mac[8] == ':' && mac[11] == ':' && mac[14] == ':') {
	for(iter = 0; iter < MAC_ADDR_LEN; iter++) {
	    if((iter == 2 || iter == 5 || iter == 8 || iter == 11 || iter == 14)) {
		continue;
	    } 
	    else if((mac[iter] > 47 && mac[iter] <= 57) || (mac[iter] > 64 && mac[iter] < 71) || (mac[iter] > 96 && mac[iter] < 103)) {
		continue;
	    }
	    else {
		CcspWifiTrace(("RDK_LOG_ERROR, (%s), MACAdress is not valid\n", __func__));
		return FALSE;
		break;
	    }
	}
    } else {
	CcspWifiTrace(("RDK_LOG_ERROR, (%s), MACAdress is not valid\n", __func__));
	return FALSE;
    }

    return TRUE;
}


#if defined (FEATURE_SUPPORT_INTERWORKING)

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.X_RDKCENTRAL-COM_InterworkingElement.

    *  InterworkingElement_GetParamBoolValue
    *  InterworkingElement_GetParamIntValue
    *  InterworkingElement_GetParamUlongValue
    *  InterworkingElement_GetParamStringValue
    *  InterworkingElement_SetParamBoolValue
    *  InterworkingElement_SetParamIntValue
    *  InterworkingElement_SetParamUlongValue
    *  InterworkingElement_SetParamStringValue
    *  InterworkingElement_Validate
    *  InterworkingElement_Commit
    *  InterworkingElement_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object

    prototype:

        BOOL
        InterworkingElement_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingElement_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{   
 
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;
    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    wifi_interworking_t *pcfg = &vap_pcfg->u.bss_info.interworking;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Internet", TRUE))
    {
        /* collect value */
        if(isVapHotspot(vap_pcfg->vap_index))
	{
            *pBool = pcfg->interworking.internetAvailable;
	    return TRUE;
	}
	else
	{
	    *pBool = pcfg->interworking.internetAvailable;
	    return TRUE;
	}
    }
    
    if( AnscEqualString(ParamName, "ASRA", TRUE))
    {
        /* collect value */
        *pBool = pcfg->interworking.asra;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "ESR", TRUE))
    {
        /* collect value */
        *pBool = pcfg->interworking.esr;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UESA", TRUE))
    {
        /* collect value */
        *pBool = pcfg->interworking.uesa;
        return TRUE;
    }

   if( AnscEqualString(ParamName, "VenueOptionPresent", TRUE))
     {
        *pBool = pcfg->interworking.venueOptionPresent;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "HESSOptionPresent", TRUE))
    {
        /* collect value */
        *pBool = pcfg->interworking.hessOptionPresent;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingElement_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingElement_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingElement_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingElement_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;
    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    wifi_interworking_t *pcfg = &vap_pcfg->u.bss_info.interworking;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "AccessNetworkType", TRUE))
    {
        /* collect value */
        *puLong = pcfg->interworking.accessNetworkType;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        InterworkingElement_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
InterworkingElement_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{   
 
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;
    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }
    wifi_interworking_t *pcfg = &vap_pcfg->u.bss_info.interworking;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "HESSID", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pcfg->interworking.hessid);
       *pUlSize = AnscSizeOfString(pcfg->interworking.hessid);
        return 0;
    }
    
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingElement_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingElement_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{    
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Internet", TRUE))
    {
        if(vapInfo->u.bss_info.interworking.interworking.internetAvailable == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d internet=%d bValue=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.internetAvailable,bValue);
        vapInfo->u.bss_info.interworking.interworking.internetAvailable = bValue;
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }
    
    if( AnscEqualString(ParamName, "ASRA", TRUE))
    {
        if(vapInfo->u.bss_info.interworking.interworking.asra == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d asra=%d bValue=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.asra,bValue);
        vapInfo->u.bss_info.interworking.interworking.asra = bValue;
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "ESR", TRUE))
    {
        if(vapInfo->u.bss_info.interworking.interworking.esr == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d esr=%d bValue=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.esr,bValue);
        vapInfo->u.bss_info.interworking.interworking.esr = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "UESA", TRUE))
    {
        if(vapInfo->u.bss_info.interworking.interworking.uesa == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d uesa=%d bValue=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.uesa,bValue);
        vapInfo->u.bss_info.interworking.interworking.uesa = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "VenueOptionPresent", TRUE))
    {
        if(vapInfo->u.bss_info.interworking.interworking.venueOptionPresent == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d venue=%d bValue=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.venueOptionPresent,bValue);
        vapInfo->u.bss_info.interworking.interworking.venueOptionPresent = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "HESSOptionPresent", TRUE))
    {
        if(vapInfo->u.bss_info.interworking.interworking.hessOptionPresent == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d hessOptionPresent=%d bValue=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.hessOptionPresent,bValue);
        vapInfo->u.bss_info.interworking.interworking.hessOptionPresent = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
    
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingElement_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingElement_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(iValue); 
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingElement_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingElement_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{   
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "AccessNetworkType", TRUE))
    {
        if ((uValue < 6) || ((uValue < 16) && (uValue > 13)))
        {
            if(vapInfo->u.bss_info.interworking.interworking.accessNetworkType == uValue)
            {
                return TRUE;
            }
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d accessNetworkType=%d Value=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.accessNetworkType,uValue);
            vapInfo->u.bss_info.interworking.interworking.accessNetworkType = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
    }

    return FALSE;


}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingElement_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingElement_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{    
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "HESSID", TRUE))
    {
        AnscCopyString(vapInfo->u.bss_info.interworking.interworking.hessid, pString);
	set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }
    
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingElement_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
InterworkingElement_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{  
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;

    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    BOOL validated = TRUE;

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    //VenueGroup must be greater or equal to 0 and less than 12
    if (!((vap_pcfg->u.bss_info.interworking.interworking.venueGroup < 12) && (vap_pcfg->u.bss_info.interworking.interworking.venueGroup >= 0))) {
	AnscCopyString(pReturnParamName, "Group");
	*puLength = AnscSizeOfString("Group");
	CcspWifiTrace(("RDK_LOG_ERROR,(%s), VenueGroup validation error!!!\n", __func__));
	validated = FALSE;
    }
    else //VenueType must be as per specifications from WiFi Alliance for every valid value of vnue group
    {
        int updateInvalidType = 0;

        switch (vap_pcfg->u.bss_info.interworking.interworking.venueGroup)
        {
            case 0:
                if (vap_pcfg->u.bss_info.interworking.interworking.venueType != 0)
                {
                    updateInvalidType = 1;
                }
                break;
            case 1:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 16) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
            case 2:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 10) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
            case 3:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 4) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
            case 4:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 2) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
            case 5:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 6) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
            case 6:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 6) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
            case 7:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 5) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;

            case 8:
                if (vap_pcfg->u.bss_info.interworking.interworking.venueType != 0)
                {
                    updateInvalidType = 1;
                }
                break;
            case 9:
                if (vap_pcfg->u.bss_info.interworking.interworking.venueType != 0)
                {
                    updateInvalidType = 1;
                }
                break;
            case 10:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 8) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
            case 11:
                if (!((vap_pcfg->u.bss_info.interworking.interworking.venueType < 7) && (vap_pcfg->u.bss_info.interworking.interworking.venueType >= 0)))
                {
                    updateInvalidType = 1;
                }
                break;
        }

        if(updateInvalidType)
        {
            AnscCopyString(pReturnParamName, "Type");
            *puLength = AnscSizeOfString("Type");
            CcspWifiTrace(("RDK_LOG_ERROR,(%s), VenueType validation error!!!\n", __func__));
            validated = FALSE;
        }

    }
    //AccessNetworkType must be greater or equal to 0 and less than 16
	 if (!(((vap_pcfg->u.bss_info.interworking.interworking.accessNetworkType < 6) && (vap_pcfg->u.bss_info.interworking.interworking.accessNetworkType >= 0)) || ((vap_pcfg->u.bss_info.interworking.interworking.accessNetworkType < 16) && (vap_pcfg->u.bss_info.interworking.interworking.accessNetworkType > 13)))) 
     {
         AnscCopyString(pReturnParamName, "AccessNetworkType");
         *puLength = AnscSizeOfString("AccessNetworkType");
         CcspWifiTrace(("RDK_LOG_ERROR,(%s), AccessNetworkType validation error!!!\n", __func__));
         validated = FALSE;        
     }

    //InternetAvailable must be greater or equal to 0 and less than 2
    if ((vap_pcfg->u.bss_info.interworking.interworking.internetAvailable < 0) || (vap_pcfg->u.bss_info.interworking.interworking.internetAvailable > 1)) {
	AnscCopyString(pReturnParamName, "InternetAvailable");
	*puLength = AnscSizeOfString("InternetAvailable");
	CcspWifiTrace(("RDK_LOG_ERROR,(%s), Internet validation error!!!\n", __func__));
	validated = FALSE;        
    } 

    //ASRA must be greater or equal to 0 and less than 2
    if ((vap_pcfg->u.bss_info.interworking.interworking.asra < 0) || (vap_pcfg->u.bss_info.interworking.interworking.asra > 1)) {
	AnscCopyString(pReturnParamName, "ASRA");
	*puLength = AnscSizeOfString("ASRA");
	CcspWifiTrace(("RDK_LOG_ERROR,(%s), ASRA validation error!!!\n", __func__));
	validated = FALSE; 
    } 

    //ESR must be greater or equal to 0 and less than 2
    if ((vap_pcfg->u.bss_info.interworking.interworking.esr < 0) || (vap_pcfg->u.bss_info.interworking.interworking.esr > 1)) {
	AnscCopyString(pReturnParamName, "ESR");
	*puLength = AnscSizeOfString("ESR");
	CcspWifiTrace(("RDK_LOG_ERROR,(%s), ESR validation error!!!\n", __func__));
	validated = FALSE;        
    } 

    //UESA must be greater or equal to 0 and less than 2
    if ((vap_pcfg->u.bss_info.interworking.interworking.uesa < 0) || (vap_pcfg->u.bss_info.interworking.interworking.uesa > 1)) {
	AnscCopyString(pReturnParamName, "UESA");
	*puLength = AnscSizeOfString("UESA");
	CcspWifiTrace(("RDK_LOG_ERROR,(%s), UESA validation error!!!\n", __func__));
	validated = FALSE;        
    } 

    //VenueOptionPresent must be greater or equal to 0 and less than 2
    if ((vap_pcfg->u.bss_info.interworking.interworking.venueOptionPresent < 0) || (vap_pcfg->u.bss_info.interworking.interworking.venueOptionPresent > 1)) {
	AnscCopyString(pReturnParamName, "VenueOptionPresent");
	*puLength = AnscSizeOfString("VenueOptionPresent");
	CcspWifiTrace(("RDK_LOG_ERROR,(%s), VenueOption validation error!!!\n", __func__));
	validated = FALSE;        
    } 


    if (vap_pcfg->u.bss_info.interworking.interworking.hessOptionPresent == TRUE) {
        /*Check for Valid Mac Address*/
	    if (IsValidMacAddress(vap_pcfg->u.bss_info.interworking.interworking.hessid) != TRUE) {
	    CcspWifiTrace(("RDK_LOG_ERROR,(%s), HESSID validation error!!!\n", __func__));   
	    AnscCopyString(pReturnParamName, "HESSID");
	    *puLength = AnscSizeOfString("HESSID");
	    validated = FALSE;
	}
    }

    return validated;
}




/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        InterworkingElement_Commit
			ANSC_HANDLE                 hInsContext
           );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
InterworkingElement_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 


        ULONG
        InterworkingElement_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
InterworkingElement_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.X_RDKCENTRAL-COM_InterworkingElement.VenueInfo.

	*	InterworkingElement_Venue_GetParamUlongValue
	*	InterworkingElement_Venue_SetParamUlongValue


***********************************************************************/
BOOL InterworkingElement_Venue_GetParamUlongValue
     (
         ANSC_HANDLE                 hInsContext,
         char*                       ParamName,
         ULONG*                      puLong
     )
 {
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;

    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_interworking_t *pcfg = &vap_pcfg->u.bss_info.interworking;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Type", TRUE))
    {
        /* collect value */
        *puLong = pcfg->interworking.venueType;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Group", TRUE))
    {
        /* collect value */
        *puLong = pcfg->interworking.venueGroup;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        InterworkingElement_Venue_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

************************************************************/
BOOL
InterworkingElement_Venue_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if( AnscEqualString(ParamName, "Type", TRUE))
    {
        int updateInvalidType = 0;
        if (uValue < 256)
        {
            switch (vapInfo->u.bss_info.interworking.interworking.venueGroup)
            {
                case 0:
                    if (uValue != 0)
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 1:
                    if (!(uValue < 16))
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 2:
                    if (!(uValue < 10))
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 3:
                    if (!(uValue < 4))
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 4:
                    if (!(uValue < 2))
                    {
                        updateInvalidType = 1;
                    }
                    break;

                case 5:
                    if (!(uValue < 6))
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 6:
                    if (!(uValue < 6))
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 7:
                    if (!(uValue < 5))
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 8:
                    if (uValue != 0)
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 9:
                    if (uValue != 0)
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 10:
                    if (!(uValue < 8))
                    {
                        updateInvalidType = 1;
                    }
                    break;
                case 11:
                    if (!(uValue < 7))
                    {
                        updateInvalidType = 1;
                    }
                    break;
            }
        }
        else 
        {
            updateInvalidType = 1;
        }


        if (! updateInvalidType)
        {
            if(vapInfo->u.bss_info.interworking.interworking.venueType  == uValue)
            {
                return TRUE;
            }
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d venueType=%d Value=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.venueType,uValue);
            vapInfo->u.bss_info.interworking.interworking.venueType = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }

    }
    if( AnscEqualString(ParamName, "Group", TRUE))
    {
        if (uValue < 12)
        {
            if(vapInfo->u.bss_info.interworking.interworking.venueGroup  == uValue)
            {
                return TRUE;
            }
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d venueGroup=%d Value=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.interworking.interworking.venueGroup,uValue);
            vapInfo->u.bss_info.interworking.interworking.venueGroup = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
    }

       /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;


}

#else // For all non xb3/dual core platforms that do have full support for interworking, we are writting stub functions
BOOL
InterworkingElement_GetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL*                       pBool
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    if( AnscEqualString(ParamName, "Internet", TRUE))
    {
        *pBool = false;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "ASRA", TRUE))
    {
        *pBool = false;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "ESR", TRUE))
    {
        *pBool = false;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "UESA", TRUE))
    {
        *pBool = false;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "VenueOptionPresent", TRUE))
    {
        *pBool = false;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "HESSOptionPresent", TRUE))
    {
        *pBool = false;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

BOOL
InterworkingElement_GetParamIntValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 int*                        pInt
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);
    //  // no param implemented in actual API.
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

BOOL
InterworkingElement_GetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG*                      puLong
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    if( AnscEqualString(ParamName, "AccessNetworkType", TRUE))
    {
        *puLong = 0;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

ULONG
InterworkingElement_GetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       pValue,
 ULONG*                      pUlSize
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    if( AnscEqualString(ParamName, "HESSID", TRUE))
    {
        AnscCopyString(pValue, "no support for non xb3");
        *pUlSize = AnscSizeOfString(pValue);
        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

BOOL
InterworkingElement_Venue_GetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG*                      puLong
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    if( AnscEqualString(ParamName, "Type", TRUE))
    {
        /* collect value */
        *puLong = 0;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Group", TRUE))
    {
        /* collect value */
        *puLong = 0;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

#endif // (DUAL_CORE_XB3) || (_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_GASConfig.{i}.

    *   GASConfig_GetEntryCount
    *   GASConfig_GetEntry
    *   GASConfig_AddEntry
    *   GASConfig_DelEntry
    *   GASConfig_GetParamBoolValue
    *   GASConfig_GetParamUlongValue

***********************************************************************/

/***********************************************************************


    caller:     owner of this object

    prototype:

        ULONG
        GASConfig_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/

ULONG
GASConfig_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ULONG                           GAS_ADVCount    = 1;
    UNREFERENCED_PARAMETER(hInsContext);
    return GAS_ADVCount;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
                GASConfig_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/

ANSC_HANDLE
GASConfig_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_GASConfiguration_t *pcfg = (wifi_GASConfiguration_t *) get_dml_wifi_gas_config();
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: nIndex:%ld\n",__func__, __LINE__, nIndex);
    *pInsNumber = nIndex + 1;
    return pcfg; /* return the handle */
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        GASConfig_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
        
                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
GASConfig_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    wifi_GASConfiguration_t *pcfg = (wifi_GASConfiguration_t *) get_dml_wifi_gas_config();

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if( AnscEqualString(ParamName, "PauseForServerResponse", TRUE))
    {
        /* collect value */
        *pBool  = pcfg->PauseForServerResponse;
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        GASConfig_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve Integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
        
                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
GASConfig_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    wifi_GASConfiguration_t *pcfg = (wifi_GASConfiguration_t *)get_dml_wifi_gas_config();

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* collect value */
    if( AnscEqualString(ParamName, "AdvertisementID", TRUE))
    {
        *puLong  = pcfg->AdvertisementID;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "ResponseTimeout", TRUE))
    {
        *puLong  = pcfg->ResponseTimeout;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "ComeBackDelay", TRUE))
    {
        *puLong  = pcfg->ComeBackDelay;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "ResponseBufferingTime", TRUE))
    {
        *puLong  = pcfg->ResponseBufferingTime;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "QueryResponseLengthLimit", TRUE))
    {
        *puLong  = pcfg->QueryResponseLengthLimit;
        return TRUE;
    }

    return FALSE;
}

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_GASStats.{i}.

    *   GASStats_GetEntryCount
    *   GASStats_GetEntry
    *   GASStats_AddEntry
    *   GASStats_DelEntry
    *   GASStats_GetParamUlongValue

***********************************************************************/

/***********************************************************************


    caller:     owner of this object

    prototype:

        ULONG
        GASStats_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/

ULONG
GASStats_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ULONG                           GAS_ADVCount    = 1;
    UNREFERENCED_PARAMETER(hInsContext);
    return GAS_ADVCount;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
            GASStats_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/

ANSC_HANDLE
GASStats_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return (ANSC_HANDLE)NULL;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        GASStats_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve Integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
        
                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
GASStats_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    wifi_gas_stats_t  *pGASStats   = (wifi_gas_stats_t *)hInsContext;

    if (pGASStats == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if(ANSC_STATUS_SUCCESS != WiFi_GetGasStats(pGASStats)){
        return FALSE;
    }
    /* collect value */
    if( AnscEqualString(ParamName, "AdvertisementID", TRUE))
    {
        *puLong  = pGASStats->AdvertisementID;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "Queries", TRUE))
    {
        *puLong  = pGASStats->Queries;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "QueryRate", TRUE))
    {
        *puLong  = pGASStats->QueryRate;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "Responses", TRUE))
    {
        *puLong  = pGASStats->Responses;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "ResponseRate", TRUE))
    {
        *puLong  = pGASStats->ResponseRate;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "NoRequestOutstanding", TRUE))
    {
        *puLong  = pGASStats->NoRequestOutstanding;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "ResponsesDiscarded", TRUE))
    {
        *puLong  = pGASStats->ResponsesDiscarded;

        return TRUE;
    }
    if( AnscEqualString(ParamName, "FailedResponses", TRUE))
    {
        *puLong  = pGASStats->FailedResponses;

        return TRUE;
    }

    return FALSE;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.X_CISCO_COM_MACFilter.

    *  MacFilter_GetParamBoolValue
    *  MacFilter_GetParamIntValue
    *  MacFilter_GetParamUlongValue
    *  MacFilter_GetParamStringValue
    *  MacFilter_SetParamBoolValue
    *  Macfilter_SetParamIntValue
    *  MacFilter_SetParamUlongValue
    *  MacFilter_SetParamStringValue
    *  MacFilter_Validate
    *  MacFilter_Commit
    *  MacFilter_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object

    prototype:

        BOOL
        MacFilter_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MacFilter_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *)hInsContext;

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    if (isVapSTAMesh(vapInfo->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vapInfo->vap_name);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* collect value */
        if(isVapHotspot(vapInfo->vap_index)){
            *pBool = true;
        } else {
            *pBool = vapInfo->u.bss_info.mac_filter_enable;
        }
        return TRUE;
    }
    
    if( AnscEqualString(ParamName, "FilterAsBlackList", TRUE))
    {
        /* collect value */
        if ((vapInfo->u.bss_info.mac_filter_enable == true) && vapInfo->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
            *pBool = TRUE;
        } else {
            *pBool = FALSE;
        }
        return TRUE;
    }


    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Macfilter_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MacFilter_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MacFilter_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MacFilter_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(puLong);
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MacFilter_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
MacFilter_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pValue);
    UNREFERENCED_PARAMETER(pUlSize);
    /* check the parameter name and return the corresponding value */
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MacFilter_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MacFilter_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* save update to backup */
        if (vapInfo->u.bss_info.mac_filter_enable != bValue)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d mac_filter_enable=%d Value=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.mac_filter_enable,bValue);
            vapInfo->u.bss_info.mac_filter_enable = bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }
    if( AnscEqualString(ParamName, "FilterAsBlackList", TRUE))
    {
         /* save update to backup */
        if (vapInfo->u.bss_info.mac_filter_mode != !bValue)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d mac_filter_mode=%d Value=%d  \n",__func__, __LINE__,vapInfo->u.bss_info.mac_filter_mode,!bValue);
            vapInfo->u.bss_info.mac_filter_mode = !bValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
         return TRUE;
    }


    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MacFilter_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MacFilter_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(iValue);
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MacFilter_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MacFilter_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(uValue);
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MacFilter_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MacFilter_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pString);
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MacFilter_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
MacFilter_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);  
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MacFilter_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
MacFilter_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MacFilter_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
MacFilter_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}X_RDKCENTRAL-COM_DPP.

    *  DPP_GetParamBoolValue
    *  DPP_GetParamIntValue
    *  DPP_GetParamUlongValue
    *  DPP_GetParamStringValue
    *  DPP_SetParamBoolValue
    *  DPP_SetParamIntValue
    *  DPP_SetParamUlongValue
    *  DPP_SetParamStringValue
    *  DPP_Validate
    *  DPP_Commit
    *  DPP_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DPP_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
DPP_Validate
    (   
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DPP_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_FAILURE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DPP_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    if (AnscEqualString(ParamName, "Version", TRUE))
    {
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
DPP_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    if( AnscEqualString(ParamName, "PrivateSigningKey", TRUE))
    {
        AnscCopyString(pValue, "");
        return 0;
    }
    if( AnscEqualString(ParamName, "PrivateReconfigAccessKey", TRUE))
    {
        AnscCopyString(pValue, "");
        return 0;
    }
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pValue);
    UNREFERENCED_PARAMETER(pUlSize);
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(uValue);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pString);
    UNREFERENCED_PARAMETER(ParamName);
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}X_RDKCENTRAL-COM_DPP.STA.{i}.

    *  DPP_STA_GetParamBoolValue
    *  DPP_STA_GetParamIntValue
    *  DPP_STA_GetParamUlongValue
    *  DPP_STA_GetParamStringValue
    *  DPP_STA_SetParamBoolValue
    *  DPP_STA_SetParamIntValue
    *  DPP_STA_SetParamUlongValue
    *  DPP_STA_SetParamStringValue
    *  DPP_STA_Validate
    *  DPP_STA_Commit
    *  DPP_STA_Rollback

***********************************************************************/

/**********************************************************************  

    caller:     owner of this object

    prototype:

        BOOL
        DPP_STA_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pBool);
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    CcspTraceError(("%s: Not Impl %d\n", __func__, __LINE__));
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pInt);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(puLong);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_STA_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
DPP_STA_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pValue);
    UNREFERENCED_PARAMETER(pUlSize);
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(bValue);

    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(iValue);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(uValue);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pString);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
DPP_STA_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_STA_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DPP_STA_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_FAILURE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_STA_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DPP_STA_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}


/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}X_RDKCENTRAL-COM_DPP.STA.{i}.

    *  DPP_STA_Credential_GetParamStringValue
    *  DPP_STA_Credential_SetParamStringValue
    *  DPP_STA_Credential_Validate
    *  DPP_STA_Credential_Commit
    *  DPP_STA_Credential_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_STA_Credential_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
DPP_STA_Credential_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(pUlSize);
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pValue);
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_Credential_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DPP_STA_Credential_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pString);
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DPP_STA_Credential_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
DPP_STA_Credential_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_STA_Credential_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DPP_STA_Credential_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DPP_STA_Credential_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DPP_STA_Credential_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return ANSC_STATUS_SUCCESS;
}

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
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AssociatedDevice1_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
AssociatedDevice1_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)hInsContext;
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return 0;
    }

    unsigned long count = 0;
    count  = get_associated_devices_count(vap_info);
    return count;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        AssociatedDevice1_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
AssociatedDevice1_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)hInsContext;
    unsigned long vap_index_mask = 0;
    if (vap_info == NULL) {
        return (ANSC_HANDLE) NULL;
    }
    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    //Will be returning the entire stats structure later just returning mac address as of now
    hash_map_t *assoc_vap_info_map = (hash_map_t *)get_associated_devices_hash_map(vap_info->vap_index);
    if (assoc_vap_info_map == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return (ANSC_HANDLE) NULL;
    }
    unsigned int count = hash_map_count(assoc_vap_info_map);
    if (nIndex > count) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return (ANSC_HANDLE) NULL;
    }

    *pInsNumber = nIndex + 1;

    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    vap_index_mask = (*pInsNumber << 8) + vap_info->vap_index;

    return (ANSC_HANDLE) vap_index_mask; /* return the handle */
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AssociatedDevice1_IsUpdated
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is checking whether the table is updated or not.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     TRUE or FALSE.

**********************************************************************/
//static ULONG AssociatedDevice1PreviousVisitTime;

#define WIFI_AssociatedDevice_TIMEOUT   20 /*unit is second*/

BOOL
AssociatedDevice1_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AssociatedDevice1_Synchronize
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to synchronize the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
AssociatedDevice1_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)hInsContext;
    if (vap_info == NULL ) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    get_associated_devices_data(vap_info->radio_index);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AssociatedDevice1_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AssociatedDevice1_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    assoc_dev_data_t *assoc_dev_data_temp = NULL, *assoc_dev_data = NULL;
    unsigned long vap_index_mask = (unsigned long) hInsContext;
    unsigned int dev_index = (vap_index_mask >> 8);
    unsigned int vap_index = (0xff & vap_index_mask);

    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

    hash_map_t *assoc_vap_info_map = (hash_map_t *)get_associated_devices_hash_map(vap_index);

    if (assoc_vap_info_map == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    } 

    assoc_dev_data_temp = hash_map_get_first(assoc_vap_info_map);

    for (unsigned int itr=1; (itr < dev_index) && (assoc_dev_data_temp != NULL); itr++) {
        assoc_dev_data_temp = hash_map_get_next(assoc_vap_info_map, assoc_dev_data_temp);
    }
    
    if (assoc_dev_data_temp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }
    
    assoc_dev_data = (assoc_dev_data_t*) malloc(sizeof(assoc_dev_data_t));

    if (NULL == assoc_dev_data) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }

    memcpy(assoc_dev_data, assoc_dev_data_temp, sizeof(assoc_dev_data_t));
    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "AuthenticationState", TRUE))
    {
        /* collect value */
        *pBool = assoc_dev_data->dev_stats.cli_AuthenticationState;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Active", TRUE))
    {
        /* collect value */
        *pBool = assoc_dev_data->dev_stats.cli_Active;
        free(assoc_dev_data);
        return TRUE;
    }


    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    free(assoc_dev_data);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AssociatedDevice1_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AssociatedDevice1_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    assoc_dev_data_t *assoc_dev_data_temp = NULL, *assoc_dev_data = NULL;
    unsigned long vap_index_mask = (unsigned long) hInsContext;
    unsigned int dev_index = (vap_index_mask >> 8);
    unsigned int vap_index = (0xff & vap_index_mask);

    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

    hash_map_t *assoc_vap_info_map = (hash_map_t *)get_associated_devices_hash_map(vap_index);

    if (assoc_vap_info_map == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    } 

    assoc_dev_data_temp = hash_map_get_first(assoc_vap_info_map);

    for (unsigned int itr=1; (itr < dev_index) && (assoc_dev_data_temp != NULL); itr++) {
        assoc_dev_data_temp = hash_map_get_next(assoc_vap_info_map, assoc_dev_data_temp);
    }
    
    if (assoc_dev_data_temp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }
    
    assoc_dev_data = (assoc_dev_data_t*) malloc(sizeof(assoc_dev_data_t));

    if (NULL == assoc_dev_data) {
       wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
       pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
       return -1; 
    }
    
    memcpy(assoc_dev_data, assoc_dev_data_temp, sizeof(assoc_dev_data_t));
    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

   /* check the parameter name and return the corresponding value */
   if( AnscEqualString(ParamName, "SignalStrength", TRUE))
   {
       /* collect value */
       *pInt = assoc_dev_data->dev_stats.cli_SignalStrength;
       free(assoc_dev_data);
       return TRUE;
   }


   if( AnscEqualString(ParamName, "X_COMCAST-COM_SNR", TRUE))
   {
       /* collect value */
       *pInt = assoc_dev_data->dev_stats.cli_SNR;
       free(assoc_dev_data);
       return TRUE;
   }

   if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_SNR", TRUE))
   {
       /* collect value */
       *pInt = assoc_dev_data->dev_stats.cli_SNR;
       free(assoc_dev_data);
       return TRUE;
   }

   if( AnscEqualString(ParamName, "X_COMCAST-COM_RSSI", TRUE))
   {
       /* collect value */
       *pInt = assoc_dev_data->dev_stats.cli_RSSI;
       free(assoc_dev_data);
       return TRUE;
   }

   if( AnscEqualString(ParamName, "X_COMCAST-COM_MinRSSI", TRUE))
   {
       /* collect value */
       *pInt = assoc_dev_data->dev_stats.cli_MinRSSI;
       free(assoc_dev_data);
       return TRUE;
   }

   if( AnscEqualString(ParamName, "X_COMCAST-COM_MaxRSSI", TRUE))
   {
       /* collect value */
       *pInt = assoc_dev_data->dev_stats.cli_MaxRSSI;
       free(assoc_dev_data);
       return TRUE;
   }

   /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
   free(assoc_dev_data);
   return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AssociatedDevice1_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AssociatedDevice1_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    assoc_dev_data_t *assoc_dev_data_temp = NULL, *assoc_dev_data = NULL;
    unsigned long vap_index_mask = (unsigned long) hInsContext;
    unsigned int dev_index = (vap_index_mask >> 8);
    unsigned int vap_index = (0xff & vap_index_mask);

    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

    hash_map_t *assoc_vap_info_map = (hash_map_t *)get_associated_devices_hash_map(vap_index);

    if (assoc_vap_info_map == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    } 

    assoc_dev_data_temp = hash_map_get_first(assoc_vap_info_map);

    for (unsigned int itr=1; (itr < dev_index) && (assoc_dev_data_temp != NULL); itr++) {
        assoc_dev_data_temp = hash_map_get_next(assoc_vap_info_map, assoc_dev_data_temp);
    }
    
    if (assoc_dev_data_temp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }
    
    assoc_dev_data = (assoc_dev_data_t*) malloc(sizeof(assoc_dev_data_t));
    if (assoc_dev_data == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }

    memcpy(assoc_dev_data, assoc_dev_data_temp, sizeof(assoc_dev_data_t));
    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    
    if( AnscEqualString(ParamName, "LastDataDownlinkRate", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_LastDataDownlinkRate;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "LastDataUplinkRate", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_LastDataUplinkRate;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Retransmissions", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_Retransmissions;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_DataFramesSentAck", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_DataFramesSentAck;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_DataFramesSentNoAck", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_DataFramesSentNoAck;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_BytesSent", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_BytesSent;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_BytesReceived", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_BytesReceived;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_Disassociations", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_Disassociations;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_AuthenticationFailures", TRUE))
    {
        /* collect value */
        *puLong = assoc_dev_data->dev_stats.cli_AuthenticationFailures;
        free(assoc_dev_data);
        return TRUE;
    }


    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    free(assoc_dev_data);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AssociatedDevice1_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
AssociatedDevice1_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    errno_t                         rc           = -1;
    assoc_dev_data_t *assoc_dev_data_temp = NULL, *assoc_dev_data = NULL;
    unsigned long vap_index_mask = (unsigned long) hInsContext;
    unsigned int dev_index = (vap_index_mask >> 8);
    unsigned int vap_index = (0xff & vap_index_mask);

    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

    hash_map_t *assoc_vap_info_map = (hash_map_t *)get_associated_devices_hash_map(vap_index);

    if (assoc_vap_info_map == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    } 

    assoc_dev_data_temp = hash_map_get_first(assoc_vap_info_map);

    for (unsigned int itr=1; (itr < dev_index) && (assoc_dev_data_temp != NULL); itr++) {
        assoc_dev_data_temp = hash_map_get_next(assoc_vap_info_map, assoc_dev_data_temp);
    }
    
    if (assoc_dev_data_temp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }
    
    assoc_dev_data = (assoc_dev_data_t*) malloc(sizeof(assoc_dev_data_t));
    if (assoc_dev_data == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }
    
    memcpy(assoc_dev_data, assoc_dev_data_temp, sizeof(assoc_dev_data_t));
    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    
    if( AnscEqualString(ParamName, "MACAddress", TRUE))
    {
        char p_mac[18];
        snprintf(p_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", assoc_dev_data->dev_stats.cli_MACAddress[0], assoc_dev_data->dev_stats.cli_MACAddress[1], assoc_dev_data->dev_stats.cli_MACAddress[2],
                   assoc_dev_data->dev_stats.cli_MACAddress[3], assoc_dev_data->dev_stats.cli_MACAddress[4], assoc_dev_data->dev_stats.cli_MACAddress[5]);
        if ( AnscSizeOfString(p_mac) < *pUlSize)
        {
            AnscCopyString(pValue, p_mac);
            free(assoc_dev_data);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(p_mac)+1;
            free(assoc_dev_data);
            return 1;
        }

        return 0;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_OperatingStandard", TRUE))
    {
        /* collect value */
        rc = strcpy_s(pValue, *pUlSize, assoc_dev_data->dev_stats.cli_OperatingStandard);
        ERR_CHK(rc);
        free(assoc_dev_data);
        return 0;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_OperatingChannelBandwidth", TRUE))
    {
        /* collect value */
        rc = strcpy_s(pValue, *pUlSize, assoc_dev_data->dev_stats.cli_OperatingChannelBandwidth);
        ERR_CHK(rc);
        free(assoc_dev_data);
        return 0;
    }

    if( AnscEqualString(ParamName, "X_COMCAST-COM_InterferenceSources", TRUE))
    {
        /* collect value */
        rc = strcpy_s(pValue, *pUlSize, assoc_dev_data->dev_stats.cli_InterferenceSources);
        ERR_CHK(rc);
        free(assoc_dev_data);
        return 0;
    }

    free(assoc_dev_data);
    return -1;
}

/**********************************************************************
 APIs for Object:
   WiFi.WiFiRestart.RssMemory

   * RSSMemory_GetParamUlongValue
   * RSSMemory_SetParamUlongValue

************************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RSSMemory_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                       pULong
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

               ULONG*                       pULong

    return:     TRUE if succeeded.

**********************************************************************/

BOOL RSSMemory_GetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG *pULong)
{
    wifi_util_error_print(WIFI_DMCLI, "Enters %s:%d\n", __func__, __LINE__);
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_dml_wifi_global_param();

    if (pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d  NULL pointer Get fail\n", __FUNCTION__, __LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Threshold1", TRUE)) {
        /* collect value */
        *pULong = pcfg->rss_memory_restart_threshold_low;
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: RSS Threshold1 = %d\n", __func__, __LINE__,
            *pULong);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Threshold2", TRUE)) {
        /* collect value */
        *pULong = pcfg->rss_memory_restart_threshold_high;
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: RSS Threshold2 = %d\n", __func__, __LINE__,
            *pULong);
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RSSMemory_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       iValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       iValue
                The updated value;

    return:     TRUE if succeeded.
**********************************************************************/

BOOL RSSMemory_SetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG iValue)
{
    wifi_util_error_print(WIFI_DMCLI, "Enters %s:%d\n", __func__, __LINE__);
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t *)get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Unable to get Global Config\n", __FUNCTION__,
            __LINE__);
        return FALSE;
    }
    /* check the parameter name and set the corresponding value */
    if (AnscEqualString(ParamName, "Threshold1", TRUE)) {
        if (global_wifi_config->global_parameters.rss_memory_restart_threshold_low == iValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: RSS Threshold1 = %d New Value = %d\n", __func__,
            __LINE__, global_wifi_config->global_parameters.rss_memory_restart_threshold_low,
            iValue);
        global_wifi_config->global_parameters.rss_memory_restart_threshold_low = iValue;
        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,
                "%s:%d: Failed to push RSS Threshold1 value to onewifi db\n", __func__, __LINE__);
        }
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Threshold2", TRUE)) {
        if (global_wifi_config->global_parameters.rss_memory_restart_threshold_high == iValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: RSS Threshold2 = %d New Value = %d\n", __func__,
            __LINE__, global_wifi_config->global_parameters.rss_memory_restart_threshold_high,
            iValue);
        global_wifi_config->global_parameters.rss_memory_restart_threshold_high = iValue;
        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,
                "%s:%d: Failed to push RSS Threshold2 value to onewifi db\n", __func__, __LINE__);
        }
        return TRUE;
    }
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.

    *  Stats_GetParamUlongValue

***********************************************************************/

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      pULong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      pULong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
Stats_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pULong
    ) 
{
    assoc_dev_data_t *assoc_dev_data_temp = NULL, *assoc_dev_data = NULL;
    unsigned long vap_index_mask = (unsigned long) hInsContext;
    unsigned int dev_index = (vap_index_mask >> 8);
    unsigned int vap_index = (0xff & vap_index_mask);

    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

    hash_map_t *assoc_vap_info_map = (hash_map_t *)get_associated_devices_hash_map(vap_index);

    if (assoc_vap_info_map == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    } 

    assoc_dev_data_temp = hash_map_get_first(assoc_vap_info_map);

    for (unsigned int itr=1; (itr < dev_index) && (assoc_dev_data_temp != NULL); itr++) {
        assoc_dev_data_temp = hash_map_get_next(assoc_vap_info_map, assoc_dev_data_temp);
    }
    
    if (assoc_dev_data_temp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }
    
    assoc_dev_data = (assoc_dev_data_t*) malloc(sizeof(assoc_dev_data_t));
    if (assoc_dev_data == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return -1;
    }

    memcpy(assoc_dev_data, assoc_dev_data_temp, sizeof(assoc_dev_data_t));
    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "BytesSent", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_BytesSent;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "BytesReceived", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_BytesReceived;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PacketsSent", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_PacketsSent;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PacketsReceived", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_PacketsReceived;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "ErrorsSent", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_ErrorsSent;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RetransCount", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_RetransCount;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "FailedRetransCount", TRUE))
    {
       /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_FailedRetransCount;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RetryCount", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_RetryCount;
        free(assoc_dev_data);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MultipleRetryCount", TRUE))
    {
        /* collect value */
        *pULong = assoc_dev_data->dev_stats.cli_MultipleRetryCount;
        free(assoc_dev_data);
        return TRUE;
    }

    free(assoc_dev_data);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Stats_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "InstantMeasurementsEnable", TRUE))
    {
        /* collect value */
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

ULONG
WEPKey64Bit_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

ANSC_HANDLE
WEPKey64Bit_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    return (ANSC_HANDLE)NULL;

}

ULONG
WEPKey64Bit_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{

    if (AnscEqualString(ParamName, "WEPKey", TRUE))
    {
        return 0;
    }

    return -1;
}

BOOL
WEPKey64Bit_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{

    if (AnscEqualString(ParamName, "WEPKey", TRUE))
    {
        return TRUE;
    }

    return FALSE;
}

BOOL
WEPKey64Bit_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

ULONG
WEPKey64Bit_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return TRUE;
}

ULONG
WEPKey64Bit_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return TRUE;
}

ULONG
WEPKey128Bit_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

ANSC_HANDLE
WEPKey128Bit_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
     return (ANSC_HANDLE)NULL;
}

ULONG
WEPKey128Bit_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{

    if (AnscEqualString(ParamName, "WEPKey", TRUE))
    {
        return 0;
    }

    return -1;
}

BOOL
WEPKey128Bit_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{

    if (AnscEqualString(ParamName, "WEPKey", TRUE))
    {
        return TRUE;
    }

    return FALSE;
}

BOOL
WEPKey128Bit_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

ULONG
WEPKey128Bit_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return TRUE;
}

ULONG
WEPKey128Bit_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
        return TRUE;
}

BOOL
RadiusSettings_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *)hInsContext;

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info Null pointer\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_vap_security_t *l_security_cfg= NULL;
    if (isVapSTAMesh(vapInfo->vap_index)) {
        l_security_cfg= (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }
	
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "PMKCaching", TRUE))
    {
        /* collect value */
        *pBool = l_security_cfg->disable_pmksa_caching;
        return TRUE;
    }
 
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

BOOL
RadiusSettings_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *)hInsContext;

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP Null pointer\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    wifi_vap_security_t *l_security_cfg= NULL;
    if (isVapSTAMesh(vapInfo->vap_index)) {
        l_security_cfg= (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "RadiusServerRetries", TRUE))
    {
        /* collect value */
        *pInt = l_security_cfg->u.radius.server_retries;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RadiusServerRequestTimeout", TRUE))
    {
        /* collect value */
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PMKLifetime", TRUE))	
    {
        /* collect value */
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PMKCacheInterval", TRUE))
    {
        /* collect value */
        return TRUE;
    }

    if( AnscEqualString(ParamName, "MaxAuthenticationAttempts", TRUE))
    {
        /* collect value */
        *pInt = l_security_cfg->u.radius.max_auth_attempts;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "BlacklistTableTimeout", TRUE))
    {
        /* collect value */
        *pInt = l_security_cfg->u.radius.blacklist_table_timeout;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "IdentityRequestRetryInterval", TRUE))
    {
        /* collect value */
        *pInt = l_security_cfg->u.radius.identity_req_retry_interval;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "QuietPeriodAfterFailedAuthentication", TRUE))
    {
        /* collect value */
        *pInt = 0; 
        return TRUE;
    }

    return FALSE;
}

BOOL
RadiusSettings_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    wifi_vap_security_t *l_security_cfg= NULL;
    if (isVapSTAMesh(vapInfo->vap_index)) {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }

    AnscTraceWarning(("ParamName: %s bvalue:%d\n", ParamName, bValue));

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "PMKCaching", TRUE))
    {
        /* save update to backup */
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d disable_pmksa_caching=%d Value=%d  \n",__func__, __LINE__,l_security_cfg->disable_pmksa_caching,bValue);
        if(l_security_cfg->disable_pmksa_caching == bValue)
        {
            return TRUE;
        }
        l_security_cfg->disable_pmksa_caching = bValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }
return FALSE;
}

BOOL
RadiusSettings_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_vap_security_t *l_security_cfg= NULL;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(vapInfo->vap_index)) {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }
    AnscTraceWarning(("ParamName: %s iValue: %d\n", ParamName, iValue));

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "RadiusServerRetries", TRUE))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d server_retries=%d Value=%d  \n",__func__, __LINE__,l_security_cfg->u.radius.server_retries,iValue);
        if(l_security_cfg->u.radius.server_retries == ((unsigned int) iValue))
        {
            return TRUE;
        }
        /* save update to backup */
        l_security_cfg->u.radius.server_retries = iValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "RadiusServerRequestTimeout", TRUE))
    {
        /* save update to backup */
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PMKLifetime", TRUE))
    {
        /* save update to backup */
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PMKCacheInterval", TRUE))
    {
        return TRUE;
    }
    if( AnscEqualString(ParamName, "MaxAuthenticationAttempts", TRUE))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d max_auth_attempts=%d Value=%d  \n",__func__, __LINE__,l_security_cfg->u.radius.max_auth_attempts,iValue);
        if(l_security_cfg->u.radius.max_auth_attempts == ((unsigned int) iValue))
        {
            return TRUE;
        }
        /* save update to backup */
        l_security_cfg->u.radius.max_auth_attempts = iValue;
        set_dml_cache_vap_config_changed(instance_number - 1);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "BlacklistTableTimeout", TRUE))
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d blacklist_table_timeout=%d Value=%d  \n",__func__, __LINE__,l_security_cfg->u.radius.blacklist_table_timeout,iValue);
        if(l_security_cfg->u.radius.blacklist_table_timeout == ((unsigned int) iValue))
        {
            return TRUE;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);
        l_security_cfg->u.radius.blacklist_table_timeout = iValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "IdentityRequestRetryInterval", TRUE))
    {
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration \n",__func__, __LINE__,l_security_cfg->mode);
            return FALSE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d identity_req_retry_interval=%d Value=%d  \n",__func__, __LINE__,l_security_cfg->u.radius.identity_req_retry_interval,iValue);
        if(l_security_cfg->u.radius.identity_req_retry_interval == ((unsigned int) iValue))
        {
            return TRUE;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);
        l_security_cfg->u.radius.identity_req_retry_interval = iValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "QuietPeriodAfterFailedAuthentication", TRUE))
    {
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

BOOL
RadiusSettings_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

ULONG
RadiusSettings_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

BOOL
Authenticator_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;

    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    wifi_vap_security_t *pcfg = &vap_pcfg->u.bss_info.security;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "EAPOLKeyTimeout", TRUE))
    {
        /* collect value */
        *puLong = pcfg->eapol_key_timeout;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPOLKeyRetries", TRUE))
    {
        /* collect value */
        *puLong = pcfg->eapol_key_retries;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPIdentityRequestTimeout", TRUE))
    {
        /* collect value */
        *puLong = pcfg->eap_identity_req_timeout;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPIdentityRequestRetries", TRUE))
    {
	    /* collect value */
        *puLong = pcfg->eap_identity_req_retries ;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPRequestTimeout", TRUE))
    {
        /* collect value */
        *puLong = pcfg->eap_req_timeout;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPRequestRetries", TRUE))
    {
        /* collect value */
        *puLong = pcfg->eap_req_retries ;
        return TRUE;
    }
    return FALSE;
}

BOOL
Authenticator_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{

    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;
    wifi_vap_security_t *l_security_cfg= NULL;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(vapInfo->vap_index)) {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_sta_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    } else {
        l_security_cfg= (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(vapInfo->vap_index);
        if(l_security_cfg== NULL)
        {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter \n",__func__, __LINE__,vapInfo->vap_name);
            return FALSE;
        }
    }
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "EAPOLKeyTimeout", TRUE))
    {
        if ( l_security_cfg->eapol_key_timeout != uValue )
        {
            /* save update to backup */
            l_security_cfg->eapol_key_timeout = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPOLKeyRetries", TRUE))
    {
        if ( l_security_cfg->eapol_key_retries != uValue )
        {
            /* save update to backup */
            l_security_cfg->eapol_key_retries = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPIdentityRequestTimeout", TRUE))
    {
        if ( l_security_cfg->eap_identity_req_timeout != uValue )
        {
            /* save update to backup */
            l_security_cfg->eap_identity_req_timeout = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPIdentityRequestRetries", TRUE))
    {
        if ( l_security_cfg->eap_identity_req_retries != uValue )
        {
            /* save update to backup */
            l_security_cfg->eap_identity_req_retries = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPRequestTimeout", TRUE))
    {
        if ( l_security_cfg->eap_req_timeout != uValue )
        {
            /* save update to backup */
            l_security_cfg->eap_req_timeout = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }

    if( AnscEqualString(ParamName, "EAPRequestRetries", TRUE))
    {
        if ( l_security_cfg->eap_req_retries != uValue )
        {
            /* save update to backup */
            l_security_cfg->eap_req_retries  = uValue;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
        return TRUE;
    }
    return FALSE;
}

BOOL
Authenticator_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    CcspTraceWarning(("Authenticator_validate"));
    return TRUE;
}

ULONG
Authenticator_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

ULONG
MacFiltTab_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside Synchronize \n",__func__, __LINE__);

    return ANSC_STATUS_SUCCESS;
}

BOOL
MacFiltTab_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return TRUE;
}

ULONG
MacFiltTab_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside GetEntryCount \n",__func__, __LINE__);
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)hInsContext;
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer \n",__func__, __LINE__);
        return 0;
    }
    unsigned int count = 0;
    if (vap_info->vap_index > MAX_VAP) {
        return 0;
    }

    hash_map_t** acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    queue_t** acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);
    
    if (*acl_device_map != NULL) {
        count  = count + hash_map_count(*acl_device_map);
    }

    if (*acl_new_entry_queue != NULL) {
        count = count + queue_count(*acl_new_entry_queue);
    } else {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ERROR NULL queue Pointer \n",__func__, __LINE__);
    }
    
    return count;
}


ANSC_HANDLE
MacFiltTab_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside GetEntry \n",__func__, __LINE__);
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)hInsContext;
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer \n",__func__, __LINE__);
        return 0;
    }
    unsigned int count_hash = 0, itr = 0, count_queue = 0;
    acl_entry_t *acl_entry = NULL;
    void** acl_vap_context = (void **)get_acl_vap_context();

    if (vap_info->vap_index > MAX_VAP) {
        return (ANSC_HANDLE)NULL;
    }

    hash_map_t** acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    queue_t** acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);
    if (*acl_new_entry_queue == NULL) {
        *acl_new_entry_queue = queue_create();
    }

    if (*acl_device_map != NULL) {
        count_hash = hash_map_count(*acl_device_map);
    } 

    if (*acl_new_entry_queue != NULL) {
        count_queue  = queue_count(*acl_new_entry_queue);
    }

    if (nIndex > (count_hash + count_queue)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Wrong nIndex\n",__func__, __LINE__);
        return (ANSC_HANDLE)NULL;
    }

    if ((*acl_device_map != NULL) && (nIndex < count_hash)) {
        acl_entry = hash_map_get_first(*acl_device_map);
        for (itr=0; (itr<nIndex) && (acl_entry != NULL); itr++) {
            acl_entry = hash_map_get_next(*acl_device_map,acl_entry);
        }
    } else if (*acl_new_entry_queue != NULL) {
        acl_entry = (acl_entry_t *) queue_peek(*acl_new_entry_queue, (nIndex - count_hash));
    }

    *pInsNumber = nIndex+1;
    *acl_vap_context = (void *)vap_info;

    return (ANSC_HANDLE)acl_entry;
}

ANSC_HANDLE
MacFiltTab_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    )
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside AddEntry \n",__func__, __LINE__);
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)hInsContext;
    acl_entry_t *acl_entry;
    unsigned int count = 0;

    if (vap_info->vap_index > MAX_VAP) {
        return (ANSC_HANDLE)NULL;
    }

    hash_map_t** acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    queue_t** acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);

    acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
    if (acl_entry == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return (ANSC_HANDLE)NULL;
    }

    if (*acl_new_entry_queue == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unexpected ERROR!!! acl_new_entry_queue should not be NULL\n", __func__,__LINE__);
        *acl_new_entry_queue = queue_create();
    }

    memset(acl_entry, 0, sizeof(acl_entry_t));
    
    if (*acl_new_entry_queue != NULL) {
        queue_push(*acl_new_entry_queue, acl_entry);
        count  = count + queue_count(*acl_new_entry_queue);
    }

    if (*acl_device_map != NULL) {
        count  = count  + hash_map_count(*acl_device_map);
    } 

    //new entry index
    *pInsNumber = count;

    //dont send the blob now because there is no valid mac entry. waits the update

    return (ANSC_HANDLE)acl_entry;
}

ULONG
MacFiltTab_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    )
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside DelEntry \n",__func__, __LINE__);
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)hInsContext;
    acl_entry_t *acl_entry = (acl_entry_t *) hInstance;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    acl_entry_t *map_acl_entry, *tmp_acl_entry;
    unsigned int count, itr;
    mac_addr_str_t mac_str;
    if (vap_info->vap_index > MAX_VAP) {
        return ANSC_STATUS_FAILURE;
    }

    if (acl_entry == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return ANSC_STATUS_FAILURE;
    }

    queue_t** acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);
    hash_map_t** acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    if (*acl_new_entry_queue ==  NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unexpected ERROR!!! acl_new_entry_queue should not be NULL\n", __func__,__LINE__);
        *acl_new_entry_queue = queue_create();
    }

    if (memcmp(acl_entry->mac, zero_mac, sizeof(mac_address_t)) == 0) {

        if (*acl_new_entry_queue != NULL) {
            count  = queue_count(*acl_new_entry_queue);
            for (itr=0; itr<count; itr++) {

                map_acl_entry = (acl_entry_t *)queue_peek(*acl_new_entry_queue, itr);
                if (map_acl_entry == acl_entry) {
                    map_acl_entry = queue_remove(*acl_new_entry_queue, itr);
                    if (map_acl_entry) {
                        free(map_acl_entry);
                    }
                    break;
                }
            }
            return ANSC_STATUS_SUCCESS;
        } 

    } else {
        to_mac_str(acl_entry->mac, mac_str);
        tmp_acl_entry = hash_map_remove(*acl_device_map, mac_str);
        if (tmp_acl_entry != NULL) {
            free(tmp_acl_entry);
        }

        // Send blob
        if(push_acl_list_dml_cache_to_one_wifidb(vap_info) == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Mac_Filter failed \n",__func__, __LINE__);
            return ANSC_STATUS_FAILURE;
        }

        return ANSC_STATUS_SUCCESS;
    }
    return ANSC_STATUS_FAILURE;    
}

ULONG
MacFiltTab_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside GetParamStringValue \n",__func__, __LINE__);
    acl_entry_t *acl_entry = (acl_entry_t *)hInsContext;

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "MACAddress", TRUE))
    {
        char buff[24] = {0};
        _ansc_sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X", acl_entry->mac[0],
                acl_entry->mac[1],
                acl_entry->mac[2],
                acl_entry->mac[3],
                acl_entry->mac[4],
                acl_entry->mac[5]);
        if ( AnscSizeOfString(buff) < *pUlSize)
        {
            AnscCopyString(pValue, buff);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(buff)+1;
            return 1;
        }
    }
    if( AnscEqualString(ParamName, "DeviceName", TRUE))
    {
        if ( AnscSizeOfString(acl_entry->device_name) < *pUlSize)
        {
            AnscCopyString(pValue, acl_entry->device_name);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(acl_entry->device_name)+1;
            return 1;
        }
    }

    return -1;
}

BOOL
MacFiltTab_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside SetParamStringValue \n",__func__, __LINE__);
    acl_entry_t *acl_entry = (acl_entry_t *)hInsContext;
    mac_address_t new_mac;
    unsigned int count = 0, itr;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    acl_entry_t *mac_acl_entry;
    void** acl_vap_context = (void **)get_acl_vap_context();
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)*acl_vap_context;
    int mac_length = -1;
    char formatted_mac[MAC_ADDR_LEN] = {0};

    /* check the parameter name and set the corresponding value */
    
    if (acl_entry ==  NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return FALSE;
    }

    hash_map_t** acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    queue_t** acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);
    if (*acl_new_entry_queue == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unexpected ERROR!!! acl_new_entry_queue should not be NULL\n", __func__,__LINE__);
        *acl_new_entry_queue = queue_create();
    }

    if( AnscEqualString(ParamName, "MACAddress", TRUE))
    {
        str_tolower(pString);
        mac_length = strlen(pString);
        if(mac_length != MAC_ADDR_LEN && mac_length != MIN_MAC_LEN) {
            return FALSE;
        }

        if(mac_length == MIN_MAC_LEN) {
            itr = 0;
            for(count = 0; count < MIN_MAC_LEN; count++) {
                formatted_mac[itr++] = pString[count];
                if(count % 2 == 1 && count != MIN_MAC_LEN -1) {
                    formatted_mac[itr++] = ':';
                }
            }
            formatted_mac[itr++] = '\0';

            if(IsValidMacAddress(formatted_mac) == FALSE ) {
                return FALSE;
            }
        }
        else {
            if(IsValidMacAddress(pString) == FALSE ) {
                return FALSE;
            }
        }

        str_to_mac_bytes(pString, new_mac);
        if (memcmp(new_mac, zero_mac, sizeof(mac_address_t)) == 0){
            //Invalid value returning FALSE
            return FALSE;
        }
        
        if (memcmp(acl_entry->mac, zero_mac, sizeof(mac_address_t)) == 0) {
            memcpy(acl_entry->mac, new_mac, sizeof(mac_address_t));
            if (*acl_device_map == NULL) {
                *acl_device_map = hash_map_create();
            }

            if (*acl_device_map == NULL) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
                return FALSE;
            }
            hash_map_put(*acl_device_map, strdup(pString), acl_entry);

            if (*acl_new_entry_queue == NULL) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
                return FALSE;
            }
            count = queue_count(*acl_new_entry_queue);
            for (itr=0; itr<count; itr++) {
                mac_acl_entry = (acl_entry_t *)queue_peek(*acl_new_entry_queue, itr);
                if (mac_acl_entry == NULL) {
                    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
                    return FALSE;
                }

                if (mac_acl_entry == acl_entry) {
                    mac_acl_entry = queue_remove(*acl_new_entry_queue, itr);
                    break;
                }
            }
        } else if (memcmp(acl_entry->mac, new_mac, sizeof(mac_address_t)) != 0) {
            memcpy(acl_entry->mac, new_mac, sizeof(mac_address_t));
        }

        return TRUE;
    }
    if( AnscEqualString(ParamName, "DeviceName", TRUE))
    {
        strncpy(acl_entry->device_name, pString, sizeof(acl_entry->device_name)-1);
        /* save update to backup */
        return TRUE;
    }
    return FALSE;    
}

BOOL
MacFiltTab_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}


ULONG
MacFiltTab_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    void** acl_vap_context = (void **)get_acl_vap_context();
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)*acl_vap_context;

    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside Commit \n",__func__, __LINE__);
    if (push_acl_list_dml_cache_to_one_wifidb(vap_info) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Mac_Filter failed \n",__func__, __LINE__);
        return -1;
    }
    return 0;    
}

ULONG
MacFilterTab_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{

    return 0;
}

BOOL
NeighboringWiFiDiagnostic_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();
    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = global_wifi_config->global_parameters.diagnostic_enable;
        return TRUE;
    }

	return FALSE;
}

ULONG
NeighboringWiFiDiagnostic_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pUlSize);
    errno_t rc = -1;

    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    if(AnscEqualString(ParamName, "DiagnosticsState", TRUE))
    {
        rc = strcpy_s(pValue, *pUlSize, monitor_param->neighbor_scan_cfg.DiagnosticsState);
        ERR_CHK(rc);
        return 0;
    }
    return -1;
}

BOOL
NeighboringWiFiDiagnostic_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if(AnscEqualString(ParamName, "Enable", TRUE))
    {
// Set WiFi Neighbour Diagnostic switch value
        if(global_wifi_config->global_parameters.diagnostic_enable == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:diagnostic_enable=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.diagnostic_enable,bValue);
        global_wifi_config->global_parameters.diagnostic_enable = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }
    return FALSE;
}


BOOL
NeighboringWiFiDiagnostic_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    
    wifi_global_config_t *global_wifi_config;
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    if( AnscEqualString(ParamName, "DiagnosticsState", TRUE))   {
        if( (strcmp(pString, "Requested") == 0) && (global_wifi_config->global_parameters.diagnostic_enable)) {
            if(strcmp(monitor_param->neighbor_scan_cfg.DiagnosticsState, "Requested") == 0)
                return TRUE;

            process_neighbor_scan_dml();
        }
	    return TRUE;
    }
	return FALSE;  
}



ULONG
NeighboringScanResult_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    return monitor_param->neighbor_scan_cfg.ResultCount;
    return 0;
}

ANSC_HANDLE
NeighboringScanResult_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UINT count = 0;
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    
    if ( nIndex >= monitor_param->neighbor_scan_cfg.ResultCount )
        return NULL;

    *pInsNumber  = nIndex + 1;

    for (UINT rIdx = 0; rIdx < (UINT)get_num_radio_dml(); rIdx++)
    {
        if (nIndex < (monitor_param->neighbor_scan_cfg.resultCountPerRadio[rIdx] + count))
        {
            return (ANSC_HANDLE)&monitor_param->neighbor_scan_cfg.pResult[rIdx][nIndex - count];
        }
        count += monitor_param->neighbor_scan_cfg.resultCountPerRadio[rIdx];
    }
    return NULL;
}

BOOL
NeighboringScanResult_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	return TRUE;

}



BOOL
NeighboringScanResult_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    wifi_neighbor_ap2_t *  pResult = (wifi_neighbor_ap2_t *)hInsContext;

    if( AnscEqualString(ParamName, "SignalStrength", TRUE))    {
        *pInt = pResult->ap_SignalStrength;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Noise", TRUE))    {
        *pInt = pResult->ap_Noise;
        return TRUE;
    }
    return FALSE;
}

BOOL
NeighboringScanResult_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    wifi_neighbor_ap2_t *  pResult = (wifi_neighbor_ap2_t *)hInsContext;

    if( AnscEqualString(ParamName, "DTIMPeriod", TRUE))    {
        *puLong = pResult->ap_DTIMPeriod;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_COMCAST-COM_ChannelUtilization", TRUE))    {
        *puLong = pResult->ap_ChannelUtilization;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "Channel", TRUE))    {
        *puLong = pResult->ap_Channel;
        return TRUE;  
    }
    if(AnscEqualString(ParamName, "BeaconPeriod", TRUE))   {
       *puLong = pResult->ap_BeaconPeriod;
       return TRUE;
    }

    return FALSE;
}

ULONG
NeighboringScanResult_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(pUlSize);
    wifi_neighbor_ap2_t *  pResult = (wifi_neighbor_ap2_t *)hInsContext;
    errno_t rc = -1;

    if( AnscEqualString(ParamName, "Radio", TRUE))    {
        wifi_freq_bands_t freqBand;

        if (freqBandStrToEnum(pResult->ap_OperatingFrequencyBand, &freqBand ) != ANSC_STATUS_SUCCESS)
            return -1;

        wifi_radio_operationParam_t *wifiRadioOperParam = NULL;
        UINT max_string = 32;
        for (UINT rIdx = 0; rIdx < (UINT)get_num_radio_dml(); rIdx++)
        {
            wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(rIdx);
            if (wifiRadioOperParam != NULL && wifiRadioOperParam->band == freqBand)
            {
                snprintf(pValue, max_string, "Device.WiFi.Radio.%u", rIdx + 1);
                return 0;
            }
        }
        return -1;
    }
    if(AnscEqualString(ParamName, "EncryptionMode", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_EncryptionMode);
        ERR_CHK(rc);
        return 0;
    }
    if( AnscEqualString(ParamName, "Mode", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_Mode);
        ERR_CHK(rc);
        return 0;  
    }
    if( AnscEqualString(ParamName, "SecurityModeEnabled", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_SecurityModeEnabled);
        ERR_CHK(rc);
        return 0;  
    }
    if( AnscEqualString(ParamName, "BasicDataTransferRates", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_BasicDataTransferRates);
        ERR_CHK(rc);
        return 0;  
    } 
    if( AnscEqualString(ParamName, "SupportedDataTransferRates", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_SupportedDataTransferRates);
        ERR_CHK(rc);
        return 0;  
    }
    if( AnscEqualString(ParamName, "OperatingChannelBandwidth", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_OperatingChannelBandwidth);
        ERR_CHK(rc);
        return 0;
    }
    if( AnscEqualString(ParamName, "OperatingStandards", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_OperatingStandards);
        ERR_CHK(rc);
        return 0;
    } 
    if( AnscEqualString(ParamName, "SupportedStandards", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_SupportedStandards);
        ERR_CHK(rc);
        return 0;
    } 
    if( AnscEqualString(ParamName, "BSSID", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_BSSID);
        ERR_CHK(rc);
        return 0;
    }     
    if(AnscEqualString(ParamName, "SSID", TRUE))     {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_SSID);
        ERR_CHK(rc);
        return 0;  
    }
    if( AnscEqualString(ParamName, "OperatingFrequencyBand", TRUE))    {
        rc = strcpy_s(pValue, *pUlSize, pResult->ap_OperatingFrequencyBand);
        ERR_CHK(rc);
        return 0;
    }    

    return -1; 
 
 }

 /***********************************************************************
 
  APIs for Object:
 
	 WiFi.X_RDKCENTRAL-COM_BandSteering.
 
	 *	BandSteering_GetParamBoolValue
	 *	BandSteering_SetParamBoolValue
	 *    BandSteering_GetParamStringValue
	 *	BandSteering_Validate
	 *	BandSteering_Commit
	 *	BandSteering_Rollback
 
 ***********************************************************************/
 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 BOOL
		 BandSteering_GetParamBoolValue
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*						 ParamName,
				 BOOL*						 pBool
			 );
 
	 description:
 
		 This function is called to retrieve Boolean parameter value; 
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 ParamName,
				 The parameter name;
 
				 BOOL*						 pBool
				 The buffer of returned boolean value;
 
	 return:	 TRUE if succeeded.
 
 **********************************************************************/
 BOOL
 BandSteering_GetParamBoolValue
	 (
		 ANSC_HANDLE				 hInsContext,
		 char*						 ParamName,
		 BOOL*						 pBool
	 )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_dml_wifi_global_param();

    if(pcfg== NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = pcfg->bandsteering_enable;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Capability", TRUE))
    {
        *pBool = TRUE;
        return TRUE;
    }
    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 BOOL
		 BandSteering_SetParamBoolValue
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*						 ParamName,
				 BOOL						 bValue
			 );
 
	 description:
 
		 This function is called to set BOOL parameter value; 
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 ParamName,
				 The parameter name;
 
				 BOOL						 bValue
				 The updated BOOL value;
 
	 return:	 TRUE if succeeded.
 
 **********************************************************************/
 BOOL
 BandSteering_SetParamBoolValue
	 (
		 ANSC_HANDLE				 hInsContext,
		 char*						 ParamName,
		 BOOL						 bValue
	 )
{
    UNREFERENCED_PARAMETER(hInsContext);
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
    
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(global_wifi_config->global_parameters.bandsteering_enable == bValue)
        {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:bandsteering_enable=%d Value = %d  \n",__func__, __LINE__,global_wifi_config->global_parameters.bandsteering_enable,bValue);
        global_wifi_config->global_parameters.bandsteering_enable = bValue;
        push_global_config_dml_cache_to_one_wifidb();
        return TRUE;
    }

     /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 ULONG
		 BandSteering_GetParamStringValue
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*						 ParamName,
				 char*						 pValue,
				 ULONG* 					 pUlSize
			 );
 
	 description:
 
		 This function is called to retrieve string parameter value; 
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 ParamName,
				 The parameter name;
 
				 char*						 pValue,
				 The string value buffer;
 
				 ULONG* 					 pUlSize
				 The buffer of length of string value;
				 Usually size of 1023 will be used.
				 If it's not big enough, put required size here and return 1;
 
	 return:	 0 if succeeded;
				 1 if short of buffer size; (*pUlSize = required size)
				 -1 if not supported.
 
 **********************************************************************/
 ULONG
 BandSteering_GetParamStringValue
	 (
		 ANSC_HANDLE				 hInsContext,
		 char*						 ParamName,
		 char*						 pValue,
		 ULONG* 					 pUlSize
	 )
 {
 	 UNREFERENCED_PARAMETER(hInsContext);
    
	 /* check the parameter name and return the corresponding value */

	 if( AnscEqualString(ParamName, "APGroup", TRUE))
	 {
		/* collect value */
		 return 0;
	 }

	 if( AnscEqualString(ParamName, "History", TRUE))
	 {
		 /* collect value */
		 
		 return 0;
	 }

	 /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
	 return -1;
 }

 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 ULONG
		 BandSteering_SetParamStringValue
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*				         ParamName,
				 char*					 pString,
			 );
 
	 description:
 
		 This function is called to retrieve string parameter value; 
 
	 argument:	 ANSC_HANDLE				 hInsContext,
			 The instance handle;
 
			 char*					 ParamName,
			 The parameter name;
 
			 char*					 pString,
			 The string value buffer;
 
 
	 return:	 TRUE if succeeded.
 
 **********************************************************************/
 BOOL
 BandSteering_SetParamStringValue
	 (
		 ANSC_HANDLE				hInsContext,
		 char*					ParamName,
		 char*					pString
	 )
 {
	 UNREFERENCED_PARAMETER(hInsContext);
	 /* check the parameter name and return the corresponding value */

	 if( AnscEqualString(ParamName, "APGroup", TRUE))
	 {
             return TRUE;
	 }

	 /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
	 return FALSE;
 }

 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 BOOL
		 BandSteering_Validate
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*						 pReturnParamName,
				 ULONG* 					 puLength
			 );
 
	 description:
 
		 This function is called to finally commit all the update.
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 pReturnParamName,
				 The buffer (128 bytes) of parameter name if there's a validation. 
 
				 ULONG* 					 puLength
				 The output length of the param name. 
 
	 return:	 TRUE if there's no validation.
 
 **********************************************************************/
 BOOL
 BandSteering_Validate
	 (
		 ANSC_HANDLE				 hInsContext,
		 char*						 pReturnParamName,
		 ULONG* 					 puLength
	 )
 {
     UNREFERENCED_PARAMETER(hInsContext);
     UNREFERENCED_PARAMETER(pReturnParamName);
     UNREFERENCED_PARAMETER(puLength);
	 return TRUE;
 }
 
 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 ULONG
		 BandSteering_Commit
			 (
				 ANSC_HANDLE				 hInsContext
			 );
 
	 description:
 
		 This function is called to finally commit all the update.
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
	 return:	 The status of the operation.
 
 **********************************************************************/
 ULONG
 BandSteering_Commit
	 (
		 ANSC_HANDLE				 hInsContext
	 )
 {
	 UNREFERENCED_PARAMETER(hInsContext);
 
	 return ANSC_STATUS_SUCCESS;
 }
 
 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 ULONG
		 BandSteering_Rollback
			 (
				 ANSC_HANDLE				 hInsContext
			 );
 
	 description:
 
		 This function is called to roll back the update whenever there's a 
		 validation found.
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
	 return:	 The status of the operation.
 
 **********************************************************************/
 ULONG
 BandSteering_Rollback
	 (
		 ANSC_HANDLE				 hInsContext
	 )
 {  
	 UNREFERENCED_PARAMETER(hInsContext);
	 return ANSC_STATUS_SUCCESS;
 }

 /***********************************************************************
 
  APIs for Object:
 
	 WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.
 
	 *    BandSetting_GetEntryCount
	 *    BandSetting_GetEntry
	 *	BandSetting_GetParamIntValue
	 *	BandSetting_SetParamIntValue
	 *	BandSteering_Validate
	 *	BandSteering_Commit
	 *	BandSteering_Rollback
 
 ***********************************************************************/
 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 ULONG
		 BandSetting_GetEntryCount
			 (
				 ANSC_HANDLE				 hInsContext
			 );
 
	 description:
 
		 This function is called to retrieve the count of the table.
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
	 return:	 The count of the table
 
 **********************************************************************/
 ULONG
 BandSetting_GetEntryCount
	 (
		 ANSC_HANDLE				 hInsContext
	 )
 {
    UNREFERENCED_PARAMETER(hInsContext);
    return get_num_radio_dml();
 }

/**********************************************************************  

	caller: 	owner of this object 

	prototype: 

		ANSC_HANDLE
		BandSetting_GetEntry
			(
				ANSC_HANDLE 				hInsContext,
				ULONG						nIndex,
				ULONG*						pInsNumber
			);

	description:

		This function is called to retrieve the entry specified by the index.

	argument:	ANSC_HANDLE 				hInsContext,
				The instance handle;

				ULONG						nIndex,
				The index of this entry;

				ULONG*						pInsNumber
				The output instance number;

	return: 	The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
BandSetting_GetEntry
	(
		ANSC_HANDLE 				hInsContext,
		ULONG						nIndex,
		ULONG*						pInsNumber
	)
{
    UNREFERENCED_PARAMETER(hInsContext);
    //WORK_AROUND to fix GUI issue
    wifi_radio_operationParam_t *wifiRadioOperParam = NULL;

    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: nIndex:%ld\n",__func__, __LINE__, nIndex);
    if ( nIndex < (UINT)get_num_radio_dml() )
    {
        wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_radio_operation_param(nIndex);
        if (wifiRadioOperParam == NULL)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %ld not found for wifiRadioOperParam\n", __FUNCTION__, nIndex));
            return NULL;
        }
        *pInsNumber = nIndex + 1;
        g_radio_instance_num = nIndex + 1;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: g_radio_instance_num:%d\n",__func__, __LINE__, g_radio_instance_num);

        return (ANSC_HANDLE)wifiRadioOperParam;
    }
    return NULL; /* return the handle */
}

/**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 BOOL
		 BandSetting_GetParamIntValue
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*						 ParamName,
				 int*						 pInt
			 );
 
	 description:
 
		 This function is called to retrieve integer parameter value; 
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 ParamName,
				 The parameter name;
 
				 int*						 pInt
				 The buffer of returned integer value;
 
	 return:	 TRUE if succeeded.
 
 **********************************************************************/
 BOOL
 BandSetting_GetParamIntValue
	 (
		 ANSC_HANDLE				 hInsContext,
		 char*						 ParamName,
		 int*						 pInt
	 )
 {
	if( AnscEqualString(ParamName, "UtilizationThreshold", TRUE))
	{
		 /* collect value */
		 return TRUE;
	}
	
	if( AnscEqualString(ParamName, "RSSIThreshold", TRUE))
	{
		 /* collect value */
		 return TRUE;
	}

	 if( AnscEqualString(ParamName, "PhyRateThreshold", TRUE))
	 {
		  /* collect value */
		  return TRUE;
	 }

	 if( AnscEqualString(ParamName, "OverloadInactiveTime", TRUE))
	 {
		  /* collect value */
		  return TRUE;
	 }

	 if( AnscEqualString(ParamName, "IdleInactiveTime", TRUE))
	 {
		  /* collect value */
		  return TRUE;
	 }

 	 /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
	 return FALSE;
 }

 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 BOOL
		 BandSetting_SetParamIntValue
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*						 ParamName,
				 int						 iValue
			 );
 
	 description:
 
		 This function is called to set integer parameter value; 
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 ParamName,
				 The parameter name;
 
				 int						 iValue
				 The updated integer value;
 
	 return:	 TRUE if succeeded.
 
 **********************************************************************/
 BOOL
 BandSetting_SetParamIntValue
	 (
		 ANSC_HANDLE				 hInsContext,
		 char*						 ParamName,
		 int						 iValue
	 )
 {

	 /* check the parameter name and set the corresponding value */
	 if( AnscEqualString(ParamName, "UtilizationThreshold", TRUE))
	 {
		 /* save update to backup */
		 return TRUE;
	 }
 
	 if( AnscEqualString(ParamName, "RSSIThreshold", TRUE))
	 {
		 /* save update to backup */
		 return TRUE;
	 }

	 if( AnscEqualString(ParamName, "PhyRateThreshold", TRUE))
	 {
		 /* save update to backup */
		 return TRUE;
	 }

	 if( AnscEqualString(ParamName, "OverloadInactiveTime", TRUE))
	 {
		 /* save update to backup */
		 return TRUE;
	 }

	 if( AnscEqualString(ParamName, "IdleInactiveTime", TRUE))
	 {
		 /* save update to backup */
		 return TRUE;
	 }

	 /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
	 return FALSE;
 }

 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 BOOL
		 BandSetting_Validate
			 (
				 ANSC_HANDLE				 hInsContext,
				 char*						 pReturnParamName,
				 ULONG* 					 puLength
			 );
 
	 description:
 
		 This function is called to finally commit all the update.
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 pReturnParamName,
				 The buffer (128 bytes) of parameter name if there's a validation. 
 
				 ULONG* 					 puLength
				 The output length of the param name. 
 
	 return:	 TRUE if there's no validation.
 
 **********************************************************************/
 BOOL
 BandSetting_Validate
	 (
		 ANSC_HANDLE				 hInsContext,
		 char*						 pReturnParamName,
		 ULONG* 					 puLength
	 )
 {
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
 }
 
 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 ULONG
		 BandSetting_Commit
			 (
				 ANSC_HANDLE				 hInsContext
			 );
 
	 description:
 
		 This function is called to finally commit all the update.
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
	 return:	 The status of the operation.
 
 **********************************************************************/
 ULONG
 BandSetting_Commit
	 (
		 ANSC_HANDLE				 hInsContext
	 )
 {
	 return ANSC_STATUS_SUCCESS;
 }
 
 /**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 ULONG
		 BandSetting_Rollback
			 (
				 ANSC_HANDLE				 hInsContext
			 );
 
	 description:
 
		 This function is called to roll back the update whenever there's a 
		 validation found.
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
	 return:	 The status of the operation.
 
 **********************************************************************/
 ULONG
 BandSetting_Rollback
	 (
		 ANSC_HANDLE				 hInsContext
	 )
 {
	 UNREFERENCED_PARAMETER(hInsContext);
	 return ANSC_STATUS_SUCCESS;
 }
 

 /***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_ATM

    *  ATM_GetParamBoolValue
    *  ATM_GetParamUlongValue
	*  ATM_SetParamBoolValue
	
***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        ATM_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ATM_GetParamBoolValue
(
	ANSC_HANDLE                 hInsContext,
	char*                       ParamName,
	BOOL*                       pBool
)
{
	UNREFERENCED_PARAMETER(hInsContext);
	if (AnscEqualString(ParamName, "Capable", TRUE)) {
		return TRUE;
	}

    if (AnscEqualString(ParamName, "Enable", TRUE)) {
		return TRUE;
	}

    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        ATM_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ATM_SetParamBoolValue
(
	ANSC_HANDLE                 hInsContext,
	char*                       ParamName,
	BOOL                        bValue
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    if( AnscEqualString(ParamName, "Enable", TRUE)) {
        return TRUE;
    }
    return FALSE;
}

BOOL
ATM_Validate
(
	ANSC_HANDLE				hInsContext,
	char*					pReturnParamName,
	ULONG* 					puLength
)
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}


ULONG
ATM_Commit
(
	ANSC_HANDLE				 hInsContext
)
{
    UNREFERENCED_PARAMETER(hInsContext);
	return ANSC_STATUS_SUCCESS;
}

ULONG
ATM_Rollback
(
	ANSC_HANDLE				 hInsContext
)
{
    UNREFERENCED_PARAMETER(hInsContext);
	return ANSC_STATUS_SUCCESS;
}
 
/***********************************************************************

 APIs for Object:

    WiFi.APGroup.{i}.

    *  APGroup_GetEntryCount
    *  APGroup_GetEntry
    *  APGroup_AddEntry
    *  APGroup_DelEntry
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
)
{
     UNREFERENCED_PARAMETER(hInsContext);
    return 0;
	
	
}


ANSC_HANDLE
APGroup_GetEntry
(
	ANSC_HANDLE                 hInsContext,
	ULONG                       nIndex,
	ULONG*                      pInsNumber
)
{
	UNREFERENCED_PARAMETER(hInsContext);
	return NULL;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        APGroup_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
APGroup_GetParamStringValue

    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(pUlSize);
	
    if( AnscEqualString(ParamName, "APList", TRUE)) {
        return 0;
    }

    return -1;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        APGroup_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
APGroup_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
	
	if( AnscEqualString(ParamName, "AirTimePercent", TRUE)) {
		return TRUE;
    }

    return FALSE;
}

BOOL
APGroup_SetParamUlongValue (
	ANSC_HANDLE                 hInsContext,
	char*                       ParamName,
	ULONG                       uValue
)
{
    CcspTraceInfo(("APGroup_SetParamUlongValue parameter '%s'\n", ParamName));
CcspTraceInfo(("---- %s %s \n", __func__, 	ParamName));
	if( AnscEqualString(ParamName, "AirTimePercent", TRUE))   {
        return TRUE;
    }
	
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        APGroup_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
APGroup_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	UNREFERENCED_PARAMETER(puLength);
	CcspTraceInfo(("APGroup_Validate parameter '%s'\n", pReturnParamName));
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        APGroup_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
APGroup_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	CcspTraceInfo(("APGroup_Commit parameter \n"));
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        APGroup_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
APGroup_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	CcspTraceInfo(("APGroup_Rollback parameter \n"));
    return ANSC_STATUS_SUCCESS;
}

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
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Sta_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
Sta_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
	return 0; 
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        Sta_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
Sta_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
	return NULL;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        Sta_AddEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to add a new entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle of new added entry.

**********************************************************************/
ANSC_HANDLE
Sta_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    )
{
	return NULL;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Sta_DelEntry
            (
                ANSC_HANDLE                 hInsContext,
                ANSC_HANDLE                 hInstance
            );

    description:

        This function is called to delete an exist entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ANSC_HANDLE                 hInstance
                The exist entry handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Sta_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    )
{
	return ANSC_STATUS_SUCCESS;
	
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Sta_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
Sta_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    CcspTraceInfo(("Sta_GetParamStringValue parameter '%s'\n", ParamName)); 

	if( AnscEqualString(ParamName, "MACAddress", TRUE)) {
        /* collect value */
        return 0;
    }
	
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Sta_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Sta_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    CcspTraceInfo(("Sta_GetParamUlongValue parameter '%s'\n", ParamName));
	if( AnscEqualString(ParamName, "AirTimePercent", TRUE))  {
        /* collect value */
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Sta_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Sta_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    CcspTraceInfo(("Sta_SetParamStringValue parameter '%s'\n", ParamName)); 
    if( AnscEqualString(ParamName, "MACAddress", TRUE)) {
		return TRUE;
    }
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Sta_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Sta_SetParamUlongValue
	(
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    CcspTraceInfo(("Sta_SetParamIntValue parameter '%s'\n", ParamName));

	if( AnscEqualString(ParamName, "AirTimePercent", TRUE))	{
		
		return TRUE;
	}
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Sta_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
Sta_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	UNREFERENCED_PARAMETER(puLength);
	CcspTraceInfo(("Sta_Validate parameter '%s'\n",pReturnParamName));
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Sta_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Sta_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	CcspTraceInfo(("Sta_Commit parameter \n"));
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Sta_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Sta_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	CcspTraceInfo(("Sta_Rollback parameter \n"));
    return ANSC_STATUS_SUCCESS;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.X_RDKCENTRAL-COM_InterworkingService.

    *  InterworkingService_GetParamStringValue
    *  InterworkingService_SetParamStringValue

***********************************************************************/

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        InterworkingService_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
InterworkingService_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;

    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    wifi_interworking_t *pcfg = &vap_pcfg->u.bss_info.interworking;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Parameters", TRUE))
    {
        /* collect value */
        if(pcfg->anqp.anqpParameters){
            if( AnscSizeOfString((char *)pcfg->anqp.anqpParameters) < *pUlSize)
            {
                AnscCopyString(pValue, (char *)pcfg->anqp.anqpParameters);
                return 0;
            }else{
                *pUlSize = AnscSizeOfString((char *)pcfg->anqp.anqpParameters)+1;
                return 1;
            }
        }
        return 0;
    }

    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterworkingService_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
InterworkingService_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Parameters", TRUE))
    {
        if( AnscEqualString((char*)vapInfo->u.bss_info.interworking.anqp.anqpParameters, (char*) pString, TRUE)){
            return TRUE;
        }else{
            cJSON *p_root = cJSON_Parse(pString);
            if(p_root == NULL) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid json for vap %s\n", __FUNCTION__,__LINE__,pcfg->vap_name);
                return FALSE;
            }
            AnscCopyString((char*)vapInfo->u.bss_info.interworking.anqp.anqpParameters,(char*)pString);
	    set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
    }
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    WiFi.AccessPoint.{i}.X_RDKCENTRAL-COM_Passpoint.

    *  Passpoint_GetParamBoolValue
    *  Passpoint_GetParamStringValue 
    *  Passpoint_SetParamBoolValue
    *  Passpoint_SetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Passpoint_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pBool

    return:     TRUE if succeeded;
                FALSE if not supported.

**********************************************************************/
BOOL
Passpoint_GetParamBoolValue
(
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
)
{
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;

    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    wifi_interworking_t *interworking_pcfg = &vap_pcfg->u.bss_info.interworking;
    if (interworking_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Capability", TRUE)) {
        return TRUE;
    }

    if (AnscEqualString(ParamName, "Enable", TRUE)) {
                //WiFi_SetHS2Status(vap_pcfg->vap_index, false, true);
	*pBool = interworking_pcfg->passpoint.enable;
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Passpoint_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
Passpoint_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{

    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)hInsContext;

    if (vap_pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,vap_pcfg->vap_name);
        return TRUE;
    }

    wifi_interworking_t *pcfg = &vap_pcfg->u.bss_info.interworking;
    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

        /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Parameters", TRUE))
    {
        if(pcfg->passpoint.hs2Parameters) {
            if( AnscSizeOfString((char *)pcfg->passpoint.hs2Parameters) < *pUlSize)
            {
                AnscCopyString(pValue, (char *)pcfg->passpoint.hs2Parameters);
                return 0;
            } else {
                *pUlSize = AnscSizeOfString((char *)pcfg->passpoint.hs2Parameters)+1;
                return 1;
            }	    
	}
        return 0;
    }

    if( AnscEqualString(ParamName, "WANMetrics", TRUE))
    {
        WiFi_GetWANMetrics((vap_pcfg->vap_index + 1), (char *)&pcfg->passpoint.wanMetricsInfo,
                sizeof(pcfg->passpoint.wanMetricsInfo));
        /* collect value */
        if( AnscSizeOfString((char *)&pcfg->passpoint.wanMetricsInfo) < *pUlSize)
        {
            AnscCopyString(pValue, (char *)&pcfg->passpoint.wanMetricsInfo);
            return 0;
        }else{
            *pUlSize = AnscSizeOfString((char *)&pcfg->passpoint.wanMetricsInfo)+1;
            return 1;
        }
        return 0;
    }

    if( AnscEqualString(ParamName, "Stats", TRUE))
    {
        WiFi_GetHS2Stats((vap_pcfg->vap_index + 1));
        /* collect value */
        if( AnscSizeOfString((char *)pcfg->anqp.passpointStats) < *pUlSize)
        {
            AnscCopyString(pValue, (char *)pcfg->anqp.passpointStats);
            return 0;
        }else{
            *pUlSize = AnscSizeOfString((char *)pcfg->anqp.passpointStats)+1;
            return 1;
        }
        return 0;
    }

    return 0;
}
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Passpoint_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Passpoint_SetParamBoolValue
(
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
)
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    //Check RFC value. Return FALSE if not enabled
    char *strValue = NULL;
    int retPsmGet = CCSP_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE)) {
        if(bValue == vapInfo->u.bss_info.interworking.passpoint.enable){
            CcspTraceWarning(("Passpoint value Already configured. Return Success\n"));
            return TRUE;
        }

        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-Passpoint.Enable", NULL, &strValue);
        if ((retPsmGet != CCSP_SUCCESS) || (false == _ansc_atoi(strValue)) || (FALSE == _ansc_atoi(strValue))){
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
            CcspTraceWarning(("Cannot Enable Passpoint. RFC Disabled\n"));
            return FALSE;
        }

        if(false == vapInfo->u.bss_info.interworking.interworking.interworkingEnabled){
            CcspTraceWarning(("Cannot Enable Passpoint. Interworking Disabled\n"));
            return FALSE;
        }
	vapInfo->u.bss_info.interworking.passpoint.enable = bValue;
	set_dml_cache_vap_config_changed(instance_number - 1);
	return TRUE;
    }
    return FALSE;
}
/**********************************************************************

    caller:     owner of this object 

    prototype: 

        BOOL
        Passpoint_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Passpoint_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{ 
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)hInsContext;

    if (pcfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointer get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number-1);

    if (vapInfo == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __FUNCTION__,__LINE__,instance_number);
        return FALSE;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __FUNCTION__,__LINE__,pcfg->vap_name);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "Parameters", TRUE))
    {
        if( AnscEqualString((char*)vapInfo->u.bss_info.interworking.passpoint.hs2Parameters, pString, TRUE)){
            return TRUE;
        }else {
             cJSON *p_root = cJSON_Parse(pString);
            if(p_root == NULL) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid json for vap %s\n", __FUNCTION__,__LINE__,pcfg->vap_name);
                return FALSE;
            }
            AnscCopyString((char*)vapInfo->u.bss_info.interworking.passpoint.hs2Parameters,pString);
	    set_dml_cache_vap_config_changed(instance_number - 1);
            return TRUE;
        }
    }
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    WiFi.X_RDKCENTRAL-COM_MgtFrameRateLimit.

    *  MgtFrameRateLimit_GetParamBoolValue
    *  MgtFrameRateLimit_SetParamBoolValue
    *  MgtFrameRateLimit_GetParamUlongValue
    *  MgtFrameRateLimit_SetParamUlongValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MgtFrameRateLimit_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL MgtFrameRateLimit_GetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL *pBool)
{
    wifi_global_param_t *pcfg = get_dml_wifi_global_param();

    UNREFERENCED_PARAMETER(hInsContext);

    if (pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Failed to get global config\n", __func__, __LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Enable", TRUE)) {
        *pBool = pcfg->mgt_frame_rate_limit_enable;
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************  
 
	 caller:	 owner of this object 
 
	 prototype: 
 
		 BOOL
		 MgtFrameRateLimit_SetParamBoolValue
			 (
				 ANSC_HANDLE					hInsContext,
				 char*						ParamName,
				 BOOL						bValue
			 );
 
	 description:
 
		 This function is called to set BOOL parameter value; 
 
	 argument:	 ANSC_HANDLE				 hInsContext,
				 The instance handle;
 
				 char*						 ParamName,
				 The parameter name;
 
				 BOOL						 bValue
				 The updated BOOL value;
 
	 return:	 TRUE if succeeded.
 
 **********************************************************************/
BOOL MgtFrameRateLimit_SetParamBoolValue(ANSC_HANDLE hInsContext, char *ParamName, BOOL bValue)
{
    wifi_global_config_t *global_wifi_config = get_dml_cache_global_wifi_config();

    UNREFERENCED_PARAMETER(hInsContext);

    if (global_wifi_config == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Failed to get global config\n", __func__, __LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "Enable", TRUE)) {
        if (global_wifi_config->global_parameters.mgt_frame_rate_limit_enable == bValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: RateLimit Enable: %d\n", __func__, __LINE__,
            bValue);
        global_wifi_config->global_parameters.mgt_frame_rate_limit_enable = bValue;

        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,
                "%s:%d: Failed to push RateLimit Enable value to onewifi db\n", __func__, __LINE__);
        }
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MgtFrameRateLimit_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      pULong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

               ULONG*                       pULong

    return:     TRUE if succeeded.

**********************************************************************/

BOOL MgtFrameRateLimit_GetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG *pULong)
{
    wifi_global_param_t *pcfg = get_dml_wifi_global_param();

    UNREFERENCED_PARAMETER(hInsContext);

    if (pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Failed to get global config\n", __func__, __LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "RateLimit", TRUE)) {
        *pULong = pcfg->mgt_frame_rate_limit;
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d RateLimit: %d\n", __func__, __LINE__, *pULong);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "WindowSize", TRUE)) {
        *pULong = pcfg->mgt_frame_rate_limit_window_size;
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Window size: %d\n", __func__, __LINE__, *pULong);
        return TRUE;
    }

    if (AnscEqualString(ParamName, "CooldownTime", TRUE)) {
        *pULong = pcfg->mgt_frame_rate_limit_cooldown_time;
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Cooldown time: %d\n", __func__, __LINE__, *pULong);
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MgtFrameRateLimit_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       iValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       iValue
                The updated value;

    return:     TRUE if succeeded.
**********************************************************************/

BOOL MgtFrameRateLimit_SetParamUlongValue(ANSC_HANDLE hInsContext, char *ParamName, ULONG iValue)
{
    wifi_global_config_t *global_wifi_config = get_dml_cache_global_wifi_config();

    UNREFERENCED_PARAMETER(hInsContext);

    if (global_wifi_config == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Failed to get global config\n", __func__, __LINE__);
        return FALSE;
    }

    if (AnscEqualString(ParamName, "RateLimit", TRUE)) {
        if ((ULONG)global_wifi_config->global_parameters.mgt_frame_rate_limit == iValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Rate Limit: %d\n", __func__, __LINE__, iValue);
        global_wifi_config->global_parameters.mgt_frame_rate_limit = iValue;

        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,
                "%s:%d: Failed to push RateLimit value to onewifi db\n", __func__, __LINE__);
        }

        return TRUE;
    }

    if (AnscEqualString(ParamName, "WindowSize", TRUE)) {
        if ((ULONG)global_wifi_config->global_parameters.mgt_frame_rate_limit_window_size ==
            iValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Rate Limit Window Size: %d\n", __func__, __LINE__,
            iValue);
        global_wifi_config->global_parameters.mgt_frame_rate_limit_window_size = iValue;

        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,
                "%s:%d: Failed to push RateLimit WindowSize value to onewifi db\n", __func__,
                __LINE__);
        }

        return TRUE;
    }

    if (AnscEqualString(ParamName, "CooldownTime", TRUE)) {
        if ((ULONG)global_wifi_config->global_parameters.mgt_frame_rate_limit_cooldown_time ==
            iValue) {
            return TRUE;
        }
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Rate Limit CooldownTime: %d\n", __func__, __LINE__,
            iValue);
        global_wifi_config->global_parameters.mgt_frame_rate_limit_cooldown_time = iValue;

        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,
                "%s:%d: Failed to push RateLimit CooldownTime value to onewifi db\n", __func__,
                __LINE__);
        }

        return TRUE;
    }

    return FALSE;
}
