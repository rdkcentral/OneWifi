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

        *  CosaWifiCreate
        *  CosaWifiInitialize
        *  CosaWifiRemove
        *  CosaDmlWifiGetPortMappingNumber
    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/
#define _XOPEN_SOURCE 700
#include <telemetry_busmessage_sender.h>
#include "cosa_apis.h"
#include "cosa_dbus_api.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_sbapi_custom.h"
#include "cosa_wifi_internal.h"
#include "plugin_main_apis.h"
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_monitor.h"
#include "wifi_easy_connect.h"
#include "ccsp_psm_helper.h"
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <strings.h>
#include <time.h>
#include "ansc_platform.h"
#include "pack_file.h"
#include "ccsp_WifiLog_wrapper.h"
#include <sysevent/sysevent.h>
#include <sys/sysinfo.h>
#include "print_uptime.h"
#include "wifi_passpoint.h"
#include "cosa_wifi_dml.h"
#include "secure_wrapper.h"

#include "wifi_ctrl.h"
#include "../../../stubs/wifi_stubs.h"
#include "wifi_util.h"
#include "dml_onewifi_api.h"

#if defined (FEATURE_SUPPORT_WEBCONFIG)
#include "wifi_webconfig.h"
#endif
#include "wifi_passpoint.h"
#include "msgpack.h"
#include "ovsdb_table.h"
#include "wifi_db.h"

#if defined(_COSA_BCM_MIPS_) || defined(_XB6_PRODUCT_REQ_) || defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_)
#include "cJSON.h"
#include <ctype.h>
#endif

#ifdef USE_NOTIFY_COMPONENT
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/un.h>
#endif
#ifdef WIFI_HAL_VERSION_3
#include "safec_lib_common.h"
#endif
#define WLAN_MAX_LINE_SIZE 1024
#define RADIO_BROADCAST_FILE "/tmp/.advertise_ssids"
#if defined(_COSA_BCM_MIPS)
#define WLAN_WAIT_LIMIT 3
#endif

#if defined(_COSA_BCM_MIPS_) || defined(_XB6_PRODUCT_REQ_) || defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_)
#define PARTNERS_INFO_FILE              "/nvram/partners_defaults.json"
#define BOOTSTRAP_INFO_FILE             "/nvram/bootstrap.json"
#endif

#ifdef FEATURE_SUPPORT_ONBOARD_LOGGING
#define OnboardLog(...)                     rdk_log_onboard("WIFI", __VA_ARGS__)
#else
#define OnboardLog(...)
#endif

#if defined (_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_)
#define MAX_BUF_SIZE 128
#endif

#ifdef WIFI_HAL_VERSION_3

#define MAX_NEIGHBOURS 250
#endif

static const char WIFI_XHS_LNF_FLAG_FILE_NAME[] = "/nvram/.bcmwifi_xhs_lnf_enabled";

static char *FactoryReset       = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.FactoryReset";
extern bool is_radio_config_changed;
struct wifiSecEncrCosaHalMap wifiSecEncrMap[] =
{
      {wifi_encryption_tkip,     COSA_DML_WIFI_AP_SEC_TKIP,     "TKIP"},
      {wifi_encryption_aes,      COSA_DML_WIFI_AP_SEC_AES,      "AES"},
      {wifi_encryption_aes_tkip, COSA_DML_WIFI_AP_SEC_AES_TKIP, "AES_TKIP"}
};

struct wifiSecCosaHalMap wifiSecMap[] =
{
      {wifi_security_mode_none,                COSA_DML_WIFI_SECURITY_None,                     "None"},
      {wifi_security_mode_wep_64,              COSA_DML_WIFI_SECURITY_WEP_64,                   "WEP_64"},
      {wifi_security_mode_wep_128,             COSA_DML_WIFI_SECURITY_WEP_128,                  "WEP_128"},
      {wifi_security_mode_wpa_personal,        COSA_DML_WIFI_SECURITY_WPA_Personal,             "WPA-Personal"},
      {wifi_security_mode_wpa2_personal,       COSA_DML_WIFI_SECURITY_WPA2_Personal,            "WPA2-Personal"},
      {wifi_security_mode_wpa3_personal,       COSA_DML_WIFI_SECURITY_WPA3_Personal,            "WPA3-Personal"},
      {wifi_security_mode_wpa_wpa2_personal,   COSA_DML_WIFI_SECURITY_WPA_WPA2_Personal,        "WPA-WPA2-Personal"},
      {wifi_security_mode_wpa3_transition,     COSA_DML_WIFI_SECURITY_WPA3_Personal_Transition, "WPA3-Personal-Transition"},
      {wifi_security_mode_wpa_enterprise,      COSA_DML_WIFI_SECURITY_WPA_Enterprise,           "WPA-Enterprise"},
      {wifi_security_mode_wpa2_enterprise,     COSA_DML_WIFI_SECURITY_WPA2_Enterprise,          "WPA2-Enterprise"},
      {wifi_security_mode_wpa3_enterprise,     COSA_DML_WIFI_SECURITY_WPA3_Enterprise,          "WPA3-Enterprise"},
      {wifi_security_mode_wpa_wpa2_enterprise, COSA_DML_WIFI_SECURITY_WPA_WPA2_Enterprise,      "WPA-WPA2-Enterprise"},
      {wifi_security_mode_enhanced_open,       COSA_DML_WIFI_SECURITY_Enhanced_Open,            "Enhanced-Open"}
};

struct wifiFreqBandHalMap wifiFreqBandMap[] =
{
    {WIFI_FREQUENCY_2_4_BAND, COSA_DML_WIFI_FREQ_BAND_2_4G, "2.4GHz"},
    {WIFI_FREQUENCY_5_BAND,   COSA_DML_WIFI_FREQ_BAND_5G,   "5GHz"},
    {WIFI_FREQUENCY_5L_BAND,  COSA_DML_WIFI_FREQ_BAND_5G_L, "Low 5GHz"},
    {WIFI_FREQUENCY_5H_BAND,  COSA_DML_WIFI_FREQ_BAND_5G_H, "High 5Ghz"},
    {WIFI_FREQUENCY_6_BAND,   COSA_DML_WIFI_FREQ_BAND_6G,   "6GHz"},
    {WIFI_FREQUENCY_60_BAND,  COSA_DML_WIFI_FREQ_BAND_60,   "60GHz"}
};

struct wifiSecMfpCosaHalMap wifiSecMFPMap[] =
{
      {wifi_mfp_cfg_disabled, "Disabled"},
      {wifi_mfp_cfg_optional, "Optional"},
      {wifi_mfp_cfg_required, "Required"},
};

struct wifiChanWidthCosaHalMap wifiChanWidthMap[] =
{
    {WIFI_CHANNELBANDWIDTH_20MHZ,    COSA_DML_WIFI_CHAN_BW_20M,    "20MHz"},
    {WIFI_CHANNELBANDWIDTH_40MHZ,    COSA_DML_WIFI_CHAN_BW_40M,    "40MHz"},
    {WIFI_CHANNELBANDWIDTH_80MHZ,    COSA_DML_WIFI_CHAN_BW_80M,    "80MHz"},
    {WIFI_CHANNELBANDWIDTH_160MHZ,   COSA_DML_WIFI_CHAN_BW_160M,   "160MHz"},
    {WIFI_CHANNELBANDWIDTH_80_80MHZ, COSA_DML_WIFI_CHAN_BW_80_80M, "80+80MHz"},
#ifdef CONFIG_IEEE80211BE
    {WIFI_CHANNELBANDWIDTH_320MHZ,   COSA_DML_WIFI_CHAN_BW_320M,   "320MHz"}
#endif /* CONFIG_IEEE80211BE */
};

struct wifiGuardIntervalMap wifiGuardIntervalMap[] ={
      {wifi_guard_interval_400,   COSA_DML_WIFI_GUARD_INTVL_400ns,  "400ns"},
      {wifi_guard_interval_800,   COSA_DML_WIFI_GUARD_INTVL_800ns,  "800ns"},
      {wifi_guard_interval_1600,  COSA_DML_WIFI_GUARD_INTVL_1600ns, "1600ns"},
      {wifi_guard_interval_3200,  COSA_DML_WIFI_GUARD_INTVL_3200ns, "3200ns"},
      {wifi_guard_interval_auto,  COSA_DML_WIFI_GUARD_INTVL_Auto,   "Auto"}
};

struct  wifiStdCosaHalMap wifiStdDmlMap[] =
{
    {WIFI_80211_VARIANT_A,  COSA_DML_WIFI_STD_a,  "a"},
    {WIFI_80211_VARIANT_B,  COSA_DML_WIFI_STD_b,  "b"},
    {WIFI_80211_VARIANT_G,  COSA_DML_WIFI_STD_g,  "g"},
    {WIFI_80211_VARIANT_N,  COSA_DML_WIFI_STD_n,  "n"},
    {WIFI_80211_VARIANT_H,  COSA_DML_WIFI_STD_h,  "h"},
    {WIFI_80211_VARIANT_AC, COSA_DML_WIFI_STD_ac, "ac"},
    {WIFI_80211_VARIANT_AD, COSA_DML_WIFI_STD_ad, "ad"},
    {WIFI_80211_VARIANT_AX, COSA_DML_WIFI_STD_ax, "ax"},
#ifdef CONFIG_IEEE80211BE
    {WIFI_80211_VARIANT_BE, COSA_DML_WIFI_STD_be, "be"}
#endif /* CONFIG_IEEE80211BE */
};

/**************************************************************************
*
*	Function Declarations
*
**************************************************************************/


#ifndef __user
#define __user
#endif

extern BOOL client_fast_reconnect(unsigned int apIndex, char *mac);
extern BOOL client_fast_redeauth(unsigned int apIndex, char *mac);
int sMac_to_cMac(char *sMac, unsigned char *cMac);

BOOL g_wifidb_rfc = FALSE;

#define  ARRAY_SZ(x)    (sizeof(x) / sizeof((x)[0]))

#include <pthread.h>

// #define wifiDbgPrintf 
#define wifiDbgPrintf printf


extern ANSC_HANDLE bus_handle;
extern char        g_Subsystem[32];

#define WIFIEXT_DM_RADIO_UPDATE  ""
#define WIFIEXT_DM_WPS_UPDATE    ""
#define WIFIEXT_DM_SSID_UPDATE   ""
#define INTERVAL 50000

#define WIFI_COMP				"eRT.com.cisco.spvtg.ccsp.wifi"
#define WIFI_BUS					"/com/cisco/spvtg/ccsp/wifi"
#define HOTSPOT_DEVICE_NAME	"AP_steering"
#ifndef WIFI_HAL_VERSION_3
#if defined(_CBR_PRODUCT_REQ_) || defined (_BWG_PRODUCT_REQ_)
#define HOTSPOT_NO_OF_INDEX			5
static const int Hotspot_Index[HOTSPOT_NO_OF_INDEX]={5,6,9,10,16};
#else
#define HOTSPOT_NO_OF_INDEX			4
static const int Hotspot_Index[HOTSPOT_NO_OF_INDEX]={5,6,9,10};
#endif
#endif
#if defined(DMCLI_SUPPORT_TO_ADD_DELETE_VAP)
#define ATH_NAME "ath"

#define GET_SSID_INDEX(ssidList, uInstanceNumber, idx) do { \
    for ( idx = 0; idx < (ULONG)gSsidCount; idx++ ) \
        if ( ssidList[idx].InstanceNumber == uInstanceNumber ) \
            break; \
    if ( idx >= (ULONG)gSsidCount ) { \
        wifiDbgPrintf("%s: SSID entry %lu not found in dB \n", __FUNCTION__, uInstanceNumber); \
        return ANSC_STATUS_FAILURE; \
    } \
}while(0)

#define GET_AP_INDEX(apList, uInstanceNumber, idx) do { \
    for ( idx = 0; idx < (ULONG)gSsidCount; idx++ ) \
        if ( apList[idx].Cfg.InstanceNumber == (ULONG)uInstanceNumber ) \
            break; \
    if ( idx >= (ULONG)gSsidCount ) { \
        wifiDbgPrintf("%s: AP entry %lu not found in dB \n", __FUNCTION__, (ULONG)uInstanceNumber); \
        return ANSC_STATUS_FAILURE; \
    } \
}while(0)
#endif

struct wifiDataTxRateHalMap wifiDataTxRateMap[] =
{
    {WIFI_BITRATE_DEFAULT, "Default"}, //Used in Set
    {WIFI_BITRATE_1MBPS,   "1"},
    {WIFI_BITRATE_2MBPS,   "2"},
    {WIFI_BITRATE_5_5MBPS, "5.5"},
    {WIFI_BITRATE_6MBPS,   "6"},
    {WIFI_BITRATE_9MBPS,   "9"},
    {WIFI_BITRATE_11MBPS,  "11"},
    {WIFI_BITRATE_12MBPS,  "12"},
    {WIFI_BITRATE_18MBPS,  "18"},
    {WIFI_BITRATE_24MBPS,  "24"},
    {WIFI_BITRATE_36MBPS,  "36"},
    {WIFI_BITRATE_48MBPS,  "48"},
    {WIFI_BITRATE_54MBPS,  "54"}
};


#define CSA_TBTT   25

/**************************************************************************
*
*       Function Definitions
*
**************************************************************************/

UINT getRegulatoryDomainFromEnums(wifi_countrycode_type_t countryCode, wifi_operating_env_t operatingEnvironment, char *regulatoryDomainStr)
{
    unsigned int i;
    char tmp_countryStr[4];
    char tmp_environment[4];

    memset(tmp_countryStr, 0, sizeof(tmp_countryStr));
    memset(tmp_environment, 0, sizeof(tmp_environment));
    for (i = 0 ; i < ARRAY_SZ(wifiCountryMapMembers); ++i)
    {
        if(countryCode == wifiCountryMapMembers[i].countryCode)
        {
            strncpy(tmp_countryStr, wifiCountryMapMembers[i].countryStr, sizeof(tmp_countryStr)-1);
            break;
        }
    }

    for (i = 0; i < ARRAY_SZ(wifiEnviromentMap); ++i)
    {
        if (operatingEnvironment == wifiEnviromentMap[i].operatingEnvironment)
        {
            strncpy(tmp_environment, wifiEnviromentMap[i].environment, sizeof(wifiEnviromentMap[i].environment)-1);
            break;
        }
    }

    snprintf(regulatoryDomainStr, 4, "%s%s", tmp_countryStr, tmp_environment);
    if (strlen(regulatoryDomainStr) == 0)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Country code enum\n", __func__));
        return 0;
    }
    return strlen(regulatoryDomainStr);
}

INT getTxDataRateFromInt(wifi_bitrate_t DataTxRate, char *DataTxRateStr)
{
    unsigned int i;
    for (i = 0 ; i < ARRAY_SZ(wifiDataTxRateMap) ; ++i)
    {
        if(DataTxRate == wifiDataTxRateMap[i].DataTxRateEnum)
        {
            strncpy(DataTxRateStr, wifiDataTxRateMap[i].DataTxRateStr, strlen(wifiDataTxRateMap[i].DataTxRateStr));
            return strlen(wifiDataTxRateMap[i].DataTxRateStr);
        }
    }

    if(strlen(DataTxRateStr) == 0)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid DataTxRate enum\n", __func__));
    }

    return 0;
}

INT getSecurityStringFromInt(wifi_security_modes_t securityType, char *securityName)
{
    unsigned int i;
    for (i = 0 ; i < ARRAY_SZ(wifiSecMap) ; ++i)
    {
        if(securityType == wifiSecMap[i].halSecCfgMethod)
        {
            if (AnscSizeOfString(securityName) != 0)
            {
                strcat(securityName, ",");
                strcat(securityName, wifiSecMap[i].wifiSecType);
            }
            else
            {
                strcpy(securityName, wifiSecMap[i].wifiSecType);
            }
       }
    }

    if(strlen(securityName) == 0)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Security type enum\n", __func__));
    }
    else
    {
        return strlen(securityName);
    }
    return 0;
}

INT getBeaconRateStringFromEnum (char *beaconName, int length, wifi_bitrate_t beaconType)
{
    unsigned int seqCounter  = 0;

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiDataTxRateMap); seqCounter++)
    {
        if (beaconType == wifiDataTxRateMap[seqCounter].DataTxRateEnum)
        {
            snprintf(beaconName, length, "%sMbps", wifiDataTxRateMap[seqCounter].DataTxRateStr);
            return 0;
        }
    }
    return 0;
}

INT getBeaconRateFromString (const char *beaconName, wifi_bitrate_t *beaconType)
{
    INT rc = -1;
    INT ind = -1;
    UINT i = 0;
    if((beaconName == NULL) || (beaconType == NULL))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s parameter NULL\n", __func__));
        return 0;
    }
    
    CHAR* tempBeaconName = (CHAR*)malloc(strlen(beaconName)+1);

    if (tempBeaconName == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Malloc failed\n", __func__));
        return 0;
    }

    snprintf(tempBeaconName, strlen(beaconName)+1, beaconName);
    char * token = strtok(tempBeaconName, "Mbps");
    if (token == NULL)
    {
        free (tempBeaconName);
        return 0;
    }

    for (i = 0 ; i < ARRAY_SZ(wifiDataTxRateMap) ; ++i)
    {
        rc = strcmp_s(token, strlen(token), wifiDataTxRateMap[i].DataTxRateStr, &ind);
        ERR_CHK(rc);
        if((!rc) && (!ind))
        {
            *beaconType = wifiDataTxRateMap[i].DataTxRateEnum;
            free (tempBeaconName);
            return 1;
        }
    }
    
    free (tempBeaconName);
    return 0;
}

INT getIpAddressFromString (const char * ipString, ip_addr_t * ip)
{
    if (inet_pton(AF_INET, ipString, &ip->u.IPv4addr) > 0) 
    {
        ip->family = wifi_ip_family_ipv4;
    } 
    else if (inet_pton(AF_INET6, ipString, ip->u.IPv6addr) > 0)
    {
        ip->family = wifi_ip_family_ipv6;
    }
    else
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s IP not recognise\n", __func__));
        return 0;
    }

    return 1;
}

ANSC_STATUS
getMFPTypeFromString (const char *MFPName, wifi_mfp_cfg_t *MFPType)
{
    INT rc = -1;
    INT ind = -1;
    UINT counter = 0;
    if( (MFPName == NULL) || (MFPType == NULL) )
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s MFP parameter NULL\n", __func__));
        return ANSC_STATUS_FAILURE;
    }
    for (counter = 0 ; counter < ARRAY_SZ(wifiSecMFPMap) ; ++counter)
    {
        rc = strcmp_s(MFPName, strlen(MFPName), wifiSecMFPMap[counter].wifiSecMFP, &ind);
        ERR_CHK(rc);
        if((!rc) && (!ind))
        {
            *MFPType = wifiSecMFPMap[counter].halSecMFP;
            return ANSC_STATUS_SUCCESS;
        }
    }
    return ANSC_STATUS_FAILURE;
}

void
CosaWiFiDmlGetWPA3TransitionRFC (BOOL *WPA3_RFC)
{
    char recName[256] = {0x0};
    char *strValue = NULL;
    memset(recName, '\0', sizeof(recName));
    sprintf(recName, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WPA3_Personal_Transition.Enable");

    if(PSM_Get_Record_Value2(bus_handle,g_Subsystem, recName, NULL, &strValue) != CCSP_SUCCESS)
    {
        *WPA3_RFC = FALSE;
        CcspTraceError(("%s: fail to get PSM record for WPA3 Transition Enable RFC\n",__func__));
    }
    else
    {
        *WPA3_RFC = atoi(strValue);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }
}

ANSC_STATUS
CosaDmlWiFi_GetGoodRssiThresholdValue( int	*piRssiThresholdValue )
{
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg != NULL) {
        *piRssiThresholdValue = pcfg->good_rssi_threshold;
    } else {
        CcspTraceInfo(("%s WIFI DB Failed to get global config\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlWiFi_GetAssocCountThresholdValue( int	*piAssocCountThresholdValue )
{
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg != NULL) {
        *piAssocCountThresholdValue= pcfg->assoc_count_threshold;
    } else {
        CcspTraceInfo(("%s WIFI DB Failed to get global config\n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlWiFi_GetAssocMonitorDurationValue( int	*piAssocMonitorDurationValue )
{
     wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
     if (pcfg != NULL) {
        *piAssocMonitorDurationValue = pcfg->assoc_monitor_duration;
        CcspTraceInfo(("%s WIFI DB get success Value: %d\n", __FUNCTION__, *piAssocMonitorDurationValue))
    } else {
        CcspTraceInfo(("%s WIFI DB Failed to get global config\n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlWiFi_GetAssocGateTimeValue( int	*piAssocGateTimeValue )
{
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg != NULL) {
        *piAssocGateTimeValue = pcfg->assoc_gate_time;
        CcspTraceInfo(("%s WIFI DB get success Value: %d\n", __FUNCTION__, *piAssocGateTimeValue));
    } else {
        CcspTraceInfo(("%s WIFI DB Failed to get global config\n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlWiFi_GetRapidReconnectThresholdValue(ULONG vAPIndex, int	*rapidReconnThresholdValue )
{
    wifi_front_haul_bss_t  *pcfg= NULL;
    pcfg = Get_wifi_object_bss_parameter(vAPIndex);
    if(pcfg != NULL)
    {
        *rapidReconnThresholdValue = pcfg->rapidReconnThreshold;
    } else {
        CcspTraceInfo(("%s WIFI DB Failed to get vap config\n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }
   return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlWiFi_GetFeatureMFPConfigValue( BOOLEAN *pbFeatureMFPConfig )
{
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg != NULL) {
       *pbFeatureMFPConfig = pcfg->mfp_config_feature;
        CcspTraceInfo(("%s MFP config value %d\n",__FUNCTION__,pcfg->mfp_config_feature));
    } else {
       CcspTraceInfo(("%s Failed to get wifi db value\n", __FUNCTION__ ));
       return ANSC_STATUS_FAILURE;
    }	
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlWiFi_GetRapidReconnectCountEnable(ULONG vAPIndex, BOOLEAN *pbReconnectCountEnable, BOOLEAN usePersistent )
{
    wifi_front_haul_bss_t  *pcfg= NULL;
    pcfg = Get_wifi_object_bss_parameter(vAPIndex);
    if(pcfg != NULL)
    {
        *pbReconnectCountEnable = pcfg->rapidReconnectEnable;
        CcspTraceInfo(("%s WIFI DB get success Value: %d\n", __FUNCTION__, *pbReconnectCountEnable));
    } else {
        CcspTraceInfo(("%s WIFI DB Failed to get vap config\n", __FUNCTION__ ));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : CosaDmlWiFiGetEnableRadiusGreylist                            */
/*                                                                               */
/* DESCRIPTION   : This function is to get the value of RadiusGreyList           */
/*                        from the PSM Database                                  */
/*                                                                               */
/* INPUT         : pbEnableRadiusGreyList - pointer to the return value          */
/*                                                                               */
/* OUTPUT        : TRUE / FALSE                                                  */
/*                                                                               */
/* RETURN VALUE  : ANSC_STATUS_SUCCESS / ANSC_STATUS_FAILURE                     */
/*                                                                               */
/*********************************************************************************/
void CosaDmlWiFiGetEnableRadiusGreylist(BOOLEAN *pbEnableRadiusGreyList)
{
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
    char *psmStrValue = NULL;

    *pbEnableRadiusGreyList = FALSE;
    CcspTraceInfo(("[%s] Get EnableRadiusGreylist Value \n",__FUNCTION__));

    if (PSM_Get_Record_Value2(bus_handle, g_Subsystem,
            "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RadiusGreyList.Enable",
            NULL, &psmStrValue) == CCSP_SUCCESS)
    {
        *pbEnableRadiusGreyList = _ansc_atoi(psmStrValue);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(psmStrValue);
    }
#else
    UNREFERENCED_PARAMETER(pbEnableRadiusGreyList);
#endif
}

#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : CosaDmlWiFiCheckEnableRadiusGreylist                          */
/*                                                                               */
/* DESCRIPTION   : This function set the rdk_greylist to TRUE/FALSE in HAL       */
/*                      at bootup                                                */
/*                                                                               */
/* INPUT         : Value                                                         */
/*                                                                               */
/* OUTPUT        : TRUE / FALSE                                                  */
/*                                                                               */
/* RETURN VALUE  : ANSC_STATUS_SUCCESS / ANSC_STATUS_FAILURE                     */
/*                                                                               */
/*********************************************************************************/
ANSC_STATUS
CosaDmlWiFiSetEnableRadiusGreylist(BOOLEAN value) {

#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
    CcspTraceInfo(("[%s] Enter\n",__FUNCTION__));
    char recName[256];
    static char *MacFilterMode      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterMode";

    if (value == TRUE)
    {
        CcspTraceInfo(("[%s] Enabled\n",__FUNCTION__));
        for (UINT index = 0; index < getTotalNumberVAPs(); ++index)
        {
            UINT apIndex;

            apIndex = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, index);
            if (isVapHotspot(apIndex))
            {
                memset(recName, 0, sizeof(recName));
                sprintf(recName, MacFilterMode, apIndex+1);
                PSM_Set_Record_Value2(bus_handle,g_Subsystem, recName, ccsp_string, "2"); 
            }
        }
    }
    else
    {
        CcspTraceInfo(("[%s] Disabled\n",__FUNCTION__));
        for (UINT index = 0; index < getTotalNumberVAPs(); ++index)
        {
            UINT apIndex;

            apIndex = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, index);
            if (isVapHotspot(apIndex))
            {
                memset(recName, 0, sizeof(recName));
                sprintf(recName, MacFilterMode, apIndex+1);
                PSM_Set_Record_Value2(bus_handle,g_Subsystem, recName, ccsp_string, "1");
            }
        }
    }

#else 
    UNREFERENCED_PARAMETER(value);
#endif    
    return ANSC_STATUS_SUCCESS;
}
#endif

ANSC_STATUS CosaDmlWiFiGetTxOverflowSelfheal(BOOLEAN *pbValue)
{
    // Initialize the value as FALSE always
    *pbValue = FALSE;
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg != NULL) {
        *pbValue = pcfg->tx_overflow_selfheal;
        return ANSC_STATUS_SUCCESS;
    }
    return ANSC_STATUS_FAILURE;
}

#define RADIO_5G        1

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : CosaDmlWiFiGetForceDisableWiFiRadio                           */
/*                                                                               */
/* DESCRIPTION   : This function will fetch the value from the PSM database.     */
/*                                                                               */
/* INPUT         : pbValue - pointer to the return value                         */
/*                                                                               */
/* OUTPUT        : TRUE / FALSE                                                  */
/*                                                                               */
/* RETURN VALUE  : ANSC_STATUS_SUCCESS / ANSC_STATUS_FAILURE                     */
/*                                                                               */
/*********************************************************************************/
ANSC_STATUS CosaDmlWiFiGetForceDisableWiFiRadio(BOOLEAN *pbValue)
{
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg != NULL) {
        *pbValue = pcfg->force_disable_radio_feature;
        return ANSC_STATUS_SUCCESS;
    }
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS CosaDmlWiFiGetCurrForceDisableWiFiRadio(BOOLEAN *pbValue)
{
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg != NULL) {
        *pbValue = pcfg->force_disable_radio_feature;
        return ANSC_STATUS_SUCCESS;
    }
    return ANSC_STATUS_FAILURE;
}

int readRemoteIP(char *sIP, int size,char *sName)
{

        #define DATA_SIZE 1024
        FILE *fp1;
        char buf[DATA_SIZE] = {0};
        char *urlPtr = NULL;
        int ret=-1;

        // Grab the ARM or ATOM RPC IP address

        fp1 = fopen("/etc/device.properties", "r");
        if (fp1 == NULL) {
            CcspTraceError(("Error opening properties file! \n"));
            return -1;
        }

        while (fgets(buf, DATA_SIZE, fp1) != NULL) {
            // Look for ARM_ARPING_IP or ATOM_ARPING_IP
            if (strstr(buf, sName) != NULL) {
                buf[strcspn(buf, "\r\n")] = 0; // Strip off any carriage returns

                // grab URL from string
                urlPtr = strstr(buf, "=");
                urlPtr++;
                strncpy(sIP, urlPtr, size);
              ret=0;
              break;
            }
        }

        fclose(fp1);
        return ret;

}

ANSC_STATUS
CosaDmlWiFi_EnableTelnet(BOOL bEnabled)
{

    if (bEnabled) {
	// Attempt to start the telnet daemon on ATOM
        char NpRemoteIP[128]="";
        readRemoteIP(NpRemoteIP, 128,"ATOM_ARPING_IP");
        if (NpRemoteIP[0] != 0 && strlen(NpRemoteIP) > 0) {
                if (get_stubs_descriptor()->v_secure_system_fn("/usr/sbin/telnetd -b %s") != 0)
                {
                        return ANSC_STATUS_FAILURE;
                }
        }
    }

    else {
        // Attempt to kill the telnet daemon on ATOM
        if (get_stubs_descriptor()->v_secure_system_fn("pkill telnetd") != 0 ) {
	    return ANSC_STATUS_FAILURE;
        }
    }

    return ANSC_STATUS_SUCCESS;

}

int
CosaDmlWiFi_Logfiles_validation(char *param)
{
    char * pch = strtok (param,",");
    while (pch != NULL)
    {
        if ((strcmp(pch,"wifiDbDbg")== 0)  || (strcmp(pch,"wifiMgrDbg")== 0)  || (strcmp(pch,"wifiWebConfigDbg")== 0)  ||(strcmp(pch,"wifiCtrlDbg")== 0) \
          || (strcmp(pch,"wifiPasspointDbg")== 0)  || (strcmp(pch,"wifiDppDbg")== 0)  || (strcmp(pch,"wifiMonDbg")== 0)  ||(strcmp(pch,"wifiDMCLI")== 0)  || (strcmp(pch,"wifiLib")== 0) \
          || (strcmp(pch,"wifiPsm")== 0)  || (strcmp(pch,"wifiLibhostapDbg")== 0)  || (strcmp(pch,"wifiHalDbg")== 0) ) {
            wifi_util_dbg_print(WIFI_DMCLI,"continue to strtok %s\n",pch);
        }
        else if (strlen(pch)!=0 || (strcmp(pch,"") == 0)) {
            wifi_util_dbg_print(WIFI_DMCLI,"api invalid param %s\n",pch);
            return -1;
        }
        pch = strtok (NULL, ",");
    }
    return 0;
}

ANSC_STATUS
CosaDmlWiFi_setWebConfig(char *webconfstr, int size,uint8_t ssid)
{
    push_event_to_ctrl_queue(webconfstr, size, wifi_event_type_webconfig, wifi_event_webconfig_set_data_webconfig, NULL);

    return ANSC_STATUS_SUCCESS;
}
ANSC_STATUS
CosaDmlWiFi_getWebConfig()
{
    //wifi_radio_config_get();
    return ANSC_STATUS_SUCCESS;
}

int cMac_to_sMac(unsigned char *cMac, char *sMac) {
	if (!sMac || !cMac) return 0;
	snprintf(sMac, 32, "%02X:%02X:%02X:%02X:%02X:%02X", cMac[0],cMac[1],cMac[2],cMac[3],cMac[4],cMac[5]);
	return 0;
}

ANSC_STATUS txRateStrToUint(char *inputStr, UINT *pTxRate)
{
    char *token;
    bool isRateInvalid = TRUE;
    UINT seqCounter = 0;
    char tmpInputString[128] = {0};

    if ((inputStr == NULL) || (pTxRate == NULL))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    snprintf(tmpInputString, sizeof(tmpInputString), "%s", inputStr);

    token = strtok(tmpInputString, ",");
    while (token != NULL)
    {
        isRateInvalid = TRUE;
        for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiDataTxRateMap); seqCounter++)
        {
            if (AnscEqualString(token, wifiDataTxRateMap[seqCounter].DataTxRateStr, TRUE))
            {
                *pTxRate |= wifiDataTxRateMap[seqCounter].DataTxRateEnum;
                //ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s Token : %s txRate : %d\n", __FUNCTION__, token, *pTxRate);
                isRateInvalid = FALSE;
            }
        }

        if (isRateInvalid == TRUE)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid txrate Token : %s\n", __FUNCTION__, token));
            return ANSC_STATUS_FAILURE;
        }

        token = strtok(NULL, ",");
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS isSupportedRate(char *inputStr)
{
    char *token;
    bool isRateInvalid = TRUE;
    UINT seqCounter = 0;
    char tmpInputString[128] = {0};

    if ((inputStr == NULL))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    snprintf(tmpInputString, sizeof(tmpInputString), "%s", inputStr);

    token = strtok(tmpInputString, ",");
    while (token != NULL)
    {
        isRateInvalid = TRUE;
        for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiDataTxRateMap); seqCounter++)
        {
            if (AnscEqualString(token, wifiDataTxRateMap[seqCounter].DataTxRateStr, TRUE))
            {
                isRateInvalid = FALSE;
            }
        }

        if (isRateInvalid == TRUE)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid txrate Token : %s\n", __FUNCTION__, token));
            return ANSC_STATUS_FAILURE;
        }

        token = strtok(NULL, ",");
    }
    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS wifiSecSupportedDmlToStr(UINT dmlSecModeSupported, char *str, UINT strSize)
{
    UINT seqCounter = 0;
    UINT strCount = 0, strLoc = 0;
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "In %s\n", __FUNCTION__);
    if (str == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s str is NULL\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiSecMap); seqCounter++)
    {
        if (dmlSecModeSupported & wifiSecMap[seqCounter].cosaSecCfgMethod)
        {
            strCount = snprintf(&str[strLoc], (strSize-strLoc), "%s,", wifiSecMap[seqCounter].wifiSecType);
            strLoc += strCount;
        }
    }
    if (strLoc == 0)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s str is NULL\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    str[strLoc-1] = '\0';
    ccspWifiDbgPrint(CCSP_WIFI_TRACE,"%s  ModeSupported  : %s\n", __FUNCTION__, str);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wifiSecModeDmlToStr(UINT dmlSecModeEnabled, char *str, UINT strSize)
{
    UINT seqCounter = 0;
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "In %s\n", __FUNCTION__);
    if (str == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s str is NULL\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }


    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiSecMap); seqCounter++)
    {
        if (dmlSecModeEnabled == wifiSecMap[seqCounter].cosaSecCfgMethod)
        {
            snprintf(str, strSize, "%s", wifiSecMap[seqCounter].wifiSecType);
            ccspWifiDbgPrint(CCSP_WIFI_TRACE,"%s  ModeEnabled  : %s\n", __FUNCTION__, wifiSecMap[seqCounter].wifiSecType);
            return ANSC_STATUS_SUCCESS;
        }
    }

    CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Security Mode\n", __FUNCTION__));
    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS wifiApIsSecmodeOpenForPrivateAP(UINT vapIndex)
{
    wifi_radio_operationParam_t *wifiRadioOperParam = NULL;
    wifi_vap_info_t *wifiVapInfo = NULL;
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s for vapIndex: %d\n", __FUNCTION__, vapIndex);

    //Check is the Vap is private
    if(isVapPrivate(vapIndex) != TRUE)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s VapIndex %d is not private VAP\n", __FUNCTION__, vapIndex));
        return ANSC_STATUS_FAILURE;
    }

    wifiVapInfo = getVapInfo(vapIndex);
    if (wifiVapInfo == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Unable to get VAP info for vapIndex : %d\n", __FUNCTION__, vapIndex));
        return ANSC_STATUS_FAILURE;
    }

    wifiRadioOperParam = getRadioOperationParam(wifiVapInfo->radio_index);
    if (wifiRadioOperParam == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d not found for wifiRadioOperParam\n", __FUNCTION__, wifiVapInfo->radio_index));
        return ANSC_STATUS_FAILURE;
    }

    //Check for 6Ghz
    if ((wifiRadioOperParam->band == WIFI_FREQUENCY_6_BAND))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d with 6G Band doesnot support WPS: %d\n", __FUNCTION__, wifiVapInfo->radio_index, wifiVapInfo->u.bss_info.security.mode));
        return ANSC_STATUS_FAILURE;
    }

    //Check for open security
    if (wifiVapInfo->u.bss_info.security.mode == wifi_security_mode_none)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Open Security for VapIndex : %d, WPS doesnot support \n", __FUNCTION__, vapIndex));
        return ANSC_STATUS_FAILURE;
    }

    if ((wifiVapInfo->u.bss_info.security.mode == wifi_security_mode_wpa3_personal) || (wifiVapInfo->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d WPS doesnot support WPA3 Mode: %d\n", __FUNCTION__, wifiVapInfo->radio_index, wifiVapInfo->u.bss_info.security.mode));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wifiRadioChannelIsValid(UINT radioIndex, UINT inputChannel)
{
    unsigned int arrayLen = 0;
    unsigned int seqCounter  = 0;
    wifi_radio_capabilities_t *wifiRadioCap = NULL;
    UINT bandArrIndex = 0;
    BOOL isBandFound = FALSE;
    wifi_radio_operationParam_t *wifiRadioOperParam = NULL;
    wifi_radio_operationParam_t l_pcfg;

    //Get the radio capability for further comparision
    wifiRadioCap = getRadioCapability(radioIndex);
    if (wifiRadioCap == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Failed for  unable to get RadioCapability wlanIndex = %d\n", __FUNCTION__, radioIndex));
        return ANSC_STATUS_FAILURE;
    }
    ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s %d for RadioIndex : %d\n", __FUNCTION__, __LINE__, radioIndex);
    //Get the RadioOperation  structure
    wifiRadioOperParam = getRadioOperationParam(radioIndex);
    if (wifiRadioOperParam == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d not found for wifiRadioOperParam\n", __FUNCTION__, radioIndex));
        return ANSC_STATUS_FAILURE;
    }
    memcpy(&l_pcfg, wifiRadioOperParam, sizeof(l_pcfg));
    wifiRadioOperParam = &l_pcfg;

    //Compare the Band from capability and operation
    for (bandArrIndex = 0; bandArrIndex < wifiRadioCap->numSupportedFreqBand; bandArrIndex++)
    {
        if (wifiRadioCap->band[bandArrIndex] == wifiRadioOperParam->band)
        {
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s Band = %d is present at array index of cap : %d \n", __FUNCTION__, wifiRadioOperParam->band, bandArrIndex);
            isBandFound = TRUE;
            break;
        }
    }

    if (isBandFound == FALSE)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Input radioIndex = %d Band=%d is  not found in capability\n", __FUNCTION__, radioIndex, wifiRadioOperParam->band));
        return ANSC_STATUS_FAILURE;
    }

    arrayLen = wifiRadioCap->channel_list[bandArrIndex].num_channels;
    for (seqCounter = 0; seqCounter < arrayLen; seqCounter++)
    {
        if (inputChannel == (UINT)wifiRadioCap->channel_list[bandArrIndex].channels_list[seqCounter])
        {
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s %d For RadioIndex : %d inputChannel : %d is supported\n", __FUNCTION__, __LINE__, radioIndex, inputChannel);
            return ANSC_STATUS_SUCCESS;
        }
    }
    CcspWifiTrace(("RDK_LOG_ERROR, %s Failed for radioIndex : %d for InputChannel : %d\n", __FUNCTION__, radioIndex, inputChannel));
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS operChanBandwidthDmlEnumtoHalEnum(UINT ccspBw, wifi_channelBandwidth_t *halBw)
{
    UINT seqCounter = 0;
    UINT isOperBwInvalid = TRUE;

    if (halBw == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiChanWidthMap); seqCounter++)
    {
        if (ccspBw == (unsigned int) wifiChanWidthMap[seqCounter].cosaWifiChanWidth)
        {
            *halBw = wifiChanWidthMap[seqCounter].halWifiChanWidth;
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s inputBw : %d halbw : %d[%s] ", __FUNCTION__, ccspBw, *halBw, wifiChanWidthMap[seqCounter].wifiChanWidthName);
            isOperBwInvalid = FALSE;
            break;
        }
    }

    if (isOperBwInvalid == TRUE)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Operational Bandwidth: %d\n", __FUNCTION__, ccspBw));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS operChanBandwidthHalEnumtoDmlEnum(wifi_channelBandwidth_t halBw, UINT *ccspBw)
{
    UINT seqCounter = 0;
    UINT isOperBwInvalid = TRUE;

    if (ccspBw == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiChanWidthMap); seqCounter++)
    {
        if ( halBw == wifiChanWidthMap[seqCounter].halWifiChanWidth)
        {
            *ccspBw =  wifiChanWidthMap[seqCounter].cosaWifiChanWidth;
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s inputBw : %d dmlbw : %d[%s] ", __FUNCTION__, halBw, *ccspBw, wifiChanWidthMap[seqCounter].wifiChanWidthName);
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d inputBw: %d dmlbw: %d[%s]\n",
                __func__, __LINE__, halBw, *ccspBw, wifiChanWidthMap[seqCounter].wifiChanWidthName);
            isOperBwInvalid = FALSE;
            break;
        }
    }

    if (isOperBwInvalid == TRUE)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Operational Bandwidth: %d\n", __FUNCTION__, halBw));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

#define REG_DOMAIN_SZ 3
#define ENV_SZ 1

ANSC_STATUS regDomainStrToEnums(char *pRegDomain, wifi_countrycode_type_t *countryCode, wifi_operating_env_t *operatingEnvironment)
{
    UINT seqCounter = 0;
    bool isregDomainInvalid = TRUE;
    char tmp_regDomain[REG_DOMAIN_SZ+1];
    char environment[ENV_SZ+1] = {'I', '\0'};
    unsigned int len = 0;

    if ((pRegDomain == NULL) || (countryCode == NULL) || (operatingEnvironment == NULL))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    len = strlen(pRegDomain);
    if ((len > REG_DOMAIN_SZ) || (len < ENV_SZ)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid country code \n", __func__, __LINE__);
        return ANSC_STATUS_FAILURE;
    }

    memset(tmp_regDomain, 0, sizeof(tmp_regDomain));
    strncpy(tmp_regDomain, pRegDomain, sizeof(tmp_regDomain)-1);
    environment[0] = tmp_regDomain[REG_DOMAIN_SZ-1];
    if (environment[0] == '\0') {
        environment[0] = ' ';
    } else if(environment[0] != 'I' && environment[0] != 'O' && environment[0] != ' ' && environment[0] != 'X') {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Invalid environment \n", __func__, __LINE__);
        return ANSC_STATUS_FAILURE;
    }

    tmp_regDomain[REG_DOMAIN_SZ-1] = '\0';


    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiCountryMapMembers); seqCounter++)
    {
        if (AnscEqualString(tmp_regDomain, wifiCountryMapMembers[seqCounter].countryStr, TRUE))
        {
            *countryCode = wifiCountryMapMembers[seqCounter].countryCode;
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s input : %s Countrycode : %d\n", __FUNCTION__, pRegDomain, *countryCode);
            isregDomainInvalid = FALSE;
            break;
        }
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiEnviromentMap); seqCounter++)
    {
        if (AnscEqualString(environment, wifiEnviromentMap[seqCounter].environment, TRUE))
        {
            *operatingEnvironment = wifiEnviromentMap[seqCounter].operatingEnvironment;
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s input : %s OperatingEnvironment : %d\n", __FUNCTION__, pRegDomain, *operatingEnvironment);
            isregDomainInvalid = FALSE;
            break;
        }
    }

    if (isregDomainInvalid == TRUE)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Regulatory Domain: %s\n", __FUNCTION__, pRegDomain));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS wifiStdStrToEnum(char *pWifiStdStr, wifi_ieee80211Variant_t *p80211VarEnum, ULONG instance_number)
{
    UINT seqCounter = 0;
    bool isWifiStdInvalid = TRUE;
    char *token;
    char tmpInputString[128] = {0};
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

    if ((pWifiStdStr == NULL) || (p80211VarEnum == NULL))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    *p80211VarEnum = 0;
    snprintf(tmpInputString, sizeof(tmpInputString), "%s", pWifiStdStr);

    token = strtok(tmpInputString, ",");
    while (token != NULL)
    {

        isWifiStdInvalid = TRUE;
        for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiStdDmlMap); seqCounter++)
        {
            if ((AnscEqualString("ax", token, TRUE)) && (instance_number == 0)
                && !rfc_pcfg->twoG80211axEnable_rfc)
            {
                CcspWifiTrace(("RDK_LOG_INFO, Radio instanceNumber:%lu Device.WiFi.2G80211axEnable"
                    "is set to FALSE(%d), hence unable to set 'AX' as operating standard\n",
                    instance_number,rfc_pcfg->twoG80211axEnable_rfc));
                isWifiStdInvalid = FALSE;
            }
            else if (AnscEqualString(token, wifiStdDmlMap[seqCounter].wifiStdName, TRUE))
            {
                *p80211VarEnum |= wifiStdDmlMap[seqCounter].halWifiStd;
                ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s input : %s wifiStandard : %d\n", __FUNCTION__, pWifiStdStr, *p80211VarEnum);
                isWifiStdInvalid = FALSE;
            }
        }

        if (isWifiStdInvalid == TRUE)
        {
            CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Wifi Standard : %s\n", __FUNCTION__, pWifiStdStr));
            return ANSC_STATUS_FAILURE;
        }

        token = strtok(NULL, ",");
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS freqBandStrToEnum(char *pFreqBandStr, wifi_freq_bands_t *pFreqBandEnum)
{
    UINT seqCounter = 0;
    bool isBandInvalid = TRUE;

    if ((pFreqBandStr == NULL) || (pFreqBandEnum == NULL))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiFreqBandMap); seqCounter++)
    {
        if (AnscEqualString(pFreqBandStr, wifiFreqBandMap[seqCounter].wifiFreqBandStr, TRUE))
        {
            *pFreqBandEnum = wifiFreqBandMap[seqCounter].halWifiFreqBand;
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s input : %s OperatingFrequencyBand : %d\n", __FUNCTION__, pFreqBandStr, *pFreqBandEnum);
            isBandInvalid = FALSE;
            break;
        }
    }

    if (isBandInvalid == TRUE)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Frequncy Band Token : %s\n", __FUNCTION__, pFreqBandStr));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS guardIntervalDmlEnumtoHalEnum(UINT ccspGiEnum, wifi_guard_interval_t *halGiEnum)
{
    bool isGuardIntervalInvalid = TRUE;
    UINT seqCounter = 0;

    if (halGiEnum == NULL)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiGuardIntervalMap); seqCounter++)
    {
        if (ccspGiEnum == wifiGuardIntervalMap[seqCounter].cosaGuardInterval)
        {
            *halGiEnum = wifiGuardIntervalMap[seqCounter].halGuardInterval;
            isGuardIntervalInvalid = FALSE;
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s Input GuardInterval : %d output GIEnum : %d str : %s\n", __FUNCTION__, ccspGiEnum, *halGiEnum, wifiGuardIntervalMap[seqCounter].wifiGuardIntervalType);
            break;
        }
    }
    if (isGuardIntervalInvalid == TRUE)
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid guard Interval : %d\n", __FUNCTION__, ccspGiEnum));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS guardIntervalHalEnumtoDmlEnum(wifi_guard_interval_t halGiEnum, UINT *ccspGiEnum)
{
    bool isGuardIntervalInvalid = TRUE;
    UINT seqCounter = 0;

    if (ccspGiEnum == NULL) {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid Argument\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiGuardIntervalMap); seqCounter++) {
        if (halGiEnum == wifiGuardIntervalMap[seqCounter].halGuardInterval) {
            *ccspGiEnum = wifiGuardIntervalMap[seqCounter].cosaGuardInterval;
            isGuardIntervalInvalid = FALSE;
            ccspWifiDbgPrint(CCSP_WIFI_TRACE, "%s output GuardInterval : %d Input GIEnum : %d str : %s\n", __FUNCTION__, *ccspGiEnum, halGiEnum, wifiGuardIntervalMap[seqCounter].wifiGuardIntervalType);
            break;
        }
    }
    if (isGuardIntervalInvalid == TRUE) {
        CcspWifiTrace(("RDK_LOG_ERROR, %s Invalid guard Interval : %d\n", __FUNCTION__, halGiEnum));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

void ccspWifiDbgPrint(int level, char *format, ...)
{
    char buff[4096] = {0};
    va_list list;
    static FILE *fpg = NULL;
    
    if (level == CCSP_WIFI_TRACE)
    {
        if ((access("/nvram/ccspWifiTrace", R_OK)) != 0) {
              return;
        }
    } else if (level == CCSP_WIFI_INFO)
    {
        if ((access("/nvram/ccspWifiInfo", R_OK)) != 0) {
              return;
        }
    } else {
          return;
    }
    
    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    if (fpg == NULL) {
          fpg = fopen("/tmp/ccspWifiDbgLog", "a+");
          if (fpg == NULL) {
                return;
          } else {
                fputs(buff, fpg);
          }
    } else {
          fputs(buff, fpg);
    }

    fflush(fpg);
}

void WriteWiFiLog(char *msg)
{
    char LogMsg_arr[512] = {0};
    char *LogMsg = LogMsg_arr;
    char LogLevel[512] = {0};

    if( !msg)
    {
        return;
    }
    /*CID: 144444 :BUFFER_SIZE_WARNING*/
    strncpy(LogLevel, msg, sizeof(LogLevel)-1);
    LogLevel[sizeof(LogLevel)-1] = '\0';
    strtok_r (LogLevel, ",",&LogMsg);
    if( AnscEqualString(LogLevel, "RDK_LOG_ERROR", TRUE))
    {
        CcspTraceError(("%s", LogMsg));
    }
    else if( AnscEqualString(LogLevel, "RDK_LOG_WARN", TRUE))
    {
        CcspTraceWarning(("%s", LogMsg));
    }
    else if( AnscEqualString(LogLevel, "RDK_LOG_NOTICE", TRUE))
    {
        CcspTraceNotice(("%s", LogMsg));
    }
    else if( AnscEqualString(LogLevel, "RDK_LOG_INFO", TRUE))
    {
        CcspTraceInfo(("%s", LogMsg));
    }
    else if( AnscEqualString(LogLevel, "RDK_LOG_DEBUG", TRUE))
    {
        CcspTraceDebug(("%s", LogMsg));
    }
    else if( AnscEqualString(LogLevel, "RDK_LOG_FATAL", TRUE))
    {
        CcspTraceCritical(("%s", LogMsg));
    }
    else
    {
        CcspTraceInfo(("%s", LogMsg));
    }
}

void AssociatedDevice_callback_register()
{
}

INT getSecurityTypeFromString(const char *securityName, wifi_security_modes_t *securityType, COSA_DML_WIFI_SECURITY *cosaSecurityType)
{
    INT rc = -1;
    INT ind = -1;
    UINT i = 0;
    if((securityName == NULL) || (securityType == NULL) || (cosaSecurityType == NULL))
    {
        CcspWifiTrace(("RDK_LOG_ERROR, %s parameter NULL\n", __func__));
        return 0;
    }
    for (i = 0 ; i < ARRAY_SZ(wifiSecMap) ; ++i)
    {
        rc = strcmp_s(securityName, strlen(securityName), wifiSecMap[i].wifiSecType, &ind);
        ERR_CHK(rc);
        if((!rc) && (!ind))
        {
            *securityType = wifiSecMap[i].halSecCfgMethod;
            *cosaSecurityType = wifiSecMap[i].cosaSecCfgMethod;

            return 1;
        }
    }
    return 0;
}

ANSC_STATUS
CosaDmlWiFiGetFactoryResetPsmData
    (
        BOOLEAN *factoryResetFlag
    )
{
    char *strValue = NULL;
    int retPsmGet = CCSP_SUCCESS;

    if (!factoryResetFlag) return ANSC_STATUS_FAILURE;

        printf("%s g_Subsytem = %s\n",__FUNCTION__, g_Subsystem);
        CcspWifiTrace(("RDK_LOG_WARN,WIFI %s \n",__FUNCTION__));
    // Get Non-vol parameters from ARM through PSM
    // PSM may not be available yet on arm so sleep if there is not connection
    int retry = 0;
    /* PSM came around 1sec after the 1st retry from wifi (sleep is 10secs)
     * So, to handle this case,  modified the sleep duration and no of iterations
     * as we can't be looping for a long time for PSM */

    while (retry++ < 10)
    {
        CcspWifiTrace(("RDK_LOG_WARN,WIFI %s :Calling PSM GET to get FactoryReset flag value\n",__FUNCTION__));
        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, FactoryReset, NULL, &strValue);
        if (retPsmGet == CCSP_SUCCESS) {
        printf("%s %s = %s \n",__FUNCTION__, FactoryReset, strValue);
        CcspWifiTrace(("RDK_LOG_WARN,WIFI %s :PSM GET Success %s = %s \n",__FUNCTION__, FactoryReset, strValue));
            *factoryResetFlag = _ansc_atoi(strValue);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);

        } else if (retPsmGet == CCSP_CR_ERR_INVALID_PARAM) {
            *factoryResetFlag = 0;
            printf("%s PSM_Get_Record_Value2 (%s) returned error %d \n",__FUNCTION__, FactoryReset, retPsmGet);
                CcspWifiTrace(("RDK_LOG_WARN,WIFI %s :PSM_Get_Record_Value2 (%s) returned error %d \n",__FUNCTION__, FactoryReset, retPsmGet));
            // Set to FALSE
            PSM_Set_Record_Value2(bus_handle,g_Subsystem, FactoryReset, ccsp_string, "0");
        } else {
            printf("%s PSM_Get_Record_Value2 returned error %d retry in 10 seconds \n",__FUNCTION__, retPsmGet);
                CcspWifiTrace(("RDK_LOG_WARN,WIFI %s :returned error %d retry in 10 seconds\n",__FUNCTION__, retPsmGet));
            AnscSleep(2000);
            continue;
        }
        break;
    }

    if (retPsmGet != CCSP_SUCCESS && retPsmGet != CCSP_CR_ERR_INVALID_PARAM) {
            printf("%s Could not connect to the server error %d\n",__FUNCTION__, retPsmGet);
                        CcspWifiTrace(("RDK_LOG_ERROR,WIFI %s : Could not connect to the server error %d \n",__FUNCTION__, retPsmGet));
            *factoryResetFlag = 0;
            return ANSC_STATUS_FAILURE;
    }
    CcspWifiTrace(("RDK_LOG_WARN,WIFI %s : Returning Success \n",__FUNCTION__));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
GetActiveMsmtStepInsNum(active_msmt_step_t *pStepCfg, ULONG *StepIns)
{
    active_msmt_t *pcfg = (active_msmt_t *) get_dml_blaster();
    if(pcfg== NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d  NULL pointer Get fail\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    int nIndex =0;

    for (nIndex = 0; nIndex < MAX_STEP_COUNT; nIndex++) {
        if ((ANSC_HANDLE)pStepCfg == ((ANSC_HANDLE)&pcfg->Step[nIndex])) {
            *StepIns = nIndex;
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_FAILURE;
}
ANSC_STATUS CosaDmlWiFiClient_ResetActiveMsmtStep (active_msmt_t *pcfg)
{
    INT stepCount = 0;
    if (pcfg == NULL) {
        CcspWifiTrace(("RDK_LOG_WARN, %s-%d Recv Param NULL \n",__FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }
    for (stepCount = 0; stepCount < MAX_STEP_COUNT; stepCount++) {
        pcfg->Step[stepCount].StepId = 0;
        memset(pcfg->Step[stepCount].SrcMac, '\0',MAC_ADDRESS_LENGTH);
        memset(pcfg->Step[stepCount].DestMac, '\0',MAC_ADDRESS_LENGTH);
    }
    return ANSC_STATUS_SUCCESS;
}
ANSC_STATUS
ValidateActiveMsmtPlanID(UCHAR *pPlanId)
{
    CHAR CheckStr[PLAN_ID_LENGTH] = {0};
    if ((strncmp((char*)pPlanId, CheckStr, strlen((char *)pPlanId))) == 0) {
        CcspTraceError(("%s:%d : Plan ID is not configured\n",__func__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

#define PARTNERS_INFO_FILE              "/nvram/partners_defaults.json"
#define BOOTSTRAP_INFO_FILE             "/nvram/bootstrap.json"

static int writeToJson(char *data, char *file)
{
    FILE *fp;
    fp = fopen(file, "w");
    if (fp == NULL)
    {
        CcspTraceWarning(("%s : %d Failed to open file %s\n", __FUNCTION__,__LINE__,file));
        return -1;
    }

    fwrite(data, strlen(data), 1, fp);
    fclose(fp);
    return 0;
}

ANSC_STATUS UpdateJsonParamLegacy
(
 char*                       pKey,
 char*           PartnerId,
 char*           pValue
 )
{
    cJSON *partnerObj = NULL;
    cJSON *json = NULL;
    FILE *fileRead = NULL;
    char * cJsonOut = NULL;
    char* data = NULL;
    int len ;
    int configUpdateStatus = -1;
    fileRead = fopen( PARTNERS_INFO_FILE, "r" );
    if( fileRead == NULL )
    {
        CcspTraceWarning(("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ ));
        return ANSC_STATUS_FAILURE;
    }

    fseek( fileRead, 0, SEEK_END );
    len = ftell( fileRead );
    /*CID: 55623 Argument cannot be negative*/
    if (len < 0) {
        CcspTraceWarning(("%s-%d : FileRead Negative \n", __FUNCTION__, __LINE__));
        fclose( fileRead );
        return ANSC_STATUS_FAILURE;
    }
    fseek( fileRead, 0, SEEK_SET );
    data = ( char* )malloc( sizeof(char) * (len + 1) );
    if (data != NULL)
    {
        memset( data, 0, ( sizeof(char) * (len + 1) ));
        /*CID: 70535 Ignoring number of bytes read*/
        if(1 != fread( data, len, 1, fileRead )) {
            fclose( fileRead );
            return ANSC_STATUS_FAILURE;
        }
        /*CID: 135238 String not null terminated*/
        data[len] ='\0';
    }
    else
    {
        CcspTraceWarning(("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__));
        fclose( fileRead );
        return ANSC_STATUS_FAILURE;
    }
    fclose( fileRead );
    if ( data == NULL )
    {
        CcspTraceWarning(("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    else if ( strlen(data) != 0)
    {
        json = cJSON_Parse( data );
        if( !json )
        {
            CcspTraceWarning((  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__));
            free(data);
            return ANSC_STATUS_FAILURE;
        }
        else
        {
            partnerObj = cJSON_GetObjectItem( json, PartnerId );
            if ( NULL != partnerObj)
            {
                if (NULL != cJSON_GetObjectItem( partnerObj, pKey) )
                {
                    cJSON_ReplaceItemInObject(partnerObj, pKey, cJSON_CreateString(pValue));
                    cJsonOut = cJSON_Print(json);
                    CcspTraceWarning(( "Updated json content is %s\n", cJsonOut));
                    configUpdateStatus = writeToJson(cJsonOut, PARTNERS_INFO_FILE);
                    cJSON_free(cJsonOut);
                    if ( !configUpdateStatus)
                    {
                        CcspTraceWarning(( "Updated Value for %s partner\n",PartnerId));
                        CcspTraceWarning(( "Param:%s - Value:%s\n",pKey,pValue));
                    }
                    else
                    {
                        CcspTraceWarning(( "Failed to update value for %s partner\n",PartnerId));
                        CcspTraceWarning(( "Param:%s\n",pKey));
                        cJSON_Delete(json);
                        return ANSC_STATUS_FAILURE;
                    }
                }
                else
                {
                    CcspTraceWarning(("%s - OBJECT  Value is NULL %s\n", pKey,__FUNCTION__ ));
                    cJSON_Delete(json);
                    return ANSC_STATUS_FAILURE;
                }

            }
            else
            {
                CcspTraceWarning(("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ ));
                cJSON_Delete(json);
                return ANSC_STATUS_FAILURE;
            }
            cJSON_Delete(json);
        }
    }
    else
    {
        CcspTraceWarning(("PARTNERS_INFO_FILE %s is empty\n", PARTNERS_INFO_FILE));
        /*CID: 65542 Resource leak*/
        free(data);
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

char wifiRegionUpdateSource[16];

void FillPartnerIDJournal(cJSON *json, char *partnerID, char *pwifiregion)
{
    cJSON *partnerObj = cJSON_GetObjectItem( json, partnerID );
    if( partnerObj != NULL)
    {
        cJSON *paramObj = cJSON_GetObjectItem(partnerObj, "Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code");
        if (paramObj != NULL)
        {
            char *valuestr = NULL;
            cJSON *paramObjVal = cJSON_GetObjectItem(paramObj, "UpdateSource");
            if (paramObjVal)
                valuestr = paramObjVal->valuestring;
            if (valuestr != NULL)
            {
                snprintf(pwifiregion, 16, "%s", valuestr);
            }
            else
            {
                CcspTraceWarning(("%s UpdateSource is NULL\n", __FUNCTION__));
            }
        }
        else
        {
            CcspTraceWarning(("%s Object is NULL\n", __FUNCTION__));
        }
    }
    else
    {
        CcspTraceWarning(("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ ));
    }
}

void getParamWifiRegionUpdateSource(void)
{
    char *data = NULL;
    cJSON *json = NULL;
    FILE *fileRead = NULL;
    char PartnerID[PARTNER_ID_LEN] = {0};
    int len;
    memset(wifiRegionUpdateSource, 0, 16);

    fileRead = fopen( BOOTSTRAP_INFO_FILE, "r" );
    if( fileRead == NULL )
    {
        CcspTraceWarning(("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ ));
        return;
    }

    fseek( fileRead, 0, SEEK_END );
    len = ftell( fileRead );

    if (len <0)
    {
        CcspTraceWarning(("%s-%d : File size reads negative \n", __FUNCTION__, __LINE__));
        fclose( fileRead );
        return;
    }
    fseek( fileRead, 0, SEEK_SET );
    data = ( char* )malloc( sizeof(char) * (len + 1) );
    if (data != NULL)
    {
        memset( data, 0, ( sizeof(char) * (len + 1) ));
        if(1 != fread( data, len, 1, fileRead ))
        {
            free(data);
            fclose( fileRead );
            return;
        }
        data[len] = '\0';
    }
    else
    {
        CcspTraceWarning(("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__));
        fclose(fileRead);
        return;
    }
    fclose(fileRead);
    if (data == NULL)
    {
        CcspTraceWarning(("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__));
        return;
    }
    else if ( strlen(data) != 0)
    {
        json = cJSON_Parse(data);
        if(!json)
        {
            CcspTraceWarning((  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__));
            free(data);
            return;
        }
        else
        {
            if( CCSP_SUCCESS == getPartnerId(PartnerID) )
            {
                if (PartnerID[0] != '\0')
                {
                    CcspTraceWarning(("%s : Partner = %s \n", __FUNCTION__, PartnerID));
                    FillPartnerIDJournal(json, PartnerID, wifiRegionUpdateSource);
                }
                else
                {
                    CcspTraceWarning(( "Reading Deafult PartnerID Values \n" ));
                    snprintf(PartnerID, sizeof(PartnerID), "%s", "comcast");
                    FillPartnerIDJournal(json, PartnerID, wifiRegionUpdateSource);
                }
            }
            else
            {
                CcspTraceWarning(("Failed to get Partner ID\n"));
            }
            cJSON_Delete(json);
        }
        free(data);
        data=NULL;
    }
    else
    {
        CcspTraceWarning(("BOOTSTRAP_INFO_FILE %s is empty\n", BOOTSTRAP_INFO_FILE));
        free(data);
        data=NULL;
        return;

    }
    return;
}

ANSC_STATUS UpdateJsonParam
(
 char*                       pKey,
 char*                   PartnerId,
 char*                   pValue,
 char*                   pSource,
 char*                   pCurrentTime
 )
{
    cJSON *partnerObj = NULL;
    cJSON *json = NULL;
    FILE *fileRead = NULL;
    char * cJsonOut = NULL;
    char* data = NULL;
    int len ;
    int configUpdateStatus = -1;
    fileRead = fopen( BOOTSTRAP_INFO_FILE, "r" );
    if( fileRead == NULL )
    {
        CcspTraceWarning(("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ ));
        return ANSC_STATUS_FAILURE;
    }
    fseek( fileRead, 0, SEEK_END );
    len = ftell( fileRead );
    /*CID: 56120 Argument cannot be negative*/
    if (len < 0) {
        CcspTraceWarning(("%s-%d : fileRead negative \n", __FUNCTION__, __LINE__));
        fclose( fileRead );
        return ANSC_STATUS_FAILURE;
    }
    fseek( fileRead, 0, SEEK_SET );
    data = ( char* )malloc( sizeof(char) * (len + 1) );
    if (data != NULL)
    {
        memset( data, 0, ( sizeof(char) * (len + 1) ));
        /*CID: 70144 Ignoring number of bytes read*/
        if( 1 != fread( data, len, 1, fileRead )) {
            fclose( fileRead );
            return ANSC_STATUS_FAILURE;
        }
        /*CID: 135285 String not null terminated*/
        data[len] ='\0';
    }
    else
    {
        CcspTraceWarning(("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__));
        fclose( fileRead );
        return ANSC_STATUS_FAILURE;
    }

    fclose( fileRead );
    if ( data == NULL )
    {
        CcspTraceWarning(("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    else if ( strlen(data) != 0)
    {
        json = cJSON_Parse( data );
        if( !json )
        {
            CcspTraceWarning((  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__));
            free(data);
            return ANSC_STATUS_FAILURE;
        }
        else
        {
            partnerObj = cJSON_GetObjectItem( json, PartnerId );
            if ( NULL != partnerObj)
            {
                cJSON *paramObj = cJSON_GetObjectItem( partnerObj, pKey);
                if (NULL != paramObj )
                {
                    cJSON_ReplaceItemInObject(paramObj, "ActiveValue", cJSON_CreateString(pValue));
                    cJSON_ReplaceItemInObject(paramObj, "UpdateTime", cJSON_CreateString(pCurrentTime));
                    cJSON_ReplaceItemInObject(paramObj, "UpdateSource", cJSON_CreateString(pSource));

                    cJsonOut = cJSON_Print(json);
                    CcspTraceWarning(( "Updated json content is %s\n", cJsonOut));
                    configUpdateStatus = writeToJson(cJsonOut, BOOTSTRAP_INFO_FILE);
                    cJSON_free(cJsonOut);
                    if ( !configUpdateStatus)
                    {
                        CcspTraceWarning(( "Bootstrap config update: %s, %s, %s, %s \n", pKey, pValue, PartnerId, pSource));
                    }
                    else
                    {
                        CcspTraceWarning(( "Failed to update value for %s partner\n",PartnerId));
                        CcspTraceWarning(( "Param:%s\n",pKey));
                        cJSON_Delete(json);
                        return ANSC_STATUS_FAILURE;
                    }
                }
                else
                {
                    CcspTraceWarning(("%s - OBJECT  Value is NULL %s\n", pKey,__FUNCTION__ ));
                    cJSON_Delete(json);
                    return ANSC_STATUS_FAILURE;
                }

            }
            else
            {
                CcspTraceWarning(("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ ));
                cJSON_Delete(json);
                return ANSC_STATUS_FAILURE;
            }
            cJSON_Delete(json);
        }
    }
    else
    {
        CcspTraceWarning(("BOOTSTRAP_INFO_FILE %s is empty\n", BOOTSTRAP_INFO_FILE));
        /*CID: 72622 Resource leak*/
        free(data);
        return ANSC_STATUS_FAILURE;
    }

    //Also update in the legacy file /nvram/partners_defaults.json for firmware roll over purposes.
    UpdateJsonParamLegacy(pKey, PartnerId, pValue);
    return ANSC_STATUS_SUCCESS;
}

bool validate_inst_client_mac(char * physAddress)
{

    wifi_util_dbg_print(WIFI_DMCLI, "%s-%d mac is ***%s***\n",__FUNCTION__,__LINE__, physAddress);
    if (physAddress && physAddress[0]) {
        if (strlen(physAddress) != MIN_MAC_LEN)
        {
            wifi_util_dbg_print(WIFI_DMCLI, "%s-%d mac length is not 12\n",__FUNCTION__,__LINE__);
            return FALSE;
        }

        if (!strcmp(physAddress,"000000000000"))
        {
            wifi_util_dbg_print(WIFI_DMCLI, "%s-%d mac is all 0\n",__FUNCTION__,__LINE__);
            return FALSE;
        }

        return TRUE;
    }
    wifi_util_dbg_print(WIFI_DMCLI, "%s-%d mac is NULL\n",__FUNCTION__,__LINE__);
    return FALSE;
}

unsigned long inst_client_reproting_periods[] = {0,1,5,15,30,60,300,900,1800,3600,10800,21600,43200,86400};
bool validate_def_reporting_period(unsigned long period)
{
    unsigned int i;

    for (i=0; i < (ARRAY_SZ(inst_client_reproting_periods)); i++) {
        if (inst_client_reproting_periods[i] == period)
            return TRUE;
    }
    return FALSE;
}

bool dml_wifi_is_instant_measurements_enable()
{
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) get_dml_harvester();
    return pcfg->b_inst_client_enabled;
}

bool get_inst_override_ttl()
{
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) get_dml_harvester();
    return pcfg->u_inst_client_def_override_ttl;
}
bool wifi_factory_reset(bool factory_reset_all_vaps)
{
    wifi_vap_info_t default_vap;
    wifi_vap_info_t *p_vapInfo = NULL;
    rdk_wifi_vap_info_t rdk_default_vap;
    rdk_wifi_vap_info_t *rdk_vap_info;
    acl_entry_t *temp_acl_entry, *acl_entry;
    mac_addr_str_t mac_str;
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    wifi_radio_operationParam_t *wifiRadioOperParam = NULL;
    unsigned int vap_index;
    wifi_radio_operationParam_t rcfg;
    wifi_radio_feature_param_t *wifiRadioFeatParam = NULL;
    wifi_radio_feature_param_t fcfg;

    wifi_util_info_print(WIFI_DMCLI,"Enter %s:%d \n",__func__, __LINE__);
    if (global_wifi_config == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }

    //Reset to all radios params to default
    for (UINT i= 0; i < getNumberRadios(); i++) {
        wifiRadioOperParam = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(i);
        wifiRadioFeatParam = (wifi_radio_feature_param_t *) get_dml_cache_radio_feat_map(i);
        if (wifiRadioOperParam == NULL || wifiRadioFeatParam == NULL) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param and Radio Feat Param for instance_number:%d\n", __FUNCTION__,__LINE__,i);
            return FALSE;
        }
        wifidb_init_radio_config_default(i,&rcfg,&fcfg);

        wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();
        if (wifidb_get_rfc_config(0,rfc_param) != 0) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Error getting RFC config\n",__func__, __LINE__);
        }

        //Update the 2.4Ghz radio AX mode based on the RFC twoG80211axEnable_rfc
        if (WIFI_FREQUENCY_2_4_BAND == rcfg.band) {
            if(rfc_param->twoG80211axEnable_rfc) {
                rcfg.variant = rcfg.variant | WIFI_80211_VARIANT_AX;
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: Updated default config with twoG80211axEnable_rfc\n",__func__, __LINE__);
            }
        }

        //Update DFS RFC for 5GHz radio
        if( (WIFI_FREQUENCY_5_BAND == rcfg.band) || (WIFI_FREQUENCY_5L_BAND == rcfg.band) || (WIFI_FREQUENCY_5H_BAND == rcfg.band) ) {
            rcfg.DfsEnabled = rfc_param->dfs_rfc;
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: Updated default config for DFS RFC %d\n",__func__, __LINE__, rfc_param->dfs_rfc);
        }

        memcpy((unsigned char *)wifiRadioOperParam,(unsigned char *)&rcfg,sizeof(wifi_radio_operationParam_t));
        memcpy((unsigned char *)wifiRadioFeatParam, (unsigned char *)&fcfg, sizeof(wifi_radio_feature_param_t));
        is_radio_config_changed = TRUE;
    }

    remove(WIFI_STUCK_DETECT_FILE_NAME);
    wifi_util_info_print(WIFI_MGR,"%s:%d removed selfHeal wifi stuck file:%s\n", __FUNCTION__,__LINE__, WIFI_STUCK_DETECT_FILE_NAME);

    if (factory_reset_all_vaps) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d remove xhs/lnf flag file:%s\n", __FUNCTION__, __LINE__, WIFI_XHS_LNF_FLAG_FILE_NAME);
        (void)remove(WIFI_XHS_LNF_FLAG_FILE_NAME);
    }

    for (UINT index = 0; index < getTotalNumberVAPs(); index++) {
        vap_index = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, index);

        if (!factory_reset_all_vaps && !isVapPrivate(vap_index))
            continue;

        p_vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(vap_index);
        rdk_vap_info = (rdk_wifi_vap_info_t *)get_dml_cache_rdk_vap_info(vap_index);

        if (p_vapInfo != NULL) {
            hash_map_t** acl_dev_map = (hash_map_t **)get_acl_hash_map(p_vapInfo);

            if ((acl_dev_map != NULL) && (*acl_dev_map)) {
                acl_entry =(acl_entry_t *)hash_map_get_first(*acl_dev_map);
                while (acl_entry != NULL) {
                       to_mac_str(acl_entry->mac,mac_str);
                       wifi_util_dbg_print(WIFI_DMCLI,"Mac address in  acl_entry %s\n",mac_str);
                       acl_entry = hash_map_get_next(*acl_dev_map,acl_entry);
                       temp_acl_entry = hash_map_remove(*acl_dev_map, mac_str);
                       if (temp_acl_entry != NULL) {
                           free(temp_acl_entry);
                       }
                }
            }

            if ((acl_dev_map != NULL) && (*acl_dev_map)) {
                hash_map_destroy(*acl_dev_map);
                *acl_dev_map = NULL;
            }

            wifidb_init_vap_config_default(vap_index,&default_vap,&rdk_default_vap);
            wifidb_init_interworking_config_default(vap_index,&default_vap.u.bss_info.interworking);
            memcpy((unsigned char *)p_vapInfo,(unsigned char *)&default_vap,sizeof(wifi_vap_info_t));
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if(rdk_default_vap.exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap_index != 2 && vap_index != 3) {
                    wifi_util_error_print(WIFI_DMCLI,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
                    rdk_default_vap.exists = true;
                }
#else
                wifi_util_error_print(WIFI_DMCLI,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
                rdk_default_vap.exists = true;
#endif /*_SR213_PRODUCT_REQ_*/
            }
#endif /*!defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)*/
            rdk_vap_info->exists = rdk_default_vap.exists;
            set_dml_cache_vap_config_changed(vap_index);
        }
    }

    if (push_radio_dml_cache_to_one_wifidb() == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Failed in setting Radios to default\n",__func__, __LINE__);
        return FALSE;
    }

    wifi_util_info_print(WIFI_DMCLI,"%s:%d RadioSettings are set to default \n",__func__, __LINE__);

    if (push_acl_list_dml_cache_to_one_wifidb(p_vapInfo) != RETURN_OK) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d MacFilter deletion  falied \n",__func__, __LINE__);
        return FALSE;
    }

    create_onewifi_factory_reset_flag();
    wifi_util_info_print(WIFI_MGR,"%s FactoryReset is done and preferPprivate=%d \n",__func__, global_wifi_config->global_parameters.prefer_private);
    if (global_wifi_config->global_parameters.prefer_private) {
        global_wifi_config->global_parameters.prefer_private = false;
        push_global_config_dml_cache_to_one_wifidb();
        push_prefer_private_ctrl_queue(false);
    }

    if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR)
    {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d ApplyAccessPointSettings falied \n",__func__, __LINE__);
        return FALSE;
    }
    wifi_util_info_print(WIFI_DMCLI,"Exit %s:%d \n",__func__, __LINE__);
    return TRUE;
}
