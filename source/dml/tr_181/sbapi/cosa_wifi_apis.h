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

    module: cosa_nat_apis.h

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


#ifndef  _COSA_WIFI_APIS_H
#define  _COSA_WIFI_APIS_H

#include "cosa_apis.h"
#include "ccsp_base_api.h"
#include "wifi_hal.h"
#include "wifi_util.h"

#ifdef WIFI_HAL_VERSION_3

#define CCSP_WIFI_TRACE 1
#define CCSP_WIFI_INFO  2

#endif

//#include "secure_wrapper.h"


#ifndef ULLONG
#define ULLONG unsigned long long
#endif

#define MAX_NUM_PRIVATE_VAP MAX_NUM_RADIOS
#define SAE_PASSPHRASE_MIN_LENGTH 8
#define SAE_PASSPHRASE_MAX_LENGTH 64
#define  COSA_DML_WIFI_MAX_MAC_FILTER_NUM           50
#define COSA_DML_WIFI_MAX_SSID_NAME_LEN               33
#define WIFI_INDEX_MAX MAX_VAP

extern char wifiRegionUpdateSource[16];

typedef  enum
_COSA_DML_WIFI_SECURITY
{
    COSA_DML_WIFI_SECURITY_None                            = 0x00000001,
    COSA_DML_WIFI_SECURITY_WEP_64                          = 0x00000002,
    COSA_DML_WIFI_SECURITY_WEP_128                         = 0x00000004,
    COSA_DML_WIFI_SECURITY_WPA_Personal                    = 0x00000008,
    COSA_DML_WIFI_SECURITY_WPA2_Personal                   = 0x00000010,
    COSA_DML_WIFI_SECURITY_WPA_WPA2_Personal               = 0x00000020,
    COSA_DML_WIFI_SECURITY_WPA_Enterprise                  = 0x00000040,
    COSA_DML_WIFI_SECURITY_WPA2_Enterprise                 = 0x00000080,
    COSA_DML_WIFI_SECURITY_WPA_WPA2_Enterprise             = 0x00000100,
    COSA_DML_WIFI_SECURITY_WPA3_Personal                   = 0x00000200,
    COSA_DML_WIFI_SECURITY_WPA3_Personal_Transition        = 0x00000400,
    COSA_DML_WIFI_SECURITY_WPA3_Enterprise                 = 0x00000800,
    COSA_DML_WIFI_SECURITY_Enhanced_Open                   = 0x00001000
}
COSA_DML_WIFI_SECURITY, *PCOSA_DML_WIFI_SECURITY;

typedef  enum
_COSA_DML_WIFI_FREQ_BAND
{
    COSA_DML_WIFI_FREQ_BAND_2_4G        = 0x1,
    COSA_DML_WIFI_FREQ_BAND_5G          = 0x2,
    COSA_DML_WIFI_FREQ_BAND_5G_L        = 0x4,
    COSA_DML_WIFI_FREQ_BAND_5G_H        = 0x8,
    COSA_DML_WIFI_FREQ_BAND_6G          = 0x10,
    COSA_DML_WIFI_FREQ_BAND_60          = 0x20
}
COSA_DML_WIFI_FREQ_BAND, *PCOSA_DML_WIFI_FREQ_BAND;

typedef  enum
_COSA_DML_WIFI_AP_SEC_ENCRYPTION
{
    COSA_DML_WIFI_AP_SEC_TKIP    = 1,
    COSA_DML_WIFI_AP_SEC_AES,
    COSA_DML_WIFI_AP_SEC_AES_TKIP,
}
COSA_DML_WIFI_AP_SEC_ENCRYPTION, *PCOSA_DML_WIFI_AP_SEC_ENCRYPTION;

typedef  enum
_COSA_DML_WIFI_CHAN_BW
{

    COSA_DML_WIFI_CHAN_BW_AUTO          = 0,
    COSA_DML_WIFI_CHAN_BW_20M,
    COSA_DML_WIFI_CHAN_BW_40M,
    COSA_DML_WIFI_CHAN_BW_80M,
    COSA_DML_WIFI_CHAN_BW_160M,
    COSA_DML_WIFI_CHAN_BW_80_80M,
    COSA_DML_WIFI_CHAN_BW_320M
}
COSA_DML_WIFI_CHAN_BW, *PCOSA_DML_WIFI_CHAN_BW;

typedef  enum
_COSA_DML_WIFI_GUARD_INTVL
{
    COSA_DML_WIFI_GUARD_INTVL_400ns     = 1,
    COSA_DML_WIFI_GUARD_INTVL_800ns,
    COSA_DML_WIFI_GUARD_INTVL_Auto,
    COSA_DML_WIFI_GUARD_INTVL_1600ns,
    COSA_DML_WIFI_GUARD_INTVL_3200ns
}
COSA_DML_WIFI_GUARD_INTVL, *PCOSA_DML_WIFI_GUARD_INTVL;

typedef  enum
_COSA_DML_WIFI_STD
{
    COSA_DML_WIFI_STD_a             = 1,
    COSA_DML_WIFI_STD_b             = 2,
    COSA_DML_WIFI_STD_g             = 4,
    COSA_DML_WIFI_STD_n             = 8,
    COSA_DML_WIFI_STD_ac            = 16,
    COSA_DML_WIFI_STD_ax            = 32,
    COSA_DML_WIFI_STD_h             = 64,
    COSA_DML_WIFI_STD_ad            = 128,
    COSA_DML_WIFI_STD_be            = 256
}
COSA_DML_WIFI_STD, *PCOSA_DML_WIFI_STD;

struct wifiChanWidthCosaHalMap
{
    wifi_channelBandwidth_t halWifiChanWidth;
    COSA_DML_WIFI_CHAN_BW  cosaWifiChanWidth;
    char wifiChanWidthName[16];
};

struct wifiSecEncrCosaHalMap
{
    wifi_encryption_method_t halSecEncrMethod;
    COSA_DML_WIFI_AP_SEC_ENCRYPTION cosaSecEncrMethod;
    char wifiSecEncrType[16];
};

struct wifiSecCosaHalMap
{
    wifi_security_modes_t halSecCfgMethod;
    COSA_DML_WIFI_SECURITY cosaSecCfgMethod;
    char wifiSecType[32];
};

struct wifiFreqBandHalMap
{
    wifi_freq_bands_t halWifiFreqBand;
    COSA_DML_WIFI_FREQ_BAND cosaWifiFreqBand;
    char wifiFreqBandStr[16];
};

struct wifiSecMfpCosaHalMap
{
    wifi_mfp_cfg_t halSecMFP;
    char wifiSecMFP[32];
};

struct wifiGuardIntervalMap
{
    wifi_guard_interval_t halGuardInterval;
    COSA_DML_WIFI_GUARD_INTVL cosaGuardInterval;
    char wifiGuardIntervalType[8];
};

struct wifiStdCosaHalMap
{
    wifi_ieee80211Variant_t halWifiStd;
    COSA_DML_WIFI_STD  cosaWifiStd;
    char wifiStdName[4];
};

/**********************************************************************
                FUNCTION PROTOTYPES
**********************************************************************/

void
CosaDmlWiFiGetEnableRadiusGreylist
    (
	BOOL *value
    );

ANSC_STATUS
CosaDmlWiFiSetEnableRadiusGreylist
   (
	BOOL value
   );

ANSC_STATUS CosaDmlWiFiGetForceDisableWiFiRadio(BOOLEAN *pbValue);

void CosaWiFiDmlGetWPA3TransitionRFC (BOOL *WPA3_RFC);

ANSC_STATUS
CosaDmlWiFi_EnableTelnet
    (
	BOOL			    bEnabled
    );

ANSC_STATUS
CosaDmlWiFi_setWebConfig(char *webconfstr, int size,uint8_t ssid);

ANSC_STATUS
CosaDmlWiFi_GetGoodRssiThresholdValue( int  *piRssiThresholdValue );

ANSC_STATUS
CosaDmlWiFi_GetAssocCountThresholdValue( int  *piAssocCountThresholdValue );

ANSC_STATUS
CosaDmlWiFi_GetAssocMonitorDurationValue( int  *piAssocMonitorDurationValue );

ANSC_STATUS
CosaDmlWiFi_GetAssocGateTimeValue( int  *piAssocGateTimeValue );

ANSC_STATUS
CosaDmlWiFi_GetRapidReconnectThresholdValue(ULONG vAPIndex, int	*rapidReconnThresholdValue );

ANSC_STATUS
CosaDmlWiFi_GetRapidReconnectCountEnable(ULONG vAPIndex, BOOLEAN *pbReconnectCountEnable, BOOLEAN usePersistent );

ANSC_STATUS
CosaDmlWiFi_GetApMFPConfigValue( ULONG vAPIndex, char *pMFPConfig );

ANSC_STATUS
CosaDmlWiFi_GetFeatureMFPConfigValue( BOOLEAN *pbFeatureMFPConfig );

struct wifiDataTxRateHalMap
{
    wifi_bitrate_t  DataTxRateEnum;
    char DataTxRateStr[8];
};


#define CCSP_WIFI_TRACE 1
#define CCSP_WIFI_INFO  2

void ccspWifiDbgPrint(int level, char *format, ...);
ANSC_STATUS txRateStrToUint(char *inputStr, UINT *pTxRate);
ANSC_STATUS freqBandStrToEnum(char *pFreqBandStr, wifi_freq_bands_t *pFreqBandEnum);
ANSC_STATUS wifiStdStrToEnum(char *pWifiStdStr, wifi_ieee80211Variant_t *p80211VarEnum, ULONG instance_num);
ANSC_STATUS regDomainStrToEnum(char *pRegDomain, wifi_countrycode_type_t *countryCode, wifi_operating_env_t *operatingEnvironment);
ANSC_STATUS guardIntervalDmlEnumtoHalEnum(UINT ccspGiEnum, wifi_guard_interval_t *halGiEnum);
ANSC_STATUS operChanBandwidthDmlEnumtoHalEnum(UINT ccspBw, wifi_channelBandwidth_t *halBw);
INT getSecurityTypeFromString(const char *securityName, wifi_security_modes_t *securityType, COSA_DML_WIFI_SECURITY *cosaSecurityType);

void WriteWiFiLog(char *);
void AssociatedDevice_callback_register();
#endif
