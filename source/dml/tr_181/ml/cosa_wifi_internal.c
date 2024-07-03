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
#include "wifi_ctrl.h"
#include "wifi_util.h"
#include "../../../stubs/wifi_stubs.h"
#include "dml_onewifi_api.h"
#include "ssp_loop.h"

static char *ApMFPConfig         = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.Security.MFPConfig";
static char *CTSProtection      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.CTSProtection";
static char *BeaconInterval     = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.BeaconInterval";
static char *DTIMInterval       = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.DTIMInterval";
static char *FragThreshold      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.FragThreshold";
static char *RTSThreshold       = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.RTSThreshold";
static char *ObssCoex           = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.ObssCoex";
static char *STBCEnable         = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.STBCEnable";
static char *GuardInterval      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.GuardInterval";
static char *GreenField         = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.GreenField";
static char *TransmitPower      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.TransmitPower";
static char *UserControl        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.UserControl";
static char *AdminControl       = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.AdminControl";
static char *MeasuringRateRd        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.Stats.X_COMCAST-COM_RadioStatisticsMeasuringRate";
static char *MeasuringIntervalRd = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.%d.Stats.X_COMCAST-COM_RadioStatisticsMeasuringInterval";
static char *SetChanUtilThreshold ="eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.%d.SetChanUtilThreshold";
static char *SetChanUtilSelfHealEnable ="eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.%d.ChanUtilSelfHealEnable";
static char *WmmEnable          = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.WmmEnable";
static char *UAPSDEnable        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.UAPSDEnable";
static char *WmmNoAck           = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.WmmNoAck";
static char *BssMaxNumSta       = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.BssMaxNumSta";
static char *MacFilterMode      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterMode";
static char *ApIsolationEnable    = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.ApIsolationEnable";
static char *BSSTransitionActivated    = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.BSSTransitionActivated";
static char *BssHotSpot        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.HotSpot";
static char *WpsPushButton = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.WpsPushButton";
static char *RapidReconnThreshold        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.RapidReconnThreshold";
static char *RapidReconnCountEnable      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.RapidReconnCountEnable";
static char *vAPStatsEnable = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.vAPStatsEnable";
static char *NeighborReportActivated     = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_NeighborReportActivated";
static char *WiFivAPStatsFeatureEnable = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.vAPStatsEnable";
static char *NotifyWiFiChanges = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges" ;
static char *DiagnosticEnable = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.NeighbouringDiagnosticEnable" ;
static char *GoodRssiThreshold   = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_GoodRssiThreshold";
static char *AssocCountThreshold = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_AssocCountThreshold";
static char *AssocMonitorDuration = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_AssocMonitorDuration";
static char *AssocGateTime = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_AssocGateTime";
static char *RapidReconnectIndicationEnable     = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_RapidReconnectIndicationEnable";
static char *FeatureMFPConfig    = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.FeatureMFPConfig";
static char *WiFiTxOverflowSelfheal = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.TxOverflowSelfheal";
static char *WiFiForceDisableWiFiRadio = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDK-CENTRAL_COM_ForceDisable";
static char *WiFiForceDisableRadioStatus = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDK-CENTRAL_COM_ForceDisable_RadioStatus";
static char *ValidateSSIDName        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.ValidateSSIDName";
#define TR181_WIFIREGION_Code    "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code"
static char *MacFilterDevice = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterDevice.%d";
static char *MacFilter = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilter.%d";
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
static char *Tscan = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelTscan";
static char *Nscan = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelNscan";
static char *Tidle = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelTidle";
#endif //FEATURE_OFF_CHANNEL_SCAN_5G



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

char* PSM_Get_Record_Status(char *recName, char *strValue)
{
    int retry = 0;
    int retPsmGet = CCSP_SUCCESS;
    while(retry++ < 2) {
        retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, recName, NULL, &strValue);
        if (retPsmGet == CCSP_SUCCESS) {
            wifi_util_dbg_print(WIFI_PSM,"%s:%d retPsmGet success for %s and strValue is %s\n", __FUNCTION__,__LINE__, recName, strValue);
            return strValue;
        } else if (retPsmGet == CCSP_CR_ERR_INVALID_PARAM) {
            wifi_util_dbg_print(WIFI_PSM,"%s:%d PSM_Get_Record_Value2 (%s) returned error %d \n",__FUNCTION__,__LINE__,recName,retPsmGet);
            return NULL;
        } else {
            wifi_util_dbg_print(WIFI_PSM,"%s:%d PSM_Get_Record_Value2 param (%s) returned error %d retry in 10 seconds \n",__FUNCTION__,__LINE__,recName,retPsmGet);
            continue;
        }
    }
    return NULL;
}

void init_mac_filter_hash_map(void)
{
    hash_map_t **psm_mac_entry;
    unsigned int l_index = 0;
    unsigned int vap_index;

    for (l_index = 0; l_index < getTotalNumberVAPs(); l_index++) {
        vap_index = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, l_index);
        psm_mac_entry = get_mac_psm_map(vap_index);
        *psm_mac_entry = hash_map_create();
    }
}

void psm_get_mac_list_entry(hash_map_t *psm_mac_map, unsigned int instance_number, unsigned int total_entry, unsigned int *data_index)
{
    char recName[256] = {0};
    char strValue[256] = {0};
    char *str = NULL;
    unsigned int index = 0;
    wifi_mac_psm_param_t *temp_psm_mac_param;

    wifi_util_dbg_print(WIFI_PSM,"%s:%d mac total entry:%d\r\n", __func__, __LINE__, total_entry);
    while (total_entry > 0) {
        index = data_index[total_entry - 1];

        temp_psm_mac_param = malloc(sizeof(wifi_mac_psm_param_t));
        if (temp_psm_mac_param == NULL) {
            wifi_util_dbg_print(WIFI_PSM,"%s:%d malloc failure mac total entry:%d\r\n", __func__, __LINE__, total_entry);
            continue;
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), MacFilterDevice, instance_number, index);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            strcpy(temp_psm_mac_param->device_name, str);
            wifi_util_dbg_print(WIFI_PSM,"psm get device_name is %s\r\n", str);
        } else {
            wifi_util_dbg_print(WIFI_PSM,"[Failure] psm record_name: %s\n", recName);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), MacFilter, instance_number, index);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            strcpy(temp_psm_mac_param->mac, str);
            str_tolower(temp_psm_mac_param->mac);
            temp_psm_mac_param->data_index = index;
            wifi_util_dbg_print(WIFI_PSM,"psm get mac is %s\n", str);
            hash_map_put(psm_mac_map, strdup(temp_psm_mac_param->mac), temp_psm_mac_param);
        } else {
            free(temp_psm_mac_param);
            wifi_util_dbg_print(WIFI_PSM,"[Failure] psm record_name: %s\n", recName);
        }
        total_entry--;
    }

}

void CosaDmlWiFiGetFromPSM(void)
{
    char recName[256] = {0};
    char strValue[256] = {0};
    char *str = NULL;
    unsigned int mac_index_list[128];
    unsigned int total_mac_list;
    wifi_radio_psm_param_t *psm_radio_param;
    wifi_radio_feat_psm_param_t *psm_radio_feat_param = NULL;
    wifi_vap_psm_param_t *psm_vap_param;
    wifi_global_psm_param_t *psm_global_param;
    hash_map_t *psm_mac_map;
    wifi_radio_operationParam_t radio_cfg;
    wifi_radio_feature_param_t radio_feat_cfg;
    wifi_vap_info_t vap_config;
    rdk_wifi_vap_info_t rdk_vap_config;
    wifi_front_haul_bss_t *bss_cfg;
    wifi_global_param_t global_cfg;
    UINT vap_index;

    init_mac_filter_hash_map();

    for (unsigned int instance_number = 1; instance_number <= getNumberRadios(); instance_number++) {
        memset(&radio_cfg, 0, sizeof(radio_cfg));
        memset(&radio_feat_cfg, 0, sizeof(radio_feat_cfg));
        wifidb_init_radio_config_default((instance_number - 1), &radio_cfg, &radio_feat_cfg);
        psm_radio_param = get_radio_psm_obj((instance_number - 1));
        if (psm_radio_param == NULL) {
            wifi_util_error_print(WIFI_PSM,"%s:%d psm radio param NULL radio_index:%d\r\n", __func__, __LINE__, (instance_number - 1));
            return;
        }
        psm_radio_feat_param = get_radio_feat_psm_obj(instance_number - 1);
        if (psm_radio_feat_param == NULL) {
            wifi_util_error_print(WIFI_PSM,"%s:%d psm radio feature param NULL radio_index:%d\r\n", __func__, __LINE__, (instance_number - 1));
            return;
        }
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
        if (is_radio_band_5G(radio_cfg.band)) {
            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), Tscan, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_radio_feat_param->Tscan = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"psm_radio_feat_param->Tscan is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_feat_param->Tscan, str, _ansc_atoi(str));
            } else {
                psm_radio_feat_param->Tscan = radio_feat_cfg.OffChanTscanInMsec;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d psm_radio_feat_param->Tscan: %d\r\n", __func__, __LINE__, radio_feat_cfg.OffChanTscanInMsec, psm_radio_feat_param->Tscan);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), Nscan, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_radio_feat_param->Nscan = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"psm_radio_feat_param->Nscan is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_feat_param->Nscan, str, _ansc_atoi(str));
            } else {
                psm_radio_feat_param->Nscan = radio_feat_cfg.OffChanNscanInSec;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d psm_radio_feat_param->Nscan: %d\r\n", __func__, __LINE__, radio_feat_cfg.OffChanNscanInSec, psm_radio_feat_param->Nscan);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), Tidle, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_radio_feat_param->Tidle = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"psm_radio_feat_param->Tidle is %d and str is %s and _ansc_atoi(str) is %d\n",psm_radio_feat_param->Tidle, str, _ansc_atoi(str));
            } else {
                psm_radio_feat_param->Tidle = radio_feat_cfg.OffChanTidleInSec;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d psm_radio_feat_param->Tidle: %d\r\n", __func__, __LINE__, radio_feat_cfg.OffChanTidleInSec, psm_radio_feat_param->Tidle);
            }
        }
#endif //FEATURE_OFF_CHANNEL_SCAN_5G

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), CTSProtection, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->cts_protection = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"psm_radio_param->cts_protection is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->cts_protection, str, _ansc_atoi(str));
        } else {
            psm_radio_param->cts_protection = radio_cfg.ctsProtection;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->cts_protection: %d\r\n", __func__, __LINE__, radio_cfg.ctsProtection, psm_radio_param->cts_protection);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), BeaconInterval, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->beacon_interval = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->beacon_interval is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->beacon_interval, str, _ansc_atoi(str));
        } else {
            psm_radio_param->beacon_interval = radio_cfg.beaconInterval;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d configure value: %d\r\n", __func__, __LINE__, radio_cfg.beaconInterval, psm_radio_param->beacon_interval);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), DTIMInterval, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->dtim_period = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->dtim_period is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->dtim_period, str, _ansc_atoi(str));
        } else {
            psm_radio_param->dtim_period = radio_cfg.dtimPeriod;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->dtimPeriod: %d\r\n", __func__, __LINE__, radio_cfg.dtimPeriod, psm_radio_param->dtim_period);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), FragThreshold, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->fragmentation_threshold = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->fragmentation_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->fragmentation_threshold, str, _ansc_atoi(str));
        } else {
            psm_radio_param->fragmentation_threshold = radio_cfg.fragmentationThreshold;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->fragmentationThreshold: %d\r\n", __func__, __LINE__, radio_cfg.fragmentationThreshold, psm_radio_param->fragmentation_threshold);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), RTSThreshold, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->rts_threshold = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->rts_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->rts_threshold, str, _ansc_atoi(str));
        } else {
            psm_radio_param->rts_threshold = radio_cfg.rtsThreshold;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->rtsThreshold: %d\r\n", __func__, __LINE__, radio_cfg.rtsThreshold, psm_radio_param->rts_threshold);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), ObssCoex, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->obss_coex = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->obss_coex is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->obss_coex, str, _ansc_atoi(str));
        } else {
            psm_radio_param->obss_coex = radio_cfg.obssCoex;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->obssCoex: %d\r\n", __func__, __LINE__, radio_cfg.obssCoex, psm_radio_param->obss_coex);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), STBCEnable, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->stbc_enable = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->stbc_enable is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->stbc_enable, str, _ansc_atoi(str));
        } else {
            psm_radio_param->stbc_enable = radio_cfg.stbcEnable;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->stbcEnable: %d\r\n", __func__, __LINE__, radio_cfg.stbcEnable, psm_radio_param->stbc_enable);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), GuardInterval, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->guard_interval = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->guard_interval is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->guard_interval, str, _ansc_atoi(str));
        } else {
            psm_radio_param->guard_interval = radio_cfg.guardInterval;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->guardInterval: %d\r\n", __func__, __LINE__, radio_cfg.guardInterval, psm_radio_param->guard_interval);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), GreenField, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->greenfield_enable = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->greenfield_enable is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->greenfield_enable, str, _ansc_atoi(str));
        } else {
            psm_radio_param->greenfield_enable = radio_cfg.greenFieldEnable;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->greenFieldEnable: %d\r\n", __func__, __LINE__, radio_cfg.greenFieldEnable, psm_radio_param->greenfield_enable);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), TransmitPower, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->transmit_power = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->transmit_power is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->transmit_power, str, _ansc_atoi(str));
        } else {
            psm_radio_param->transmit_power = radio_cfg.transmitPower;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->transmitPower: %d\r\n", __func__, __LINE__, radio_cfg.transmitPower, psm_radio_param->transmit_power);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), UserControl, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->user_control = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->user_control is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->user_control, str, _ansc_atoi(str));
        } else {
            psm_radio_param->user_control = radio_cfg.userControl;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->userControl: %d\r\n", __func__, __LINE__, radio_cfg.userControl, psm_radio_param->user_control);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), AdminControl, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->admin_control = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->admin_control is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->admin_control, str, _ansc_atoi(str));
        } else {
            psm_radio_param->admin_control = radio_cfg.adminControl;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d cfg->adminControl: %d\r\n", __func__, __LINE__, radio_cfg.adminControl, psm_radio_param->admin_control);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), MeasuringRateRd, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->radio_stats_measuring_rate = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->radio_stats_measuring_rate is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->radio_stats_measuring_rate, str, _ansc_atoi(str));
        } else {
            psm_radio_param->radio_stats_measuring_rate = radio_cfg.radioStatsMeasuringRate;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d radioStatsMeasuringRate: %d\r\n", __func__, __LINE__, radio_cfg.radioStatsMeasuringRate, psm_radio_param->radio_stats_measuring_rate);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), MeasuringIntervalRd, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->radio_stats_measuring_interval = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->radio_stats_measuring_interval is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->radio_stats_measuring_interval, str, _ansc_atoi(str));
        } else {
            psm_radio_param->radio_stats_measuring_interval = radio_cfg.radioStatsMeasuringInterval;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d radioStatsMeasuringInterval: %d\r\n", __func__, __LINE__, radio_cfg.radioStatsMeasuringInterval, psm_radio_param->radio_stats_measuring_interval);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), SetChanUtilThreshold, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->chan_util_threshold = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->chan_util_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->chan_util_threshold, str, _ansc_atoi(str));
        } else {
            psm_radio_param->chan_util_threshold = radio_cfg.chanUtilThreshold;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d chanUtilThreshold: %d\r\n", __func__, __LINE__, radio_cfg.chanUtilThreshold, psm_radio_param->chan_util_threshold);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), SetChanUtilSelfHealEnable, instance_number);
        str = PSM_Get_Record_Status(recName, strValue);
        if (str != NULL) {
            psm_radio_param->chan_util_selfheal_enable = _ansc_atoi(str);
            wifi_util_dbg_print(WIFI_PSM,"cfg->chan_util_selfheal_enable is %d and str is %s and _ansc_atoi(str) is %d\n", psm_radio_param->chan_util_selfheal_enable, str, _ansc_atoi(str));
        } else {
            psm_radio_param->chan_util_selfheal_enable = radio_cfg.chanUtilSelfHealEnable;
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: Set default value:%d chanUtilSelfHealEnable: %d\r\n", __func__, __LINE__, radio_cfg.chanUtilSelfHealEnable, psm_radio_param->chan_util_selfheal_enable);
        }
       }

       for (unsigned int vap_array_index = 0; vap_array_index < getTotalNumberVAPs(); vap_array_index++) {
            unsigned int instance_number;

            vap_index = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, vap_array_index);
            instance_number = vap_index + 1;
            memset(&vap_config, 0, sizeof(vap_config));
            wifidb_init_vap_config_default(vap_index, &vap_config, &rdk_vap_config);

            if (isVapSTAMesh(vap_index)) {
                continue;
            }

            bss_cfg = &vap_config.u.bss_info;
            psm_vap_param = get_vap_psm_obj(vap_index);
            if (psm_vap_param == NULL) {
                wifi_util_dbg_print(WIFI_PSM,"%s:%d psm vap param NULL vap_index:%d\r\n", __func__, __LINE__, (instance_number - 1));
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), WmmEnable, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->wmm_enabled = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->wmm_enabled is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->wmm_enabled, str, _ansc_atoi(str));
            } else {
                psm_vap_param->wmm_enabled = bss_cfg->wmm_enabled;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->wmm_enabled, psm_vap_param->wmm_enabled);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), UAPSDEnable, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->uapsd_enabled = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->uapsd_enabled is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->uapsd_enabled, str, _ansc_atoi(str));
            } else {
                psm_vap_param->wmm_enabled = bss_cfg->UAPSDEnabled;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->UAPSDEnabled, psm_vap_param->uapsd_enabled);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), vAPStatsEnable, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                convert_ascii_string_to_bool(str, &psm_vap_param->vap_stats_enable);
                wifi_util_dbg_print(WIFI_PSM,"cfg->vap_stats_enable is %d and str is %s\n", psm_vap_param->vap_stats_enable, str);
            } else {
                psm_vap_param->vap_stats_enable = bss_cfg->vapStatsEnable;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->vapStatsEnable, psm_vap_param->vap_stats_enable);
           }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), WmmNoAck, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->wmm_noack = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->wmm_noack is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->wmm_noack, str, _ansc_atoi(str));
            } else {
                psm_vap_param->wmm_noack = bss_cfg->wmmNoAck;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->wmmNoAck, psm_vap_param->wmm_noack);
           }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), BssMaxNumSta, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->bss_max_sta = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->bss_max_sta is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->bss_max_sta, str, _ansc_atoi(str));
            } else {
                psm_vap_param->bss_max_sta = bss_cfg->bssMaxSta;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->bssMaxSta, psm_vap_param->bss_max_sta);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), MacFilterMode, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                unsigned int mf_mode = _ansc_atoi(str);
                if (mf_mode == 0) {
                    psm_vap_param->mac_filter_enable = false;
                    psm_vap_param->mac_filter_mode  = wifi_mac_filter_mode_black_list;
                } else if(mf_mode == 1) {
                    psm_vap_param->mac_filter_enable = true;
                    psm_vap_param->mac_filter_mode  = wifi_mac_filter_mode_white_list;
                } else if(mf_mode == 2) {
                    psm_vap_param->mac_filter_enable = true;
                    psm_vap_param->mac_filter_mode  = wifi_mac_filter_mode_black_list;
                }
                wifi_util_dbg_print(WIFI_PSM,"cfg->mac_filter_mode is %d and str is %s and atoi(str) is %d\n", psm_vap_param->mac_filter_mode, str, _ansc_atoi(str));
            } else {
                psm_vap_param->mac_filter_mode = bss_cfg->mac_filter_mode;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->mac_filter_mode, psm_vap_param->mac_filter_mode);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), ApIsolationEnable, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->isolation_enabled = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->isolation_enabled is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->isolation_enabled, str, _ansc_atoi(str));
            } else {
                psm_vap_param->isolation_enabled = bss_cfg->isolation;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->isolation, psm_vap_param->isolation_enabled);
           }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), BSSTransitionActivated, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                convert_ascii_string_to_bool(str, &psm_vap_param->bss_transition_activated);
                wifi_util_dbg_print(WIFI_PSM,"cfg->bss_transition_activated is %d and str is %s\n", psm_vap_param->bss_transition_activated, str);
            } else {
                psm_vap_param->bss_transition_activated = bss_cfg->bssTransitionActivated;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->bssTransitionActivated, psm_vap_param->bss_transition_activated);
           }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), BssHotSpot, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->bss_hotspot = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->bss_hotspot is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->bss_hotspot, str, _ansc_atoi(str));
            } else {
                psm_vap_param->bss_hotspot = bss_cfg->bssHotspot;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->bssHotspot, psm_vap_param->bss_hotspot);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), WpsPushButton, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->wps_push_button = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->wps_push_button is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->wps_push_button, str, _ansc_atoi(str));
            } else {
                psm_vap_param->wps_push_button = bss_cfg->wpsPushButton;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->wpsPushButton, psm_vap_param->wps_push_button);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), RapidReconnThreshold, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->rapid_connect_threshold = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->rapid_connect_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->rapid_connect_threshold, str, _ansc_atoi(str));
            } else {
                psm_vap_param->rapid_connect_threshold = bss_cfg->rapidReconnThreshold;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->rapidReconnThreshold, psm_vap_param->rapid_connect_threshold);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), RapidReconnCountEnable, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                psm_vap_param->rapid_connect_enable = _ansc_atoi(str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->rapid_connect_enable is %d and str is %s and _ansc_atoi(str) is %d\n", psm_vap_param->rapid_connect_enable, str, _ansc_atoi(str));
            } else {
                psm_vap_param->rapid_connect_enable = bss_cfg->rapidReconnectEnable;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->rapidReconnectEnable, psm_vap_param->rapid_connect_enable);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), NeighborReportActivated, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                convert_ascii_string_to_bool(str, &psm_vap_param->nbr_report_activated);
                wifi_util_dbg_print(WIFI_PSM,"cfg->nbr_report_activated is %d and str is %s\n", psm_vap_param->nbr_report_activated, str);
            } else {
                psm_vap_param->nbr_report_activated = bss_cfg->nbrReportActivated;
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, bss_cfg->nbrReportActivated, psm_vap_param->nbr_report_activated);
            }

            memset(recName, 0, sizeof(recName));
            memset(strValue, 0, sizeof(strValue));
            snprintf(recName, sizeof(recName), ApMFPConfig, instance_number);
            str = PSM_Get_Record_Status(recName, strValue);
            if (str != NULL) {
                strcpy(psm_vap_param->mfp, str);
                wifi_util_dbg_print(WIFI_PSM,"cfg->mfp is %s and str is %s\n", psm_vap_param->mfp, str);
            } else {
                char instanceNumStr[32];
                memset(instanceNumStr, 0, sizeof(instanceNumStr));
                _ansc_itoa(bss_cfg->security.mfp, instanceNumStr, 10);
                strcpy(psm_vap_param->mfp, instanceNumStr);
                wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, instanceNumStr, psm_vap_param->mfp);
            }

            strcpy(psm_vap_param->beacon_rate_ctl, bss_cfg->beaconRateCtl);
            wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value for BeaconRateCtl: %d : %d\r\n", __func__, __LINE__, bss_cfg->beaconRateCtl, psm_vap_param->beacon_rate_ctl);

            if (!isVapHotspot(instance_number - 1)) {
                if (get_psm_total_mac_list(instance_number, &total_mac_list, strValue) == RETURN_OK) {
                    update_data_mac_list_entry(strValue, mac_index_list);
                    psm_mac_map = get_mac_psm_obj(instance_number - 1);
                    if (psm_mac_map == NULL) {
                        wifi_util_dbg_print(WIFI_PSM,"hash_map_mac_list NULL :%d\r\n", (instance_number - 1));
                    } else {
                        psm_get_mac_list_entry(psm_mac_map, instance_number, total_mac_list, mac_index_list);
                    }
                }
            }
       }

     psm_global_param = get_global_psm_obj();
     if (psm_global_param == NULL) {
          wifi_util_dbg_print(WIFI_PSM,"%s:%d psm global param NULL\r\n", __func__, __LINE__);
     }

    memset(&global_cfg, 0, sizeof(global_cfg));
    wifidb_init_global_config_default(&global_cfg);

     memset(strValue, 0, sizeof(strValue));
     str = PSM_Get_Record_Status(WiFivAPStatsFeatureEnable, strValue);
     if (str != NULL) {
         convert_ascii_string_to_bool(str, &psm_global_param->vap_stats_feature);
         wifi_util_dbg_print(WIFI_PSM,"cfg->vap_stats_feature is %d and str is %s\n", psm_global_param->vap_stats_feature, str);
     } else {
         psm_global_param->vap_stats_feature = global_cfg.vap_stats_feature;
         wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.vap_stats_feature, psm_global_param->vap_stats_feature);
     }

    psm_global_param->vlan_cfg_version = global_cfg.vlan_cfg_version;
    wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value for WifiVlanCfgVersion: %d : %d\r\n", __func__, __LINE__, global_cfg.vlan_cfg_version, psm_global_param->vlan_cfg_version);

    psm_global_param->prefer_private = global_cfg.prefer_private;
    wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value for PreferPrivate: %d : %d\r\n", __func__, __LINE__, global_cfg.prefer_private, psm_global_param->prefer_private);

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(NotifyWiFiChanges, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &psm_global_param->notify_wifi_changes);
        wifi_util_dbg_print(WIFI_PSM,"cfg->notify_wifi_changes is %d and str is %s\n", psm_global_param->notify_wifi_changes, str);
    } else {
        psm_global_param->notify_wifi_changes = global_cfg.notify_wifi_changes;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.notify_wifi_changes, psm_global_param->notify_wifi_changes);
     }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(DiagnosticEnable, strValue);
    if (str != NULL) {
        psm_global_param->diagnostic_enable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->diagnostic_enable is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->diagnostic_enable, str, _ansc_atoi(str));
    } else {
        psm_global_param->diagnostic_enable = global_cfg.diagnostic_enable;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.diagnostic_enable, psm_global_param->diagnostic_enable);
     }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(GoodRssiThreshold, strValue);
    if (str != NULL) {
        psm_global_param->good_rssi_threshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->good_rssi_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->good_rssi_threshold, str, _ansc_atoi(str));
    } else {
        psm_global_param->good_rssi_threshold = global_cfg.good_rssi_threshold;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.good_rssi_threshold, psm_global_param->good_rssi_threshold);
     }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(AssocCountThreshold, strValue);
    if (str != NULL) {
        psm_global_param->assoc_count_threshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->assoc_count_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->assoc_count_threshold, str, _ansc_atoi(str));
    } else {
        psm_global_param->assoc_count_threshold = global_cfg.assoc_count_threshold;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.assoc_count_threshold, psm_global_param->assoc_count_threshold);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(AssocMonitorDuration, strValue);
    if (str != NULL) {
        psm_global_param->assoc_monitor_duration = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->assoc_monitor_duration is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->assoc_monitor_duration, str, _ansc_atoi(str));
    } else {
        psm_global_param->assoc_monitor_duration = global_cfg.assoc_monitor_duration;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.assoc_monitor_duration, psm_global_param->assoc_monitor_duration);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(AssocGateTime, strValue);
    if (str != NULL) {
        psm_global_param->assoc_gate_time = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->assoc_gate_time is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->assoc_gate_time, str, _ansc_atoi(str));
    } else {
        psm_global_param->assoc_gate_time = global_cfg.assoc_gate_time;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.assoc_gate_time, psm_global_param->assoc_gate_time);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(RapidReconnectIndicationEnable, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &psm_global_param->rapid_reconnect_enable);
        wifi_util_dbg_print(WIFI_PSM,"cfg->rapid_reconnect_enable is %d and str is %s\n", psm_global_param->rapid_reconnect_enable, str);
    } else {
        psm_global_param->rapid_reconnect_enable = global_cfg.rapid_reconnect_enable;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.rapid_reconnect_enable, psm_global_param->rapid_reconnect_enable);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(FeatureMFPConfig, strValue);
    if (str != NULL) {
        psm_global_param->mfp_config_feature = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->mfp_config_feature is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->mfp_config_feature, str, _ansc_atoi(str));
    } else {
        psm_global_param->mfp_config_feature = global_cfg.mfp_config_feature;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.mfp_config_feature, psm_global_param->mfp_config_feature);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(WiFiTxOverflowSelfheal, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &psm_global_param->tx_overflow_selfheal);
        wifi_util_dbg_print(WIFI_PSM,"cfg->tx_overflow_selfheal is %d and str is %s\n", psm_global_param->tx_overflow_selfheal, str);
    } else {
        psm_global_param->tx_overflow_selfheal = global_cfg.tx_overflow_selfheal;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.tx_overflow_selfheal, psm_global_param->tx_overflow_selfheal);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(WiFiForceDisableWiFiRadio, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &psm_global_param->force_disable_radio_feature);
        wifi_util_dbg_print(WIFI_PSM,"cfg->force_disable_radio_feature is %d and str is %s\n", psm_global_param->force_disable_radio_feature, str);
    } else {
        psm_global_param->force_disable_radio_feature = global_cfg.force_disable_radio_feature;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.force_disable_radio_feature, psm_global_param->force_disable_radio_feature);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(WiFiForceDisableRadioStatus, strValue);
    if (str != NULL) {
        psm_global_param->force_disable_radio_status = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->force_disable_radio_status is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->force_disable_radio_status, str, _ansc_atoi(str));
    } else {
        psm_global_param->force_disable_radio_status = global_cfg.force_disable_radio_status;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.force_disable_radio_status, psm_global_param->force_disable_radio_status);
    }

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(ValidateSSIDName, strValue);
    if (str != NULL) {
        psm_global_param->validate_ssid = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->validate_ssid is %d and str is %s and _ansc_atoi(str) is %d\n", psm_global_param->validate_ssid, str, _ansc_atoi(str));
    }  else {
        psm_global_param->validate_ssid = global_cfg.validate_ssid;
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.validate_ssid, psm_global_param->validate_ssid);
    }

    psm_global_param->fixed_wmm_params = global_cfg.fixed_wmm_params;
    wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value for FixedWmmParams: %d : %d\r\n", __func__, __LINE__, global_cfg.fixed_wmm_params, psm_global_param->fixed_wmm_params);

    memset(strValue, 0, sizeof(strValue));
    str = PSM_Get_Record_Status(TR181_WIFIREGION_Code, strValue);
    if (str != NULL) {
        strcpy(psm_global_param->wifi_region_code, str);
        wifi_util_dbg_print(WIFI_PSM,"cfg->wifi_region_code is %s and str is %s \n", psm_global_param->wifi_region_code, str);
    } else {
        strcpy(psm_global_param->wifi_region_code, global_cfg.wifi_region_code);
        wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value:%d : %d\r\n", __func__, __LINE__, global_cfg.wifi_region_code, psm_global_param->wifi_region_code);
    }

    strcpy(psm_global_param->wps_pin, global_cfg.wps_pin);
    wifi_util_dbg_print(WIFI_PSM,":%s:%d set default value for WpsPin: %d : %d\r\n", __func__, __LINE__, global_cfg.wps_pin, psm_global_param->wps_pin);
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
    int resetSSID[MAX_NUM_RADIOS] = {0};
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
    
    for (index = 0; index < getTotalNumberVAPs(); index++)
    {
        UINT apIndex;

        apIndex = VAP_INDEX(((webconfig_dml_t *)get_webconfig_dml())->hal_cap, index);
        if (CosaDmlWiFi_GetRapidReconnectCountEnable(apIndex , (BOOLEAN *) &bReconnectCountEnable, false) != ANSC_STATUS_SUCCESS)
        {
            /* Set default value */
            if (isVapPrivate(apIndex)) {
                bReconnectCountEnable = 1;
            } else {
                bReconnectCountEnable = 0;
            }
        }
        set_multi_vap_dml_parameters(apIndex, RECONNECT_COUNT_STATUS, &bReconnectCountEnable);
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
        l_intValue = 0;
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
    int retPsmGet = CCSP_SUCCESS;
    char *strValue = NULL;
    char list[128] = {0};


    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem,"dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WHIX.NormalizedRssiList",NULL,&strValue);

    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strValue && strlen(strValue))
        {
            strncpy(list, strValue , strlen(strValue)+1);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }
    } else {
        wifi_util_dbg_print(WIFI_MON, "%s:%d The PSM_Get_Record_Value2  is failed with %d retval  \n",__FUNCTION__,__LINE__,retPsmGet);
        strncpy(list, "1,2", sizeof(list)-1);
    }
    list[sizeof(list)-1] = '\0';

    push_event_to_ctrl_queue(list, (strlen(list) + 1), wifi_event_type_command, wifi_event_type_normalized_rssi, NULL);

    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem,"dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WIFI_TELEMETRY.SNRList",NULL,&strValue);

    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strValue && strlen(strValue))
        {
            strncpy(list, strValue , strlen(strValue)+1);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }
    } else {
        wifi_util_dbg_print(WIFI_MON, "%s:%d The PSM_Get_Record_Value2  is failed with %d retval  \n",__FUNCTION__,__LINE__,retPsmGet);
        strncpy(list, "1,2", sizeof(list)-1);
    }
    list[sizeof(list)-1] = '\0';

    push_event_to_ctrl_queue(list, (strlen(list) + 1), wifi_event_type_command, wifi_event_type_snr, NULL);

    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem,"dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WHIX.CliStatList",NULL,&strValue);

    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strValue && strlen(strValue))
        {
            strncpy(list, strValue , strlen(strValue)+1);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }
    } else {
        wifi_util_dbg_print(WIFI_MON, "%s:%d The PSM_Get_Record_Value2  is failed with %d retval  \n",__FUNCTION__,__LINE__,retPsmGet);
        strncpy(list, "1,2", sizeof(list)-1);
    }
    list[sizeof(list)-1] = '\0';

    push_event_to_ctrl_queue(list, (strlen(list) + 1), wifi_event_type_command, wifi_event_type_cli_stat, NULL);

    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem,"dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WHIX.TxRxRateList",NULL,&strValue);

    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strValue && strlen(strValue))
        {
            strncpy(list, strValue , strlen(strValue)+1);
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
        }
    } else {
        wifi_util_dbg_print(WIFI_MON, "%s:%d The PSM_Get_Record_Value2  is failed with %d retval  \n",__FUNCTION__,__LINE__,retPsmGet);
        strncpy(list, "1,2", sizeof(list)-1);
    }
    list[sizeof(list)-1] = '\0';

    push_event_to_ctrl_queue(list, (strlen(list) + 1), wifi_event_type_command, wifi_event_type_txrx_rate, NULL);
}

void CosaDmlWiFiGetRFCDataFromPSM(void)
{
    int retPsmGet = CCSP_SUCCESS;
    char *strValue = NULL;
    bool l_interworking_RFC, l_passpoint_RFC;
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
    bool wifi_radius_greylist_status;
#endif
    wifi_global_config_t *global_wifi_config;
    global_wifi_config = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

    wifi_util_dbg_print(WIFI_DMCLI,"Enter %s:%d \n",__func__, __LINE__);
    if (global_wifi_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return ;
    }

   // bool rfc;
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
    push_rfc_dml_cache_to_one_wifidb(l_interworking_RFC,wifi_event_type_wifi_interworking_rfc);
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

    push_rfc_dml_cache_to_one_wifidb(l_passpoint_RFC,wifi_event_type_wifi_passpoint_rfc);

#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
    bool l_offchannelscan_RFC;
    char *str = NULL;
    str = PSM_Get_Record_Status("Device.DeviceInfo.X_RDK_RFC.Feature.OffChannelScan.Enable", strValue);
    if (str != NULL){
        l_offchannelscan_RFC = _ansc_atoi(str);
    }
    else
    {
        /* Set default value */
        l_offchannelscan_RFC = 0;
    }

    push_rfc_dml_cache_to_one_wifidb(l_offchannelscan_RFC, wifi_event_type_wifi_offchannelscan_rfc);
#endif //FEATURE_OFF_CHANNEL_SCAN_5G

#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
    CosaDmlWiFiGetEnableRadiusGreylist((BOOLEAN *)&wifi_radius_greylist_status);
    push_rfc_dml_cache_to_one_wifidb(wifi_radius_greylist_status,wifi_event_type_radius_grey_list_rfc);
    wifi_util_info_print(WIFI_DMCLI,"radiusGrey list value=%d preferpriv=%d\n",wifi_radius_greylist_status,global_wifi_config->global_parameters.prefer_private);
    if (wifi_radius_greylist_status && global_wifi_config->global_parameters.prefer_private) {
        global_wifi_config->global_parameters.prefer_private = false;
        push_global_config_dml_cache_to_one_wifidb();
        push_prefer_private_ctrl_queue(false);
    }
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

    get_stubs_descriptor()->v_secure_system_fn("touch /tmp/wifi_dml_complete");
    get_stubs_descriptor()->v_secure_system_fn("uptime > /tmp/wifi_dml_complete");

    get_all_param_from_psm_and_set_into_db();

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
    get_stubs_descriptor()->t2_event_d_fn("WIFI_INFO_CosaWifiinit",1);

    set_dml_init_status(true);
    getParamWifiRegionUpdateSource();
#ifndef NEWPLATFORM_PORT
    CosaDmlWiFiGetDataFromPSM();
    CosaDmlWiFiGetExternalDataFromPSM();
    CosaDmlWiFiGetRFCDataFromPSM();
    CosaDmlWiFiGetFromPSM();
#endif // NEWPLATFORM_PORT

EXIT:
        CcspTraceWarning(("CosaWifiInitialize - returnStatus %ld\n", returnStatus));

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
