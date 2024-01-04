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
#include <stdio.h>
#include <stdbool.h>
#include "ansc_platform.h"
#include <unistd.h>
#include <pthread.h>
#include "scheduler.h"
#include "ssp_loop.h"
#include "cosa_wifi_apis.h"
#include "wifi_hal_radio.h"
#include "wifi_hal_ap.h"
#include "wifi_hal.h"
#include "wifi_util.h"
#include "wifi_mgr.h"

static char *WpsPin = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.WPSPin";
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
static char *BeaconRateCtl   = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.BeaconRateCtl";
static char *BSSTransitionActivated    = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.BSSTransitionActivated";
static char *BssHotSpot        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.HotSpot";
static char *WpsPushButton = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.WpsPushButton";
static char *RapidReconnThreshold        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.RapidReconnThreshold";
static char *RapidReconnCountEnable      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.RapidReconnCountEnable";
static char *vAPStatsEnable = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.vAPStatsEnable";
static char *NeighborReportActivated     = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_NeighborReportActivated";
static char *WiFivAPStatsFeatureEnable = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.vAPStatsEnable";
static char *WifiVlanCfgVersion ="eRT.com.cisco.spvtg.ccsp.Device.WiFi.VlanCfgVerion";
static char *PreferPrivate      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.PreferPrivate";
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
static char *FixedWmmParams        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.FixedWmmParamsValues";
#define TR181_WIFIREGION_Code    "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code"
static char *MacFilter = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilter.%d";
static char *MacFilterDevice = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterDevice.%d";
static char *MacFilterList      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterList";
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
static char *Tscan = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelTscan";
static char *Nscan = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelNscan";
static char *Tidle = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelTidle";
#endif //FEATURE_OFF_CHANNEL_SCAN_5G

ssp_loop_t g_ssp_loop;
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
wifi_psm_param_t g_psm_obj;

wifi_psm_param_t *get_psm_obj(void)
{
    return &g_psm_obj;
}

wifi_radio_feat_psm_param_t *get_radio_feat_psm_obj(unsigned char radio_index)
{
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G) //CAN BE REMOVED IF MORE PARAMS ARE ADDED
    wifi_psm_param_t *p_wifi_psm_param = get_psm_obj();

    if ((radio_index < getNumberRadios())) {
        return &p_wifi_psm_param->radio_feat_psm_cfg[radio_index];
    } else {
        wifi_util_error_print(WIFI_PSM, "%s:%d wrong radio_index %d\n", __func__, __LINE__, radio_index);
        return NULL;
    }
#else //FEATURE_OFF_CHANNEL_SCAN_5G
    return NULL;
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
}

wifi_radio_psm_param_t *get_radio_psm_obj(unsigned char radio_index)
{
    wifi_psm_param_t *p_wifi_psm_param = get_psm_obj();

    if ((radio_index < getNumberRadios())) {
        return &p_wifi_psm_param->radio_psm_cfg[radio_index];
    } else {
        wifi_util_error_print(WIFI_PSM, "%s:%d wrong radio_index %d\n", __func__, __LINE__, radio_index);
        return NULL;
    }
}

wifi_vap_psm_param_t *get_vap_psm_obj(unsigned char vap_index)
{
    wifi_psm_param_t *p_wifi_psm_param = get_psm_obj();

    if (wifi_util_is_vap_index_valid(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, (int)vap_index)) {
        return &p_wifi_psm_param->vap_psm_cfg[vap_index];
    } else {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d wrong vap_index %d\n", __func__, __LINE__, vap_index);
        return NULL;
    }
}

wifi_global_psm_param_t *get_global_psm_obj(void)
{
    wifi_psm_param_t *p_wifi_psm_param = get_psm_obj();

    return &p_wifi_psm_param->global_psm_cfg;
}

hash_map_t *get_mac_psm_obj(unsigned char vap_index)
{
    wifi_psm_param_t *p_wifi_psm_param = get_psm_obj();

    if (wifi_util_is_vap_index_valid(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, (int)vap_index)) {
        return p_wifi_psm_param->mac_psm_cfg.mac_entry[vap_index];
    } else {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d wrong vap_index %d \r\n", __func__, __LINE__, vap_index);
        return NULL;
    }
}

hash_map_t **get_mac_psm_map(unsigned char vap_index)
{
    wifi_psm_param_t *p_wifi_psm_param = get_psm_obj();

    if (wifi_util_is_vap_index_valid(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, (int)vap_index)) {
        return &p_wifi_psm_param->mac_psm_cfg.mac_entry[vap_index];
    } else {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d wrong vap_index %d\n", __func__, __LINE__, vap_index);
        return NULL;
    }
}

void Psm_Db_Write_Radio_Feat(wifi_radio_feature_param_t *fcfg)
{
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G) //this can be removed and the below macro can be used if additional members are added into wifi_radio_feature_param_t
    char recName[256];
    char instanceNumStr[64] = {0};
    wifi_radio_feat_psm_param_t *cfg;
    int retPsmSet;
    int instance_number = fcfg->radio_index + 1;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    wifi_util_info_print(WIFI_PSM, "%s:%d update radio features for radio index:%d\n", __func__,
        __LINE__, fcfg->radio_index);

    cfg = get_radio_feat_psm_obj(fcfg->radio_index);
    if (cfg == NULL) {
        wifi_util_error_print(WIFI_PSM, "%s:%d psm radio param NULL\r\n", __func__, __LINE__);
        return;
    }

    if(is_radio_band_5G(mgr->radio_config[fcfg->radio_index].oper.band)) {
        if(fcfg->OffChanTscanInMsec != cfg->Tscan) {
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName), Tscan, instance_number);
            _ansc_itoa(fcfg->OffChanTscanInMsec, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->Tscan = fcfg->OffChanTscanInMsec;
                wifi_util_dbg_print(WIFI_PSM, "%s:%d Tscan cfg->Tscan is %d\n",__func__, __LINE__,cfg->Tscan);
            } else {
                wifi_util_error_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting Tscan, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(fcfg->OffChanNscanInSec != cfg->Nscan) {
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName), Nscan, instance_number);
            _ansc_itoa(fcfg->OffChanNscanInSec, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->Nscan = fcfg->OffChanNscanInSec;
                wifi_util_dbg_print(WIFI_PSM, "%s:%d Nscan cfg->Nscan is %d\n",__func__, __LINE__,cfg->Nscan);
            } else {
                wifi_util_error_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting Nscan, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(fcfg->OffChanTidleInSec != cfg->Tidle) {
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName), Tidle, instance_number);
            _ansc_itoa(fcfg->OffChanTidleInSec, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->Tidle = fcfg->OffChanTidleInSec;
                wifi_util_dbg_print(WIFI_PSM, "%s:%d Tidle cfg->Tidle is %d\n",__func__, __LINE__,cfg->Tidle);
            } else {
                wifi_util_error_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting Tidle, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d update radio features done\n", __func__, __LINE__);
#else //FEATURE_OFF_CHANNEL_SCAN_5G
    return;
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
}

void Psm_Db_Write_Radio(wifi_radio_operationParam_t *rcfg)
{
    char recName[256];
    char instanceNumStr[64] = {0};
    wifi_radio_psm_param_t *cfg;
    int radio_index = 0;
    int instance_number = 0;
    int retPsmSet;

    wifi_util_info_print(WIFI_PSM, "%s:%d update radio config for band:%d\n", __func__, __LINE__,
        rcfg->band);

    if (convert_freq_band_to_radio_index(rcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_PSM, "%s:%d failed to convert band %d to radio index\r\n",
            __func__, __LINE__, rcfg->band);
        return;
    }

    instance_number = radio_index + 1;
    cfg = get_radio_psm_obj(radio_index);
    if (cfg == NULL) {
        wifi_util_error_print(WIFI_PSM, "%s:%d psm radio param NULL radio_index:%d\r\n", __func__,
            __LINE__, radio_index);
        return;
    }

    if(rcfg->ctsProtection != cfg->cts_protection) {
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), CTSProtection, instance_number);
        _ansc_itoa(rcfg->ctsProtection, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->cts_protection = rcfg->ctsProtection;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d CTSprotection cfg->cts_protection is %d\n",__func__, __LINE__,cfg->cts_protection);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting CTSprotection, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->beaconInterval != cfg->beacon_interval){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), BeaconInterval, instance_number);
        _ansc_itoa(rcfg->beaconInterval, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->beacon_interval = rcfg->beaconInterval;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d BeaconInterval cfg->beacon_interval is %d\n",__func__, __LINE__,cfg->beacon_interval);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting BeaconInterval, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->dtimPeriod != cfg->dtim_period){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), DTIMInterval, instance_number);
        _ansc_itoa(rcfg->dtimPeriod, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->dtim_period = rcfg->dtimPeriod;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d DTIMInterval cfg->dtim_period is %d\n",__func__, __LINE__,cfg->dtim_period);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting DTIMInterval, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->fragmentationThreshold != cfg->fragmentation_threshold){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), FragThreshold, instance_number);
        _ansc_itoa(rcfg->fragmentationThreshold, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->fragmentation_threshold = rcfg->fragmentationThreshold;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d FragThreshold cfg->fragmentation_threshold is %d\n",__func__, __LINE__,cfg->fragmentation_threshold);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting FragThreshold, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->rtsThreshold != cfg->rts_threshold){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), RTSThreshold, instance_number);
        _ansc_itoa(rcfg->rtsThreshold, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->rts_threshold = rcfg->rtsThreshold;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d RTSThreshold cfg->rts_threshold is %d\n",__func__, __LINE__,cfg->rts_threshold);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting RTSThreshold, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }


    if(rcfg->obssCoex != cfg->obss_coex){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), ObssCoex, instance_number);
        _ansc_itoa(rcfg->obssCoex, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->obss_coex = rcfg->obssCoex;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d ObssCoex cfg->obss_coex is %d\n",__func__, __LINE__,cfg->obss_coex);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting ObssCoex, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->stbcEnable != cfg->stbc_enable){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), STBCEnable, instance_number);
        _ansc_itoa(rcfg->stbcEnable, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->stbc_enable = rcfg->stbcEnable;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d STBCEnable cfg->stbc_enable is %d\n",__func__, __LINE__,cfg->stbc_enable);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting STBCEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->guardInterval != cfg->guard_interval){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), GuardInterval, instance_number);
        _ansc_itoa(rcfg->guardInterval, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->guard_interval = rcfg->guardInterval;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d GuardInterval cfg->guard_interval is %d\n",__func__, __LINE__,cfg->guard_interval);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting GuardInterval, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->greenFieldEnable != cfg->greenfield_enable ){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), GreenField, instance_number);
        _ansc_itoa(rcfg->greenFieldEnable, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->greenfield_enable = rcfg->greenFieldEnable;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d GreenField cfg->greenfield_enable is %d\n",__func__, __LINE__,cfg->greenfield_enable);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting GreenFieldEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->transmitPower != cfg->transmit_power){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), TransmitPower, instance_number);
        _ansc_itoa(rcfg->transmitPower, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->transmit_power = rcfg->transmitPower;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d TransmitPower cfg->transmit_power is %d\n",__func__, __LINE__,cfg->transmit_power);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting TransmitPower, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->userControl != cfg->user_control){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), UserControl, instance_number);
        _ansc_itoa(rcfg->userControl, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->user_control = rcfg->userControl;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d UserControl cfg->user_control is %d\n",__func__, __LINE__,cfg->user_control);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting UserControl, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->adminControl != cfg->admin_control){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), AdminControl, instance_number);
        _ansc_itoa(rcfg->adminControl, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->admin_control = rcfg->adminControl;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d AdminControl cfg->admin_control is %d\n",__func__, __LINE__,cfg->admin_control);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting AdminControl, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->radioStatsMeasuringRate != cfg->radio_stats_measuring_rate){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), MeasuringRateRd, instance_number);
        _ansc_itoa(rcfg->radioStatsMeasuringRate, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->radio_stats_measuring_rate = rcfg->radioStatsMeasuringRate;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d cfg->radio_stats_measuring_rate is %d\n",__func__, __LINE__,cfg->radio_stats_measuring_rate);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting MeasuringRateRd, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->radioStatsMeasuringInterval != cfg->radio_stats_measuring_interval){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), MeasuringIntervalRd, instance_number);
        _ansc_itoa(rcfg->radioStatsMeasuringInterval, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->radio_stats_measuring_interval = rcfg->radioStatsMeasuringInterval;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d cfg->radio_stats_measuring_interval is %d\n",__func__, __LINE__,cfg->radio_stats_measuring_interval);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting MeasuringIntervalRd, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    if(rcfg->chanUtilThreshold != cfg->chan_util_threshold){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), SetChanUtilThreshold, instance_number);
        _ansc_itoa(rcfg->chanUtilThreshold, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->chan_util_threshold = rcfg->chanUtilThreshold;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d SetChanUtilThreshold cfg->chan_util_threshold is %d\n",__func__, __LINE__,cfg->chan_util_threshold);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting SetChanUtilThreshold, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
     }

    if(rcfg->chanUtilSelfHealEnable != cfg->chan_util_selfheal_enable){
        memset(recName, '\0', sizeof(recName));
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        snprintf(recName, sizeof(recName), SetChanUtilSelfHealEnable, instance_number);
        _ansc_itoa(rcfg->chanUtilSelfHealEnable, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->chan_util_selfheal_enable = rcfg->chanUtilSelfHealEnable;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d SetChanUtilSelfHealEnable cfg->chan_util_selfheal_enable is %d\n",__func__, __LINE__,cfg->chan_util_selfheal_enable);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting SetChanUtilSelfHealEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d update radio config done\n", __func__, __LINE__);
}

void Psm_Db_Write_Vapinfo(wifi_vap_info_t *acfg)
{
    char recName[256];
    char instanceNumStr[256];
    int retPsmSet = CCSP_SUCCESS;
    wifi_vap_psm_param_t *cfg;
    cfg = get_vap_psm_obj(acfg->vap_index);
    if (cfg == NULL) {
        wifi_util_error_print(WIFI_PSM, "%s:%d psm vap param NULL vap_index:%d\n", __func__,
            __LINE__, acfg->vap_index);
        return;
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d update vap info for vap index:%d\n", __func__, __LINE__,
        acfg->vap_index);

    int instance_number = (acfg->vap_index + 1);

        if(acfg->u.bss_info.wmm_enabled != cfg->wmm_enabled ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),WmmEnable, instance_number);
            _ansc_itoa(acfg->u.bss_info.wmm_enabled, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->wmm_enabled = acfg->u.bss_info.wmm_enabled;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d cfg->wmm_enabled is %d\n",__func__, __LINE__,cfg->wmm_enabled);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WmmEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }
        if(acfg->u.bss_info.UAPSDEnabled != cfg->uapsd_enabled ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),UAPSDEnable, instance_number);
            _ansc_itoa(acfg->u.bss_info.UAPSDEnabled, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->uapsd_enabled = acfg->u.bss_info.UAPSDEnabled;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d cfg->uapsd_enabled is %d\n",__func__, __LINE__,cfg->uapsd_enabled);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting UAPSDEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.wmmNoAck != cfg->wmm_noack ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),WmmNoAck, instance_number);
            _ansc_itoa(acfg->u.bss_info.wmmNoAck, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->wmm_noack= acfg->u.bss_info.wmmNoAck;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d cfg->wmm_noack is %d\n",__func__, __LINE__,cfg->wmm_noack);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WmmNoAck, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.bssMaxSta != cfg->bss_max_sta ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),BssMaxNumSta, instance_number);
            _ansc_itoa(acfg->u.bss_info.bssMaxSta, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->bss_max_sta = acfg->u.bss_info.bssMaxSta;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d cfg->bss_max_sta is %d\n",__func__, __LINE__,cfg->bss_max_sta);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting BssMaxNumSta, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if((acfg->u.bss_info.mac_filter_enable != cfg->mac_filter_enable) ||
                    (acfg->u.bss_info.mac_filter_mode != cfg->mac_filter_mode)){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),MacFilterMode, instance_number);
            if (acfg->u.bss_info.mac_filter_enable == false) {
                strcpy(instanceNumStr, "0");
            } else if ((acfg->u.bss_info.mac_filter_enable == true) &&
                        (acfg->u.bss_info.mac_filter_mode != wifi_mac_filter_mode_black_list)) {
                strcpy(instanceNumStr, "1");
            }  else if ((acfg->u.bss_info.mac_filter_enable == true) &&
                        (acfg->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list)) {
                strcpy(instanceNumStr, "2");
            }

            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->mac_filter_mode   = acfg->u.bss_info.mac_filter_mode;
                cfg->mac_filter_enable = acfg->u.bss_info.mac_filter_enable;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d MacFilterMode mac_filter_enable:%d cfg->mac_filter_mode is %d str_mac_mode:%s\r\n",
                                                __func__, __LINE__, cfg->mac_filter_enable, cfg->mac_filter_mode, instanceNumStr);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting MacFilterMode, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.isolation != cfg->isolation_enabled ){
           memset(recName, '\0', sizeof(recName));
           memset(instanceNumStr, '\0', sizeof(instanceNumStr));
           snprintf(recName, sizeof(recName),ApIsolationEnable, instance_number);
           _ansc_itoa(acfg->u.bss_info.isolation, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->isolation_enabled = acfg->u.bss_info.isolation;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d ApIsolationEnable cfg->isolation_enabled is %d\n",__func__, __LINE__,cfg->isolation_enabled);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting ApIsolationEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.bssTransitionActivated != cfg->bss_transition_activated ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),BSSTransitionActivated, instance_number);
            convert_bool_to_ascii_string(acfg->u.bss_info.bssTransitionActivated, instanceNumStr, sizeof(instanceNumStr));
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->bss_transition_activated = acfg->u.bss_info.bssTransitionActivated;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d BSSTransitionActivated cfg->bss_transition_activated is %d\n",__func__, __LINE__,cfg->bss_transition_activated);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting BSSTransitionActivated, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.bssHotspot != cfg->bss_hotspot ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),BssHotSpot, instance_number);
            _ansc_itoa(acfg->u.bss_info.bssHotspot, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->bss_hotspot = acfg->u.bss_info.bssHotspot;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d BssHotSpot cfg->bss_hotspot is %d\n",__func__, __LINE__,cfg->bss_hotspot);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting BssHotSpot, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.wpsPushButton != cfg->wps_push_button ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),WpsPushButton, instance_number);
            _ansc_itoa(acfg->u.bss_info.wpsPushButton, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->wps_push_button = acfg->u.bss_info.wpsPushButton;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d WpsPushButton cfg->wps_push_button is %d\n",__func__, __LINE__,cfg->wps_push_button);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WpsPushButton, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.rapidReconnThreshold != cfg->rapid_connect_threshold ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),RapidReconnThreshold, instance_number);
            _ansc_itoa(acfg->u.bss_info.rapidReconnThreshold, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->rapid_connect_threshold = acfg->u.bss_info.rapidReconnThreshold;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d RapidReconnThreshold cfg->rapid_connect_threshold is %d\n",__func__, __LINE__,cfg->rapid_connect_threshold);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting RapidReconnThreshold, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.rapidReconnectEnable != cfg->rapid_connect_enable ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),RapidReconnCountEnable, instance_number);
            _ansc_itoa(acfg->u.bss_info.rapidReconnectEnable, instanceNumStr, 10);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->rapid_connect_enable = acfg->u.bss_info.rapidReconnectEnable;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d RapidReconnCountEnable cfg->rapid_connect_enable is %d\n",__func__, __LINE__,cfg->rapid_connect_enable);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting RapidReconnCountEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(acfg->u.bss_info.vapStatsEnable != cfg->vap_stats_enable ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),vAPStatsEnable, instance_number);
            convert_bool_to_ascii_string(acfg->u.bss_info.vapStatsEnable, instanceNumStr, sizeof(instanceNumStr));
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->vap_stats_enable = acfg->u.bss_info.vapStatsEnable;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d vAPStatsEnable cfg->vap_stats_enable is %d\n",__func__, __LINE__,cfg->vap_stats_enable);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting vAPStatsEnable, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
	}

        if(acfg->u.bss_info.nbrReportActivated != cfg->nbr_report_activated ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),NeighborReportActivated, instance_number);
            convert_bool_to_ascii_string(acfg->u.bss_info.nbrReportActivated, instanceNumStr, sizeof(instanceNumStr));
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                cfg->nbr_report_activated = acfg->u.bss_info.nbrReportActivated;
                wifi_util_dbg_print(WIFI_PSM,"%s:%d NeighborReportActivated cfg->nbr_report_activated is %d\n",__func__, __LINE__,cfg->nbr_report_activated);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting NeighborReportActivated, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

        if(strncmp(acfg->u.bss_info.beaconRateCtl, cfg->beacon_rate_ctl, strlen(cfg->beacon_rate_ctl)) != 0 ){
            memset(recName, '\0', sizeof(recName));
            memset(instanceNumStr, '\0', sizeof(instanceNumStr));
            snprintf(recName, sizeof(recName),BeaconRateCtl, instance_number);
            retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
            if(retPsmSet == CCSP_SUCCESS) {
                strcpy(cfg->beacon_rate_ctl, acfg->u.bss_info.beaconRateCtl);
                wifi_util_dbg_print(WIFI_PSM,"%s:%d BeaconRateCtl cfg->beacon_rate_ctl is %s\n",__func__, __LINE__,cfg->beacon_rate_ctl);
            } else {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting BeaconRateCtl, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
            }
        }

    wifi_util_info_print(WIFI_PSM, "%s:%d update vap info done\n", __func__, __LINE__);
}


void Psm_Db_Write_Global(wifi_global_param_t *gcfg)
{
    char instanceNumStr[256];
    int retPsmSet = CCSP_SUCCESS;
    wifi_global_psm_param_t *cfg;

    cfg = get_global_psm_obj();
    if (cfg == NULL) {
        wifi_util_error_print(WIFI_PSM, "%s:%d psm global param NULL\n", __func__, __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d update global config\n", __func__, __LINE__);

    if(gcfg->vlan_cfg_version != cfg->vlan_cfg_version){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->vlan_cfg_version, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, WifiVlanCfgVersion, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->vlan_cfg_version = gcfg->vlan_cfg_version;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d WifiVlanCfgVersion cfg->vlan_cfg_version is %d\n",__func__, __LINE__,cfg->vlan_cfg_version);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WifiVlanCfgVersion\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->prefer_private != cfg->prefer_private){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->prefer_private, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, PreferPrivate, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->prefer_private = gcfg->prefer_private;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PreferPrivate cfg->prefer_private is %d\n",__func__, __LINE__,cfg->prefer_private);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting PreferPrivate\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->notify_wifi_changes != cfg->notify_wifi_changes){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        if (gcfg->notify_wifi_changes) {
            strcpy(instanceNumStr,"true");
        }
        else {
            strcpy(instanceNumStr,"false");
        }

        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, NotifyWiFiChanges, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->notify_wifi_changes = gcfg->notify_wifi_changes;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d NotifyWiFiChanges cfg->notify_wifi_changes is %d\n",__func__, __LINE__,cfg->notify_wifi_changes);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting NotifyWiFiChanges\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->diagnostic_enable != cfg->diagnostic_enable){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->diagnostic_enable, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, DiagnosticEnable, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->diagnostic_enable = gcfg->diagnostic_enable;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d DiagnosticEnable cfg->diagnostic_enable is %d\n",__func__, __LINE__,cfg->diagnostic_enable);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting DiagnosticEnable\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->good_rssi_threshold != cfg->good_rssi_threshold){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->good_rssi_threshold, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, GoodRssiThreshold, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->good_rssi_threshold = gcfg->good_rssi_threshold;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d GoodRssiThreshold cfg->good_rssi_threshold is %d\n",__func__, __LINE__,cfg->good_rssi_threshold);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting GoodRssiThreshold\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->assoc_count_threshold != cfg->assoc_count_threshold){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->assoc_count_threshold, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, AssocCountThreshold, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->assoc_count_threshold = gcfg->assoc_count_threshold;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d AssocCountThreshold cfg->assoc_count_threshold is %d\n",__func__, __LINE__,cfg->assoc_count_threshold);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting AssocCountThreshold\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->assoc_monitor_duration != cfg->assoc_monitor_duration){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->assoc_monitor_duration, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, AssocMonitorDuration, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->assoc_monitor_duration = gcfg->assoc_monitor_duration;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d AssocMonitorDuration cfg->assoc_monitor_duration is %d\n",__func__, __LINE__,cfg->assoc_monitor_duration);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting AssocMonitorDuration\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->assoc_gate_time != cfg->assoc_gate_time){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->assoc_gate_time, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, AssocGateTime, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->assoc_gate_time = gcfg->assoc_gate_time;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d AssocGateTime cfg->assoc_gate_time is %d\n",__func__, __LINE__,cfg->assoc_gate_time);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting AssocGateTime\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->rapid_reconnect_enable != cfg->rapid_reconnect_enable){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->rapid_reconnect_enable, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, RapidReconnectIndicationEnable, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->prefer_private = gcfg->prefer_private;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d RapidReconnectIndicationEnable cfg->prefer_private is %d\n",__func__, __LINE__, cfg->prefer_private);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting RapidReconnectIndicationEnable\n",__func__, __LINE__, retPsmSet);
        }
     }

    if(gcfg->mfp_config_feature != cfg->mfp_config_feature){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->mfp_config_feature, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, FeatureMFPConfig, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->mfp_config_feature = gcfg->mfp_config_feature;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d FeatureMFPConfig cfg->mfp_config_feature is %d\n",__func__, __LINE__,cfg->mfp_config_feature);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting FeatureMFPConfig\n",__func__, __LINE__, retPsmSet);
        }
     }

    if(gcfg->tx_overflow_selfheal != cfg->tx_overflow_selfheal){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        convert_bool_to_ascii_string(gcfg->tx_overflow_selfheal, instanceNumStr, sizeof(instanceNumStr));
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, WiFiTxOverflowSelfheal, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->tx_overflow_selfheal = gcfg->tx_overflow_selfheal;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d WiFiTxOverflowSelfheal cfg->tx_overflow_selfheal is %d\n",__func__, __LINE__,cfg->tx_overflow_selfheal);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WiFiTxOverflowSelfheal\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->force_disable_radio_feature != cfg->force_disable_radio_feature){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        convert_bool_to_ascii_string(gcfg->force_disable_radio_feature, instanceNumStr, sizeof(instanceNumStr));
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, WiFiForceDisableWiFiRadio, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->force_disable_radio_feature = gcfg->force_disable_radio_feature;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d WiFiForceDisableWiFiRadio cfg->force_disable_radio_feature is %d\n",__func__, __LINE__,cfg->force_disable_radio_feature);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WiFiForceDisableWiFiRadio\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->force_disable_radio_status != cfg->force_disable_radio_status){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->force_disable_radio_status, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, WiFiForceDisableRadioStatus, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->force_disable_radio_status = gcfg->force_disable_radio_status;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d WiFiForceDisableRadioStatus cfg->force_disable_radio_status is %d\n",__func__, __LINE__,cfg->force_disable_radio_status);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WiFiForceDisableRadioStatus\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->validate_ssid != cfg->validate_ssid){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->validate_ssid, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, ValidateSSIDName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->validate_ssid = gcfg->validate_ssid;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d ValidateSSIDName cfg->validate_ssid is %d\n",__func__, __LINE__, cfg->validate_ssid);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting ValidateSSIDName\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->fixed_wmm_params != cfg->fixed_wmm_params){
        memset(instanceNumStr, '\0', sizeof(instanceNumStr));
        _ansc_itoa(gcfg->fixed_wmm_params, instanceNumStr, 10);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, FixedWmmParams, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->fixed_wmm_params = gcfg->fixed_wmm_params;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d FixedWmmParams cfg->fixed_wmm_params iss %d\n",__func__, __LINE__,cfg->fixed_wmm_params);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting FixedWmmParams\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(strncmp(gcfg->wifi_region_code, cfg->wifi_region_code, strlen(cfg->wifi_region_code)) != 0){
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, TR181_WIFIREGION_Code, ccsp_string, gcfg->wifi_region_code);
        if(retPsmSet == CCSP_SUCCESS) {
            strcpy(cfg->wifi_region_code, gcfg->wifi_region_code);
            wifi_util_dbg_print(WIFI_PSM, "%s:%d TR181_WIFIREGION_Code cfg->wifi_region_code is %s\n",__func__, __LINE__,cfg->wifi_region_code);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting TR181_WIFIREGION_Code\n",__func__, __LINE__, retPsmSet);
        }
    }

    if(gcfg->vap_stats_feature != cfg->vap_stats_feature){
    memset(instanceNumStr, '\0', sizeof(instanceNumStr));
    convert_bool_to_ascii_string(gcfg->vap_stats_feature, instanceNumStr, sizeof(instanceNumStr));
    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, WiFivAPStatsFeatureEnable, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            cfg->vap_stats_feature = gcfg->vap_stats_feature;
            wifi_util_dbg_print(WIFI_PSM, "%s:%d WiFivAPStatsFeatureEnable cfg->vap_stats_feature is %d\n",__func__, __LINE__,cfg->vap_stats_feature);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WiFivAPStatsFeatureEnable\n",__func__, __LINE__, retPsmSet);
        }
    }

    if (strncmp(gcfg->wps_pin, cfg->wps_pin, strlen(cfg->wps_pin)) != 0 ) {
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, WpsPin, ccsp_string, gcfg->wps_pin);
        if(retPsmSet == CCSP_SUCCESS) {
           strcpy(cfg->wps_pin, gcfg->wps_pin);
           wifi_util_dbg_print(WIFI_PSM, "%s:%d WpsPin cfg->wps_pin is %s\n",__func__, __LINE__,cfg->wps_pin);
        } else {
           wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting WpsPin\n",__func__, __LINE__, retPsmSet);
        }
   }

   wifi_util_info_print(WIFI_PSM, "%s:%d update global config done\n", __func__, __LINE__);
}

void Psm_Db_Write_Security(wifi_security_psm_param_t *scfg)
{
    int instance_number = 0;
    char recName[256];
    char instanceNumStr[50] = {0};
    int retPsmSet = CCSP_SUCCESS;
    wifi_vap_psm_param_t *cfg;

    cfg = get_vap_psm_obj(scfg->vap_index);
    if (cfg == NULL) {
        wifi_util_error_print(WIFI_PSM, "%s:%d psm vap param NULL vap index:%d\n", __func__,
            __LINE__, scfg->vap_index);
        return;
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d update security for vap index:%d mfp:%s\n", __func__,
        __LINE__, scfg->vap_index, scfg->mfp);

    instance_number = (scfg->vap_index + 1);

    memset(instanceNumStr, '\0', sizeof(instanceNumStr));
    strncpy(instanceNumStr, scfg->mfp, (strlen(scfg->mfp) + 1));
    if(strncmp(instanceNumStr, cfg->mfp, strlen(cfg->mfp)) != 0 ){
        memset(recName, 0, sizeof(recName));
        snprintf(recName, sizeof(recName),ApMFPConfig, instance_number);
        retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
        if(retPsmSet == CCSP_SUCCESS) {
            strcpy(cfg->mfp, instanceNumStr);
            wifi_util_dbg_print(WIFI_PSM, "%s:%d  ApMFPConfig cfg->mfp is %s\n",__func__, __LINE__,cfg->mfp);
        } else {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting ApMFPConfig, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
        }
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d update security done for vap index:%d\n", __func__,
        __LINE__, scfg->vap_index);
}

int update_data_mac_list_entry(char *str, unsigned int *data_index)
{
    wifi_util_dbg_print(WIFI_PSM, "%s:%d  mac_filter_list:%s\n",__func__, __LINE__, str);
    char* token;
    char* rest = str;
    int count;
    token = strtok_r(rest, ":", &rest);
    if ((token == NULL) || (rest == NULL)) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d  invalid mac_filter_list:%s\n",__func__, __LINE__, str);
        return RETURN_ERR;
    }

    count = atoi(token);
    while ((token = strtok_r(rest, ",", &rest))) {
        count--;
        if (count == -1) {
            wifi_util_dbg_print(WIFI_PSM, "%s:%d  invalid mac_filter_list count:%d\n",__func__, __LINE__, count);
            break;
        }
        *(data_index + count) = atoi(token);
    }

    return RETURN_OK;
}

int get_psm_total_mac_list(int instance_number, unsigned int *total_entries, char *mac_list)
{
    int l_total_entries = 0;
    int retPsmGet = CCSP_SUCCESS;
    char recName[256] = {0};
    char strValue[256] = {0};
    char *l_strValue = NULL;

    memset(recName, '\0', sizeof(recName));
    snprintf(recName, sizeof(recName), MacFilterList, instance_number);
    memset(strValue, 0, sizeof(strValue));
    wifi_util_dbg_print(WIFI_PSM, "%s:%d  recName: %s instance_number:%d\n",__func__, __LINE__, recName, instance_number);
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, recName, NULL, &l_strValue);
    if((retPsmGet == CCSP_SUCCESS) && (strlen(l_strValue) > 0) )
    {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d  mac list data:%s\n",__func__, __LINE__, l_strValue);
        strncpy(strValue, l_strValue, (strlen(l_strValue) + 1));
        sscanf(strValue, "%d:", &l_total_entries);
        wifi_util_dbg_print(WIFI_PSM, "%s:%d  recName: %s total entry:%d\n",__func__, __LINE__, recName, l_total_entries);
        if (l_total_entries != 0) {
            *total_entries = (unsigned int)l_total_entries;
            strncpy(mac_list, strValue, (strlen(strValue) + 1));
            wifi_util_dbg_print(WIFI_PSM, "%s:%d  recName: %s total entry:%d list:%s\n",__func__, __LINE__, recName, *total_entries, mac_list);
            return RETURN_OK;
        }
    } else {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM maclist get failure:%d mac list data:%s\n",__func__, __LINE__, retPsmGet, l_strValue);
    }

    return RETURN_ERR;
}

void update_macfilter_list(int instance_number, int total_entries, hash_map_t *psm_mac_map)
{
    int retPsmSet = CCSP_SUCCESS;
    unsigned int l_data_index[128];
    unsigned char l_index = 0;
    int count = total_entries;
    char list[256] = {0};
    char recName[256] = {0};
    char index_list[256] = {0};
    char index_instances[8] = {0};
    memset(index_instances, '\0', sizeof(index_instances));
    memset(index_list, '\0', sizeof(index_list));
    memset(recName, '\0', sizeof(recName));
    memset(list, '\0', sizeof(list));
    memset(l_data_index, 0, sizeof(l_data_index));

    wifi_mac_psm_param_t *mac_entry = hash_map_get_first(psm_mac_map);
    while(mac_entry != NULL) {

        if (count == 0) {
            wifi_util_dbg_print(WIFI_PSM,"%s:%d: wrong data\n", __func__, __LINE__);
            break;
        }
        count--;
        l_data_index[count] = mac_entry->data_index;
        mac_entry = hash_map_get_next(psm_mac_map, mac_entry);
    }

    for (l_index = 0; l_index < total_entries; l_index++) {
        if ((l_index + 1) == total_entries) {
            snprintf(index_instances, sizeof(index_instances), "%d", l_data_index[l_index]);
        } else {
            snprintf(index_instances, sizeof(index_instances), "%d,", l_data_index[l_index]);
        }
        strcat(index_list, index_instances);
    }

    wifi_util_dbg_print(WIFI_PSM, "%s:%d total mac filter list entry:%s\r\n",__func__, __LINE__, index_list);
    snprintf(list, sizeof(list), "%d:%s", total_entries, index_list);
    snprintf(recName, sizeof(recName), MacFilterList, instance_number);
    wifi_util_dbg_print(WIFI_PSM, "%s:%d mac filter list:%s\r\n",__func__, __LINE__, list);
    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, list);
    if(retPsmSet == CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d  MacFilterDevice list is %s\n",__func__, __LINE__,list);
    } else {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record_Value2 returned error %d while setting MacFilterList, instance_number is %d\n",__func__, __LINE__, retPsmSet, instance_number);
    }
}

int get_last_hash_map_entry(hash_map_t *mac_entry, wifi_mac_psm_param_t **r_data)
{
    unsigned int count = 0;

    count = hash_map_count(mac_entry);
    if (count == 0) {
        wifi_util_dbg_print(WIFI_PSM,"%s:%d: no data available\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    *r_data = hash_map_get_first(mac_entry);
    if (*r_data == NULL) {
        wifi_util_dbg_print(WIFI_PSM,"%s:%d: data not available\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int set_psm_record_by_name(unsigned int instance_number, unsigned int data_index, char *record_name, char *psm_set_data)
{
    int retPsmSet = CCSP_SUCCESS;
    char recName[256] = {0};

    memset(recName, '\0', sizeof(recName));
    snprintf(recName, sizeof(recName), record_name, instance_number, data_index);
    wifi_util_dbg_print(WIFI_PSM, "%s:%d  psm set :%s\n",__func__, __LINE__, recName);
    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, psm_set_data);
    if(retPsmSet == CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d  set psm data is %s\n",__func__, __LINE__, psm_set_data);
        return RETURN_OK;
    } else {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_Set_Record returned error %d record_name:%s\r\n",__func__, __LINE__, retPsmSet, recName);
    }

    return RETURN_ERR;
}

void Psm_Db_Write_MacFilter(wifi_mac_entry_param_t *mcfg)
{
    int ret;
    unsigned int count = 0;
    hash_map_t *psm_mac_map;
    wifi_mac_psm_param_t *mac_psm_data = NULL;
    wifi_mac_psm_param_t *temp_mac_entry;
    char *mcfg_mac;

    wifi_util_info_print(WIFI_PSM, "%s:%d update mac filter for vap index:%d\n", __func__, __LINE__,
        mcfg->vap_index);

    if (isVapHotspot(mcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d mac filter not supported for hotspot vap:%d\r\n",__func__, __LINE__, mcfg->vap_index);
        return;
    }

    psm_mac_map = get_mac_psm_obj(mcfg->vap_index);
    mcfg_mac = strdup(mcfg->mac); // Coverity fix [280369]
    str_tolower(mcfg_mac);
    wifi_util_dbg_print(WIFI_PSM, "%s:%d mac filter vap_index:%d hash_map_address:%p\r\n",__func__, __LINE__, mcfg->vap_index, psm_mac_map);
    wifi_util_dbg_print(WIFI_PSM, "%s:%d mac strdup(mcfg->mac):%s\r\n",__func__, __LINE__, mcfg_mac);
    wifi_util_dbg_print(WIFI_PSM, "%s:%d strlen:%s:%s:\r\n",__func__, __LINE__, mcfg->mac, mcfg->device_name);
    ret = get_last_hash_map_entry(psm_mac_map, &mac_psm_data);
    if (ret == RETURN_OK) {
        if ((strlen(mcfg->device_name) != 0) && (strlen(mcfg->mac) != 0)) {
            unsigned int temp_index = mac_psm_data->data_index + 1;
            temp_mac_entry = hash_map_get(psm_mac_map, mcfg_mac);
            if (temp_mac_entry != NULL) {
                temp_index = temp_mac_entry->data_index;
            }
            ret = set_psm_record_by_name((mcfg->vap_index + 1), temp_index, MacFilterDevice, mcfg->device_name);
            if (ret == RETURN_OK) {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d device_name_psm_set success:%d:%d\r\n",__func__, __LINE__, (mcfg->vap_index + 1), temp_index);
            }
        }
        if (strlen(mcfg->mac) != 0) {
            temp_mac_entry = hash_map_get(psm_mac_map, mcfg_mac);
            if (temp_mac_entry != NULL) {
                if (strlen(mcfg->device_name) != 0) {
                    strncpy(temp_mac_entry->device_name, mcfg->device_name, strlen(mcfg->device_name) + 1);
                }
                wifi_util_dbg_print(WIFI_PSM, "%s:%d mac entry already present\r\n",__func__, __LINE__);
                return;
            }
            ret = set_psm_record_by_name((mcfg->vap_index + 1), (mac_psm_data->data_index + 1), MacFilter, mcfg->mac);
            if (ret == RETURN_OK) {
                temp_mac_entry = malloc(sizeof(wifi_mac_psm_param_t));
                if (temp_mac_entry == NULL) {
                    wifi_util_dbg_print(WIFI_PSM, "%s:%d malloc failure\r\n",__func__, __LINE__);
                    return;
                }
                temp_mac_entry->data_index = (mac_psm_data->data_index + 1);
                strncpy(temp_mac_entry->mac, mcfg->mac, strlen(mcfg->mac) + 1);
                if (strlen(mcfg->device_name) != 0) {
                    strncpy(temp_mac_entry->device_name, mcfg->device_name, strlen(mcfg->device_name) + 1);
                }
                hash_map_put(psm_mac_map, mcfg_mac, temp_mac_entry);
                count = hash_map_count(psm_mac_map);
                update_macfilter_list((mcfg->vap_index + 1), count, psm_mac_map);
            }
        }
        free(mcfg_mac);
    } else {
        if ((strlen(mcfg->device_name) != 0) && (strlen(mcfg->mac) != 0)) {
            ret = set_psm_record_by_name((mcfg->vap_index + 1), 1, MacFilterDevice, mcfg->device_name);
            if (ret == RETURN_OK) {
                wifi_util_dbg_print(WIFI_PSM, "%s:%d device_name_psm_set success:%d:%d\r\n",__func__, __LINE__, (mcfg->vap_index + 1), 1);
            }
        }
        if (strlen(mcfg->mac) != 0) {
            str_tolower(mcfg->mac);
            temp_mac_entry = hash_map_get(psm_mac_map, mcfg->mac);
            if (temp_mac_entry != NULL) {
                if (strlen(mcfg->device_name) != 0) {
                    strncpy(temp_mac_entry->device_name, mcfg->device_name, strlen(mcfg->device_name) + 1);
                }
                wifi_util_dbg_print(WIFI_PSM, "%s:%d mac entry already present\r\n",__func__, __LINE__);
                return;
            }
            ret = set_psm_record_by_name((mcfg->vap_index + 1), 1, MacFilter, mcfg->mac);
            if (ret == RETURN_OK) {
                temp_mac_entry = malloc(sizeof(wifi_mac_psm_param_t));
                if (temp_mac_entry == NULL) {
                    wifi_util_dbg_print(WIFI_PSM, "%s:%d malloc failure\r\n",__func__, __LINE__);
                    return;
                }
                temp_mac_entry->data_index = 1;
                strncpy(temp_mac_entry->mac, mcfg->mac, strlen(mcfg->mac) + 1);
                if (strlen(mcfg->device_name) != 0) {
                    strncpy(temp_mac_entry->device_name, mcfg->device_name, strlen(mcfg->device_name) + 1);
                }
                hash_map_put(psm_mac_map, strdup(mcfg->mac), temp_mac_entry);
                count = hash_map_count(psm_mac_map);
                update_macfilter_list( (mcfg->vap_index + 1), count, psm_mac_map);
            }
        }
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d update mac filter done\n", __func__, __LINE__);
}

void delete_psm_entry(char *record_name, int vap_index, int index)
{
    int retPsmSet = CCSP_SUCCESS;
    char recName[256] = {0};
    int instance_number = vap_index + 1;

    memset(recName, '\0', sizeof(recName));
    snprintf(recName, sizeof(recName), record_name, instance_number, index);
    retPsmSet = PSM_Del_Record(bus_handle, g_Subsystem, recName);
    if(retPsmSet == CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d  psm record delete:%s\r\n",__func__, __LINE__, recName);
    } else {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d PSM_del_Record returned error %d instance_number is %d:%s\n",__func__, __LINE__, retPsmSet, instance_number, recName);
    }
}

void Psm_Db_Delete_MacFilter(wifi_mac_entry_param_t *mcfg)
{
    hash_map_t *psm_mac_map;
    int count = 0;
    wifi_mac_psm_param_t *temp_mac_entry;

    wifi_util_info_print(WIFI_PSM, "%s:%d delete mac filter for vap index:%d\n", __func__, __LINE__,
        mcfg->vap_index);

    if (isVapHotspot(mcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d mac filter not supported for hotspot vap:%d\r\n",__func__, __LINE__, mcfg->vap_index);
        return;
    }

    psm_mac_map = get_mac_psm_obj(mcfg->vap_index);
    wifi_util_dbg_print(WIFI_PSM, "%s:%d mac filter vap_index:%d hash_map_address:%p\r\n",__func__, __LINE__, mcfg->vap_index, psm_mac_map);
    if (psm_mac_map == NULL) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d invalid mac filter vap_index:%d hash_map_address:%p\r\n",__func__, __LINE__, mcfg->vap_index, psm_mac_map);
        return;
    }

    temp_mac_entry = hash_map_remove(psm_mac_map, mcfg->mac);
    if (temp_mac_entry == NULL) {
        wifi_util_error_print(WIFI_PSM, "%s:%d mac filter entry not found for vap_index:%d hash_map_address:%p \r\n",
                                __func__, __LINE__, mcfg->vap_index, psm_mac_map);
        return;
    }
    wifi_util_dbg_print(WIFI_PSM, "%s:%d remove mac filter enetry:%s:%s\r\n",__func__, __LINE__, mcfg->mac, temp_mac_entry->mac);
    delete_psm_entry(MacFilter, mcfg->vap_index, temp_mac_entry->data_index);
    delete_psm_entry(MacFilterDevice, mcfg->vap_index, temp_mac_entry->data_index);
    count = hash_map_count(psm_mac_map);
    update_macfilter_list( (mcfg->vap_index + 1), count, psm_mac_map);
    if (temp_mac_entry != NULL) {
        free(temp_mac_entry);
    }

    wifi_util_info_print(WIFI_PSM, "%s:%d delete mac filter done\n", __func__, __LINE__);
}

void Psm_Db_Write(void *msg, ssp_event_subtype_t sub_type)
{
    wifi_radio_operationParam_t *rcfg;
    wifi_vap_info_t *acfg;
    wifi_global_param_t *gcfg;
    wifi_security_psm_param_t *scfg;
    wifi_mac_entry_param_t *mcfg;
    wifi_radio_feature_param_t *fcfg;

        switch(sub_type) {
            case radio_config: {
                rcfg = (wifi_radio_operationParam_t*)msg;
                Psm_Db_Write_Radio(rcfg);
                break;
            }

            case radio_feature_config: {
                fcfg = (wifi_radio_feature_param_t*)msg;
                Psm_Db_Write_Radio_Feat(fcfg);
                break;
            }

            case vap_config: {
                acfg = (wifi_vap_info_t*)msg;
                Psm_Db_Write_Vapinfo(acfg);
                break;
            }
            case global_config: {
                gcfg = (wifi_global_param_t*)msg;
                Psm_Db_Write_Global(gcfg);
                break;
            }
            case security_config: {
                scfg = (wifi_security_psm_param_t*)msg;
                Psm_Db_Write_Security(scfg);
                break;
            }
            case mac_config_add: {
                mcfg = (wifi_mac_entry_param_t*)msg;
                Psm_Db_Write_MacFilter(mcfg);
                break;
            }
            case mac_config_delete: {
                mcfg = (wifi_mac_entry_param_t*)msg;
                Psm_Db_Delete_MacFilter(mcfg);
                break;
            }
            default:
                break;
        }
}

void ssp_loop()
{
    struct timespec time_to_wait;
    struct timespec tv_now;
    int rc;
    ssp_event_t *queue_data = NULL;
    while (g_ssp_loop.exit_loop == false) {
        clock_gettime(CLOCK_MONOTONIC, &tv_now);
        time_to_wait.tv_nsec = 0;
        time_to_wait.tv_sec = tv_now.tv_sec + 30;

        pthread_mutex_lock(&g_ssp_loop.lock);
        rc = pthread_cond_timedwait(&g_ssp_loop.cond, &g_ssp_loop.lock, &time_to_wait);
        if (rc == 0) {
            while (queue_count(g_ssp_loop.queue)) {
                queue_data = queue_pop(g_ssp_loop.queue);
                if (queue_data == NULL) {
                    pthread_mutex_unlock(&g_ssp_loop.lock);
                    continue;
                }
                switch (queue_data->event_type) {
                    case ssp_event_type_psm_read:
                        break;

                    case ssp_event_type_psm_write:
                        Psm_Db_Write(queue_data->msg, queue_data->sub_type);
                        break;

                    default:
                        break;
                }

                if(queue_data->msg) {
                    free(queue_data->msg);
                }

                free(queue_data);
            }
        }
        pthread_mutex_unlock(&g_ssp_loop.lock);
    }
}

int push_data_to_ssp_queue(const void *msg, unsigned int len, ssp_event_type_t type, ssp_event_subtype_t sub_type)
{
    ssp_event_t *data;
    data = (ssp_event_t *)malloc(sizeof(ssp_event_t));
    if((data == NULL) || (g_ssp_loop.queue == NULL)){
        wifi_util_dbg_print(WIFI_PSM, "%s:%d NULL Pointer\n", __func__, __LINE__);
        free(data);
        return -1;
    }
    memset(data, 0, sizeof(ssp_event_t));
    data->event_type = type;
    data->sub_type = sub_type;

    if (msg != NULL) {
        data->msg = malloc(len + 1);
        if(data->msg == NULL) {
            free(data);
            return -1;
        }
        /* copy msg to data */
        memcpy(data->msg, msg, len);
        data->len = len;
    } else {
        data->msg = NULL;
        data->len = 0;
    }

    pthread_mutex_lock(&g_ssp_loop.lock);
    queue_push(g_ssp_loop.queue, data);
    pthread_cond_signal(&g_ssp_loop.cond);
    pthread_mutex_unlock(&g_ssp_loop.lock);

    return 0;
}
int ssp_loop_init()
{
    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&g_ssp_loop.cond, &cond_attr);
    pthread_condattr_destroy(&cond_attr);
    pthread_mutex_init(&g_ssp_loop.lock, NULL);
    g_ssp_loop.queue = queue_create();
    if (g_ssp_loop.queue == NULL) {
        wifi_util_dbg_print(WIFI_PSM, "%s:%d - Failed to create ssp queue\n", __func__, __LINE__);
        return -1;
    }
    g_ssp_loop.exit_loop = false;
    g_ssp_loop.post = push_data_to_ssp_queue;
    return 0;
}
