/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
  http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <pthread.h>
#include <ev.h>
#include <sys/time.h>
#include <assert.h>
#include "wifi_data_plane.h"
#if DML_SUPPORT
#include "wifi_monitor.h"
#endif // DML_SUPPORT
#include "wifi_db.h"
#include "wifi_mgr.h"
#include "wifi_ctrl.h"
#if DML_SUPPORT
#include "ssp_main.h"
#else
#include <stdlib.h>
#include <cap.h>
#endif // DML_SUPPORT

#include "wifi_util.h"

#if DML_SUPPORT
#include <execinfo.h>
#endif // DML_SUPPORT

#include <semaphore.h>
#include <fcntl.h>

#if DML_SUPPORT
extern void* bus_handle;
extern char g_Subsystem[32];

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
static char *WpsPin = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.WPSPin";
static char *FixedWmmParams        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.FixedWmmParamsValues";
static char *WifiVlanCfgVersion ="eRT.com.cisco.spvtg.ccsp.Device.WiFi.VlanCfgVerion";
static char *PreferPrivate      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.PreferPrivate";
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
static char *PreferPrivateConfigure = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.PreferPrivateConfigure";
static char *FactoryReset = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.FactoryReset";
static char *BandSteer_Enable = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable";
static char *InstWifiClientEnabled = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.InstWifiClientEnabled";
static char *InstWifiClientReportingPeriod = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.InstWifiClientReportingPeriod";
static char *InstWifiClientMacAddress = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.InstWifiClientMacAddress";
static char *InstWifiClientDefReportingPeriod = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.InstWifiClientDefReportingPeriod";
static char *WiFiActiveMsmtEnabled = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.WiFiActiveMsmtEnabled";
static char *WiFiActiveMsmtPktSize = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.WiFiActiveMsmtPktSize";
static char *WiFiActiveMsmtNumberOfSample = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.WiFiActiveMsmtNumberOfSample";
static char *WiFiActiveMsmtSampleDuration = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.WiFiActiveMsmtSampleDuration";
#define TR181_WIFIREGION_Code    "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code"
static char *MacFilter = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilter.%d";
static char *MacFilterDevice = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterDevice.%d";
static char *MacFilterList      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterList";
#endif // DML_SUPPORT

wifi_mgr_t g_wifi_mgr;
sem_t *sem;

static void daemonize(void) {
    int fd;

    /* initialize semaphores for shared processes */
    sem = sem_open ("pSemCcspWifi", O_CREAT | O_EXCL, 0644, 0);
    if (SEM_FAILED == sem) {
        wifi_util_error_print(WIFI_MGR,"Failed to create semaphore %d - %s\n", errno, strerror(errno));
        _exit(1);
    }
    /* name of semaphore is "pSemCcspWifi", semaphore is reached using this name */
    sem_unlink ("pSemCcspWifi");
    /* unlink prevents the semaphore existing forever */
    /* if a crash occurs during the execution         */
    wifi_util_dbg_print(WIFI_MGR,"Semaphore initialization Done!!\n");

    switch (fork()) {
        case 0:
            break;
        case -1:
            // Error
            wifi_util_error_print(WIFI_MGR,"Error daemonizing (fork)! %d - %s\n", errno, strerror(errno));
            exit(0);
            break;
        default:
            sem_wait (sem);
            sem_close (sem);
            _exit(0);
    }

    if (setsid() < 0) {
        wifi_util_error_print(WIFI_MGR,"Error demonizing (setsid)! %d - %s\n", errno, strerror(errno));
        exit(0);
    }

    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
}

wifi_db_t *get_wifidb_obj(void)
{
    return &g_wifi_mgr.wifidb;
}

wifi_ctrl_t *get_wifictrl_obj(void)
{
    return &g_wifi_mgr.ctrl;
}

wifi_mgr_t *get_wifimgr_obj(void)
{
    return &g_wifi_mgr;
}

int init_wifi_hal()
{
    int ret = RETURN_OK;

    wifi_util_info_print(WIFI_CTRL,"%s: start wifi hal init\n",__FUNCTION__);

    ret = wifi_hal_init();
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s wifi_init failed:ret :%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    /* Get the wifi capabilities from from hal*/
    ret = wifi_hal_getHalCapability(&g_wifi_mgr.hal_cap);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s wifi_getHalCapability returned with error %d\n", __FUNCTION__, ret);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int init_global_radio_config(rdk_wifi_radio_t *radios_cfg, UINT radio_index)
{
    UINT vap_array_index = 0;
    UINT i;
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();

    if (radios_cfg == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    snprintf(radios_cfg->name, sizeof(radios_cfg->name),"radio%d", radio_index+1);
    for (i = 0; i < (sizeof(wifi_hal_cap_obj->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); i++)
    {
        if (wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name[0] != '\0' && wifi_hal_cap_obj->wifi_prop.interface_map[i].rdk_radio_index == radio_index) {
            radios_cfg->vaps.rdk_vap_array[vap_array_index].vap_index = wifi_hal_cap_obj->wifi_prop.interface_map[i].index;
            radios_cfg->vaps.vap_map.vap_array[vap_array_index].vap_index = wifi_hal_cap_obj->wifi_prop.interface_map[i].index;
            radios_cfg->vaps.vap_map.vap_array[vap_array_index].radio_index = radio_index;
            strcpy((char *)radios_cfg->vaps.rdk_vap_array[vap_array_index].vap_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name);
            strcpy((char *)radios_cfg->vaps.vap_map.vap_array[vap_array_index].vap_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name);

            radios_cfg->vaps.rdk_vap_array[vap_array_index].associated_devices_map = hash_map_create();
            if (radios_cfg->vaps.rdk_vap_array[vap_array_index].associated_devices_map == NULL) {
                wifi_util_info_print(WIFI_CTRL,"%s:%d hash_map_create (associated_devices_hash_map) failed\n",__FUNCTION__, __LINE__);
            }
            radios_cfg->vaps.rdk_vap_array[vap_array_index].acl_map = hash_map_create();
            if (radios_cfg->vaps.rdk_vap_array[vap_array_index].acl_map == NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d hash_map_create(acl_map) failed\n",__FUNCTION__, __LINE__);
            }
            vap_array_index++;
            if (vap_array_index >= MAX_NUM_VAP_PER_RADIO) {
                break;
            }
        }
    }
    radios_cfg->vaps.radio_index = radio_index;
    radios_cfg->vaps.num_vaps = vap_array_index;
    radios_cfg->vaps.vap_map.num_vaps = vap_array_index;
    return RETURN_OK;
}

bool is_device_type_xb7(void)
{
    FILE *fp = NULL;
    char box_type[64] = {0};

    memset(box_type, '\0', sizeof(box_type)-1);
    fp = popen("cat /etc/device.properties | grep MODEL_NUM | cut -f 2 -d\"=\"", "r");
    if (fp != NULL) {
         while (fgets(box_type, sizeof(box_type), fp) != NULL) {
                wifi_util_dbg_print(WIFI_MGR,"%s:%d:box_type is %s\n", __func__, __LINE__, box_type);
        }
        pclose(fp);
    }

    if (strncmp(box_type, "CGM4331COM",strlen(box_type)-1) == 0) {
        return true;
    } else {
        return false;
    }
}

#if DML_SUPPORT
char* Get_PSM_Record_Status(char *recName, char *strValue)
{
    int retry = 0;
    int retPsmGet = RETURN_ERR;
    while(retry++ < 2) {
        retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, recName, NULL, &strValue);
        if (retPsmGet == CCSP_SUCCESS) {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d retPsmGet success for %s and strValue is %s\n", __FUNCTION__,__LINE__, recName, strValue);
            return strValue;
        } else if (retPsmGet == CCSP_CR_ERR_INVALID_PARAM) {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d PSM_Get_Record_Value2 (%s) returned error %d \n",__FUNCTION__,__LINE__,recName,retPsmGet);
            return NULL;
        } else {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d PSM_Get_Record_Value2 param (%s) returned error %d retry in 10 seconds \n",__FUNCTION__,__LINE__,recName,retPsmGet);
            continue;
        }
    }
    return NULL;
}

int wifi_db_update_global_config(wifi_global_param_t *global_cfg)
{
    char *str = NULL;
    char strValue[256] = {0};

    memset(global_cfg, 0, sizeof(wifi_global_param_t));
    wifidb_init_global_config_default(global_cfg);

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFivAPStatsFeatureEnable, strValue);
    if (str != NULL) {
        global_cfg->vap_stats_feature = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->vap_stats_feature; is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->vap_stats_feature, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for vap_stats_feature:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WifiVlanCfgVersion, strValue);
    if (str != NULL) {
        global_cfg->vlan_cfg_version = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->vlan_cfg_version is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->vlan_cfg_version, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for vlan_cfg_version:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(PreferPrivate, strValue);
    if (str != NULL) {
        global_cfg->prefer_private = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->prefer_private is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->prefer_private, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for prefer_private:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(NotifyWiFiChanges, strValue);
    if (str != NULL) {
        global_cfg->notify_wifi_changes = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->notify_wifi_changes is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->notify_wifi_changes, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for notify_wifi_changes:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(DiagnosticEnable, strValue);
    if (str != NULL) {
        global_cfg->diagnostic_enable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->diagnostic_enable is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->diagnostic_enable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for diagnostic_enable:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(GoodRssiThreshold, strValue);
    if (str != NULL) {
        global_cfg->good_rssi_threshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->good_rssi_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->good_rssi_threshold, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for good_rssi_threshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(AssocCountThreshold, strValue);
    if (str != NULL) {
        global_cfg->assoc_count_threshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->assoc_count_threshold is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->assoc_count_threshold, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for assoc_count_threshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(AssocMonitorDuration, strValue);
    if (str != NULL) {
        global_cfg->assoc_monitor_duration = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->assoc_monitor_duration is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->assoc_monitor_duration, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for assoc_monitor_duration:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(AssocGateTime, strValue);
    if (str != NULL) {
        global_cfg->assoc_gate_time = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->assoc_gate_time is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->assoc_gate_time, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for assoc_gate_time:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(RapidReconnectIndicationEnable, strValue);
    if (str != NULL) {
        global_cfg->rapid_reconnect_enable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->rapid_reconnect_enable is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->rapid_reconnect_enable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for rapid_reconnect_enable:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(FeatureMFPConfig, strValue);
    if (str != NULL) {
        global_cfg->mfp_config_feature = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->mfp_config_feature is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->mfp_config_feature, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for mfp_config_feature:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFiTxOverflowSelfheal, strValue);
    if (str != NULL) {
        global_cfg->tx_overflow_selfheal = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->tx_overflow_selfheal is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->tx_overflow_selfheal, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for tx_overflow_selfheal:%s \r\n", __func__, __LINE__, str);    
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFiForceDisableWiFiRadio, strValue);
    if (str != NULL) {
        global_cfg->force_disable_radio_feature = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->force_disable_radio_feature is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->force_disable_radio_feature, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for force_disable_radio_feature:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFiForceDisableRadioStatus, strValue);
    if (str != NULL) {
        global_cfg->force_disable_radio_status = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->force_disable_radio_status is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->force_disable_radio_status, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for force_disable_radio_status:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(ValidateSSIDName, strValue);
    if (str != NULL) {
        global_cfg->validate_ssid = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->validate_ssid is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->validate_ssid, str, _ansc_atoi(str));
    }  else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for validate_ssid:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(FixedWmmParams, strValue);
    if (str != NULL) {
        global_cfg->fixed_wmm_params = _ansc_atoi(strValue);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->fixed_wmm_params is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->fixed_wmm_params, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for fixed_wmm_params:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(TR181_WIFIREGION_Code, strValue);
    if (str != NULL) {
        strcpy(global_cfg->wifi_region_code, str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_region_code is %s and str is %s \n", global_cfg->wifi_region_code, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_region_code:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WpsPin, strValue);
    if (str != NULL) {
        //global_cfg->wps_pin = _ansc_atoi(str);
        strcpy(global_cfg->wps_pin, str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wps_pin is %s and str is %s and _ansc_atoi(str) is %d\n", global_cfg->wps_pin, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wps_pin:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(PreferPrivateConfigure, strValue);
    if (str != NULL) {
        global_cfg->prefer_private_configure = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->prefer_private_configure is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->prefer_private_configure, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for prefer_private_configure:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(FactoryReset, strValue);
    if (str != NULL) {
        global_cfg->factory_reset = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->factory_reset is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->factory_reset, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for factory_reset:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(BandSteer_Enable, strValue);
    if (str != NULL) {
        global_cfg->bandsteering_enable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->bandsteering_enable is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->bandsteering_enable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for bandsteering_enable:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(InstWifiClientEnabled, strValue);
    if (str != NULL) {
        global_cfg->inst_wifi_client_enabled = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_enabled is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->inst_wifi_client_enabled, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_enabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(InstWifiClientReportingPeriod, strValue);
    if (str != NULL) {
        global_cfg->inst_wifi_client_reporting_period = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_reporting_period is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->inst_wifi_client_reporting_period, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_reporting_period:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(InstWifiClientMacAddress, strValue);
    if (str != NULL) {
        str_to_mac_bytes(str, global_cfg->inst_wifi_client_mac);
        //strncpy(global_cfg->inst_wifi_client_mac,str,sizeof(global_cfg->inst_wifi_client_mac)-1);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_mac is %s and str is %s \r\n", global_cfg->inst_wifi_client_mac, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_mac:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(InstWifiClientDefReportingPeriod, strValue);
    if (str != NULL) {
        global_cfg->inst_wifi_client_def_reporting_period = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_def_reporting_period is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->inst_wifi_client_def_reporting_period, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_def_reporting_period:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFiActiveMsmtEnabled, strValue);
    if (str != NULL) {
        global_cfg->wifi_active_msmt_enabled = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_enabled is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->wifi_active_msmt_enabled, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_enabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFiActiveMsmtPktSize, strValue);
    if (str != NULL) {
        global_cfg->wifi_active_msmt_pktsize = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_pktsize is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->wifi_active_msmt_pktsize, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_pktsize:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFiActiveMsmtNumberOfSample, strValue);
    if (str != NULL) {
        global_cfg->wifi_active_msmt_num_samples = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_num_samples is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->wifi_active_msmt_num_samples, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_num_samples:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WiFiActiveMsmtSampleDuration, strValue);
    if (str != NULL) {
        global_cfg->wifi_active_msmt_sample_duration = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_sample_duration is %d and str is %s and _ansc_atoi(str) is %d\n", global_cfg->wifi_active_msmt_sample_duration, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_sample_duration:%s \r\n", __func__, __LINE__, str);
    }

    if (wifidb_update_wifi_global_config(global_cfg) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: Failed to update global config\n", __func__, __LINE__);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: Updated global config table successfully\n",__func__, __LINE__);
    }

    return RETURN_OK;
}

int get_total_mac_list_from_psm(int instance_number, unsigned int *total_entries, char *mac_list)
{
    int l_total_entries = 0;
    int retPsmGet = CCSP_SUCCESS;
    char recName[256] = {0};
    char strValue[256] = {0};
    char *l_strValue = NULL;

    memset(recName, '\0', sizeof(recName));
    snprintf(recName, sizeof(recName), MacFilterList, instance_number);
    memset(strValue, 0, sizeof(strValue));
    wifi_util_dbg_print(WIFI_MGR, "%s:%d  recName: %s instance_number:%d\n",__func__, __LINE__, recName, instance_number);
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, recName, NULL, &l_strValue);
    if((retPsmGet == CCSP_SUCCESS) && (strlen(l_strValue) > 0) )
    {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d  mac list data:%s\n",__func__, __LINE__, l_strValue);
        strncpy(strValue, l_strValue, (strlen(l_strValue) + 1));
        sscanf(strValue, "%d:", &l_total_entries);
        wifi_util_dbg_print(WIFI_MGR, "%s:%d  recName: %s total entry:%d\n",__func__, __LINE__, recName, l_total_entries);
        if (l_total_entries != 0) {
            *total_entries = (unsigned int)l_total_entries;
            strncpy(mac_list, strValue, (strlen(strValue) + 1));
            wifi_util_dbg_print(WIFI_MGR, "%s:%d  recName: %s total entry:%d list:%s\n",__func__, __LINE__, recName, *total_entries, mac_list);
            return RETURN_OK;
        }
    } else {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d PSM maclist get failure:%d mac list data:%s\n",__func__, __LINE__, retPsmGet, l_strValue);
    }

    return RETURN_ERR;
}

void get_radio_params_from_psm(unsigned int radio_index, wifi_radio_operationParam_t *radio_cfg)
{
    char *str = NULL;
    char recName[256] = {0};
    char strValue[256] = {0};
    unsigned int instance_number = radio_index + 1;

    memset(radio_cfg, 0, sizeof(wifi_radio_operationParam_t));
    wifidb_init_radio_config_default((instance_number - 1), radio_cfg);

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), CTSProtection, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->ctsProtection = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->ctsProtection is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->ctsProtection, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for ctsProtection:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BeaconInterval, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->beaconInterval = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->beaconInterval is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->beaconInterval, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for beaconInterval:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), DTIMInterval, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->dtimPeriod = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->dtimPeriod is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->dtimPeriod, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for dtimPeriod:%s \r\n", __func__, __LINE__,str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), FragThreshold, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->fragmentationThreshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->fragmentationThreshold is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->fragmentationThreshold, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for fragmentationThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), RTSThreshold, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->rtsThreshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->rtsThreshold is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->rtsThreshold, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for rtsThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), ObssCoex, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->obssCoex = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->obssCoex is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->obssCoex, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for obssCoex:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), STBCEnable, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->stbcEnable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->stbcEnable is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->stbcEnable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for stbcEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), GuardInterval, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->guardInterval = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->guardInterval is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->guardInterval, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for guardInterval:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), GreenField, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->greenFieldEnable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->greenFieldEnable is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->greenFieldEnable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for greenFieldEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), TransmitPower, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->transmitPower = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->transmitPower is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->transmitPower, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for transmitPower:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), UserControl, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->userControl = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->userControl is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->userControl, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for userControl:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), AdminControl, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->adminControl = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->adminControl is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->adminControl, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for adminControl:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), MeasuringRateRd, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->radioStatsMeasuringRate = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->radioStatsMeasuringRate is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->radioStatsMeasuringRate, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for radioStatsMeasuringRate:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), MeasuringIntervalRd, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->radioStatsMeasuringInterval = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->radioStatsMeasuringInterval is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->radioStatsMeasuringInterval, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for radioStatsMeasuringInterval:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), SetChanUtilThreshold, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->chanUtilThreshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->chanUtilThreshold is %d and str is %s and ansc_atoi-str is %d\n", radio_cfg->chanUtilThreshold, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for chanUtilThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), SetChanUtilSelfHealEnable, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        radio_cfg->chanUtilSelfHealEnable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->chanUtilSelfHealEnable is %d and str is %s and _ansc_atoi(str) is %d\n", radio_cfg->chanUtilSelfHealEnable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for chanUtilSelfHealEnable:%s \r\n", __func__, __LINE__, str);
    }
}

int mac_list_entry_update_data(char *str, unsigned int *data_index)
{
    wifi_util_dbg_print(WIFI_MGR, "%s:%d  mac_filter_list:%s\n",__func__, __LINE__, str);
    char* token;
    char* rest = str;
    int count;
    token = strtok_r(rest, ":", &rest);
    if ((token == NULL) || (rest == NULL)) {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d  invalid mac_filter_list:%s\n",__func__, __LINE__, str);
        return RETURN_ERR;
    }

    count = atoi(token);
    while ((token = strtok_r(rest, ",", &rest))) {
        count--;
        if (count == -1) {
            wifi_util_dbg_print(WIFI_MGR, "%s:%d  invalid mac_filter_list count:%d\n",__func__, __LINE__, count);
            break;
        }
        *(data_index + count) = atoi(token);
    }

    return RETURN_OK;
}

void get_psm_mac_list_entry(unsigned int instance_number, char *l_vap_name, unsigned int total_entry, unsigned int *data_index)
{
    char recName[256] = {0};
    char strValue[256] = {0};
    char macfilterkey[128] = {0};
    char *str = NULL;
    unsigned int index = 0;
    acl_entry_t *temp_psm_mac_param;
    mac_addr_str_t new_mac_str;
    memset(new_mac_str, 0, sizeof(new_mac_str));
    memset(macfilterkey, 0, sizeof(macfilterkey));

    wifi_util_dbg_print(WIFI_MGR,"%s:%d mac total entry:%d\r\n", __func__, __LINE__, total_entry);
    while (total_entry > 0) {
        index = data_index[total_entry - 1];

        temp_psm_mac_param = malloc(sizeof(acl_entry_t));
        if (temp_psm_mac_param == NULL) {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d malloc failure mac total entry:%d\r\n", __func__, __LINE__, total_entry);
            continue;
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), MacFilterDevice, instance_number, index);
        str = Get_PSM_Record_Status(recName, strValue);
        if (str != NULL) {
            strcpy(temp_psm_mac_param->device_name, str);
            wifi_util_dbg_print(WIFI_MGR,"psm get device_name is %s\r\n", str);
        } else {
            wifi_util_dbg_print(WIFI_MGR,"[Failure] psm record_name: %s\n", recName);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), MacFilter, instance_number, index);
        str = Get_PSM_Record_Status(recName, strValue);
        if (str != NULL) {
            str_to_mac_bytes(str, temp_psm_mac_param->mac);
            wifi_util_dbg_print(WIFI_MGR,"psm get mac is %s\n", str);

            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", l_vap_name, str);
            wifidb_update_wifi_macfilter_config(macfilterkey, temp_psm_mac_param, true);
        } else {
            wifi_util_dbg_print(WIFI_MGR,"[Failure] psm record_name: %s\n", recName);
        }
        total_entry--;
    }
}

int get_vap_params_from_psm(unsigned int vap_index, wifi_vap_info_t *vap_config)
{
    wifi_front_haul_bss_t *bss_cfg;

    char *str = NULL;
    char recName[256] = {0};
    char strValue[256] = {0};
    unsigned int instance_number = vap_index + 1;

    memset(vap_config, 0, sizeof(wifi_vap_info_t));
    wifidb_init_vap_config_default((instance_number - 1), vap_config);
    if (isVapSTAMesh(vap_config->vap_index)) {
        return RETURN_ERR;
    }
    bss_cfg = &vap_config->u.bss_info;

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), WmmEnable, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->wmm_enabled = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->wmm_enabled is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->wmm_enabled, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for wmm_enabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), UAPSDEnable, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->UAPSDEnabled = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->UAPSDEnabled is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->UAPSDEnabled, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for UAPSDEnabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), vAPStatsEnable, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->vapStatsEnable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->vapStatsEnable is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->vapStatsEnable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for vapStatsEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), WmmNoAck, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->wmmNoAck = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->wmmNoAck is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->wmmNoAck, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for wmmNoAck:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BssMaxNumSta, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->bssMaxSta = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->bssMaxSta is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->bssMaxSta, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for bssMaxSta:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), MacFilterMode, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        unsigned int mf_mode = _ansc_atoi(str);
        if (mf_mode == 0) {
            bss_cfg->mac_filter_enable = false;
            bss_cfg->mac_filter_mode  = wifi_mac_filter_mode_black_list;
        } else if(mf_mode == 1) {
            bss_cfg->mac_filter_enable = true;
            bss_cfg->mac_filter_mode  = wifi_mac_filter_mode_white_list;
        } else if(mf_mode == 2) {
            bss_cfg->mac_filter_enable = true;
            bss_cfg->mac_filter_mode  = wifi_mac_filter_mode_black_list;
        }
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->mac_filter_mode is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->mac_filter_mode, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for mac_filter_mode:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), ApIsolationEnable, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->isolation = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->isolation is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->isolation, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for isolation:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BSSTransitionActivated, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->bssTransitionActivated = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->bssTransitionActivated is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->bssTransitionActivated, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for bssTransitionActivated:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BssHotSpot, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->bssHotspot = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->bssHotspot is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->bssHotspot, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for bssHotspot:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), WpsPushButton, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->wpsPushButton = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->wpsPushButton is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->wpsPushButton, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for wpsPushButton:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), RapidReconnThreshold, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->rapidReconnThreshold = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->rapidReconnThreshold is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->rapidReconnThreshold, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for rapidReconnThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), RapidReconnCountEnable, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->rapidReconnectEnable = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->rapidReconnectEnable is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->rapidReconnectEnable, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for rapidReconnectEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), NeighborReportActivated, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->nbrReportActivated = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->nbrReportActivated is %d and str is %s and _ansc_atoi(str) is %d\n", bss_cfg->nbrReportActivated, str, _ansc_atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for nbrReportActivated:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), ApMFPConfig, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        bss_cfg->security.mfp = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"cfg->mfp is %d and str is %s\n", bss_cfg->security.mfp, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for mfp:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BeaconRateCtl, instance_number);
    str = Get_PSM_Record_Status(recName, strValue);
    if (str != NULL) {
        strcpy(bss_cfg->beaconRateCtl,str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->beaconRateCtl is %s and str is %s \r\n", bss_cfg->beaconRateCtl, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for beaconRateCtl:%s \r\n", __func__, __LINE__, str);
    }

    nvram_get_current_ssid(bss_cfg->ssid, (instance_number - 1));
    wifi_security_modes_t mode = bss_cfg->security.mode;
    if ((mode == wifi_security_mode_wpa_enterprise) || (mode == wifi_security_mode_wpa2_enterprise ) || (mode == wifi_security_mode_wpa3_enterprise) || (mode == wifi_security_mode_wpa_wpa2_enterprise)) {
        //TBD
    } else {
        nvram_get_current_password(bss_cfg->security.u.key.key, (instance_number - 1));
    }

    return RETURN_OK;
}

int wifi_db_update_radio_config()
{
    wifi_radio_operationParam_t radio_cfg;
    unsigned int radio_index;
    int retval=0;

    for(radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        memset(&radio_cfg, 0, sizeof(wifi_radio_operationParam_t));

        /* read values from psm and update db */
        get_radio_params_from_psm(radio_index, &radio_cfg);

        retval = wifidb_update_wifi_radio_config(radio_index, &radio_cfg);
        if (retval != 0) {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: Failed to update radio config in wifi db\n",__func__, __LINE__);
        } else {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: Successfully updated radio config in wifidb for index:%d\n",__func__, __LINE__,radio_index);
        }
    }

    return RETURN_OK;
}

int wifi_db_update_vap_config()
{
    wifi_vap_info_t vap_cfg;
    int retval;
    unsigned int mac_index_list[128];
    unsigned int total_mac_list;
    char strValue[256] = {0};

    memset(mac_index_list, 0, sizeof(mac_index_list));

    /* read values from psm and update db */
    for (unsigned int vap_index = 0; vap_index < getTotalNumberVAPs(); vap_index++) {

        get_vap_params_from_psm(vap_index, &vap_cfg);

        if (!isVapHotspot(vap_index)) {
            if (get_total_mac_list_from_psm((vap_index + 1), &total_mac_list, strValue) == RETURN_OK) {
                mac_list_entry_update_data(strValue, mac_index_list);
                get_psm_mac_list_entry((vap_index + 1), vap_cfg.vap_name, total_mac_list, mac_index_list);
            }
        }

        retval = wifidb_update_wifi_vap_info(vap_cfg.vap_name, &vap_cfg);
        if (retval != 0) {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: Failed to update vap config in wifi db\n",__func__, __LINE__);
        } else {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: Successfully updated vap config in wifidb \r\n",__func__, __LINE__);
        }

        if (isVapSTAMesh(vap_cfg.vap_index)) {
            retval = wifidb_update_wifi_security_config(vap_cfg.vap_name, &vap_cfg.u.sta_info.security);
        } else {
            retval = wifidb_update_wifi_security_config(vap_cfg.vap_name, &vap_cfg.u.bss_info.security);
        }
        if (retval != 0) {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: Failed to update vap config in wifi db\n",__func__, __LINE__);
        } else {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: Successfully updated vap config in wifidb \r\n",__func__, __LINE__);
        }
    }

    return RETURN_OK;
}

int wifi_db_update_psm_values()
{
    int retval;
    wifi_global_param_t global_config;
    memset(&global_config, 0, sizeof(global_config));

    retval = wifi_db_update_global_config(&global_config);
    wifi_util_dbg_print(WIFI_MGR,"%s:%d: Global config update %d\n",__func__, __LINE__,retval);

    retval = wifi_db_update_radio_config();

    wifi_util_dbg_print(WIFI_MGR,"%s:%d: Radio config update %d\n",__func__, __LINE__,retval);

    retval = wifi_db_update_vap_config();

    wifi_util_dbg_print(WIFI_MGR,"%s:%d: Vap config update %d\n",__func__, __LINE__,retval);
    return retval;
}

static void rbus_subscription_handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

    wifi_util_dbg_print(WIFI_MGR,"%s:%d rbus rbus_subscription_handler\n", __func__, __LINE__);
}

int wifi_mgr_rbus_subsription(rbusHandle_t *rbus_handle)
{
    int rc;
    char *component_name = "WifiMgr";

    rc = rbus_open(rbus_handle, component_name);

    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d Rbus open failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_MGR,"%s:%d rbus open success\n", __func__, __LINE__);

    if (rbusEvent_Subscribe(*rbus_handle, WIFI_PSM_DB_NAMESPACE, rbus_subscription_handler, NULL, 0) != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, WIFI_PSM_DB_NAMESPACE);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, WIFI_PSM_DB_NAMESPACE);
    }

    if (rbusEvent_Subscribe(*rbus_handle, LAST_REBOOT_REASON_NAMESPACE, rbus_subscription_handler, NULL, 0) != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, LAST_REBOOT_REASON_NAMESPACE);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, LAST_REBOOT_REASON_NAMESPACE);
    }

    return RETURN_OK;
}

int get_wifi_db_psm_enable_status(bool *wifi_psm_db_enabled)
{
    char *str = NULL;
    char strValue[256] = {0};

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(WIFI_PSM_DB_NAMESPACE, strValue);
    if (str != NULL) {
        *wifi_psm_db_enabled = _ansc_atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"str is %s and wifi_psm_db_enabled is %d\n", str, *wifi_psm_db_enabled);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d  wifi_psm_db_enabled:%d\r\n", __func__, __LINE__, *wifi_psm_db_enabled);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_wifi_last_reboot_reason_psm_value(char *last_reboot_reason)
{
    char *str = NULL;
    char strValue[256] = {0};

    memset(strValue, 0, sizeof(strValue));
    str = Get_PSM_Record_Status(LAST_REBOOT_REASON_NAMESPACE, strValue);
    if (str != NULL) {
        strcpy(last_reboot_reason, str);
        wifi_util_dbg_print(WIFI_MGR,"str is %s and last_reboot_reason is %s\n", str, last_reboot_reason);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d last_reboot_reason:%s \r\n", __func__, __LINE__, last_reboot_reason);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int set_bool_psm_value(bool data_value, char *recName)
{
    char instanceNumStr[64] = {0};
    int retPsmSet;

    _ansc_itoa(data_value, instanceNumStr, 10);
    wifi_util_dbg_print(WIFI_MGR, "%s:%d record_name:%s\n",__func__, __LINE__, recName);

    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_string, instanceNumStr);
    if(retPsmSet == CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d set bool value:%d\n",__func__, __LINE__, data_value);
    } else {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d PSM_Set_Record_Value2 returned error %d while setting bool param %d\n",__func__, __LINE__, retPsmSet, data_value);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_all_param_from_psm_and_set_into_db(void)
{
/*      check for psm-db(Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-PSM-DB.Enable) and
**      last reboot reason(Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason)
**      if psm-db is false and last reboot reason if not factory-reset,
**      then update wifi-db with values from psm */
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    if (is_device_type_xb7() == true) {
        bool wifi_psm_db_enabled = false;
        char last_reboot_reason[32];
        memset(last_reboot_reason, 0, sizeof(last_reboot_reason));

        rbusHandle_t rbus_handle;
        if (wifi_mgr_rbus_subsription(&rbus_handle) == RETURN_OK) {
            if (get_rbus_param(rbus_handle, rbus_bool_data, WIFI_PSM_DB_NAMESPACE, &wifi_psm_db_enabled) != RETURN_OK) {
                get_wifi_db_psm_enable_status(&wifi_psm_db_enabled);
            }
            if (get_rbus_param(rbus_handle, rbus_string_data, LAST_REBOOT_REASON_NAMESPACE, last_reboot_reason) != RETURN_OK) {
                get_wifi_last_reboot_reason_psm_value(last_reboot_reason);
            }
        } else {
            get_wifi_db_psm_enable_status(&wifi_psm_db_enabled);
            get_wifi_last_reboot_reason_psm_value(last_reboot_reason);
        }

        if (g_wifidb->is_db_update_required == true) {
            int retval;
            retval = wifi_db_update_psm_values();
            if (retval == RETURN_OK) {
                wifi_util_info_print(WIFI_MGR,"%s updated WIFI DB from psm\n",__func__);
            } else {
                wifi_util_error_print(WIFI_MGR,"%s: failed to update WIFI DB from psm\n",__func__);
                return RETURN_ERR;
            }
            sleep(1);
        }

        if (wifi_psm_db_enabled == true) {
            set_bool_psm_value(false, WIFI_PSM_DB_NAMESPACE);
        }

    }

    init_wifidb_data();//TBD

    //Set Wifi Global Parameters
    init_wifi_global_config();

    return RETURN_OK;
}
#endif // DML_SUPPORT

int init_wifimgr()
{
    if (!drop_root()) {
        wifi_util_error_print(WIFI_MGR,"%s: drop_root function failed!\n", __func__);
        gain_root_privilege();
    }
    struct stat sb;
    char db_file[128];

    if(wifi_hal_pre_init() != RETURN_OK) {
        wifi_util_error_print(WIFI_MGR,"%s wifi hal pre_init failed\n", __func__);
        return -1;
    }

    //Initialize HAL and get Capabilities
    assert(init_wifi_hal() == RETURN_OK);

#if DML_SUPPORT
    int itr=0;
    for (itr=0; itr < (int)getNumberRadios(); itr++) {
        init_global_radio_config(&g_wifi_mgr.radio_config[itr], itr);
    }
#endif // DML_SUPPORT

#if DML_SUPPORT
    pthread_cond_init(&g_wifi_mgr.dml_init_status, NULL);
    pthread_mutex_init(&g_wifi_mgr.lock, NULL);
#endif // DML_SUPPORT

    sprintf(db_file, "%s/rdkb-wifi.db", WIFIDB_DIR);
    if (stat(db_file, &sb) != 0) {
        wifi_util_info_print(WIFI_MGR,"WiFiDB file not present FRcase\n");
        g_wifi_mgr.ctrl.factory_reset = true;
        wifi_util_info_print(WIFI_MGR,"WiFiDB  FRcase factory_reset is true\n");
    } else {
        g_wifi_mgr.ctrl.factory_reset = false;
        wifi_util_info_print(WIFI_MGR,"WiFiDB FRcase factory_reset is false\n");

        //get_all_param_from_psm_and_set_into_db();
    }

    if (init_wifi_ctrl(&g_wifi_mgr.ctrl) != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifi ctrl init failed\n", __func__);
        return -1;
    } else {
        wifi_util_info_print(WIFI_MGR,"%s: wifi ctrl initalization success\n", __func__);
    }

    //Init csi_data_queue
    if (g_wifi_mgr.csi_data_queue == NULL) {
        g_wifi_mgr.csi_data_queue = queue_create();
    }

#if DML_SUPPORT
    //init ssp_loop.
    if (ssp_loop_init() < 0) {
        wifi_util_error_print(WIFI_MGR,"%s:%d ssp_loop_init failed \n", __func__, __LINE__);
    }
#endif // DML_SUPPORT

    //Start Wifi DB server, and Initialize data Cache
    init_wifidb();

    return 0;
}

int start_wifimgr()
{
#if DML_SUPPORT
    start_dml_main(&g_wifi_mgr.ssp);
    wifi_util_info_print(WIFI_MGR,"%s: waiting for dml init\n", __func__);
    pthread_cond_wait(&g_wifi_mgr.dml_init_status,&g_wifi_mgr.lock);
    wifi_util_info_print(WIFI_MGR,"%s: dml init complete\n", __func__);

    pthread_cond_destroy(&g_wifi_mgr.dml_init_status);
    pthread_mutex_unlock(&g_wifi_mgr.lock);
#endif // DML_SUPPORT

    if (start_wifi_ctrl(&g_wifi_mgr.ctrl) != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifi ctrl start failed\n", __func__);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    bool run_daemon = true;
    int  idx = 0;

    for (idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-c" ) == 0) {
            run_daemon = false;
        }
    }

    if (run_daemon) {
        daemonize();
    }

    if (init_wifimgr() != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifimgr init failed\n", __func__);
        return -1;
    }

    rbus_get_vap_init_parameter(WIFI_DEVICE_MODE, &g_wifi_mgr.ctrl.network_mode);
    if (start_wifimgr() != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifimgr start failed\n", __func__);
        return -1;
    }

    wifi_util_info_print(WIFI_MGR,"%s: Exiting Wifi mgr\n", __func__);
    return 0;
}
