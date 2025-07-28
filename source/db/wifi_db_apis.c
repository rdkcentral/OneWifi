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

#include "wifi_data_plane.h"
#include "wifi_monitor.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#include <cjson/cJSON.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "os.h"
#include "util.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"
#include "schema.h"
#include "log.h"
#include "ds.h"
#include "json_util.h"
#include "target.h"
#include <ev.h>
#include "wifi_db.h"
#include "dirent.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"
#include "wifi_mgr.h"
#include "wifi_dml.h"
#include "wifi_monitor.h"

#define MAX_BUF_SIZE 128
#define ONEWIFI_DB_VERSION_EXISTS_FLAG 100017
#define ONEWIFI_DB_OLD_VERSION_FILE "/tmp/wifi_db_old_version"
#define ONEWIFI_DB_VERSION_OFFCHANNELSCAN_FLAG 100018
#define ONEWIFI_DB_VERSION_LOGINTERVAL_FLAG 100022
#define ONEWIFI_DB_VERSION_CHUTILITY_LOGINTERVAL_FLAG 100023
#define ONEWIFI_DB_VERSION_IEEE80211BE_FLAG 100025
#define ONEWIFI_DB_VERSION_MBO_FLAG 100031
#define OFFCHAN_DEFAULT_TSCAN_IN_MSEC 63
#define OFFCHAN_DEFAULT_NSCAN_IN_SEC 10800
#define OFFCHAN_DEFAULT_TIDLE_IN_SEC 5
#define BOOTSTRAP_INFO_FILE             "/opt/secure/bootstrap.json"
#define COUNTRY_CODE_LEN 4
#define RDKB_CCSP_SUCCESS               100

#define ONEWIFI_DB_VERSION_DFS_TIMER_RADAR_DETECT_FLAG 100030
#define DFS_DEFAULT_TIMER_IN_MIN 30
#define ONEWIFI_DB_VERSION_TCM_FLAG 100032
#define TCM_TIMEOUT_MS 150
#define TCM_MIN_MGMT_FRAMES 3
#define TCM_WEIGHTAGE "0.6"
#define TCM_THRESHOLD "0.18"

#define ONEWIFI_DB_VERSION_WPA3_COMP_FLAG 100033
#define WPA3_COMPATIBILITY 8192
#define ONEWIFI_DB_VERSION_HOSTAP_MGMT_FRAME_CTRL_FLAG 100034
#define ONEWIFI_DB_VERSION_RSS_MEMORY_THRESHOLD_FLAG 100035
#define ONEWIFI_DB_VERSION_MGT_FRAME_RATE_LIMIT 100036
#define ONEWIFI_DB_VERSION_MANAGED_WIFI_FLAG 100038
#define DEFAULT_MANAGED_WIFI_SPEED_TIER 2
#define ONEWIFI_DB_VERSION_STATS_FLAG 100037
#define ONEWIFI_DB_VERSION_MEMWRAPTOOL_FLAG 100040
#define DEFAULT_WHIX_CHUTILITY_LOGINTERVAL 900
#define DEFAULT_WHIX_LOGINTERVAL 3600

#define ONEWIFI_DB_VERSION_WPA3_T_DISABLE_FLAG 100042

#ifdef CONFIG_NO_MLD_ONLY_PRIVATE
#define MLD_UNIT_COUNT 8
#else
#define MLD_UNIT_COUNT 1
#endif /* CONFIG_NO_MLD_ONLY_PRIVATE */

ovsdb_table_t table_Wifi_Radio_Config;
ovsdb_table_t table_Wifi_VAP_Config;
ovsdb_table_t table_Wifi_Security_Config;
ovsdb_table_t table_Wifi_Device_Config;
ovsdb_table_t table_Wifi_Interworking_Config;
ovsdb_table_t table_Wifi_GAS_Config;
ovsdb_table_t table_Wifi_Global_Config;
ovsdb_table_t table_Wifi_MacFilter_Config;
ovsdb_table_t table_Wifi_Passpoint_Config;
ovsdb_table_t table_Wifi_Anqp_Config;
ovsdb_table_t table_Wifi_Preassoc_Control_Config;
ovsdb_table_t table_Wifi_Postassoc_Control_Config;
ovsdb_table_t table_Wifi_Connection_Control_Config;
ovsdb_table_t table_Wifi_Rfc_Config;

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
static char *BeaconRateCtl   = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.Radio.AccessPoint.%d.BeaconRateCtl";
static char *BSSTransitionActivated    = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.BSSTransitionActivated";
static char *BssHotSpot        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.HotSpot";
#ifdef FEATURE_SUPPORT_WPS
static char *WpsPushButton = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.WpsPushButton";
#endif
static char *RapidReconnThreshold        = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.RapidReconnThreshold";
static char *RapidReconnCountEnable      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.RapidReconnCountEnable";
static char *vAPStatsEnable = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.vAPStatsEnable";
static char *NeighborReportActivated     = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_NeighborReportActivated";
static char *WhixLoginterval = "dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WHIX.LogInterval";
static char *WhixChUtilityLoginterval = "dmsb.device.deviceinfo.X_RDKCENTRAL-COM_WHIX.ChUtilityLogInterval";
#ifndef NEWPLATFORM_PORT
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
#endif // NEWPLATFORM_PORT
#define TR181_WIFIREGION_Code    "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code"
static char *MacFilter = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilter.%d";
static char *MacFilterDevice = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterDevice.%d";
static char *MacFilterList      = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.MacFilterList";
#if defined(FEATURE_OFF_CHANNEL_SCAN_5G)
static char *Tscan = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelTscan";
static char *Nscan = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelNscan";
static char *Tidle = "Device.WiFi.Radio.%d.Radio_X_RDK_OffChannelTidle";
#endif //FEATURE_OFF_CHANNEL_SCAN_5G

#ifdef ONEWIFI_DB_SUPPORT

static bool dbwritten = false;

void wifidb_init_gas_config_default(wifi_GASConfiguration_t *config);

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Device_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Device_Config  holds value before modification
                new_rec - schema_Wifi_Device_Config  holds value after modification
  Description : Callback function called when Wifi_Device_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_Device_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Device_Config *old_rec,
        struct schema_Wifi_Device_Config *new_rec)
{
    if (mon->mon_type == OVSDB_UPDATE_DEL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__); 
    } else if (mon->mon_type == OVSDB_UPDATE_NEW) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:New\n", __func__, __LINE__);
    } else if (mon->mon_type == OVSDB_UPDATE_MODIFY) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Modify\n", __func__, __LINE__);
    } else {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
}
/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Rfc_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Rfc_Config  holds value before modification
                new_rec - schema_Wifi_Rfc_Config  holds value after modification
  Description : Callback function called when Wifi_Rfc_Config modified in wifidb
 *************************************************************************************
 *************************************************************************************/
void callback_Wifi_Rfc_Config(ovsdb_update_monitor_t *mon, struct schema_Wifi_Rfc_Config *old_rec,
    struct schema_Wifi_Rfc_Config *new_rec)
{
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d:Delete\n", __func__, __LINE__);
    } else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY)) {

        wifi_util_dbg_print(WIFI_DB, "%s:%d:RFC Config New/Modify \n", __func__, __LINE__);
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        strcpy(rfc_param->rfc_id, new_rec->rfc_id);
        rfc_param->wifipasspoint_rfc = new_rec->wifipasspoint_rfc;
        rfc_param->wifiinterworking_rfc = new_rec->wifiinterworking_rfc;
        rfc_param->radiusgreylist_rfc = new_rec->radiusgreylist_rfc;
        rfc_param->dfsatbootup_rfc = new_rec->dfsatbootup_rfc;
        rfc_param->dfs_rfc = new_rec->dfs_rfc;
        rfc_param->wpa3_rfc = new_rec->wpa3_rfc;
        rfc_param->levl_enabled_rfc = new_rec->levl_enabled_rfc;
        rfc_param->twoG80211axEnable_rfc = new_rec->twoG80211axEnable_rfc;
        rfc_param->hotspot_open_2g_last_enabled = new_rec->hotspot_open_2g_last_enabled;
        rfc_param->hotspot_open_5g_last_enabled = new_rec->hotspot_open_5g_last_enabled;
        rfc_param->hotspot_open_6g_last_enabled = new_rec->hotspot_open_6g_last_enabled;
        rfc_param->hotspot_secure_2g_last_enabled = new_rec->hotspot_secure_2g_last_enabled;
        rfc_param->hotspot_secure_5g_last_enabled = new_rec->hotspot_secure_5g_last_enabled;
        rfc_param->memwraptool_app_rfc = new_rec->memwraptool_app_rfc;
        rfc_param->wifi_offchannelscan_app_rfc = new_rec->wifi_offchannelscan_app_rfc;
        rfc_param->wifi_offchannelscan_sm_rfc = new_rec->wifi_offchannelscan_sm_rfc;
        rfc_param->hotspot_secure_6g_last_enabled = new_rec->hotspot_secure_6g_last_enabled;
        rfc_param->tcm_enabled_rfc = new_rec->tcm_enabled_rfc;
        rfc_param->wpa3_compatibility_enable = new_rec->wpa3_compatibility_enable;

        wifi_util_dbg_print(WIFI_DB,
            "%s:%d wifipasspoint_rfc=%d wifiinterworking_rfc=%d radiusgreylist_rfc=%d "
            "dfsatbootup_rfc=%d dfs_rfc=%d wpa3_rfc=%d twoG80211axEnable_rfc=%d "
            "hotspot_open_2g_last_enabled=%dhotspot_open_5g_last_enabled=%d "
            "hotspot_open_6g_last_enabled=%d hotspot_secure_2g_last_enabled=%d "
            "hotspot_secure_5g_last_enabled=%d hotspot_secure_6g_last_enabled=%d "
            "wifi_offchannelscan_app_rfc=%d offchannelscan=%d rfc_id=%s "
            "MemwrapTool=%d levl_enabled_rfc=%d tcm_enabled_rfc=%d wpa3_compatibility_enable=%d \n",
            __func__, __LINE__, rfc_param->wifipasspoint_rfc, rfc_param->wifiinterworking_rfc,
            rfc_param->radiusgreylist_rfc, rfc_param->dfsatbootup_rfc, rfc_param->dfs_rfc,
            rfc_param->wpa3_rfc, rfc_param->twoG80211axEnable_rfc,
            rfc_param->hotspot_open_2g_last_enabled, rfc_param->hotspot_open_5g_last_enabled,
            rfc_param->hotspot_open_6g_last_enabled, rfc_param->hotspot_secure_2g_last_enabled,
            rfc_param->hotspot_secure_5g_last_enabled, rfc_param->hotspot_secure_6g_last_enabled,
            rfc_param->wifi_offchannelscan_app_rfc, rfc_param->wifi_offchannelscan_sm_rfc,
            rfc_param->rfc_id, rfc_param->memwraptool_app_rfc, rfc_param->levl_enabled_rfc,
            rfc_param->tcm_enabled_rfc, rfc_param->wpa3_compatibility_enable);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
}
/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Radio_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Radio_Config  holds value before modification
                new_rec - schema_Wifi_Radio_Config  holds value after modification
  Description : Callback function called when Wifi_Radio_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_Radio_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Radio_Config *old_rec,
        struct schema_Wifi_Radio_Config *new_rec)

{
    int index = 0;
    int i = 0;
    int band;
    char *tmp, *ptr;
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    wifi_radio_operationParam_t *l_radio_cfg = NULL;
    wifi_radio_feature_param_t *f_radio_cfg = NULL;
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        if(old_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Radio config update failed \n",__func__, __LINE__);
            return;
        }
        if((convert_radio_name_to_index((unsigned int *)&index,old_rec->radio_name))!=0)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid radio name \n",__func__, __LINE__,old_rec->radio_name);
            return;
        }
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Update radio data for radio index=%d \n",__func__, __LINE__,index);
        l_radio_cfg = get_wifidb_radio_map(index);
        if(l_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_map \n",__func__, __LINE__,index);
            return;
        }
        f_radio_cfg = get_wifidb_radio_feat_map(index);
        if(f_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_feat_map \n",__func__, __LINE__,index);
            return;
        }
        wifidb_init_radio_config_default(index, l_radio_cfg, f_radio_cfg);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Radio Config New/Modify \n", __func__, __LINE__);
        if(new_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Radio config update failed \n",__func__, __LINE__);
            return;
        }
        if((convert_radio_name_to_index((unsigned int *)&index,new_rec->radio_name))!=0)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid radio name \n",__func__, __LINE__,new_rec->radio_name);
            return;
        }
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Update radio data for radio index=%d \n",__func__, __LINE__,index);
        if(index > (int)getNumberRadios())
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid radio index, Data not fount \n",__func__, __LINE__,index);
            return;
        }
        l_radio_cfg = get_wifidb_radio_map(index);
        if(l_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalide get_wifidb_radio_map \n",__func__, __LINE__,index);
            return;
        }
        f_radio_cfg = get_wifidb_radio_feat_map(index);
        if(f_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_feat_map \n",__func__, __LINE__,index);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        strncpy(g_wifidb->radio_config[index].name,new_rec->radio_name,sizeof(g_wifidb->radio_config[index].name)-1);
        l_radio_cfg->enable = new_rec->enabled;

        /* The band is fixed by interface map in HAL */
        if (convert_radio_index_to_freq_band(&g_wifidb->hal_cap.wifi_prop, index,
            &band) == RETURN_OK)
        {
            l_radio_cfg->band = band;
        }
        else
        {
            wifi_util_dbg_print(WIFI_DB, "%s:%d Failed to convert radio index %d to band\n",
                __func__, __LINE__, index);
            l_radio_cfg->band = new_rec->freq_band;
        }

        l_radio_cfg->autoChannelEnabled = new_rec->auto_channel_enabled;
        l_radio_cfg->channel = new_rec->channel;
        l_radio_cfg->channelWidth = new_rec->channel_width;
        if ((new_rec->hw_mode != 0) && (validate_wifi_hw_variant(new_rec->freq_band, new_rec->hw_mode) == RETURN_OK)) {
            l_radio_cfg->variant = new_rec->hw_mode;
        }
        l_radio_cfg->csa_beacon_count = new_rec->csa_beacon_count;
        if (new_rec->country != 0) {
            l_radio_cfg->countryCode = new_rec->country;
        }
        if (new_rec->operating_environment != 0) {
            l_radio_cfg->operatingEnvironment = new_rec->operating_environment;
        }
        l_radio_cfg->DCSEnabled = new_rec->dcs_enabled;
        l_radio_cfg->DfsEnabled = new_rec->dfs_enabled;
        l_radio_cfg->DfsEnabledBootup = rfc_param->dfsatbootup_rfc;
        l_radio_cfg->dtimPeriod = new_rec->dtim_period;
        if (new_rec->beacon_interval != 0) {
            l_radio_cfg->beaconInterval = new_rec->beacon_interval;
        }
        l_radio_cfg->operatingClass = new_rec->operating_class;
        l_radio_cfg->basicDataTransmitRates = new_rec->basic_data_transmit_rate;
        l_radio_cfg->operationalDataTransmitRates = new_rec->operational_data_transmit_rate;
        l_radio_cfg->fragmentationThreshold = new_rec->fragmentation_threshold;
        l_radio_cfg->guardInterval = new_rec->guard_interval;
        if (new_rec->transmit_power != 0) {
            l_radio_cfg->transmitPower = new_rec->transmit_power;
        }
        l_radio_cfg->rtsThreshold = new_rec->rts_threshold;
        l_radio_cfg->factoryResetSsid = new_rec->factory_reset_ssid;
        l_radio_cfg->radioStatsMeasuringRate = new_rec->radio_stats_measuring_rate;
        l_radio_cfg->radioStatsMeasuringInterval = new_rec->radio_stats_measuring_interval;
        l_radio_cfg->ctsProtection = new_rec->cts_protection;
        l_radio_cfg->obssCoex = new_rec->obss_coex;
        l_radio_cfg->stbcEnable = new_rec->stbc_enable;
        l_radio_cfg->greenFieldEnable = new_rec->greenfield_enable;
        l_radio_cfg->userControl = new_rec->user_control;
        l_radio_cfg->adminControl = new_rec->admin_control;
        l_radio_cfg->chanUtilThreshold = new_rec->chan_util_threshold;
        l_radio_cfg->chanUtilSelfHealEnable = new_rec->chan_util_selfheal_enable;
        l_radio_cfg->EcoPowerDown = new_rec->eco_power_down;
        l_radio_cfg->DFSTimer = new_rec->dfs_timer;
        if(strlen(new_rec->radar_detected) != 0) {
            strncpy(l_radio_cfg->radarDetected, new_rec->radar_detected, sizeof(l_radio_cfg->radarDetected)-1);
        }
#ifdef FEATURE_SUPPORT_ECOPOWERDOWN
        if (l_radio_cfg->EcoPowerDown)
        {
            //Update enable status based on EcoPowerDown.
            l_radio_cfg->enable = false;
        }
#endif // FEATURE_SUPPORT_ECOPOWERDOWN

        tmp = new_rec->secondary_channels_list;
        while ((ptr = strchr(tmp, ',')) != NULL)
        {
            ptr++;
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config Secondary Channel list %d \t",__func__, __LINE__,atoi(tmp));
            l_radio_cfg->channelSecondary[i] = atoi(tmp);
            tmp = ptr;
            i++;
        }
        l_radio_cfg->numSecondaryChannels = new_rec->num_secondary_channels;

        i = 0;
        tmp = new_rec->amsdu_tid;
        while ((ptr = strchr(tmp, ',')) != NULL)
        {
            ptr++;
            l_radio_cfg->amsduTid[i] = atoi(tmp);
            tmp = ptr;
            i++;
        }

        f_radio_cfg->OffChanTscanInMsec = new_rec->Tscan;
        f_radio_cfg->OffChanNscanInSec = (new_rec->Nscan == 0) ? 0 : (24*3600)/(new_rec->Nscan);
        f_radio_cfg->OffChanTidleInSec = new_rec->Tidle;
        f_radio_cfg->radio_index = index;
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d OperatingEnviroment=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d, radio_stats_measuring_rate = %d, radio_stats_measuring_interval = %d, cts_protection %d, obss_coex= %d, stbc_enable= %d, greenfield_enable= %d, user_control= %d, admin_control= %d,chan_util_threshold= %d, chan_util_selfheal_enable= %d, eco_power_down= %d dfs_timer:%d radar_Detected:%s amsdu_tid: [%d, %d, %d, %d, %d, %d, %d, %d] \n",__func__, __LINE__,l_radio_cfg->enable,l_radio_cfg->band,l_radio_cfg->autoChannelEnabled,l_radio_cfg->channel,l_radio_cfg->channelWidth,l_radio_cfg->variant,l_radio_cfg->csa_beacon_count,l_radio_cfg->countryCode,l_radio_cfg->operatingEnvironment,l_radio_cfg->DCSEnabled,l_radio_cfg->numSecondaryChannels,new_rec->secondary_channels_list,l_radio_cfg->dtimPeriod,l_radio_cfg->beaconInterval,l_radio_cfg->operatingClass,l_radio_cfg->basicDataTransmitRates,l_radio_cfg->operationalDataTransmitRates,l_radio_cfg->fragmentationThreshold,l_radio_cfg->guardInterval,l_radio_cfg->transmitPower,l_radio_cfg->rtsThreshold,l_radio_cfg->factoryResetSsid,l_radio_cfg->radioStatsMeasuringInterval,l_radio_cfg->radioStatsMeasuringInterval,l_radio_cfg->ctsProtection,l_radio_cfg->obssCoex,l_radio_cfg->stbcEnable,l_radio_cfg->greenFieldEnable,l_radio_cfg->userControl,l_radio_cfg->adminControl,l_radio_cfg->chanUtilThreshold,l_radio_cfg->chanUtilSelfHealEnable, l_radio_cfg->EcoPowerDown, l_radio_cfg->DFSTimer, l_radio_cfg->radarDetected, l_radio_cfg->amsduTid[0], l_radio_cfg->amsduTid[1], l_radio_cfg->amsduTid[2], l_radio_cfg->amsduTid[3], l_radio_cfg->amsduTid[4], l_radio_cfg->amsduTid[5], l_radio_cfg->amsduTid[6], l_radio_cfg->amsduTid[7]);
        wifi_util_dbg_print(WIFI_DB, "%s:%d Wifi_Radio_Config data Tscan=%lu Nscan=%lu, Tidle=%lu\n", __FUNCTION__, __LINE__, f_radio_cfg->OffChanTscanInMsec, f_radio_cfg->OffChanNscanInSec, f_radio_cfg->OffChanTidleInSec);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }

    stop_wifi_sched_timer(index, ctrl, wifi_radio_sched);
}

/************************************************************************************
 ************************************************************************************
  Function    : logSecurityKeyConfiguration
  Parameter   : radioIndex     - Index number of radio

  Description : It will check if the private vap's passwords are same or different
                when we changed the keypassPhrase.
 *************************************************************************************
**************************************************************************************/
static UINT logSecurityKeyConfiguration (UINT radioIndex)
{
    wifi_vap_info_t *wifiVapInfo = NULL;
    unsigned int index = 0;
    char Passphrase1[64] = {0};
    char Passphrase2[64] = {0};
    char *RadioFreqBand1 = NULL;
    char *RadioFreqBand2 = NULL;
    char *RadioBandstr1 = NULL;
    char *RadioBandstr2 = NULL;
    char TempRadioFreqBand1[32] = {0};
    char TempRadioFreqBand2[32] = {0};
    UINT apIndex = 0;
    char *saveptr = NULL;

    apIndex = getPrivateApFromRadioIndex(radioIndex);
    wifi_util_info_print(WIFI_DB, "Value of apIndex = %u and value of radioIndex = %u \n", apIndex, radioIndex);
    wifiVapInfo = getVapInfo(apIndex);
    if (NULL == wifiVapInfo) {
        wifi_util_error_print(WIFI_DB, "%s:%d: Value of wifiVapInfo is NULL\n", __func__, __LINE__);
        return -1;
    }
    memset(Passphrase1, 0, sizeof(Passphrase1));
    strncpy((char*)Passphrase1, wifiVapInfo->u.bss_info.security.u.key.key, sizeof(Passphrase1) - 1);
    RadioBandstr1 = convert_radio_index_to_band_str_g(radioIndex);
    if (NULL == RadioBandstr1) {
        wifi_util_error_print(WIFI_DB, "%s:%d: Value of RadioBandstr1 is NULL and radioIndex = %u\n", __func__, __LINE__, radioIndex);
        return -1;
    }
    strncpy((char*)TempRadioFreqBand1, RadioBandstr1, sizeof(TempRadioFreqBand1) - 1);
    RadioFreqBand1 = strtok_r(TempRadioFreqBand1, "GHz", &saveptr);
    for(index = 0; index < getNumberRadios(); index++) {
        if (index == radioIndex) {
            continue;
        }
        RadioBandstr2 = convert_radio_index_to_band_str_g(index);
        if (NULL == RadioBandstr2) {
            wifi_util_error_print(WIFI_DB, "%s:%d: Value of RadioBandstr2 is NULL and radioIndex = %u\n", __func__, __LINE__, index);
            return -1;
        }
        strncpy((char*)TempRadioFreqBand2, RadioBandstr2, sizeof(TempRadioFreqBand2) - 1);
        RadioFreqBand2 = strtok_r(TempRadioFreqBand2, "GHz", &saveptr);
        apIndex = getPrivateApFromRadioIndex(index);
        wifiVapInfo = getVapInfo(apIndex);
        if (NULL == wifiVapInfo) {
            wifi_util_error_print(WIFI_DB, "Value of wifiVapInfo is NULL and index = %u\n", apIndex);
            return -1;
        }
        memset(Passphrase2, 0, sizeof(Passphrase2));
        strncpy((char*)Passphrase2, wifiVapInfo->u.bss_info.security.u.key.key, sizeof(Passphrase2) - 1);
        /* If the string length varies, the password should also vary; otherwise, it may or may not be the same. */
        if (strlen(Passphrase1) != strlen(Passphrase2)) {
            wifi_util_info_print(WIFI_DB,"Different passwords were configured on User Private SSID for %s and %s GHz radios. \n",
                                (radioIndex < index) ?  RadioFreqBand1 : RadioFreqBand2, (radioIndex > index) ?  RadioFreqBand1 : RadioFreqBand2);
        } else if (strncmp(Passphrase1, Passphrase2, sizeof(Passphrase1)) == 0) {
            wifi_util_info_print(WIFI_DB,"Same password was configured on User Private SSID for %s and %s GHz radios. \n",
                                 (radioIndex < index) ?  RadioFreqBand1 : RadioFreqBand2, (radioIndex > index) ?  RadioFreqBand1 : RadioFreqBand2);
        } else {
            wifi_util_info_print(WIFI_DB,"Different passwords were configured on User Private SSID for %s and %s GHz radios. \n",
                                (radioIndex < index) ?  RadioFreqBand1 : RadioFreqBand2, (radioIndex > index) ?  RadioFreqBand1 : RadioFreqBand2);
        }
    }
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Security_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Security_Config  holds value before modification
                new_rec - schema_Wifi_Security_Config  holds value after modification
  Description : Callback function called when Wifi_Security_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_Security_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Security_Config *old_rec,
        struct schema_Wifi_Security_Config *new_rec)
{
    int i = 0;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_vap_security_t *l_security_cfg = NULL;
    int vap_index = 0;
    UINT radio_index = 0;
    bool is_keypassphrase_changed = false;
    int mfp;

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        if(old_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Security config update failed \n",__func__, __LINE__);
            return;
        }

        i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(i == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        if (isVapSTAMesh(i)) {
            l_security_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(i);
            if(l_security_cfg == NULL)
            {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter \n",__func__, __LINE__,old_rec->vap_name);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
        } else {
            l_security_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(i);
            if(l_security_cfg == NULL)
            {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_bss_security_parameter \n",__func__, __LINE__,old_rec->vap_name);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
        }
        memset(l_security_cfg, 0, sizeof(wifi_vap_security_t));
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(vap_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:New/Modify %d\n", __func__, __LINE__,mon->mon_type);

        if(new_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Security config update failed \n",__func__, __LINE__);
            return;
        }

        i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(i == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }

        if (isVapSTAMesh(i)) {
            l_security_cfg = (wifi_vap_security_t *)  Get_wifi_object_sta_security_parameter(i);
            if(l_security_cfg == NULL)
            {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter \n",__func__, __LINE__,new_rec->vap_name);
                return;
            }
        } else {
            l_security_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(i);
            if(l_security_cfg == NULL)
            {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_bss_security_parameter \n",__func__, __LINE__,new_rec->vap_name);
                return;
            }
            if (isVapPrivate(i)) {
                if ((strncmp(l_security_cfg->u.key.key, new_rec->keyphrase, sizeof(new_rec->keyphrase))) != 0) {
                    is_keypassphrase_changed = true;
                }
            }
        }

        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        l_security_cfg->mode = new_rec->security_mode;
        l_security_cfg->mode = new_rec->security_mode_new;
        l_security_cfg->encr = new_rec->encryption_method;

        convert_security_mode_string_to_integer(&mfp,(char *)&new_rec->mfp_config);
        l_security_cfg->mfp = (wifi_mfp_cfg_t)mfp;
        l_security_cfg->rekey_interval = new_rec->rekey_interval;
        l_security_cfg->strict_rekey = new_rec->strict_rekey;
        l_security_cfg->eapol_key_timeout = new_rec->eapol_key_timeout;
        l_security_cfg->eapol_key_retries = new_rec->eapol_key_retries;
        l_security_cfg->eap_identity_req_timeout = new_rec->eap_identity_req_timeout;
        l_security_cfg->eap_identity_req_retries = new_rec->eap_identity_req_retries;
        l_security_cfg->eap_req_timeout = new_rec->eap_req_timeout;
        l_security_cfg->eap_req_retries = new_rec->eap_req_retries;
        l_security_cfg->disable_pmksa_caching = new_rec->disable_pmksa_caching;
        l_security_cfg->wpa3_transition_disable = new_rec->wpa3_transition_disable;
        if (!security_mode_support_radius(l_security_cfg->mode))
        {
            l_security_cfg->u.key.type = new_rec->key_type;
            strncpy(l_security_cfg->u.key.key,new_rec->keyphrase,sizeof(l_security_cfg->u.key.key)-1);
        }
        else
        {
            if (strlen(new_rec->radius_server_ip) != 0) {
                strncpy((char *)l_security_cfg->u.radius.ip,(char *)new_rec->radius_server_ip,sizeof(l_security_cfg->u.radius.ip)-1);
            }

            if (strlen(new_rec->secondary_radius_server_ip) != 0) {
                strncpy((char *)l_security_cfg->u.radius.s_ip,new_rec->secondary_radius_server_ip,sizeof(l_security_cfg->u.radius.s_ip)-1);
            }
            l_security_cfg->u.radius.port = new_rec->radius_server_port;
            if (strlen(new_rec->radius_server_key) != 0) {
                strncpy(l_security_cfg->u.radius.key,new_rec->radius_server_key,sizeof(l_security_cfg->u.radius.key)-1);
            }
            l_security_cfg->u.radius.s_port = new_rec->secondary_radius_server_port;
            if (strlen(new_rec->secondary_radius_server_key) != 0) {
                strncpy(l_security_cfg->u.radius.s_key,new_rec->secondary_radius_server_key,sizeof(l_security_cfg->u.radius.s_key)-1);
            }
            l_security_cfg->u.radius.max_auth_attempts = new_rec->max_auth_attempts;
            l_security_cfg->u.radius.blacklist_table_timeout = new_rec->blacklist_table_timeout;
            l_security_cfg->u.radius.identity_req_retry_interval = new_rec->identity_req_retry_interval;
            l_security_cfg->u.radius.server_retries = new_rec->server_retries;
            getIpAddressFromString(new_rec->das_ip,&l_security_cfg->u.radius.dasip);
            l_security_cfg->u.radius.dasport = new_rec->das_port;
            if (strlen(new_rec->das_key) != 0) {
                strncpy(l_security_cfg->u.radius.daskey,new_rec->das_key,sizeof(l_security_cfg->u.radius.daskey)-1);
            }
        }
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d "
                "rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d mfg=%s cfg_key_type=%d vap_name=%s rekey_interval = %d strict_rekey  = %d "
                "eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d "
                "eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d "
                "identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d wpa3_transition_disable=%d security_mode_new=%d\n",
                __func__, __LINE__,new_rec->security_mode,new_rec->encryption_method,new_rec->radius_server_ip,new_rec->radius_server_port,
                new_rec->secondary_radius_server_ip,new_rec->secondary_radius_server_port,new_rec->mfp_config,new_rec->key_type,new_rec->vap_name,
                new_rec->rekey_interval,new_rec->strict_rekey,new_rec->eapol_key_timeout,new_rec->eapol_key_retries,new_rec->eap_identity_req_timeout,
                new_rec->eap_identity_req_retries,new_rec->eap_req_timeout,new_rec->eap_req_retries,new_rec->disable_pmksa_caching,
                new_rec->max_auth_attempts,new_rec->blacklist_table_timeout,new_rec->identity_req_retry_interval,new_rec->server_retries,
                new_rec->das_ip,new_rec->das_port,new_rec->wpa3_transition_disable,new_rec->security_mode_new);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if (vap_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        if (is_keypassphrase_changed == true) {
            radio_index = getRadioIndexFromAp(vap_index);
            if ((logSecurityKeyConfiguration(radio_index)) != 0) {
                wifi_util_error_print(WIFI_DB,"%s:%d: Failed to execute logSecurityKeyConfiguration \n", __func__, __LINE__);
            }
            is_keypassphrase_changed = false;
        }
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Interworking_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Interworking_Config  holds value before modification
                new_rec - schema_Wifi_Interworking_Config  holds value after modification
  Description : Callback function called when Wifi_Interworking_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_Interworking_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Interworking_Config *old_rec,
        struct schema_Wifi_Interworking_Config *new_rec)
{
    int i = 0;
    int vap_index = 0;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_interworking_t *l_interworking_cfg = NULL;

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        if(old_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Interworking config update failed \n",__func__, __LINE__);
            return;
        }
        i =convert_vap_name_to_array_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(i == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(vap_index == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }

        l_interworking_cfg = Get_wifi_object_interworking_parameter(vap_index);
        if(l_interworking_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_interworking_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        wifidb_init_interworking_config_default(vap_index,l_interworking_cfg->interworking);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:New/Modify %d\n", __func__, __LINE__,mon->mon_type);
        if(new_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Interworking config update failed \n",__func__, __LINE__);
            return;
        }

        i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(i == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }

        l_interworking_cfg = Get_wifi_object_interworking_parameter(i);
        if(l_interworking_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_interworking_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        l_interworking_cfg->interworking.interworkingEnabled = new_rec->enable;
        l_interworking_cfg->interworking.accessNetworkType = new_rec->access_network_type;
        l_interworking_cfg->interworking.internetAvailable = new_rec->internet;
        l_interworking_cfg->interworking.asra = new_rec->asra;
        l_interworking_cfg->interworking.esr = new_rec->esr;
        l_interworking_cfg->interworking.uesa = new_rec->uesa;
        l_interworking_cfg->interworking.hessOptionPresent = new_rec->hess_option_present;
        if (strlen(new_rec->hessid) != 0) {
            strncpy(l_interworking_cfg->interworking.hessid, new_rec->hessid, sizeof(l_interworking_cfg->interworking.hessid)-1);
        }
        l_interworking_cfg->interworking.venueGroup = new_rec->venue_group;
        l_interworking_cfg->interworking.venueType = new_rec->venue_type;
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Update Wifi_Interworking_Config table vap_name=%s Enable=%d access_network_type=%d internet=%d asra=%d esr=%d uesa=%d hess_present=%d hessid=%s venue_group=%d venue_type=%d",__func__, __LINE__,new_rec->vap_name,new_rec->enable,new_rec->access_network_type,new_rec->internet,new_rec->asra,new_rec->esr,new_rec->uesa,new_rec->hess_option_present,new_rec->hessid,new_rec->venue_group,new_rec->venue_type); 
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(vap_index == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_VAP_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_VAP_Config  holds value before modification
                new_rec - schema_Wifi_VAP_Config  holds value after modification
  Description : Callback function called when Wifi_VAP_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_VAP_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_VAP_Config *old_rec,
        struct schema_Wifi_VAP_Config *new_rec)
{
    int radio_index = 0;
    int vap_index = 0;
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    wifi_front_haul_bss_t *l_bss_param_cfg = NULL;
    wifi_back_haul_sta_t *l_sta_param_cfg = NULL;
    wifi_vap_info_t *l_vap_param_cfg = NULL;
    wifi_vap_info_map_t *l_vap_param_map_cfg = NULL;
    wifi_vap_info_t *l_vap_info = NULL;
    rdk_wifi_vap_info_t *l_rdk_vap_info = NULL;

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(vap_index == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
        l_vap_info = getVapInfo(vap_index);
        if(l_vap_info == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid getVapInfo(%d) \n",__func__, __LINE__, vap_index);
            return;
        }
        l_rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
        if (l_rdk_vap_info == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: Failed to get rdk vap info for index %d\n",
                __func__, __LINE__, vap_index);
            return;
        }
        wifidb_init_vap_config_default(vap_index, l_vap_info, l_rdk_vap_info);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:New/Modify %d\n", __func__, __LINE__,mon->mon_type);
        if(new_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Vap config update failed \n",__func__, __LINE__);
            return;
        }

        if((convert_radio_name_to_index((unsigned int *)&radio_index,new_rec->radio_name))!=0)
        {
             wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid radio name \n",__func__, __LINE__,new_rec->radio_name);
             return;
        }

        l_vap_param_map_cfg = get_wifidb_vap_map(radio_index);
        if(l_vap_param_map_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_parameters \n",__func__, __LINE__);
            return;
        }

        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(vap_index == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }

        l_vap_info = get_wifidb_vap_parameters(vap_index);
        if (l_vap_info == NULL) {
            wifi_util_error_print(WIFI_DB, "%s:%d: Failed to get rdk vap info for index %d\n", __func__, __LINE__, vap_index);
            return;
        }

        l_rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
        if (l_rdk_vap_info == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: Failed to get rdk vap info for index %d\n",
                __func__, __LINE__, vap_index);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
        if(new_rec->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
            if(vap_index != 2 && vap_index != 3) {
                wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
                new_rec->exists = true;
            }
#else

            wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
            new_rec->exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
        }
#endif /*!defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)*/
        l_rdk_vap_info->exists = new_rec->exists;
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);

        if (strlen(new_rec->repurposed_vap_name) != 0) {
            strncpy(l_vap_info->repurposed_vap_name, new_rec->repurposed_vap_name, (sizeof(l_vap_info->repurposed_vap_name) - 1));
        }

        if (isVapSTAMesh(vap_index)) {
            l_sta_param_cfg = get_wifi_object_sta_parameter(vap_index);
            if (l_sta_param_cfg == NULL) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Get_wifi_object_sta_parameter failed \n",__func__, __LINE__);
                return;
            }
            l_vap_param_cfg = get_wifidb_vap_parameters(vap_index);
            if (l_vap_param_cfg == NULL) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer get_wifidb_vap_parameters failed \n",__func__, __LINE__);
                return;
            }
            pthread_mutex_lock(&g_wifidb->data_cache_lock);
            l_vap_param_cfg->radio_index = radio_index;
            l_vap_param_cfg->vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
            if ((int)l_vap_param_cfg->vap_index < 0) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            strncpy(l_vap_param_cfg->vap_name, new_rec->vap_name,(sizeof(l_vap_param_cfg->vap_name)-1));
            if (strlen(new_rec->bridge_name) != 0){
                strncpy(l_vap_param_cfg->bridge_name, new_rec->bridge_name,(sizeof(l_vap_param_cfg->bridge_name)-1));
            } else {
                get_vap_interface_bridge_name(vap_index, l_vap_param_cfg->bridge_name);
            }

            if (strlen(new_rec->ssid) != 0) {
                strncpy((char *)l_sta_param_cfg->ssid, new_rec->ssid, (sizeof(l_sta_param_cfg->ssid) - 1));
            }
            l_sta_param_cfg->enabled = new_rec->enabled;
            l_sta_param_cfg->scan_params.period = new_rec->period;
            l_sta_param_cfg->scan_params.channel.channel = new_rec->channel;
            l_sta_param_cfg->scan_params.channel.band = new_rec->freq_band;
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        } else {
            l_bss_param_cfg = Get_wifi_object_bss_parameter(vap_index);
            if (l_bss_param_cfg == NULL) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Get_wifi_object_bss_parameter failed \n",__func__, __LINE__);
                return;
            }
            l_vap_param_cfg = get_wifidb_vap_parameters(vap_index);
            if (l_vap_param_cfg == NULL) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer get_wifidb_vap_parameters failed \n",__func__, __LINE__);
                return;
            }
            pthread_mutex_lock(&g_wifidb->data_cache_lock);
            l_vap_param_cfg->radio_index = radio_index;
            l_vap_param_cfg->vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
            if ((int)l_vap_param_cfg->vap_index < 0) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__, new_rec->vap_name);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            strncpy(l_vap_param_cfg->vap_name, new_rec->vap_name,(sizeof(l_vap_param_cfg->vap_name)-1));
            if (strlen(new_rec->ssid) != 0) {
                strncpy(l_bss_param_cfg->ssid,new_rec->ssid,(sizeof(l_bss_param_cfg->ssid)-1));
            }
            l_bss_param_cfg->enabled = new_rec->enabled;
            l_bss_param_cfg->showSsid = new_rec->ssid_advertisement_enabled;
            l_bss_param_cfg->isolation = new_rec->isolation_enabled;
            l_bss_param_cfg->mgmtPowerControl = new_rec->mgmt_power_control;
            l_bss_param_cfg->bssMaxSta = new_rec->bss_max_sta;
            l_bss_param_cfg->bssTransitionActivated = new_rec->bss_transition_activated;
            l_bss_param_cfg->nbrReportActivated = new_rec->nbr_report_activated;
            l_bss_param_cfg->network_initiated_greylist = new_rec->network_initiated_greylist;
            l_bss_param_cfg->connected_building_enabled = new_rec->connected_building_enabled;
            l_bss_param_cfg->mdu_enabled = new_rec->mdu_enabled;
            l_bss_param_cfg->am_config.npc.speed_tier = new_rec->speed_tier;
            l_bss_param_cfg->rapidReconnectEnable = new_rec->rapid_connect_enabled;
            l_bss_param_cfg->rapidReconnThreshold = new_rec->rapid_connect_threshold;
            l_bss_param_cfg->vapStatsEnable = new_rec->vap_stats_enable;
            l_bss_param_cfg->mac_filter_enable = new_rec->mac_filter_enabled;
            l_bss_param_cfg->mac_filter_mode = new_rec->mac_filter_mode;
            l_bss_param_cfg->wmm_enabled = new_rec->wmm_enabled;
            if (strlen(new_rec->anqp_parameters) != 0) {
                strncpy((char *)l_bss_param_cfg->interworking.anqp.anqpParameters,new_rec->anqp_parameters,(sizeof(l_bss_param_cfg->interworking.anqp.anqpParameters)-1));
            }
            if (strlen(new_rec->hs2_parameters) != 0) {
                strncpy((char *)l_bss_param_cfg->interworking.passpoint.hs2Parameters,new_rec->hs2_parameters,(sizeof(l_bss_param_cfg->interworking.passpoint.hs2Parameters)-1));
            }
            l_bss_param_cfg->UAPSDEnabled = new_rec->uapsd_enabled;
            l_bss_param_cfg->beaconRate = new_rec->beacon_rate;
            
            if (isVapLnfPsk(vap_index) && new_rec->mdu_enabled) {
                if (strlen(new_rec->repurposed_bridge_name) != 0) {
                    strncpy(l_vap_param_cfg->bridge_name, new_rec->repurposed_bridge_name, sizeof(l_vap_param_cfg->bridge_name)-1);
                    l_vap_param_cfg->bridge_name[sizeof(l_vap_param_cfg->bridge_name)-1] = '\0';
                    strncpy(l_vap_param_cfg->repurposed_bridge_name, new_rec->bridge_name, sizeof(l_vap_param_cfg->repurposed_bridge_name));
                    l_vap_param_cfg->repurposed_bridge_name[sizeof(l_vap_param_cfg->repurposed_bridge_name)-1] = '\0';
                }
            } else {
                if (strlen(new_rec->bridge_name) != 0) {
                    strncpy(l_vap_param_cfg->bridge_name, new_rec->bridge_name, sizeof(l_vap_param_cfg->bridge_name)-1);
                    l_vap_param_cfg->bridge_name[sizeof(l_vap_param_cfg->bridge_name)-1] = '\0';
                } else {
                    get_vap_interface_bridge_name(vap_index, l_vap_param_cfg->bridge_name);
                }
            }
            
            l_bss_param_cfg->wmmNoAck = new_rec->wmm_noack;
            l_bss_param_cfg->wepKeyLength = new_rec->wep_key_length;
            l_bss_param_cfg->bssHotspot = new_rec->bss_hotspot;
#if defined(FEATURE_SUPPORT_WPS)
            l_bss_param_cfg->wpsPushButton = new_rec->wps_push_button;
            l_bss_param_cfg->wps.methods = new_rec->wps_config_methods;
            l_bss_param_cfg->wps.enable = new_rec->wps_enabled;
#endif
            if (strlen(new_rec->beacon_rate_ctl) != 0) {
                strncpy(l_bss_param_cfg->beaconRateCtl, new_rec->beacon_rate_ctl,(sizeof(l_bss_param_cfg->beaconRateCtl)-1));
            }
            l_bss_param_cfg->hostap_mgt_frame_ctrl = new_rec->hostap_mgt_frame_ctrl;
            l_bss_param_cfg->interop_ctrl = new_rec->interop_ctrl;
            l_bss_param_cfg->inum_sta = new_rec->inum_sta;
            l_bss_param_cfg->mbo_enabled = new_rec->mbo_enabled;
            wifi_util_dbg_print(WIFI_DB,
                "%s:%d:VAP Config radio_name=%s vap_name=%s ssid=%s enabled=%d "
                "ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d "
                "bss_max_sta=%d bss_transition_activated=%d nbr_report_activated=%d  "
                "rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d "
                "mac_filter_enabled=%d mac_filter_mode=%d mac_addr_acl_enabled=%d "
                "wmm_enabled=%d anqp_parameters=%s hs2Parameters=%s uapsd_enabled=%d "
                "beacon_rate=%d bridge_name=%s wmm_noack=%d wep_key_length=%d bss_hotspot=%d "
                "wps_push_button=%d wps_config_methods=%d wps_enabled=%d beacon_rate_ctl=%s "
                "mfp_config=%s network_initiated_greylist=%d repurposed_vap_name=%s "
                "connected_building_enabled=%d exists=%d hostap_mgt_frame_ctrl=%d mbo_enabled=%d interop_ctrl=%d inum_sta=%d\n",
                __func__, __LINE__, new_rec->radio_name, new_rec->vap_name, new_rec->ssid,
                new_rec->enabled, new_rec->ssid_advertisement_enabled, new_rec->isolation_enabled,
                new_rec->mgmt_power_control, new_rec->bss_max_sta,
                new_rec->bss_transition_activated, new_rec->nbr_report_activated,
                new_rec->rapid_connect_enabled, new_rec->rapid_connect_threshold,
                new_rec->vap_stats_enable, new_rec->mac_filter_enabled, new_rec->mac_filter_mode,
                new_rec->mac_addr_acl_enabled, new_rec->wmm_enabled, new_rec->anqp_parameters,
                new_rec->hs2_parameters, new_rec->uapsd_enabled, new_rec->beacon_rate,
                new_rec->bridge_name, new_rec->wmm_noack, new_rec->wep_key_length,
                new_rec->bss_hotspot, new_rec->wps_push_button, new_rec->wps_config_methods,
                new_rec->wps_enabled, new_rec->beacon_rate_ctl, new_rec->mfp_config,
                new_rec->network_initiated_greylist, new_rec->repurposed_vap_name,
                new_rec->connected_building_enabled, new_rec->exists,
                new_rec->hostap_mgt_frame_ctrl, new_rec->mbo_enabled,new_rec->interop_ctrl,new_rec->inum_sta);
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        }
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }

    stop_wifi_sched_timer(vap_index, ctrl, wifi_vap_sched);
}

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_GAS_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_GAS_Config  holds value before modification
                new_rec - schema_Wifi_GAS_Config holds value after modification
  Description : Callback function called when Wifi_GAS_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_GAS_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_GAS_Config *old_rec,
        struct schema_Wifi_GAS_Config *new_rec)
{
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    int ad_id = 0;
    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        wifidb_init_gas_config_default(&g_wifidb->global_config.gas_config);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Gas Config New/Modify \n", __func__, __LINE__);
        if(new_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Gas config update failed \n",__func__, __LINE__);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        if  ((new_rec->advertisement_id[0] == '0') && (new_rec->advertisement_id[1] == '\0'))  {
            ad_id = atoi(new_rec->advertisement_id);
            g_wifidb->global_config.gas_config.AdvertisementID = ad_id;
            g_wifidb->global_config.gas_config.PauseForServerResponse = new_rec->pause_for_server_response;
            g_wifidb->global_config.gas_config.ResponseTimeout =  new_rec->response_timeout;
            g_wifidb->global_config.gas_config.ComeBackDelay = new_rec->comeback_delay;
            g_wifidb->global_config.gas_config.ResponseBufferingTime = new_rec->response_buffering_time;
            g_wifidb->global_config.gas_config.QueryResponseLengthLimit = new_rec->query_responselength_limit;

            wifi_util_dbg_print(WIFI_DB,"%s:%d advertisement_id=%d pause_for_server_response=%d response_timeout=%d comeback_delay=%d response_buffering_time=%d query_responselength_limit=%d\n", __func__, __LINE__,g_wifidb->global_config.gas_config.AdvertisementID,g_wifidb->global_config.gas_config.PauseForServerResponse,g_wifidb->global_config.gas_config.ResponseTimeout, g_wifidb->global_config.gas_config.ComeBackDelay,g_wifidb->global_config.gas_config.ResponseBufferingTime,g_wifidb->global_config.gas_config.QueryResponseLengthLimit);
        } else {
             wifidb_print("%s:%d Invalid Wifi GAS Config table entry advertisement_id : '%s'\n",__func__, __LINE__, new_rec->advertisement_id);
        }

       pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Global_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Global_Config  holds value before modification
                new_rec - schema_Wifi_Global_Config holds value after modification
  Description : Callback function called when Wifi_Global_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_Global_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Global_Config *old_rec,
        struct schema_Wifi_Global_Config *new_rec)
{
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        wifidb_init_global_config_default(&g_wifidb->global_config.global_parameters);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Global Config New/Modify \n", __func__, __LINE__);
        if(new_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Global config update failed \n",__func__, __LINE__);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        g_wifidb->global_config.global_parameters.notify_wifi_changes = new_rec->notify_wifi_changes;
        g_wifidb->global_config.global_parameters.prefer_private = new_rec->prefer_private;
        g_wifidb->global_config.global_parameters.prefer_private_configure = new_rec->prefer_private_configure;
        g_wifidb->global_config.global_parameters.factory_reset = new_rec->factory_reset;
        g_wifidb->global_config.global_parameters.tx_overflow_selfheal = new_rec->tx_overflow_selfheal;
        g_wifidb->global_config.global_parameters.inst_wifi_client_enabled = new_rec->inst_wifi_client_enabled;
        g_wifidb->global_config.global_parameters.inst_wifi_client_reporting_period = new_rec->inst_wifi_client_reporting_period;
        string_mac_to_uint8_mac((uint8_t *)&g_wifidb->global_config.global_parameters.inst_wifi_client_mac, 
        new_rec->inst_wifi_client_mac);
        //strncpy(g_wifidb->global_config.global_parameters.inst_wifi_client_mac,new_rec->inst_wifi_client_mac,sizeof(g_wifidb->global_config.global_parameters.inst_wifi_client_mac)-1);
        g_wifidb->global_config.global_parameters.inst_wifi_client_def_reporting_period = new_rec->inst_wifi_client_def_reporting_period;
        g_wifidb->global_config.global_parameters.wifi_active_msmt_enabled = new_rec->wifi_active_msmt_enabled;
        g_wifidb->global_config.global_parameters.wifi_active_msmt_pktsize = new_rec->wifi_active_msmt_pktsize;
        g_wifidb->global_config.global_parameters.wifi_active_msmt_num_samples = new_rec->wifi_active_msmt_num_samples;
        g_wifidb->global_config.global_parameters.wifi_active_msmt_sample_duration = new_rec->wifi_active_msmt_sample_duration;
        g_wifidb->global_config.global_parameters.memwraptool.rss_check_interval = new_rec->rss_check_interval;
        g_wifidb->global_config.global_parameters.memwraptool.rss_threshold = new_rec->rss_threshold;
        g_wifidb->global_config.global_parameters.memwraptool.rss_maxlimit = new_rec->rss_maxlimit;
        g_wifidb->global_config.global_parameters.memwraptool.heapwalk_duration = new_rec->heapwalk_duration;
        g_wifidb->global_config.global_parameters.memwraptool.heapwalk_interval = new_rec->heapwalk_interval;
        g_wifidb->global_config.global_parameters.vlan_cfg_version = new_rec->vlan_cfg_version;
#ifdef FEATURE_SUPPORT_WPS
        if (strlen(new_rec->wps_pin) != 0) {
            strncpy(g_wifidb->global_config.global_parameters.wps_pin,new_rec->wps_pin,sizeof(g_wifidb->global_config.global_parameters.wps_pin)-1);
        } else {
            strcpy(g_wifidb->global_config.global_parameters.wps_pin, DEFAULT_WPS_PIN);
        }
#endif
        g_wifidb->global_config.global_parameters.bandsteering_enable = new_rec->bandsteering_enable;
        g_wifidb->global_config.global_parameters.good_rssi_threshold = new_rec->good_rssi_threshold;
        g_wifidb->global_config.global_parameters.assoc_count_threshold = new_rec->assoc_count_threshold;
        g_wifidb->global_config.global_parameters.assoc_gate_time = new_rec->assoc_gate_time;
         if (new_rec->whix_log_interval > 0) {
            g_wifidb->global_config.global_parameters.whix_log_interval =
                new_rec->whix_log_interval;
        } else {
            g_wifidb->global_config.global_parameters.whix_log_interval = DEFAULT_WHIX_LOGINTERVAL;
        }
       if (new_rec->whix_chutility_loginterval > 0) {
            g_wifidb->global_config.global_parameters.whix_chutility_loginterval =
                new_rec->whix_chutility_loginterval;
        } else {
            g_wifidb->global_config.global_parameters.whix_chutility_loginterval =
                DEFAULT_WHIX_CHUTILITY_LOGINTERVAL;
        }
        g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_low =
            new_rec->rss_memory_restart_threshold_low;
        g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_high =
            new_rec->rss_memory_restart_threshold_high;
        g_wifidb->global_config.global_parameters.assoc_monitor_duration =
            new_rec->assoc_monitor_duration;
        g_wifidb->global_config.global_parameters.rapid_reconnect_enable =
            new_rec->rapid_reconnect_enable;
        g_wifidb->global_config.global_parameters.vap_stats_feature = new_rec->vap_stats_feature;
        g_wifidb->global_config.global_parameters.mfp_config_feature = new_rec->mfp_config_feature;
        g_wifidb->global_config.global_parameters.force_disable_radio_feature = new_rec->force_disable_radio_feature;
        g_wifidb->global_config.global_parameters.force_disable_radio_status = new_rec->force_disable_radio_status;
        g_wifidb->global_config.global_parameters.fixed_wmm_params = new_rec->fixed_wmm_params;
        if (strlen(new_rec->wifi_region_code) != 0) {
            strncpy(g_wifidb->global_config.global_parameters.wifi_region_code,new_rec->wifi_region_code,sizeof(g_wifidb->global_config.global_parameters.wifi_region_code)-1);
        }
        g_wifidb->global_config.global_parameters.diagnostic_enable = new_rec->diagnostic_enable;
        g_wifidb->global_config.global_parameters.validate_ssid = new_rec->validate_ssid;
        g_wifidb->global_config.global_parameters.device_network_mode = new_rec->device_network_mode;
        if (strlen(new_rec->normalized_rssi_list) != 0) {
            strncpy(g_wifidb->global_config.global_parameters.normalized_rssi_list,new_rec->normalized_rssi_list,sizeof(g_wifidb->global_config.global_parameters.normalized_rssi_list)-1);
            g_wifidb->global_config.global_parameters.normalized_rssi_list[sizeof(g_wifidb->global_config.global_parameters.normalized_rssi_list)-1] = '\0';
        }
        if (strlen(new_rec->snr_list) != 0) {
            strncpy(g_wifidb->global_config.global_parameters.snr_list,new_rec->snr_list,sizeof(g_wifidb->global_config.global_parameters.snr_list)-1);
            g_wifidb->global_config.global_parameters.snr_list[sizeof(g_wifidb->global_config.global_parameters.snr_list)-1] = '\0';
        }
        if (strlen(new_rec->cli_stat_list) != 0) {
            strncpy(g_wifidb->global_config.global_parameters.cli_stat_list,new_rec->cli_stat_list,sizeof(g_wifidb->global_config.global_parameters.cli_stat_list)-1);
            g_wifidb->global_config.global_parameters.cli_stat_list[sizeof(g_wifidb->global_config.global_parameters.cli_stat_list)-1] = '\0';
        }
        if (strlen(new_rec->txrx_rate_list) != 0) {
            strncpy(g_wifidb->global_config.global_parameters.txrx_rate_list,new_rec->txrx_rate_list,sizeof(g_wifidb->global_config.global_parameters.txrx_rate_list)-1);
            g_wifidb->global_config.global_parameters.txrx_rate_list[sizeof(g_wifidb->global_config.global_parameters.txrx_rate_list)-1] = '\0';
        }

        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit_enable =
            new_rec->mgt_frame_rate_limit_enable;
        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit =
            new_rec->mgt_frame_rate_limit;
        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit_window_size =
            new_rec->mgt_frame_rate_limit_window_size;
        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit_cooldown_time =
            new_rec->mgt_frame_rate_limit_cooldown_time;

        wifi_util_dbg_print(WIFI_DB,
            "%s:%d notify_wifi_changes %d prefer_private %d prefer_private_configure %d "
            "factory_reset %d tx_overflow_selfheal %d inst_wifi_client_enabled %d "
            "inst_wifi_client_reporting_period %d inst_wifi_client_mac %s "
            "inst_wifi_client_def_reporting_period %d wifi_active_msmt_enabled %d "
            "wifi_active_msmt_pktsize %d wifi_active_msmt_num_samples %d "
            "wifi_active_msmt_sample_duration %d vlan_cfg_version %d wps_pin %s "
            "bandsteering_enable %d good_rssi_threshold %d assoc_count_threshold %d "
            "assoc_gate_time %d whix_loginterval %d rss_memory_restart_threshold_low %lu "
            "rss_memory_restart_threshold_high %lu assoc_monitor_duration %d "
            "rapid_reconnect_enable %d vap_stats_feature %d mfp_config_feature %d "
            "force_disable_radio_feature %d force_disable_radio_status %d fixed_wmm_params %d "
            "wifi_region_code %s diagnostic_enable %d validate_ssid %d device_network_mode %d "
            "normalized_rssi_list %s snr_list %s cli_stat_list %s txrx_rate_list %s "
            "mgt_frame_rate_limit_enable %d mgt_frame_rate_limit %d mgt_frame_window_size %d"
            "mgt_frame_cooldown_time %d rss_check_interval %d rss_threshold %d rss_maxlimit %d "
            "heapwalk_duration %d heapwalk_interval %d\n",
            __func__, __LINE__, new_rec->notify_wifi_changes, new_rec->prefer_private,
            new_rec->prefer_private_configure, new_rec->factory_reset,
            new_rec->tx_overflow_selfheal, new_rec->inst_wifi_client_enabled,
            new_rec->inst_wifi_client_reporting_period, new_rec->inst_wifi_client_mac,
            new_rec->inst_wifi_client_def_reporting_period, new_rec->wifi_active_msmt_enabled,
            new_rec->wifi_active_msmt_pktsize, new_rec->wifi_active_msmt_num_samples,
            new_rec->wifi_active_msmt_sample_duration, new_rec->vlan_cfg_version, new_rec->wps_pin,
            new_rec->bandsteering_enable, new_rec->good_rssi_threshold,
            new_rec->assoc_count_threshold, new_rec->assoc_gate_time, new_rec->whix_log_interval,
            new_rec->rss_memory_restart_threshold_low, new_rec->rss_memory_restart_threshold_high,
            new_rec->assoc_monitor_duration, new_rec->rapid_reconnect_enable,
            new_rec->vap_stats_feature, new_rec->mfp_config_feature,
            new_rec->force_disable_radio_feature, new_rec->force_disable_radio_status,
            new_rec->fixed_wmm_params, new_rec->wifi_region_code, new_rec->diagnostic_enable,
            new_rec->validate_ssid, new_rec->device_network_mode, new_rec->normalized_rssi_list,
            new_rec->snr_list, new_rec->cli_stat_list, new_rec->txrx_rate_list,
            new_rec->mgt_frame_rate_limit_enable, new_rec->mgt_frame_rate_limit,
            new_rec->mgt_frame_rate_limit_window_size, new_rec->mgt_frame_rate_limit_cooldown_time,
            new_rec->rss_check_interval, new_rec->rss_threshold, new_rec->rss_maxlimit,
            new_rec->heapwalk_duration, new_rec->heapwalk_interval);

        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }

}

void callback_Wifi_Passpoint_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Passpoint_Config *old_rec,
        struct schema_Wifi_Passpoint_Config *new_rec)
{
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Enter\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    if (mon->mon_type == OVSDB_UPDATE_DEL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Delete\n", __func__, __LINE__);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY)) {
        if(new_rec == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Passpoint update failed\n", __func__, __LINE__);
            return;
        }
        int i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(i == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        wifi_interworking_t *l_interworking_cfg = Get_wifi_object_interworking_parameter(i);
        if(l_interworking_cfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_interworking_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        cJSON *cpass_o = cJSON_CreateObject();
        cJSON *nai_h_o = cJSON_Parse((char*)new_rec->nai_home_realm_element);
        cJSON *op_f_o = cJSON_Parse((char*)new_rec->operator_friendly_name_element);
        cJSON *cc_o = cJSON_Parse((char*)new_rec->connection_capability_element);
        if((cpass_o == NULL) || (nai_h_o == NULL) || (op_f_o == NULL) || (cc_o == NULL)) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d Null json objs - Failed to update cache\n", __func__, __LINE__);
            if(cc_o != NULL) { cJSON_Delete(cc_o); }
            if(op_f_o != NULL) { cJSON_Delete(op_f_o); }
            if(nai_h_o != NULL) { cJSON_Delete(nai_h_o); }
            if(cpass_o != NULL) { cJSON_Delete(cpass_o); }
            return;
        }
        cJSON_AddBoolToObject(cpass_o, "PasspointEnable", new_rec->enable);
        cJSON_AddBoolToObject(cpass_o, "GroupAddressedForwardingDisable", new_rec->group_addressed_forwarding_disable);
        cJSON_AddBoolToObject(cpass_o, "P2pCrossConnectionDisable", new_rec->p2p_cross_connect_disable);
        cJSON_AddItemToObject(cpass_o, "NAIHomeRealmANQPElement", nai_h_o);
        cJSON_AddItemToObject(cpass_o, "OperatorFriendlyNameANQPElement", op_f_o);
        cJSON_AddItemToObject(cpass_o, "ConnectionCapabilityListANQPElement", cc_o);
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        l_interworking_cfg->passpoint.capabilityInfoLength = 0;
        webconfig_error_t ret = decode_passpoint_object(cpass_o, l_interworking_cfg);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        if(ret == webconfig_error_none) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d  updated cache\n", __func__, __LINE__);
        }
        else {
            wifi_util_dbg_print(WIFI_DB, "%s:%d  decode error - Failed to update cache\n", __func__, __LINE__);
        }
        cJSON_Delete(cpass_o);
    }
}

void callback_Wifi_Anqp_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Anqp_Config *old_rec,
        struct schema_Wifi_Anqp_Config *new_rec)
{
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Enter\n", __func__, __LINE__);
    if(mon == NULL) {
       wifi_util_dbg_print(WIFI_DB,"%s:%d: NULL mon, Unable to proceed\n", __func__, __LINE__);
       return;
    }
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Delete\n", __func__, __LINE__);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY)) {
        if(new_rec == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Anqp update failed\n", __func__, __LINE__);
            return;
        }
        int i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(i == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        wifi_interworking_t *l_interworking_cfg = Get_wifi_object_interworking_parameter(i);
        if(l_interworking_cfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_interworking_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        cJSON *canqp_o = cJSON_CreateObject();
        cJSON *caddr_o = cJSON_CreateObject();
        cJSON *ven_o = cJSON_Parse((char*)new_rec->venue_name_element);
        cJSON *dom_o = cJSON_Parse((char*)new_rec->domain_name_element);
        cJSON *roam_o = cJSON_Parse((char*)new_rec->roaming_consortium_element);
        cJSON *realm_o = cJSON_Parse((char*)new_rec->nai_realm_element);
        cJSON *gpp_o = cJSON_Parse((char*)new_rec->gpp_cellular_element);
        if((canqp_o == NULL) || (caddr_o == NULL) || (ven_o == NULL) || (dom_o == NULL) ||
           (roam_o == NULL) || (realm_o == NULL) || (gpp_o == NULL)) {
            if(canqp_o != NULL) { cJSON_Delete(canqp_o); }
            if(caddr_o != NULL) { cJSON_Delete(caddr_o); }
            if(ven_o != NULL) { cJSON_Delete(ven_o); }
            if(dom_o != NULL) { cJSON_Delete(dom_o); }
            if(roam_o != NULL) { cJSON_Delete(roam_o); }
            if(realm_o != NULL) { cJSON_Delete(realm_o); }
            if(gpp_o != NULL) { cJSON_Delete(gpp_o); }
            wifi_util_dbg_print(WIFI_DB, "%s:%d Null json objs - Failed to update cache\n", __func__, __LINE__);
            return;
        }
        cJSON_AddNumberToObject(caddr_o, "IPv4AddressType", new_rec->ipv4_address_type);
        cJSON_AddNumberToObject(caddr_o, "IPv6AddressType", new_rec->ipv6_address_type);
        cJSON_AddItemToObject(canqp_o, "IPAddressTypeAvailabilityANQPElement", caddr_o);
        cJSON_AddItemToObject(canqp_o, "DomainANQPElement", dom_o);
        cJSON_AddItemToObject(canqp_o, "RoamingConsortiumANQPElement", roam_o);
        cJSON_AddItemToObject(canqp_o, "NAIRealmANQPElement", realm_o);
        cJSON_AddItemToObject(canqp_o, "VenueNameANQPElement", ven_o);
        cJSON_AddItemToObject(canqp_o, "3GPPCellularANQPElement", gpp_o);
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        l_interworking_cfg->anqp.capabilityInfoLength = 0;
        webconfig_error_t ret = webconfig_error_none;
        ret = decode_anqp_object(canqp_o, l_interworking_cfg);

        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        if(ret == webconfig_error_none) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d  updated cache\n", __func__, __LINE__);
        }
        else {
            wifi_util_dbg_print(WIFI_DB, "%s:%d  decode error - Failed to update cache\n", __func__, __LINE__);
        }
        cJSON_Delete(canqp_o);
    }

}

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Preassoc_Control_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Preassoc_Control_Config  holds value before modification
                new_rec - schema_Wifi_Preassoc_Control_Config  holds value after modification
  Description : Callback function called when schema_Wifi_Preassoc_Control_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_Preassoc_Control_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Preassoc_Control_Config *old_rec,
        struct schema_Wifi_Preassoc_Control_Config *new_rec)
{
    int i = 0;
    int vap_index = 0;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_preassoc_control_t *l_preassoc_ctrl_cfg = NULL;

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        if(old_rec == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer connection control config update failed \n",__func__, __LINE__);
            return;
        }
        i = convert_vap_name_to_array_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(i == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(vap_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }

        l_preassoc_ctrl_cfg = Get_wifi_object_preassoc_ctrl_parameter(vap_index);
        if(l_preassoc_ctrl_cfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_preassoc_ctrl_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        wifidb_init_preassoc_conn_ctrl_config_default(vap_index, l_preassoc_ctrl_cfg);
    } else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY)) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:New/Modify %d\n", __func__, __LINE__,mon->mon_type);
        if(new_rec == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer preassoc control config update failed \n",__func__, __LINE__);
            return;
        }

        i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(i == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }

        l_preassoc_ctrl_cfg = Get_wifi_object_preassoc_ctrl_parameter(i);
        if(l_preassoc_ctrl_cfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_preassoc_ctrl_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        strcpy(l_preassoc_ctrl_cfg->rssi_up_threshold, new_rec->rssi_up_threshold);
        strcpy(l_preassoc_ctrl_cfg->snr_threshold, new_rec->snr_threshold);
        strcpy(l_preassoc_ctrl_cfg->cu_threshold, new_rec->cu_threshold);
        strcpy(l_preassoc_ctrl_cfg->basic_data_transmit_rates, new_rec->basic_data_transmit_rates);
        strcpy(l_preassoc_ctrl_cfg->operational_data_transmit_rates, new_rec->operational_data_transmit_rates);
        strcpy(l_preassoc_ctrl_cfg->supported_data_transmit_rates, new_rec->supported_data_transmit_rates);
        strcpy(l_preassoc_ctrl_cfg->minimum_advertised_mcs, new_rec->minimum_advertised_mcs);
        strcpy(l_preassoc_ctrl_cfg->sixGOpInfoMinRate, new_rec->sixGOpInfoMinRate);
        l_preassoc_ctrl_cfg->time_ms = new_rec->time_ms;
        l_preassoc_ctrl_cfg->min_num_mgmt_frames = new_rec->min_num_mgmt_frames;
        strcpy(l_preassoc_ctrl_cfg->tcm_exp_weightage, new_rec->tcm_exp_weightage);
        strcpy(l_preassoc_ctrl_cfg->tcm_gradient_threshold, new_rec->tcm_gradient_threshold);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Update Wifi_Preassoc_Control_Config table vap_name=%s rssi_up_threshold=%s snr_threshold=%s cu_threshold=%s basic_data_transmit_rates=%s operational_data_transmit_rates=%s supported_data_transmit_rates=%s minimum_advertised_mcs=%s tcm_timeout:%d tcm_min_mgmt_frames:%d tcmexp:%s tcmgradient:%s \n",__func__, __LINE__,new_rec->vap_name,new_rec->rssi_up_threshold,new_rec->snr_threshold,new_rec->cu_threshold,new_rec->basic_data_transmit_rates,new_rec->operational_data_transmit_rates,new_rec->supported_data_transmit_rates,new_rec->minimum_advertised_mcs,new_rec->time_ms,new_rec->min_num_mgmt_frames,new_rec->tcm_exp_weightage,new_rec->tcm_gradient_threshold);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(vap_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
    } else {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Postassoc_Control_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Postassoc_Control_Config  holds value before modification
                new_rec - schema_Wifi_Postassoc_Control_Config  holds value after modification
  Description : Callback function called when schema_Wifi_Postassoc_Control_Config modified in wifidb
 *************************************************************************************
**************************************************************************************/
void callback_Wifi_Postassoc_Control_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Postassoc_Control_Config *old_rec,
        struct schema_Wifi_Postassoc_Control_Config *new_rec)
{
    int i = 0;
    int vap_index = 0;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_postassoc_control_t *l_postassoc_ctrl_cfg = NULL;

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (dbwritten == false) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Db is not initialised yet\n", __func__, __LINE__);
        return;
    }

    if (mon->mon_type == OVSDB_UPDATE_DEL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        if(old_rec == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer connection control config update failed \n",__func__, __LINE__);
            return;
        }
        i = convert_vap_name_to_array_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(i == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(vap_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }

        l_postassoc_ctrl_cfg = Get_wifi_object_postassoc_ctrl_parameter(vap_index);
        if(l_postassoc_ctrl_cfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_postassoc_ctrl_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        wifidb_init_postassoc_conn_ctrl_config_default(vap_index, l_postassoc_ctrl_cfg);
    } else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY)) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:New/Modify %d\n", __func__, __LINE__,mon->mon_type);
        if(new_rec == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer postassoc control config update failed \n",__func__, __LINE__);
            return;
        }

        i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(i == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }

        l_postassoc_ctrl_cfg = Get_wifi_object_postassoc_ctrl_parameter(i);
        if(l_postassoc_ctrl_cfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_postassoc_ctrl_parameter \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        strcpy(l_postassoc_ctrl_cfg->rssi_up_threshold, new_rec->rssi_up_threshold);
        strcpy(l_postassoc_ctrl_cfg->sampling_interval, new_rec->sampling_interval);
        strcpy(l_postassoc_ctrl_cfg->snr_threshold, new_rec->snr_threshold);
        strcpy(l_postassoc_ctrl_cfg->sampling_count, new_rec->sampling_count);
        strcpy(l_postassoc_ctrl_cfg->cu_threshold, new_rec->cu_threshold);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Update Wifi_Postassoc_Control_Config table vap_name=%s rssi_up_threshold=%s,sampling_interval=%s,snr_threshold=%s,sampling_count=%s,cu_threshold=%s\n",__func__, __LINE__,new_rec->vap_name,new_rec->rssi_up_threshold,new_rec->sampling_interval,new_rec->snr_threshold,new_rec->sampling_count,new_rec->cu_threshold);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, new_rec->vap_name);
        if(vap_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
        }
    } else {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_interworking
  Parameter   : vap_name     - Name of vap
                interworking - wifi_InterworkingElement_t to be updated to wifidb
  Description : Update wifi_InterworkingElement_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_interworking_config(char *vap_name, wifi_InterworkingElement_t *interworking)
{
    struct schema_Wifi_Interworking_Config cfg, *pcfg;

    json_t *where;
    bool update = false;
    int count;
    int ret;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &count);
    if ((count != 0) && (pcfg != NULL)) {
        memcpy(&cfg, pcfg, sizeof(struct schema_Wifi_Interworking_Config));
        update = true;
        free(pcfg);
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Found %d records with key: %s in Wifi VAP table\n", 
                        __func__, __LINE__, count, vap_name);
        strcpy(cfg.vap_name, vap_name);
        cfg.enable = interworking->interworkingEnabled;
        cfg.access_network_type = interworking->accessNetworkType;
        cfg.internet = interworking->internetAvailable;
        cfg.asra = interworking->asra;
        cfg.esr = interworking->esr;
        cfg.uesa = interworking->uesa;
        cfg.hess_option_present = interworking->hessOptionPresent;
        strcpy(cfg.hessid, interworking->hessid);
        cfg.venue_group = interworking->venueGroup;
        cfg.venue_type = interworking->venueType;
        if (update == true) {
            where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
            ret = onewifi_ovsdb_table_update_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &cfg);
            if (ret == -1) {
                wifidb_print("%s:%d WIFI DB update error !!!. Failed to update table_Wifi_Interworking_Config table \n",__func__, __LINE__);
                return -1;
            } else if (ret == 0) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: nothing to update table_Wifi_Interworking_Config table\n", __func__, __LINE__);
            } else {
                wifidb_print("%s:%d Updated WIFI DB. table_Wifi_Interworking_Config table updated successful. \n",__func__, __LINE__);
            }
        } else {
            if (onewifi_ovsdb_table_insert(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, &cfg) == false) {
                wifidb_print("%s:%d WIFI DB update error !!!. Failed to insert in table_Wifi_Interworking_Config \n",__func__, __LINE__);
                return -1;
             } else {
                wifidb_print("%s:%d Updated WIFI DB. insert in table_Wifi_Interworking_Config successful. \n",__func__, __LINE__);
             }
        }
        return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_interworking_config
  Parameter   : vap_name     - Name of vap
                interworking - Updated with wifi_InterworkingElement_t from wifidb
  Description : Get wifi_InterworkingElement_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_interworking_config(char *vap_name, wifi_InterworkingElement_t *interworking)
{
    struct schema_Wifi_Interworking_Config  *pcfg;
    json_t *where;
    int count;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    wifi_util_dbg_print(WIFI_DB,"%s:%d:Get table Wifi_Interworking_Config \n",__func__, __LINE__);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &count);
    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_Interworking_Config not found, entry count=%d \n",__func__, __LINE__, count);
        return -1;
    }
    interworking->interworkingEnabled = pcfg->enable;
    interworking->accessNetworkType = pcfg->access_network_type;
    interworking->internetAvailable = pcfg->internet;
    interworking->asra = pcfg->asra;
    interworking->esr = pcfg->esr;
    interworking->uesa = pcfg->uesa;
    interworking->hessOptionPresent = pcfg->hess_option_present;
    if (strlen(pcfg->hessid) != 0) {
        strncpy(interworking->hessid, pcfg->hessid, sizeof(interworking->hessid)-1);
    }
    interworking->venueGroup = pcfg->venue_group;
    interworking->venueType = pcfg->venue_type;
    free(pcfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_print_interworking_config
  Parameter   : void
  Description : print  wifi_InterworkingElement_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
void wifidb_print_interworking_config ()
{
    struct schema_Wifi_Interworking_Config  *pcfg;
    json_t *where;
    int count;
    int i;
    CHAR vap_name[32];
    const int num_interworking_vaps = 5;
    BOOL (*vap_func[num_interworking_vaps])(UINT);
    char output[4096];
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    /* setup filter function array */
    vap_func[0] = isVapPrivate;
    vap_func[1] = isVapXhs;
    vap_func[2] = isVapHotspotOpen;
    vap_func[3] = isVapLnfPsk;
    vap_func[4] = isVapHotspotSecure;

    wifi_util_dbg_print(WIFI_DB,"WIFIDB JSON\nname:Open_vSwitch, version:1.00.000\n");
    wifi_util_dbg_print(WIFI_DB,"table: Wifi_Interworking_Config \n");

    for (i = 0; i < num_interworking_vaps; i++) {
        UINT vap_index;

        for (UINT index = 0; index < getTotalNumberVAPs(); index++) {
            vap_index = VAP_INDEX(wifi_mgr->hal_cap, index);

            /* continue to next VAP if not what looking for */
            if (vap_func[i](vap_index) == FALSE)
                continue;

            convert_vap_index_to_name(&wifi_mgr->hal_cap.wifi_prop, vap_index, vap_name);
            where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
            pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &count);

            if ((pcfg == NULL) || (!count)) {
                continue;
            }
            json_t *data_base = onewifi_ovsdb_table_to_json(&table_Wifi_Interworking_Config, pcfg);
            if(data_base) {
                memset(output,0,sizeof(output));
                if(json_get_str(data_base,output, sizeof(output))) {
                    wifi_util_dbg_print(WIFI_DB,"key: %s\nCount: %d\n%s\n", vap_name,count,output);
                } else {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Unable to print Row\n", __func__, __LINE__);
                }
            }

            free(pcfg);
            pcfg = NULL;
        }
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_rfc_config
  Parameter   : rfc_id     - ID of rfc config structure
                rfc_info -  rfc_info to be updated with wifidb
  Description : Get wifidb_get_device_config structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_rfc_config(UINT rfc_id, wifi_rfc_dml_parameters_t *rfc_info)
{
    struct schema_Wifi_Rfc_Config  *pcfg;
    json_t *where;
    int count; 
    char index[4] = {0};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    sprintf(index,"%d",rfc_id);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "rfc_id", OFUNC_EQ, index);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Rfc_Config, where, &count);
    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_Rfc_Config not found entry count=%d\n",__func__, __LINE__, count);
        return -1;
    }
    rfc_info->wifipasspoint_rfc = pcfg->wifipasspoint_rfc;
    rfc_info->wifiinterworking_rfc = pcfg->wifiinterworking_rfc;
    rfc_info->radiusgreylist_rfc = pcfg->radiusgreylist_rfc;
    rfc_info->dfsatbootup_rfc = pcfg->dfsatbootup_rfc;
    rfc_info->dfs_rfc = pcfg->dfs_rfc;
    rfc_info->wpa3_rfc = pcfg->wpa3_rfc;
    rfc_info->memwraptool_app_rfc = pcfg->memwraptool_app_rfc;
    rfc_info->levl_enabled_rfc = pcfg->levl_enabled_rfc;
#ifdef ALWAYS_ENABLE_AX_2G
    rfc_info->twoG80211axEnable_rfc = true;
#else
    rfc_info->twoG80211axEnable_rfc = pcfg->twoG80211axEnable_rfc;
#endif
    rfc_info->hotspot_open_2g_last_enabled= pcfg->hotspot_open_2g_last_enabled;
    rfc_info->hotspot_open_5g_last_enabled= pcfg->hotspot_open_5g_last_enabled;
    rfc_info->hotspot_open_6g_last_enabled= pcfg->hotspot_open_6g_last_enabled;
    rfc_info->hotspot_secure_2g_last_enabled= pcfg->hotspot_secure_2g_last_enabled;
    rfc_info->hotspot_secure_2g_last_enabled= pcfg->hotspot_secure_5g_last_enabled;
    rfc_info->hotspot_secure_6g_last_enabled= pcfg->hotspot_secure_6g_last_enabled;
    rfc_info->wifi_offchannelscan_app_rfc = pcfg->wifi_offchannelscan_app_rfc;
    rfc_info->wifi_offchannelscan_sm_rfc = pcfg->wifi_offchannelscan_sm_rfc;
    rfc_info->tcm_enabled_rfc = pcfg->tcm_enabled_rfc;
    rfc_info->wpa3_compatibility_enable = pcfg->wpa3_compatibility_enable;
    free(pcfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : convert_radio_to_name
  Parameter   : index - radio index
                name  - name of radio
  Description : convert radio index to radio name
 *************************************************************************************
**************************************************************************************/
int convert_radio_to_name(int index,char *name)
{
    if(index == 0)
    {
        strncpy(name,"radio1",BUFFER_LENGTH_WIFIDB);
        return 0;
    }
    else if(index == 1)
    {
        strncpy(name,"radio2",BUFFER_LENGTH_WIFIDB);
        return 0;
    }
    else if(index == 2)
    {
        strncpy(name,"radio3",BUFFER_LENGTH_WIFIDB);
        return 0;
    }

    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_radio_config
  Parameter   : radio_index - Radio index
                config      - update wifi_radio_operationParam_t to wifidb
                feat_config - update wifi_radio_feature_param_t structure to db (currently only for offchannel scan)
  Description : update wifi_radio_operationParam_t and wifi_radio_feature_param_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    struct schema_Wifi_Radio_Config cfg;
    char name[BUFFER_LENGTH_WIFIDB] = {0};
    char *insert_filter[] = {"-",SCHEMA_COLUMN(Wifi_Radio_Config,vap_configs),NULL};
    unsigned int i = 0;
    int k = 0;
    int len = 0;
    char list_buffer[BUFFER_LENGTH_WIFIDB] = {0};
    len = sizeof(list_buffer)-1;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    memset(&cfg,0,sizeof(cfg));
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Update Radio Config for radio_index=%d \n",__func__, __LINE__,radio_index);
    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifidb_print("%s:%d Failed to update Radio Config and Radio Feat Config for radio_index %d \n",__func__, __LINE__,radio_index);
        return -1;
    }
    if(feat_config == NULL)
    {
        wifidb_print("%s:%d Failed to Get Radio Feature Config \n",__func__, __LINE__);
        return RETURN_ERR;
    }
    cfg.enabled = config->enable;
    cfg.freq_band = config->band;
    cfg.auto_channel_enabled = config->autoChannelEnabled;
    cfg.channel = config->channel;
    cfg.channel_width = config->channelWidth;
    cfg.hw_mode = config->variant;
    cfg.csa_beacon_count = config->csa_beacon_count;
    cfg.country = config->countryCode;
    cfg.operating_environment = config->operatingEnvironment;
    cfg.dcs_enabled = config->DCSEnabled;
    cfg.dfs_enabled = config->DfsEnabled;
    cfg.dtim_period = config->dtimPeriod;
    cfg.beacon_interval = config->beaconInterval;
    cfg.operating_class = config->operatingClass;
    cfg.basic_data_transmit_rate = config->basicDataTransmitRates;
    cfg.operational_data_transmit_rate = config->operationalDataTransmitRates;
    cfg.fragmentation_threshold = config->fragmentationThreshold;
    cfg.guard_interval = config->guardInterval;
    cfg.transmit_power = config->transmitPower;
    cfg.rts_threshold = config->rtsThreshold;
    cfg.factory_reset_ssid = config->factoryResetSsid;
    cfg.radio_stats_measuring_rate = config->radioStatsMeasuringRate;
    cfg.radio_stats_measuring_interval = config->radioStatsMeasuringInterval;
    cfg.cts_protection = config->ctsProtection;
    cfg.obss_coex = config->obssCoex;
    cfg.stbc_enable = config->stbcEnable;
    cfg.greenfield_enable = config->greenFieldEnable;
    cfg.user_control = config->userControl;
    cfg.admin_control = config->adminControl;
    cfg.chan_util_threshold = config->chanUtilThreshold;
    cfg.chan_util_selfheal_enable = config->chanUtilSelfHealEnable;
    cfg.eco_power_down = config->EcoPowerDown;
    cfg.dfs_timer = config->DFSTimer;
    if(strlen(config->radarDetected) != 0) {
        strncpy(cfg.radar_detected, config->radarDetected, sizeof(cfg.radar_detected));
    }
#ifdef FEATURE_SUPPORT_ECOPOWERDOWN
    //Update enable status based on EcoPowerDown.
    if(cfg.eco_power_down)
    {
        cfg.enabled = false;
    }
#endif //FEATURE_SUPPORT_ECOPOWERDOWN
    cfg.Tscan = feat_config->OffChanTscanInMsec;
    cfg.Nscan = (feat_config->OffChanNscanInSec == 0) ? 0 : (24*3600)/(feat_config->OffChanNscanInSec);
    cfg.Tidle = feat_config->OffChanTidleInSec;

    for(i=0;i<(config->numSecondaryChannels);i++)
    {
        if(k >= (len-1))
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi_Radio_Config table Maximum size reached for secondary_channels_list\n",__func__, __LINE__);
            break;
        }
        snprintf(list_buffer+k,sizeof(list_buffer)-k,"%d,",config->channelSecondary[i]);
        wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi_Radio_Config table Channel list %s %d\t",__func__, __LINE__,list_buffer,strlen(list_buffer));
        k = strlen(list_buffer);
    }
    strncpy(cfg.secondary_channels_list,list_buffer,sizeof(cfg.secondary_channels_list)-1);
    cfg.num_secondary_channels = config->numSecondaryChannels;
    strncpy(cfg.radio_name,name,sizeof(cfg.radio_name)-1);

    k = 0;
    memset(list_buffer, 0, sizeof(list_buffer));
    for(i=0;i<MAX_AMSDU_TID;i++)
    {
        if(k >= (len-1))
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi_Radio_Config table Maximum size reached for amsdu_tid list\n",__func__, __LINE__);
            break;
        }
        snprintf(list_buffer+k,sizeof(list_buffer)-k,"%d,",config->amsduTid[i]);
        k = strlen(list_buffer);
    }
    strncpy(cfg.amsdu_tid,list_buffer,sizeof(cfg.amsdu_tid)-1);
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d  radio_stats_measuring_rate = %d   radio_stats_measuring_interval = %d cts_protection = %d obss_coex = %d  stbc_enable = %d  greenfield_enable = %d user_control = %d  admin_control = %d  chan_util_threshold = %d  chan_util_selfheal_enable = %d  eco_power_down = %d DFSTimer:%d radarDetected:%s, amsduTid: %d, %d, %d, %d, %d, %d, %d, %d\n",__func__, __LINE__,config->enable,config->band,config->autoChannelEnabled,config->channel,config->channelWidth,config->variant,config->csa_beacon_count,config->countryCode,config->DCSEnabled,config->numSecondaryChannels,cfg.secondary_channels_list,config->dtimPeriod,config->beaconInterval,config->operatingClass,config->basicDataTransmitRates,config->operationalDataTransmitRates,config->fragmentationThreshold,config->guardInterval,config->transmitPower,config->rtsThreshold,config->factoryResetSsid,config->radioStatsMeasuringRate,config->radioStatsMeasuringInterval,config->ctsProtection,config->obssCoex,config->stbcEnable,config->greenFieldEnable,config->userControl,config->adminControl,config->chanUtilThreshold,config->chanUtilSelfHealEnable,config->EcoPowerDown, config->DFSTimer, config->radarDetected, config->amsduTid[0], config->amsduTid[1],config->amsduTid[2], config->amsduTid[3],config->amsduTid[4], config->amsduTid[5],config->amsduTid[6], config->amsduTid[7]);
    wifi_util_dbg_print(WIFI_DB, " %s:%d Wifi_Radio_Config data Tscan=%lu Nscan=%lu Tidle=%lu \n", __FUNCTION__, __LINE__, feat_config->OffChanTscanInMsec, feat_config->OffChanNscanInSec, feat_config->OffChanTidleInSec);
    if(onewifi_ovsdb_table_upsert_f(g_wifidb->wifidb_sock_path,&table_Wifi_Radio_Config,&cfg,false,insert_filter) == false)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to insert Wifi_Radio_Config table, radio=%d\n",
                __func__, __LINE__, radio_index);
        return -1;
    }
    else
    {
        wifidb_print("%s:%d Updated WIFI DB. Insert Wifi_Radio_Config table completed successful. \n",__func__, __LINE__);
#if ONEWIFI_DML_SUPPORT
#ifndef NEWPLATFORM_PORT
        wifidml_desc_t *p_desc = &get_wifidml_obj()->desc;
        p_desc->push_data_to_ssp_queue_fn(config, sizeof(wifi_radio_operationParam_t), ssp_event_type_psm_write, radio_config);
        p_desc->push_data_to_ssp_queue_fn(feat_config, sizeof(wifi_radio_feature_param_t), ssp_event_type_psm_write, radio_feature_config);
#endif // NEWPLATFORM_PORT
#endif
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_wifi_radio_config
  Parameter   : radio_index - Radio index
                config      - wifi_radio_operationParam_t to be updated from wifidb
                feat_config - wifi_radio_feature_param_t to be updated from wifidb (currently only for offchan)
  Description : Get wifi_radio_operationParam_t and wifi_radio_feature_param_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    struct schema_Wifi_Radio_Config *cfg;
    json_t *where;
    int count;
    char name[BUFFER_LENGTH_WIFIDB] = {0};
    int i = 0;
    int band;
    char *tmp, *ptr;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    wifi_radio_operationParam_t oper_radio;
    static bool is_bootup = TRUE;
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();

    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifidb_print("%s:%d Failed to Get Radio Config \n",__func__, __LINE__);
        return RETURN_ERR;
    }
    if(feat_config == NULL)
    {
        wifidb_print("%s:%d Failed to Get Radio Feature Config \n",__func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Get radio config for index=%d radio_name=%s \n",__func__, __LINE__,radio_index,name);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "radio_name", OFUNC_EQ, name);
    cfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Radio_Config, where, &count);
    if(cfg == NULL)
    {
        wifidb_print("%s:%d Table table_Wifi_Radio_Config not found, entry count=%d\n",__func__, __LINE__, count);
        return RETURN_ERR;
    }

    if (convert_radio_index_to_freq_band(&rdk_wifi_get_hal_capability_map()->wifi_prop, radio_index,
        &band) == RETURN_ERR)
    {
        wifidb_print("%s:%d Failed to convert radio index %d to band, use default\n", __func__,
            __LINE__, radio_index);
    }
    else
    {
        config->band = band;
    }

    config->enable = cfg->enabled;
    config->autoChannelEnabled = cfg->auto_channel_enabled;

    memset(&oper_radio,0,sizeof(wifi_radio_operationParam_t));
    oper_radio.band = band;
    oper_radio.channel = cfg->channel;
    oper_radio.channelWidth = cfg->channel_width;
    oper_radio.DfsEnabled = cfg->dfs_enabled;

    if (wifi_radio_operationParam_validation(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap, &oper_radio) == RETURN_OK) {
        if((is_bootup) && (config->band == WIFI_FREQUENCY_5L_BAND
          || config->band == WIFI_FREQUENCY_5H_BAND || config->band == WIFI_FREQUENCY_5_BAND)) {
            is_bootup = FALSE;
            if((config->autoChannelEnabled == TRUE) && (is_5g_20M_channel_in_dfs(cfg->channel) || (cfg->channel_width == WIFI_CHANNELBANDWIDTH_160MHZ))) {
                wifi_util_info_print(WIFI_DB,"%s:%d RadioIndex=%d Configure default channel=%d and default BandWidth=%d since autochannel is enabled \n",
                                    __func__, __LINE__,radio_index,config->channel,config->channelWidth);
            } else {
                config->channelWidth = cfg->channel_width;
                config->channel = cfg->channel;
            }

        } else {
            config->channelWidth = cfg->channel_width;
            config->channel = cfg->channel;
        }
    }
    else {
        wifi_util_info_print(WIFI_DB,"%s:%d Validation of channel/channel_width of existing DB failed, setting default values chan=%d chanwidth=%d \n", __func__, __LINE__, config->channel, config->channelWidth);
    }

    if ((cfg->hw_mode != 0) && (validate_wifi_hw_variant(cfg->freq_band, cfg->hw_mode) == RETURN_OK)) {
        config->variant = cfg->hw_mode;
    }
    config->csa_beacon_count = cfg->csa_beacon_count;
    if (cfg->country != 0) {
        config->countryCode = cfg->country;
    }
    if (cfg->operating_environment != 0) {
        config->operatingEnvironment = cfg->operating_environment;
    }
    config->DCSEnabled = cfg->dcs_enabled;
    config->DfsEnabled = cfg->dfs_enabled;
    config->DfsEnabledBootup = rfc_param->dfsatbootup_rfc;
    config->dtimPeriod = cfg->dtim_period;
    if (cfg->beacon_interval != 0) {
        config->beaconInterval = cfg->beacon_interval;
    }
    config->operatingClass = cfg->operating_class;
    config->basicDataTransmitRates = cfg->basic_data_transmit_rate;
    config->operationalDataTransmitRates = cfg->operational_data_transmit_rate;
    config->fragmentationThreshold = cfg->fragmentation_threshold;
    config->guardInterval = cfg->guard_interval;
    config->transmitPower = cfg->transmit_power != 0 ? cfg->transmit_power : 100;
    config->rtsThreshold = cfg->rts_threshold;
    config->factoryResetSsid = cfg->factory_reset_ssid;
    config->radioStatsMeasuringRate = cfg->radio_stats_measuring_rate;
    config->radioStatsMeasuringInterval = cfg->radio_stats_measuring_interval;
    config->ctsProtection = cfg->cts_protection;
    config->obssCoex = cfg->obss_coex;
    config->stbcEnable = cfg->stbc_enable;
    config->greenFieldEnable = cfg->greenfield_enable;
    config->userControl = cfg->user_control;
    config->adminControl = cfg->admin_control;
    config->chanUtilThreshold = cfg->chan_util_threshold;
    config->chanUtilSelfHealEnable = cfg->chan_util_selfheal_enable;
    config->EcoPowerDown = cfg->eco_power_down;
    config->DFSTimer = cfg->dfs_timer;
    if(strlen(cfg->radar_detected) != 0) {
        strncpy(config->radarDetected,cfg->radar_detected,sizeof(config->radarDetected)-1);
    }
#ifdef FEATURE_SUPPORT_ECOPOWERDOWN
    //Update enable status based on EcoPowerDown.
    if(config->EcoPowerDown)
    {
        config->enable = false;
    }
#endif //FEATURE_SUPPORT_ECOPOWERDOWN
    feat_config->OffChanTscanInMsec = cfg->Tscan;
    feat_config->OffChanNscanInSec = (cfg->Nscan == 0) ? 0 : (24*3600)/(cfg->Nscan);
    feat_config->OffChanTidleInSec = cfg->Tidle;
    feat_config->radio_index = radio_index;

    tmp = cfg->secondary_channels_list;
    while ((ptr = strchr(tmp, ',')) != NULL)
    {
        ptr++;
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config Secondary Channel list %d \t",__func__, __LINE__,atoi(tmp));
        config->channelSecondary[i] = atoi(tmp);
        tmp = ptr;
        i++;
    }
    config->numSecondaryChannels = cfg->num_secondary_channels;

    i = 0;
    tmp = cfg->amsdu_tid;
    while ((ptr = strchr(tmp, ',')) != NULL)
    {
        ptr++;
        config->amsduTid[i] = atoi(tmp);
        tmp = ptr;
        i++;
    }

    wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d operatingEnvironment=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d, radio_stats_measuring_rate = %d, radio_stats_measuring_interval = %d, cts_protection %d, obss_coex= %d, stbc_enable= %d, greenfield_enable= %d, user_control= %d, admin_control= %d,chan_util_threshold= %d, chan_util_selfheal_enable= %d, eco_power_down=%d DFSTimer:%d radarDetected:%s, amsduTid:[%d, %d, %d, %d, %d, %d, %d, %d]\n",__func__, __LINE__,config->enable,config->band,config->autoChannelEnabled,config->channel,config->channelWidth,config->variant,config->csa_beacon_count,config->countryCode,config->operatingEnvironment,config->DCSEnabled,config->numSecondaryChannels,cfg->secondary_channels_list,config->dtimPeriod,config->beaconInterval,config->operatingClass,config->basicDataTransmitRates,config->operationalDataTransmitRates,config->fragmentationThreshold,config->guardInterval,config->transmitPower,config->rtsThreshold,config->factoryResetSsid,config->radioStatsMeasuringInterval,config->radioStatsMeasuringInterval,config->ctsProtection,config->obssCoex,config->stbcEnable,config->greenFieldEnable,config->userControl,config->adminControl,config->chanUtilThreshold,config->chanUtilSelfHealEnable, config->EcoPowerDown, config->DFSTimer, config->radarDetected, config->amsduTid[0], config->amsduTid[1], config->amsduTid[2], config->amsduTid[3], config->amsduTid[4], config->amsduTid[5], config->amsduTid[6], config->amsduTid[7]);
    wifi_util_dbg_print(WIFI_DB, " %s:%d Wifi_Radio_Config data Tscan=%lu Nscan=%lu Tidle=%lu \n", __FUNCTION__, __LINE__, feat_config->OffChanTscanInMsec, feat_config->OffChanNscanInSec, feat_config->OffChanTidleInSec);
    free(cfg);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_wifi_vap_config
  Parameter   : radio_index - Radio index
                config      - wifi_vap_info_map_t to be updated from wifidb
  Description : Get wifi_vap_info_map_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_wifi_vap_config(int radio_index, wifi_vap_info_map_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    struct schema_Wifi_VAP_Config *pcfg;
    json_t *where;
    char name[BUFFER_LENGTH_WIFIDB] = {0};
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};
    int i =0;
    int vap_count = 0;
    char address[BUFFER_LENGTH_WIFIDB] = {0};
    int vap_index = 0;
    int l_vap_index = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    wifi_InterworkingElement_t interworking;

    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifidb_print("%s:%d Failed to Get VAP Config for radio index %d\n",__func__, __LINE__, radio_index);
        return -1;
    }

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "radio_name", OFUNC_EQ, name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_VAP_Config, where, &vap_count);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config get index=%d radio_name=%s \n",__func__, __LINE__,radio_index,name);
    if((pcfg == NULL) || (vap_count== 0))
    {
        wifidb_print("%s:%d Table table_Wifi_VAP_Config not found, entry count=%d \n",__func__, __LINE__,vap_count);
        return -1;
    }

    for (i = 0; i < vap_count; i++)
    {
        if(pcfg != NULL)
        {

            strncpy(vap_name,(pcfg+i)->vap_name,sizeof(vap_name));
            vap_index = convert_vap_name_to_array_index(&((wifi_mgr_t*)get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
            if(vap_index == -1)
            {
                wifi_util_error_print(WIFI_DB,"%s:%d: %s vap_name is invalid\n",__func__, __LINE__,vap_name);
                continue;
            }
            config->vap_array[vap_index].radio_index = radio_index;
            l_vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
            if (l_vap_index < 0) {
                wifi_util_error_print(WIFI_DB,"%s:%d: %s vap_name is invalid\n",__func__, __LINE__,vap_name);
                continue;
            }
            config->vap_array[vap_index].vap_index = l_vap_index;
            wifidb_get_wifi_vap_info(vap_name,&config->vap_array[vap_index],&rdk_config[vap_index]);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %svap name vap_index=%d radio_ondex=%d\n",__func__, __LINE__,vap_name,vap_index,radio_index);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_VAP_Config verify count=%d\n",__func__, __LINE__,vap_count);
            wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config Row=%d radio_name=%s radioindex=%d vap_name=%s vap_index=%d ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  wmm_enabled=%d anqpParameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d wps_config_methods=%d wps_enabled = %d beacon_rate_ctl =%s network_initiated_greylist=%d repurposed_vap_name=%s exists=%d connected_building_enabled=%d mdu_enabled=%d speed_tier=%d\n",__func__, __LINE__,i,name,config->vap_array[vap_index].radio_index,config->vap_array[vap_index].vap_name,config->vap_array[vap_index].vap_index,config->vap_array[vap_index].u.bss_info.ssid,config->vap_array[vap_index].u.bss_info.enabled,config->vap_array[vap_index].u.bss_info.showSsid ,config->vap_array[vap_index].u.bss_info.isolation,config->vap_array[vap_index].u.bss_info.mgmtPowerControl,config->vap_array[vap_index].u.bss_info.bssMaxSta,config->vap_array[vap_index].u.bss_info.bssTransitionActivated,config->vap_array[vap_index].u.bss_info.nbrReportActivated,config->vap_array[vap_index].u.bss_info.rapidReconnectEnable,config->vap_array[vap_index].u.bss_info.rapidReconnThreshold,config->vap_array[vap_index].u.bss_info.vapStatsEnable,config->vap_array[vap_index].u.bss_info.mac_filter_enable,config->vap_array[vap_index].u.bss_info.mac_filter_mode,config->vap_array[vap_index].u.bss_info.wmm_enabled,config->vap_array[vap_index].u.bss_info.interworking.anqp.anqpParameters,config->vap_array[vap_index].u.bss_info.interworking.passpoint.hs2Parameters,config->vap_array[vap_index].u.bss_info.UAPSDEnabled,config->vap_array[vap_index].u.bss_info.beaconRate,config->vap_array[vap_index].bridge_name,config->vap_array[vap_index].u.bss_info.wmmNoAck,config->vap_array[vap_index].u.bss_info.wepKeyLength,config->vap_array[vap_index].u.bss_info.bssHotspot,config->vap_array[vap_index].u.bss_info.wpsPushButton, config->vap_array[vap_index].u.bss_info.wps.methods, config->vap_array[vap_index].u.bss_info.wps.enable, config->vap_array[vap_index].u.bss_info.beaconRateCtl, config->vap_array[vap_index].u.bss_info.network_initiated_greylist, config->vap_array[vap_index].repurposed_vap_name, rdk_config[vap_index].exists,config->vap_array[vap_index].u.bss_info.connected_building_enabled, config->vap_array[vap_index].u.bss_info.mdu_enabled, config->vap_array[vap_index].u.bss_info.am_config.npc.speed_tier);

            (void)memcpy(&interworking, &config->vap_array[vap_index].u.bss_info.interworking.interworking, sizeof(interworking));
            if(!wifidb_get_interworking_config(vap_name,&interworking))
            {   //if no error
                (void)memcpy(&config->vap_array[vap_index].u.bss_info.interworking.interworking, &interworking, sizeof(interworking));
            }
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Interworking_Config table vap_name=%s Enable=%d accessNetworkType=%d internetAvailable=%d asra=%d esr=%d uesa=%d hess_present=%d hessid=%s venueGroup=%d venueType=%d \n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.bss_info.interworking.interworking.interworkingEnabled,config->vap_array[vap_index].u.bss_info.interworking.interworking.accessNetworkType,config->vap_array[vap_index].u.bss_info.interworking.interworking.internetAvailable,config->vap_array[vap_index].u.bss_info.interworking.interworking.asra,config->vap_array[vap_index].u.bss_info.interworking.interworking.esr,config->vap_array[vap_index].u.bss_info.interworking.interworking.uesa,config->vap_array[vap_index].u.bss_info.interworking.interworking.hessOptionPresent,config->vap_array[vap_index].u.bss_info.interworking.interworking.hessid,config->vap_array[vap_index].u.bss_info.interworking.interworking.venueGroup,config->vap_array[vap_index].u.bss_info.interworking.interworking.venueType);


            if (isVapSTAMesh(l_vap_index)) {
                wifidb_get_wifi_security_config(vap_name,&config->vap_array[vap_index].u.sta_info.security);

                if ((!security_mode_support_radius(config->vap_array[vap_index].u.sta_info.security.mode))) {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table sec type=%d\n",__func__, __LINE__,config->vap_array[vap_index].u.sta_info.security.u.key.type);
                } else {
                    getIpStringFromAdrress(address,&config->vap_array[vap_index].u.sta_info.security.u.radius.dasip);
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table radius server ip =%s  port =%d Secondary radius server ip=%s port=%d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d\n",__func__, __LINE__,config->vap_array[vap_index].u.sta_info.security.u.radius.ip,config->vap_array[vap_index].u.sta_info.security.u.radius.port,config->vap_array[vap_index].u.sta_info.security.u.radius.s_ip,config->vap_array[vap_index].u.sta_info.security.u.radius.s_port,config->vap_array[vap_index].u.sta_info.security.u.radius.max_auth_attempts,config->vap_array[vap_index].u.sta_info.security.u.radius.blacklist_table_timeout,config->vap_array[vap_index].u.sta_info.security.u.radius.identity_req_retry_interval,config->vap_array[vap_index].u.sta_info.security.u.radius.server_retries,address,config->vap_array[vap_index].u.sta_info.security.u.radius.dasport);
                }
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table vap_name=%s Sec_mode=%d enc_mode=%d mfg_config=%d rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d \n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.sta_info.security.mode,config->vap_array[vap_index].u.sta_info.security.encr,config->vap_array[vap_index].u.sta_info.security.mfp,config->vap_array[vap_index].u.sta_info.security.rekey_interval,config->vap_array[vap_index].u.sta_info.security.strict_rekey,config->vap_array[vap_index].u.sta_info.security.eapol_key_timeout,config->vap_array[vap_index].u.sta_info.security.eapol_key_retries,config->vap_array[vap_index].u.sta_info.security.eap_identity_req_timeout,config->vap_array[vap_index].u.sta_info.security.eap_identity_req_retries,config->vap_array[vap_index].u.sta_info.security.eap_req_timeout,config->vap_array[vap_index].u.sta_info.security.eap_req_retries,config->vap_array[vap_index].u.sta_info.security.disable_pmksa_caching);
            } else {
                wifidb_get_wifi_security_config(vap_name,&config->vap_array[vap_index].u.bss_info.security);

                if (!security_mode_support_radius(config->vap_array[vap_index].u.bss_info.security.mode)) {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table sec type=%d\n",__func__, __LINE__,config->vap_array[vap_index].u.bss_info.security.u.key.type);
                } else {
                    getIpStringFromAdrress(address,&config->vap_array[vap_index].u.bss_info.security.u.radius.dasip);
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table radius server ip =%s  port =%d Secondary radius server ip=%s port=%d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d \n",__func__, __LINE__,config->vap_array[vap_index].u.bss_info.security.u.radius.ip,config->vap_array[vap_index].u.bss_info.security.u.radius.port,config->vap_array[vap_index].u.bss_info.security.u.radius.s_ip,config->vap_array[vap_index].u.bss_info.security.u.radius.s_port,config->vap_array[vap_index].u.bss_info.security.u.radius.max_auth_attempts,config->vap_array[vap_index].u.bss_info.security.u.radius.blacklist_table_timeout,config->vap_array[vap_index].u.bss_info.security.u.radius.identity_req_retry_interval,config->vap_array[vap_index].u.bss_info.security.u.radius.server_retries,address,config->vap_array[vap_index].u.bss_info.security.u.radius.dasport);
                }
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table vap_name=%s Sec_mode=%d enc_mode=%d mfg_config=%d rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d wpa3_transition_disable=%d\n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.bss_info.security.mode,config->vap_array[vap_index].u.bss_info.security.encr,config->vap_array[vap_index].u.bss_info.security.mfp,config->vap_array[vap_index].u.bss_info.security.rekey_interval,config->vap_array[vap_index].u.bss_info.security.strict_rekey,config->vap_array[vap_index].u.bss_info.security.eapol_key_timeout,config->vap_array[vap_index].u.bss_info.security.eapol_key_retries,config->vap_array[vap_index].u.bss_info.security.eap_identity_req_timeout,config->vap_array[vap_index].u.bss_info.security.eap_identity_req_retries,config->vap_array[vap_index].u.bss_info.security.eap_req_timeout,config->vap_array[vap_index].u.bss_info.security.eap_req_retries,config->vap_array[vap_index].u.bss_info.security.disable_pmksa_caching,config->vap_array[vap_index].u.bss_info.security.wpa3_transition_disable);
            }
        }
    }
    free(pcfg);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config get index=%d radio_name=%s complete \n",__func__, __LINE__,radio_index,name);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_vap_config
  Parameter   : radio_index - Radio index
                config      - wifi_vap_info_map_t updated to wifidb
  Description : Update wifi_vap_info_map_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_vap_config(int radio_index, wifi_vap_info_map_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    unsigned int i = 0;
    uint8_t vap_index = 0;
    char name[BUFFER_LENGTH_WIFIDB];

    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config update for radio index=%d No of Vaps=%d\n",__func__, __LINE__,radio_index,config->num_vaps);
    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Vap Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    for(i=0;i<config->num_vaps;i++)
    {
        wifidb_print("%s:%d Updated WIFI DB. vap Config updated successful for radio %s and vap_name %s. \n",__func__, __LINE__,name,config->vap_array[i].vap_name);
        wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
            &rdk_config[i]);
        vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, config->vap_array[i].vap_name);
        if ((int)vap_index < 0) {
            wifi_util_error_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,config->vap_array[i].vap_name);
            continue;
        }
        if (isVapSTAMesh(vap_index)) {
            wifidb_update_wifi_security_config(config->vap_array[i].vap_name,&config->vap_array[i].u.sta_info.security);
        } else {
            wifidb_update_wifi_security_config(config->vap_array[i].vap_name,&config->vap_array[i].u.bss_info.security);
            wifidb_update_wifi_interworking_config(config->vap_array[i].vap_name,&config->vap_array[i].u.bss_info.interworking.interworking);
        }
    }
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_wifi_security_config
  Parameter   : vap_name     - Name of vap
                interworking - wifi_vap_security_t updated from wifidb
  Description : Get wifi_vap_security_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_wifi_security_config(char *vap_name, wifi_vap_security_t *sec)
{
    struct schema_Wifi_Security_Config  *pcfg;
    json_t *where;
    int count;
    int vap_index = 0;
    int radio_index = 0;
    int band = 0;
    int def_mode = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    int mfp;

    if(sec == NULL)
    {
        wifidb_print("%s:%d Failed to Get table_Wifi_Security_Config \n",__func__, __LINE__);
        return -1;
    }

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Security_Config, where, &count);
    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_Security_Config table not found, entry count=%d \n",__func__, __LINE__, count);
        return -1;
    }
    vap_index = convert_vap_name_to_array_index(&((wifi_mgr_t*)get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
    if(vap_index < 0) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s vap_name is invalid\n",__func__, __LINE__,vap_name);
        return -1;
    }

    radio_index = convert_vap_name_to_radio_array_index(&((wifi_mgr_t*)get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
    if(radio_index < 0) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s vap_name is invalid\n",__func__, __LINE__,vap_name);
        return -1;
    }
    if (convert_radio_index_to_freq_band(&((wifi_mgr_t*)get_wifimgr_obj())->hal_cap.wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_DB, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return -1;
    }
    
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d mfg=%s cfg_key_type=%d vap_name=%s rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d wpa3_transition_disable=%d\n",__func__, __LINE__,pcfg->security_mode,pcfg->encryption_method,pcfg->radius_server_ip,pcfg->radius_server_port,pcfg->secondary_radius_server_ip,pcfg->secondary_radius_server_port,pcfg->mfp_config,pcfg->key_type,pcfg->vap_name,pcfg->rekey_interval,pcfg->strict_rekey,pcfg->eapol_key_timeout,pcfg->eapol_key_retries,pcfg->eap_identity_req_timeout,pcfg->eap_identity_req_retries,pcfg->eap_req_timeout,pcfg->eap_req_retries,pcfg->disable_pmksa_caching,pcfg->max_auth_attempts,pcfg->blacklist_table_timeout,pcfg->identity_req_retry_interval,pcfg->server_retries,pcfg->das_ip,pcfg->das_port,pcfg->wpa3_transition_disable);

    def_mode = sec->mode;
    if ((band == WIFI_FREQUENCY_6_BAND)  && (pcfg->security_mode != wifi_security_mode_wpa3_personal && \
      pcfg->security_mode != wifi_security_mode_wpa3_enterprise &&  pcfg->security_mode != wifi_security_mode_enhanced_open)) {
        sec->mode = wifi_security_mode_wpa3_personal;
        sec->encr = wifi_encryption_aes;
        wifi_util_error_print(WIFI_DB, "%s:%d Invalid Security mode for 6G %d\n", __func__, __LINE__, pcfg->security_mode);
    } else {
        sec->mode = (pcfg->security_mode_new == WPA3_COMPATIBILITY) ? pcfg->security_mode_new : pcfg->security_mode;
        sec->encr = pcfg->encryption_method;
    }

    convert_security_mode_string_to_integer(&mfp,(char *)&pcfg->mfp_config);
    sec->mfp = (wifi_mfp_cfg_t)mfp;
    if ((sec->mode == wifi_security_mode_wpa3_transition) && (sec->mfp != wifi_mfp_cfg_optional)) {
        wifi_util_error_print(WIFI_DB, "%s:%d Invalid MFP Config\n", __func__, __LINE__);
        sec->mfp = wifi_mfp_cfg_optional;
    } else if (((sec->mode == wifi_security_mode_wpa3_enterprise) || (sec->mode == wifi_security_mode_enhanced_open) || (sec->mode == wifi_security_mode_wpa3_personal)) && (sec->mfp != wifi_mfp_cfg_required)) {
        wifi_util_error_print(WIFI_DB, "%s:%d Invalid MFP Config\n", __func__, __LINE__);
        sec->mfp = wifi_mfp_cfg_required;
    }

    sec->rekey_interval = pcfg->rekey_interval;
    sec->strict_rekey = pcfg->strict_rekey;
    sec->eapol_key_timeout = pcfg->eapol_key_timeout;
    sec->eapol_key_retries = pcfg->eapol_key_retries;
    sec->eap_identity_req_timeout = pcfg->eap_identity_req_timeout;
    sec->eap_identity_req_retries = pcfg->eap_identity_req_retries;
    sec->eap_req_timeout = pcfg->eap_req_timeout;
    sec->eap_req_retries = pcfg->eap_req_retries;
    sec->disable_pmksa_caching = pcfg->disable_pmksa_caching;
    sec->wpa3_transition_disable = pcfg->wpa3_transition_disable;
    if (!security_mode_support_radius(sec->mode)) {
        sec->u.key.type = pcfg->key_type;
        strncpy(sec->u.key.key,pcfg->keyphrase,sizeof(sec->u.key.key)-1);
        
        if (sec->mode != wifi_security_mode_none && sec->mode != wifi_security_mode_enhanced_open) {
            if ((strlen(sec->u.key.key) < MIN_PWD_LEN) || (strlen(sec->u.key.key) > MAX_PWD_LEN)) {
                wifi_util_error_print(WIFI_DB, "%s:%d: Incorrect password length %d for vap '%s'\n", __func__, __LINE__, strlen(sec->u.key.key), vap_name);
                strncpy(sec->u.key.key, INVALID_KEY, sizeof(sec->u.key.key));
            }
        }
    }
    else {
        if (((strlen(pcfg->radius_server_ip) != 0) && (strncmp(pcfg->radius_server_ip, INVALID_IP_STRING, (strlen(INVALID_IP_STRING))) != 0)) ||
            !security_mode_support_radius(def_mode)) {
            strncpy((char *)sec->u.radius.ip,pcfg->radius_server_ip,sizeof(sec->u.radius.ip)-1);
        } else {
            wifi_util_error_print(WIFI_DB, "%s:%d [%s]Invalid radius_server_ip Db value:%s default value:%s\n", __func__, __LINE__, vap_name, pcfg->radius_server_ip, sec->u.radius.ip);
        }
        if (pcfg->radius_server_port != 0 || !security_mode_support_radius(def_mode)) {
            sec->u.radius.port = pcfg->radius_server_port;
        } else {
            wifi_util_error_print(WIFI_DB, "%s:%d [%s]Invalid radius_server_port Db value:%d default value:%d\n", __func__, __LINE__, vap_name, pcfg->radius_server_port, sec->u.radius.port);
        }
        if (((strlen(pcfg->radius_server_key) != 0) && ((strncmp(pcfg->radius_server_key, INVALID_KEY, (strlen(INVALID_KEY))) != 0) ||
            (strncmp(pcfg->radius_server_key, "1234", (strlen("1234"))) != 0))) ||
            !security_mode_support_radius(def_mode)) {
            strncpy(sec->u.radius.key,pcfg->radius_server_key,sizeof(sec->u.radius.key)-1);
        } else {
            wifi_util_error_print(WIFI_DB, "%s:%d [%s]Invalid radius_server_key, used default key\n", __func__, __LINE__, vap_name);
        }

        if (((strlen(pcfg->secondary_radius_server_ip) != 0) && (strncmp(pcfg->secondary_radius_server_ip, INVALID_IP_STRING, (strlen(INVALID_IP_STRING))) != 0)) ||
            !security_mode_support_radius(def_mode)) {
            strncpy((char *)sec->u.radius.s_ip,pcfg->secondary_radius_server_ip,sizeof(sec->u.radius.s_ip)-1);
        } else {
            wifi_util_error_print(WIFI_DB, "%s:%d [%s]Invalid secondary_radius_server_ip Db value:%s default value:%s\n", __func__, __LINE__, vap_name, pcfg->secondary_radius_server_ip, sec->u.radius.s_ip);
        }
        if (pcfg->secondary_radius_server_port != 0 || !security_mode_support_radius(def_mode)) {
            sec->u.radius.s_port = pcfg->secondary_radius_server_port;
        } else {
            wifi_util_error_print(WIFI_DB, "%s:%d [%s]Invalid S_radius_server_port Db value:%d default value:%d\n", __func__, __LINE__, vap_name, pcfg->secondary_radius_server_port, sec->u.radius.s_port);
        }
        if (((strlen(pcfg->secondary_radius_server_key) != 0) && ((strncmp(pcfg->secondary_radius_server_key, INVALID_KEY, (strlen(INVALID_KEY))) != 0) ||
            (strncmp(pcfg->secondary_radius_server_key, "1234", (strlen("1234"))) != 0))) ||
            !security_mode_support_radius(def_mode)) {
            strncpy(sec->u.radius.s_key,pcfg->secondary_radius_server_key,sizeof(sec->u.radius.s_key)-1);
        } else {
            wifi_util_error_print(WIFI_DB, "%s:%d [%s]Invalid secondary_radius_server_key, used default key\n", __func__, __LINE__, vap_name);
        }
        sec->u.radius.max_auth_attempts = pcfg->max_auth_attempts;
        sec->u.radius.blacklist_table_timeout = pcfg->blacklist_table_timeout;
        sec->u.radius.identity_req_retry_interval = pcfg->identity_req_retry_interval;
        sec->u.radius.server_retries = pcfg->server_retries;
        getIpAddressFromString(pcfg->das_ip,&sec->u.radius.dasip);
        sec->u.radius.dasport = pcfg->das_port;
        if (strlen(pcfg->das_key) != 0) {
            strncpy(sec->u.radius.daskey,pcfg->das_key,sizeof(sec->u.radius.daskey)-1);
        }
    }
    free(pcfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_interworking_config
  Parameter   : vap_name     - Name of vap
                config      - wifi_InterworkingElement_t will be updated to wifidb
  Description : Update wifi_InterworkingElement_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_interworking_config(char *vap_name, wifi_InterworkingElement_t *config)
{
    struct schema_Wifi_Interworking_Config cfg_interworking;
    char *filter_vapinterworking[] = {"-",NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    memset(&cfg_interworking,0,sizeof(cfg_interworking));

    wifi_util_dbg_print(WIFI_DB,"%s:%d:Interworking update for vap name=%s\n",__func__, __LINE__,vap_name);
    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Interworking - Null pointer \n",__func__, __LINE__);
        return -1;
    }

    cfg_interworking.enable = config->interworkingEnabled;
    cfg_interworking.access_network_type = config->accessNetworkType;
    cfg_interworking.internet = config->internetAvailable;
    cfg_interworking.asra = config->asra;
    cfg_interworking.esr = config->esr;
    cfg_interworking.uesa = config->uesa;
    cfg_interworking.hess_option_present = config->hessOptionPresent;
    strncpy(cfg_interworking.hessid,config->hessid,sizeof(cfg_interworking.hessid));
    cfg_interworking.venue_group = config->venueGroup;
    cfg_interworking.venue_type = config->venueType;
    strncpy(cfg_interworking.vap_name, vap_name,(sizeof(cfg_interworking.vap_name)-1));

    wifi_util_dbg_print(WIFI_DB,"%s:%d: Update Wifi_Interworking_Config table vap_name=%s Enable=%d access_network_type=%d internet=%d asra=%d esr=%d uesa=%d hess_present=%d hessid=%s venue_group=%d venue_type=%d \n",__func__, __LINE__,cfg_interworking.vap_name,cfg_interworking.enable,cfg_interworking.access_network_type,cfg_interworking.internet,cfg_interworking.asra,cfg_interworking.esr,cfg_interworking.uesa,cfg_interworking.hess_option_present,cfg_interworking.hessid,cfg_interworking.venue_group,cfg_interworking.venue_type);

    if(onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_Interworking_Config,&cfg_interworking,false,filter_vapinterworking,SCHEMA_TABLE(Wifi_VAP_Config),onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name),vap_name),SCHEMA_COLUMN(Wifi_VAP_Config,interworking)) == false)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi Interworking Config table\n",__func__, __LINE__);
    }
    else
    {
        wifidb_print("%s:%d Updated WIFI DB. Wifi Interworking Config table updated successful. \n",__func__, __LINE__);
    }
    return 0;
}


extern const char* get_passpoint_json_by_vap_name(const char* vap_name);
extern const char* get_anqp_json_by_vap_name(const char* vap_name);
extern void reset_passpoint_json(const char* vap_name);
extern void reset_anqp_json(const char* vap_name);
extern int get_wifi_last_reboot_reason_psm_value(char *last_reboot_reason);

void wifidb_reset_macfilter_hashmap()
{
    acl_entry_t *tmp_acl_entry = NULL, *acl_entry = NULL;
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    unsigned int vap_index;
    mac_addr_str_t mac_str;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++) {
        vap_index = VAP_INDEX(mgr->hal_cap, index);
        wifi_vap_info_t *vapInfo = getVapInfo(vap_index);
        if (vapInfo == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: VAP info for VAP index %d not found\n", __func__, __LINE__, vap_index);
            continue;
        }
        l_rdk_vap_array = get_wifidb_rdk_vap_info(vap_index);
        if (l_rdk_vap_array == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: VAP Array for VAP Index %d not found\n", __func__, __LINE__, vap_index);
            continue;
        }

        if (l_rdk_vap_array->acl_map != NULL) {
            acl_entry = (acl_entry_t *)hash_map_get_first(l_rdk_vap_array->acl_map);

            while(acl_entry != NULL) {
                to_mac_str(acl_entry->mac, mac_str);
                acl_entry = hash_map_get_next(l_rdk_vap_array->acl_map, acl_entry);
                tmp_acl_entry = hash_map_remove(l_rdk_vap_array->acl_map, mac_str);
                if (tmp_acl_entry != NULL) {
                    free(tmp_acl_entry);
                }
            }
        }
    }

    return;
}
 
void wifidb_get_wifi_macfilter_config()
{
    struct schema_Wifi_MacFilter_Config *pcfg;
    int count, itr;
    char *ptr_t, *tmp, *tmp_mac, *tmp_vap_name, delim[2] = "-";
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    wifi_db_t *g_wifidb;
    acl_entry_t *tmp_acl_entry = NULL;
    mac_address_t mac;
    int vap_index;

    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_MacFilter_Config, NULL, &count);
    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_MacFilter_Config not found, entry count=%d\n",__func__, __LINE__, count);
        return;
    }

    for (itr = 0; (itr < count) && (pcfg != NULL); itr++) {
        tmp = strdup(pcfg->macfilter_key);
        if (tmp != NULL) {
            tmp_vap_name = strtok_r(tmp, delim, &ptr_t);
            vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, tmp_vap_name);
            if (vap_index == -1) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Unable to find vap_index for vap_name %s\n", __func__, __LINE__, tmp_vap_name);
                pcfg++;
                free(tmp);
                continue;
            }
            free(tmp);
        } else {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: NULL Pointer \n", __func__, __LINE__);
            pcfg++;
            continue;
        }

        l_rdk_vap_array = get_wifidb_rdk_vap_info(vap_index);

        if ((l_rdk_vap_array != NULL) && (l_rdk_vap_array->acl_map != NULL)) {
            tmp_mac = strdup(pcfg->device_mac);
            str_tolower(tmp_mac);
            tmp_acl_entry = hash_map_get(l_rdk_vap_array->acl_map, tmp_mac);
            if (tmp_acl_entry == NULL) {
                tmp_acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
                if (tmp_acl_entry == NULL) {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: NULL Pointer \n", __func__, __LINE__);
                    if(tmp_mac) {
                        free(tmp_mac);
                    }
                    return;
                }
                memset(tmp_acl_entry, 0, sizeof(acl_entry_t));

                str_to_mac_bytes(tmp_mac, mac);
                memcpy(tmp_acl_entry->mac, mac, sizeof(mac_address_t));

                strncpy(tmp_acl_entry->device_name, pcfg->device_name, strlen(pcfg->device_name)+1);
                tmp_acl_entry->reason = pcfg->reason;
                tmp_acl_entry->expiry_time = pcfg->expiry_time;

                hash_map_put(l_rdk_vap_array->acl_map, strdup(tmp_mac), tmp_acl_entry);
            } else {
                memset(tmp_acl_entry, 0, sizeof(acl_entry_t));

                str_to_mac_bytes(tmp_mac, mac);
                memcpy(tmp_acl_entry->mac, mac, sizeof(mac_address_t));

                strncpy(tmp_acl_entry->device_name, pcfg->device_name, strlen(pcfg->device_name)+1);
                tmp_acl_entry->reason = pcfg->reason;
                tmp_acl_entry->expiry_time = pcfg->expiry_time;
            }

            if(tmp_mac) {
                free(tmp_mac);
            }
        }
        pcfg++;
    }

    return;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_vap_info
  Parameter   : vap_name     - Name of vap
                config      - wifi_vap_info_t will be updated to wifidb
  Description : Update wifi_vap_info_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_vap_info(char *vap_name, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    struct schema_Wifi_VAP_Config cfg;
    char *filter_vap[] = {"-",SCHEMA_COLUMN(Wifi_VAP_Config,security),SCHEMA_COLUMN(Wifi_VAP_Config,interworking),SCHEMA_COLUMN(Wifi_VAP_Config,mac_filter),NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    char radio_name[BUFFER_LENGTH_WIFIDB] = {0};
    int radio_index = 0;
    int l_vap_index = 0;
    memset(&cfg,0,sizeof(cfg));

    if(config == NULL || rdk_config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update VAP Config \n",__func__, __LINE__);
        return RETURN_ERR;
    }
    radio_index = convert_vap_name_to_radio_array_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
    if (radio_index < 0) {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Vap Config - Invalid radio_index %d \n",__func__, __LINE__,radio_index);
        return RETURN_ERR;
    }
    if((convert_radio_to_name(radio_index,radio_name))!=0)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Vap Config - Invalid radio_index %d \n",__func__, __LINE__,radio_index);
        return RETURN_ERR;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Update radio=%s vap name=%s \n",__func__, __LINE__,radio_name,config->vap_name);
    strncpy(cfg.radio_name,radio_name,sizeof(cfg.radio_name)-1);
    strncpy(cfg.vap_name, config->vap_name,(sizeof(cfg.vap_name)-1));
    if (strlen(config->repurposed_vap_name) != 0) {
        strncpy(cfg.repurposed_vap_name, config->repurposed_vap_name, (strlen(config->repurposed_vap_name) + 1));
    }
    l_vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, config->vap_name);
    if (l_vap_index < 0) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Unable to get vap index for vap_name %s\n", __func__, __LINE__, config->vap_name);
            return RETURN_ERR;
    }
      if (isVapLnfPsk(l_vap_index) && config->u.bss_info.mdu_enabled) {
        strncpy(cfg.repurposed_bridge_name, config->bridge_name,(sizeof(cfg.repurposed_bridge_name)-1));
        strncpy(cfg.bridge_name, config->repurposed_bridge_name,(sizeof(cfg.bridge_name)-1));
    }
    else {
        strncpy(cfg.bridge_name, config->bridge_name,(sizeof(cfg.bridge_name)-1));
    }
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
    if(rdk_config->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
        if(l_vap_index != 2 && l_vap_index != 3) {
            wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,l_vap_index);
            rdk_config->exists = true;
        }
#else
        wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,l_vap_index);
        rdk_config->exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
    }
#endif /* !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_) */
    cfg.exists = rdk_config->exists;

    if (isVapSTAMesh(l_vap_index)) {
        strncpy(cfg.ssid, config->u.sta_info.ssid, (sizeof(cfg.ssid)-1));
        cfg.enabled = config->u.sta_info.enabled;
        cfg.period = config->u.sta_info.scan_params.period;
        cfg.channel = config->u.sta_info.scan_params.channel.channel;
        cfg.freq_band = config->u.sta_info.scan_params.channel.band;
        strncpy(cfg.mfp_config,"Disabled",sizeof(cfg.mfp_config)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config update data cfg.radio_name=%s cfg.vap_name=%s cfg.ssid=%s cfg.enabled=%d\r\n", __func__, __LINE__, cfg.radio_name,cfg.vap_name,cfg.ssid,cfg.enabled);
    } else {
        strncpy(cfg.ssid, config->u.bss_info.ssid, (sizeof(cfg.ssid)-1));
        cfg.enabled = config->u.bss_info.enabled;
        cfg.ssid_advertisement_enabled = config->u.bss_info.showSsid;
        cfg.isolation_enabled = config->u.bss_info.isolation;
        cfg.mgmt_power_control = config->u.bss_info.mgmtPowerControl;
        cfg.bss_max_sta = config->u.bss_info.bssMaxSta;
        cfg.bss_transition_activated = config->u.bss_info.bssTransitionActivated;
        cfg.nbr_report_activated = config->u.bss_info.nbrReportActivated;
        cfg.network_initiated_greylist = config->u.bss_info.network_initiated_greylist;
        cfg.connected_building_enabled = config->u.bss_info.connected_building_enabled;
        cfg.speed_tier = config->u.bss_info.am_config.npc.speed_tier;
        cfg.mdu_enabled = config->u.bss_info.mdu_enabled;
        cfg.rapid_connect_enabled = config->u.bss_info.rapidReconnectEnable;
        cfg.rapid_connect_threshold = config->u.bss_info.rapidReconnThreshold;
        cfg.vap_stats_enable = config->u.bss_info.vapStatsEnable;
        cfg.mac_filter_enabled = config->u.bss_info.mac_filter_enable;
        cfg.mac_filter_mode = config->u.bss_info.mac_filter_mode;
        cfg.wmm_enabled = config->u.bss_info.wmm_enabled;
        strncpy((char *)cfg.anqp_parameters, (char *)config->u.bss_info.interworking.anqp.anqpParameters, (sizeof(cfg.anqp_parameters)-1));
        strncpy((char *)cfg.hs2_parameters, (char *)config->u.bss_info.interworking.passpoint.hs2Parameters, (sizeof(cfg.hs2_parameters)-1));
        cfg.uapsd_enabled = config->u.bss_info.UAPSDEnabled;
        cfg.beacon_rate = config->u.bss_info.beaconRate;
        cfg.wmm_noack = config->u.bss_info.wmmNoAck;
        cfg.wep_key_length = config->u.bss_info.wepKeyLength;
        cfg.bss_hotspot = config->u.bss_info.bssHotspot;
#ifdef FEATURE_SUPPORT_WPS
        cfg.wps_push_button = config->u.bss_info.wpsPushButton;
        cfg.wps_config_methods = config->u.bss_info.wps.methods;
        cfg.wps_enabled = config->u.bss_info.wps.enable;
#endif
        strncpy(cfg.beacon_rate_ctl,config->u.bss_info.beaconRateCtl,sizeof(cfg.beacon_rate_ctl)-1);
        strncpy(cfg.mfp_config,"Disabled",sizeof(cfg.mfp_config)-1);
        cfg.hostap_mgt_frame_ctrl = config->u.bss_info.hostap_mgt_frame_ctrl;
        cfg.mbo_enabled = config->u.bss_info.mbo_enabled;
        cfg.interop_ctrl = config->u.bss_info.interop_ctrl;
        cfg.inum_sta = config->u.bss_info.inum_sta;
        wifi_util_dbg_print(WIFI_DB,
            "%s:%d: VAP Config update data cfg.radio_name=%s cfg.vap_name=%s cfg.ssid=%s "
            "cfg.enabled=%d cfg.advertisement=%d cfg.isolation_enabled=%d "
            "cfg.mgmt_power_control=%d cfg.bss_max_sta=%d cfg.bss_transition_activated=%d "
            "cfg.nbr_report_activated=%d cfg.rapid_connect_enabled=%d "
            "cfg.rapid_connect_threshold=%d cfg.vap_stats_enable=%d cfg.mac_filter_enabled=%d "
            "cfg.mac_filter_mode=%d cfg.wmm_enabled=%d anqp_parameters=%s hs2_parameters=%s "
            "uapsd_enabled=%d beacon_rate=%d bridge_name=%s cfg.wmm_noack=%d cfg.wep_key_length=%d "
            "cfg.bss_hotspot=%d cfg.wps_push_button=%d cfg.wps_config_methods=%d "
            "cfg.wps_enabled=%d cfg.beacon_rate_ctl=%s cfg.mfp_config=%s "
            "network_initiated_greylist=%d exists=%d hostap_mgt_frame_ctrl=%d mbo_enabled=%d "
            "interop_ctrl:%d inum_sta:%d\n",
            __func__, __LINE__, cfg.radio_name, cfg.vap_name, cfg.ssid, cfg.enabled,
            cfg.ssid_advertisement_enabled, cfg.isolation_enabled, cfg.mgmt_power_control,
            cfg.bss_max_sta, cfg.bss_transition_activated, cfg.nbr_report_activated,
            cfg.rapid_connect_enabled, cfg.rapid_connect_threshold, cfg.vap_stats_enable,
            cfg.mac_filter_enabled, cfg.mac_filter_mode, cfg.wmm_enabled, cfg.anqp_parameters,
            cfg.hs2_parameters, cfg.uapsd_enabled, cfg.beacon_rate, cfg.bridge_name, cfg.wmm_noack,
            cfg.wep_key_length, cfg.bss_hotspot, cfg.wps_push_button, cfg.wps_config_methods,
            cfg.wps_enabled, cfg.beacon_rate_ctl, cfg.mfp_config, cfg.network_initiated_greylist,
            cfg.exists, cfg.hostap_mgt_frame_ctrl, cfg.mbo_enabled,
            cfg.interop_ctrl, cfg.inum_sta);
    }
    if(onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_VAP_Config,&cfg,false,filter_vap,SCHEMA_TABLE(Wifi_Radio_Config),(onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_Radio_Config,radio_name),radio_name)),SCHEMA_COLUMN(Wifi_Radio_Config,vap_configs)) == false)
    {
      wifidb_print("%s:%d WIFI DB update error !!!. Failed to update table_Wifi_VAP_Config table\n",__func__, __LINE__);
    }
    else
    {
        wifidb_print("%s:%d Updated WIFI DB. table_Wifi_VAP_Config table updated successful\n",__func__, __LINE__);
#if ONEWIFI_DML_SUPPORT
#ifndef NEWPLATFORM_PORT
        wifidml_desc_t *p_desc = &get_wifidml_obj()->desc;
        p_desc->push_data_to_ssp_queue_fn(config, sizeof(wifi_vap_info_t), ssp_event_type_psm_write, vap_config);
#endif // NEWPLATFORM_PORT
#endif
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_preassoc_ctrl
  Parameter   : vap_name     - Name of vap
                preassoc - wifi_preassoc_control_t to be updated to wifidb
  Description : Update wifi_preassoc_control_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_preassoc_ctrl_config(char *vap_name, wifi_preassoc_control_t *preassoc)
{
    struct schema_Wifi_Preassoc_Control_Config cfg;
    char *filter_preassoc[] = {"-", NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if(preassoc == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Preassoc CAC - Null pointer \n",__func__, __LINE__);
        return -1;
    }

    strcpy(cfg.vap_name, vap_name);
    strcpy(cfg.rssi_up_threshold, preassoc->rssi_up_threshold);
    strcpy(cfg.snr_threshold, preassoc->snr_threshold);
    strcpy(cfg.cu_threshold, preassoc->cu_threshold);
    strcpy(cfg.basic_data_transmit_rates, preassoc->basic_data_transmit_rates);
    strcpy(cfg.operational_data_transmit_rates, preassoc->operational_data_transmit_rates);
    strcpy(cfg.supported_data_transmit_rates, preassoc->supported_data_transmit_rates);
    strcpy(cfg.minimum_advertised_mcs, preassoc->minimum_advertised_mcs);
    strcpy(cfg.sixGOpInfoMinRate, preassoc->sixGOpInfoMinRate);
    cfg.time_ms = preassoc->time_ms;
    cfg.min_num_mgmt_frames = preassoc->min_num_mgmt_frames;
    strcpy(cfg.tcm_exp_weightage, preassoc->tcm_exp_weightage);
    strcpy(cfg.tcm_gradient_threshold, preassoc->tcm_gradient_threshold);

    if (onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path, &table_Wifi_Preassoc_Control_Config, &cfg, false, filter_preassoc, SCHEMA_TABLE(Wifi_Connection_Control_Config), onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_Connection_Control_Config,vap_name), vap_name), SCHEMA_COLUMN(Wifi_Connection_Control_Config, pre_assoc)) ==  false) {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi_Preassoc_Control Config table \n",__func__, __LINE__);
        return -1;
    }
    else {
        wifidb_print("%s:%d Updated WIFI DB. Wifi_Preassoc_Control Config table updated successful\n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_preassoc_ctrl
  Parameter   : vap_name     - Name of vap
                preassoc - Updated with wifi_preassoc_control_t from wifidb
  Description : Get wifi_preassoc_control_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_preassoc_ctrl_config(char *vap_name, wifi_preassoc_control_t *preassoc)
{
    struct schema_Wifi_Preassoc_Control_Config  *pcfg;
    json_t *where;
    int count;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    wifi_util_dbg_print(WIFI_DB,"%s:%d:Get table Wifi_Preassoc_Control_Config \n",__func__, __LINE__);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Preassoc_Control_Config, where, &count);
    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_Preassoc_Control_Config not found, entry count=%d \n",__func__, __LINE__, count);
        return -1;
    }
    strcpy(preassoc->vap_name, vap_name);
    strcpy(preassoc->rssi_up_threshold, pcfg->rssi_up_threshold);
    strcpy(preassoc->snr_threshold, pcfg->snr_threshold);
    strcpy(preassoc->cu_threshold, pcfg->cu_threshold);
    strcpy(preassoc->basic_data_transmit_rates, pcfg->basic_data_transmit_rates);
    strcpy(preassoc->operational_data_transmit_rates, pcfg->operational_data_transmit_rates);
    strcpy(preassoc->supported_data_transmit_rates, pcfg->supported_data_transmit_rates);
    strcpy(preassoc->minimum_advertised_mcs, pcfg->minimum_advertised_mcs);
    strcpy(preassoc->sixGOpInfoMinRate, pcfg->sixGOpInfoMinRate);
    preassoc->time_ms = pcfg->time_ms;
    preassoc->min_num_mgmt_frames = pcfg->min_num_mgmt_frames;
    strcpy(preassoc->tcm_exp_weightage, pcfg->tcm_exp_weightage);
    strcpy(preassoc->tcm_gradient_threshold, pcfg->tcm_gradient_threshold);
    free(pcfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_postassoc_ctrl
  Parameter   : vap_name     - Name of vap
                postassoc - wifi_postassoc_control_t to be updated to wifidb
  Description : Update wifi_postassoc_control_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_postassoc_ctrl_config(char *vap_name, wifi_postassoc_control_t *postassoc)
{
    struct schema_Wifi_Postassoc_Control_Config cfg;
    char *filter_postassoc[] = {"-", NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if(postassoc == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Postassoc CAC - Null pointer \n",__func__, __LINE__);
        return -1;
    }

    strcpy(cfg.vap_name, vap_name);
    strcpy(cfg.rssi_up_threshold, postassoc->rssi_up_threshold);
    strcpy(cfg.sampling_interval, postassoc->sampling_interval);
    strcpy(cfg.snr_threshold, postassoc->snr_threshold);
    strcpy(cfg.sampling_count, postassoc->sampling_count);
    strcpy(cfg.cu_threshold, postassoc->cu_threshold);

    if (onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path, &table_Wifi_Postassoc_Control_Config, &cfg, false, filter_postassoc, SCHEMA_TABLE(Wifi_Connection_Control_Config), onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_Connection_Control_Config,vap_name), vap_name), SCHEMA_COLUMN(Wifi_Connection_Control_Config, post_assoc)) ==  false) {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi_Postassoc_Control Config table \n",__func__, __LINE__);
        return -1;
    }
    else {
        wifidb_print("%s:%d Updated WIFI DB. Wifi_Postassoc_Control Config table updated successful\n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_postassoc_ctrl
  Parameter   : vap_name     - Name of vap
                postassoc - Updated with wifi_postassoc_control_t from wifidb
  Description : Get wifi_postassoc_control_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_postassoc_ctrl_config(char *vap_name, wifi_postassoc_control_t *postassoc)
{
    struct schema_Wifi_Postassoc_Control_Config  *pcfg;
    json_t *where;
    int count;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    wifi_util_dbg_print(WIFI_DB,"%s:%d:Get table Wifi_Postassoc_Control_Config \n",__func__, __LINE__);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Postassoc_Control_Config, where, &count);
    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_Postassoc_Control_Config not found, entry count=%d \n",__func__, __LINE__, count);
        return -1;
    }
    strcpy(postassoc->vap_name, vap_name);
    strcpy(postassoc->rssi_up_threshold, pcfg->rssi_up_threshold);
    strcpy(postassoc->sampling_interval, pcfg->sampling_interval);
    strcpy(postassoc->snr_threshold, pcfg->snr_threshold);
    strcpy(postassoc->sampling_count, pcfg->sampling_count);
    strcpy(postassoc->cu_threshold, pcfg->cu_threshold);
    free(pcfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_cac_config
  Parameter   : config      - wifi_vap_info_map_t updated to wifidb
  Description : Update wifi_vap_info_map_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_cac_config(wifi_vap_info_map_t *config)
{
    unsigned int i = 0;
    uint8_t vap_index = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update CAC Config \n",__func__, __LINE__);
        return RETURN_ERR;
    }

    for(i=0;i<config->num_vaps;i++)
    {
        struct schema_Wifi_Connection_Control_Config cfg;
        char *filter_vap[] = {"-",SCHEMA_COLUMN(Wifi_Connection_Control_Config,pre_assoc),SCHEMA_COLUMN(Wifi_Connection_Control_Config,post_assoc),NULL};

        vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, config->vap_array[i].vap_name);

        if ((int)vap_index < 0 || !isVapHotspot(vap_index)) {
            wifi_util_error_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,config->vap_array[i].vap_name);
            continue;
        }

        memset(&cfg,0,sizeof(cfg));
        strncpy(cfg.vap_name, config->vap_array[i].vap_name,(sizeof(cfg.vap_name)-1));

        if(onewifi_ovsdb_table_upsert_f(g_wifidb->wifidb_sock_path,&table_Wifi_Connection_Control_Config,&cfg,false,filter_vap) == false)
        {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to insert table_Wifi_Connection_Control_Config table \n",__func__, __LINE__);
            return -1;
        }
        else
        {
            wifidb_print("%s:%d Updated WIFI DB. Insert Wifi_Radio_Config table completed successful. \n",__func__, __LINE__);
        }

        wifidb_update_preassoc_ctrl_config(config->vap_array[i].vap_name,&config->vap_array[i].u.bss_info.preassoc);
        wifidb_update_postassoc_ctrl_config(config->vap_array[i].vap_name,&config->vap_array[i].u.bss_info.postassoc);
    }
    return 0;
}


/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_table_entry
  Parameter   : key      - value of column
                key_name - name of column of schema
                table    - name of the table
                key_type - type of column(OCLM_STR ,OCLM_INT,OCLM_BOOL)
  Description : Get wifidb table based on key and other arguments
 *************************************************************************************
**************************************************************************************/
void *wifidb_get_table_entry(char *key, char *key_name,ovsdb_table_t *table,ovsdb_col_t key_type)
{
    json_t *where;
    void *pcfg;
    int count;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    
    if (key == NULL) {
        struct schema_Wifi_Global_Config *gcfg = NULL;
        json_t *jrow;
        where = json_array();
        pjs_errmsg_t perr;

        jrow  = onewifi_ovsdb_sync_select_where(g_wifidb->wifidb_sock_path,SCHEMA_TABLE(Wifi_Global_Config),where);
        if (json_array_size(jrow) != 1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Empty global config table\n",__func__, __LINE__);
            return NULL;
        }
        gcfg = (struct schema_Wifi_Global_Config*)malloc(sizeof(struct schema_Wifi_Global_Config));
        if (gcfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Failed to allocate memory\n",__func__, __LINE__);
            return NULL;
        }
        memset(gcfg,0,sizeof(struct schema_Wifi_Global_Config));
        if (!schema_Wifi_Global_Config_from_json(
                  gcfg,
                  json_array_get(jrow, 0),
                  false,
                  perr))
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Error in parsing globalconfig \n",__func__, __LINE__);
            //return NULL;
        }
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Global vlan %d\n",__func__, __LINE__,gcfg->vlan_cfg_version);
        return gcfg;
    } else {
        where = (json_t *)onewifi_ovsdb_tran_cond(key_type, key_name, OFUNC_EQ, key);
        pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, table, where, &count);

        if (pcfg == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d:  Table not found\n",__func__, __LINE__);
            return NULL;
        }
    }
    return pcfg;
}

/******************************************************************************************************
 ******************************************************************************************************
  Function    : wifidb_update_table_entry
  Parameter   : key      - value of column 
                key_name - name of column of schema
                key_type - type of column(OCLM_STR ,OCLM_INT,OCLM_BOOL)
                table    - name of the table
                cfg      - schema structure with values which will be updated to wifidb
                filter   - char of 3 following format to configure Coulumns to be ignored or included
                { "X",   - column has to be "+" or "-" to select filter in/out 
                 SCHEMA_COLUMN(Table name,column name), - Name of table and column
                 NULL     - key value
                }
  Description : Update wifidb table based on key and other arguments
 ******************************************************************************************************
*******************************************************************************************************/
int wifidb_update_table_entry(char *key, char *key_name,ovsdb_col_t key_type, ovsdb_table_t *table, void *cfg,char *filter[])
{
    json_t *where;
    int ret;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if (key == NULL) {
        ret = onewifi_ovsdb_table_upsert_f(g_wifidb->wifidb_sock_path, table,cfg,false,filter);
    } else {
        where = onewifi_ovsdb_tran_cond(key_type, key_name, OFUNC_EQ, key);
        ret = onewifi_ovsdb_table_update_where_f(g_wifidb->wifidb_sock_path, table,where, cfg,filter);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: ret val %d",__func__, __LINE__,ret);
    }
    return ret;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_global_config
  Parameter   : config - wifi_global_param_t will be updated to wifidb
  Description : Update wifi_global_param_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_global_config(wifi_global_param_t *config)
{
    struct schema_Wifi_Global_Config cfg;
    char *filter_global[] = {"-",SCHEMA_COLUMN(Wifi_Global_Config,gas_config),NULL};
    char str[BUFFER_LENGTH_WIFIDB] = {0};
    memset(&cfg,0,sizeof(cfg));
    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Global Config table \n",__func__, __LINE__);
        return -1;
    }

    cfg.notify_wifi_changes = config->notify_wifi_changes;
    cfg.prefer_private = config->prefer_private;
    cfg.prefer_private_configure = config->prefer_private_configure;
    cfg.factory_reset = config->factory_reset;
    cfg.tx_overflow_selfheal = config->tx_overflow_selfheal;
    cfg.inst_wifi_client_enabled = config->inst_wifi_client_enabled;
    cfg.inst_wifi_client_reporting_period = config->inst_wifi_client_reporting_period;
    uint8_mac_to_string_mac((uint8_t *)config->inst_wifi_client_mac, str);
    strncpy(cfg.inst_wifi_client_mac,str,BUFFER_LENGTH_WIFIDB);
    cfg.inst_wifi_client_def_reporting_period = config->inst_wifi_client_def_reporting_period;
    cfg.wifi_active_msmt_enabled = config->wifi_active_msmt_enabled;
    cfg.wifi_active_msmt_pktsize = config->wifi_active_msmt_pktsize;
    cfg.wifi_active_msmt_num_samples = config->wifi_active_msmt_num_samples;
    cfg.wifi_active_msmt_sample_duration = config->wifi_active_msmt_sample_duration;
    cfg.rss_check_interval = config->memwraptool.rss_check_interval;
    cfg.rss_threshold = config->memwraptool.rss_threshold;
    cfg.rss_maxlimit = config->memwraptool.rss_maxlimit;
    cfg.heapwalk_duration = config->memwraptool.heapwalk_duration;
    cfg.heapwalk_interval = config->memwraptool.heapwalk_interval;
    cfg.vlan_cfg_version = config->vlan_cfg_version;
    strncpy(cfg.wps_pin,config->wps_pin,sizeof(cfg.wps_pin)-1);
    cfg.bandsteering_enable = config->bandsteering_enable;
    cfg.good_rssi_threshold = config->good_rssi_threshold;
    cfg.assoc_count_threshold = config->assoc_count_threshold;
    cfg.assoc_gate_time = config->assoc_gate_time;
    cfg.whix_log_interval = config->whix_log_interval;
    cfg.whix_chutility_loginterval = config->whix_chutility_loginterval;
    cfg.rss_memory_restart_threshold_low = config->rss_memory_restart_threshold_low;
    cfg.rss_memory_restart_threshold_high = config->rss_memory_restart_threshold_high;
    cfg.assoc_monitor_duration = config->assoc_monitor_duration;
    cfg.rapid_reconnect_enable = config->rapid_reconnect_enable;
    cfg.vap_stats_feature = config->vap_stats_feature;
    cfg.mfp_config_feature = config->mfp_config_feature;
    cfg.force_disable_radio_feature = config->force_disable_radio_feature;
    cfg.force_disable_radio_status = config->force_disable_radio_status;
    cfg.fixed_wmm_params = config->fixed_wmm_params;
    strncpy(cfg.wifi_region_code,config->wifi_region_code,sizeof(cfg.wifi_region_code)-1);
    cfg.diagnostic_enable = config->diagnostic_enable;
    cfg.validate_ssid = config->validate_ssid;
    cfg.device_network_mode = config->device_network_mode;

    strncpy(cfg.normalized_rssi_list,config->normalized_rssi_list,sizeof(cfg.normalized_rssi_list)-1);
    cfg.normalized_rssi_list[sizeof(cfg.normalized_rssi_list)-1] = '\0';

    strncpy(cfg.snr_list,config->snr_list,sizeof(cfg.snr_list)-1);
    cfg.snr_list[sizeof(cfg.snr_list)-1] = '\0';

    strncpy(cfg.cli_stat_list,config->cli_stat_list,sizeof(cfg.cli_stat_list)-1);
    cfg.cli_stat_list[sizeof(cfg.cli_stat_list)-1] = '\0';

    strncpy(cfg.txrx_rate_list,config->txrx_rate_list,sizeof(cfg.txrx_rate_list)-1);
    cfg.txrx_rate_list[sizeof(cfg.txrx_rate_list)-1] = '\0';

    cfg.mgt_frame_rate_limit_enable = config->mgt_frame_rate_limit_enable;
    cfg.mgt_frame_rate_limit = config->mgt_frame_rate_limit;
    cfg.mgt_frame_rate_limit_window_size = config->mgt_frame_rate_limit_window_size;
    cfg.mgt_frame_rate_limit_cooldown_time = config->mgt_frame_rate_limit_cooldown_time;


#if ONEWIFI_DML_SUPPORT
#ifndef NEWPLATFORM_PORT
    wifidml_desc_t *p_desc = &get_wifidml_obj()->desc;
    p_desc->push_data_to_ssp_queue_fn(config, sizeof(wifi_global_param_t), ssp_event_type_psm_write, global_config);
#endif // NEWPLATFORM_PORT
#endif
    wifi_util_dbg_print(WIFI_DB,
        "%s:%d notify_wifi_changes %d prefer_private %d prefer_private_configure %d "
        "factory_reset %d tx_overflow_selfheal %d inst_wifi_client_enabled %d "
        "inst_wifi_client_reporting_period %d inst_wifi_client_mac %s "
        "inst_wifi_client_def_reporting_period %d wifi_active_msmt_enabled %d "
        "wifi_active_msmt_pktsize %d wifi_active_msmt_num_samples %d "
        "wifi_active_msmt_sample_duration %d vlan_cfg_version %d wps_pin %s "
        "bandsteering_enable %d good_rssi_threshold %d assoc_count_threshold %d assoc_gate_time %d"
        "rss_memory_restart_threshold_low %d rss_memory_restart_threshold_high %d "
        "assoc_monitor_duration %d rapid_reconnect_enable %d vap_stats_feature %d "
        "mfp_config_feature %d force_disable_radio_feature %d force_disable_radio_status %d "
        "fixed_wmm_params %d wifi_region_code %s diagnostic_enable %d validate_ssid %d "
        "device_network_mode:%d normalized_rssi_list %s snr_list %s cli_stat_list %s "
        "txrx_rate_list %s mgt_frame_rate_limit_enable %d mgt_frame_rate_limit %d "
        "mgt_frame_rate_limit_window_size %d mgt_frame_rate_limit_cooldown_time %d"
        "rss_check_interval %d rss_threshold %d rss_maxlimit %d "
        "heapwalk_duration %d heapwalk_interval %d\n",
        __func__, __LINE__, config->notify_wifi_changes, config->prefer_private,
        config->prefer_private_configure, config->factory_reset, config->tx_overflow_selfheal,
        config->inst_wifi_client_enabled, config->inst_wifi_client_reporting_period,
        config->inst_wifi_client_mac, config->inst_wifi_client_def_reporting_period,
        config->wifi_active_msmt_enabled, config->wifi_active_msmt_pktsize,
        config->wifi_active_msmt_num_samples, config->wifi_active_msmt_sample_duration,
        config->vlan_cfg_version, config->wps_pin, config->bandsteering_enable,
        config->good_rssi_threshold, config->assoc_count_threshold, config->assoc_gate_time,
        config->rss_memory_restart_threshold_low, config->rss_memory_restart_threshold_high,
        config->assoc_monitor_duration, config->rapid_reconnect_enable, config->vap_stats_feature,
        config->mfp_config_feature, config->force_disable_radio_feature,
        config->force_disable_radio_status, config->fixed_wmm_params, config->wifi_region_code,
        config->diagnostic_enable, config->validate_ssid, config->device_network_mode,
        config->normalized_rssi_list, config->snr_list, config->cli_stat_list,
        config->txrx_rate_list, config->mgt_frame_rate_limit_enable, config->mgt_frame_rate_limit,
        config->mgt_frame_rate_limit_window_size, config->mgt_frame_rate_limit_cooldown_time,
        config->memwraptool.rss_check_interval, config->memwraptool.rss_threshold,
        config->memwraptool.rss_maxlimit, config->memwraptool.heapwalk_duration,
        config->memwraptool.heapwalk_interval);


    if (wifidb_update_table_entry(NULL,NULL,OCLM_UUID,&table_Wifi_Global_Config,&cfg,filter_global) <= 0)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Global Config table \n",__func__, __LINE__);
        return -1;
    }
    else
    {
        wifidb_print("%s:%d Updated WIFI DB. Global Config table updated successful. \n",__func__, __LINE__);
    }
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_wifi_global_config
  Parameter   : config - get wifi_global_param_t from wifidb
  Description : Get wifi_global_param_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_wifi_global_config(wifi_global_param_t *config)
{
    struct schema_Wifi_Global_Config *pcfg = NULL;

    pcfg = (struct schema_Wifi_Global_Config  *) wifidb_get_table_entry(NULL, NULL,&table_Wifi_Global_Config,OCLM_UUID);
    if (pcfg == NULL) 
    {
        wifidb_print("%s:%d Table table_Wifi_Global_Config not found \n",__func__, __LINE__);
        return -1;
    }
    else
    {
        config->notify_wifi_changes = pcfg->notify_wifi_changes;
        config->prefer_private = pcfg->prefer_private;
        config->prefer_private_configure = pcfg->prefer_private_configure;
        config->factory_reset = pcfg->factory_reset;
        config->tx_overflow_selfheal = pcfg->tx_overflow_selfheal;
        config->inst_wifi_client_enabled = pcfg->inst_wifi_client_enabled;
        config->inst_wifi_client_reporting_period = pcfg->inst_wifi_client_reporting_period;
        string_mac_to_uint8_mac((uint8_t *)&config->inst_wifi_client_mac, pcfg->inst_wifi_client_mac);
        config->inst_wifi_client_def_reporting_period = pcfg->inst_wifi_client_def_reporting_period;
        config->wifi_active_msmt_enabled = pcfg->wifi_active_msmt_enabled;
        config->wifi_active_msmt_pktsize = pcfg->wifi_active_msmt_pktsize;
        config->wifi_active_msmt_num_samples = pcfg->wifi_active_msmt_num_samples;
        config->wifi_active_msmt_sample_duration = pcfg->wifi_active_msmt_sample_duration;
        config->vlan_cfg_version = pcfg->vlan_cfg_version;
#ifdef FEATURE_SUPPORT_WPS
        if (strlen(pcfg->wps_pin) != 0) {
            strncpy(config->wps_pin,pcfg->wps_pin,sizeof(config->wps_pin)-1);
        } else {
            strcpy(config->wps_pin, DEFAULT_WPS_PIN);
        }
#endif
        config->bandsteering_enable = pcfg->bandsteering_enable;
        config->good_rssi_threshold = pcfg->good_rssi_threshold;
        config->assoc_count_threshold = pcfg->assoc_count_threshold;
        config->assoc_gate_time = pcfg->assoc_gate_time;
        if (pcfg->whix_log_interval > 0) {
            config->whix_log_interval = pcfg->whix_log_interval;
        } else {
            config->whix_log_interval = DEFAULT_WHIX_LOGINTERVAL;
        }
        if (pcfg->whix_chutility_loginterval > 0) {
            config->whix_chutility_loginterval = pcfg->whix_chutility_loginterval;
        } else {
            config->whix_chutility_loginterval = DEFAULT_WHIX_CHUTILITY_LOGINTERVAL;
        }        
        config->memwraptool.rss_check_interval = pcfg->rss_check_interval;
        config->memwraptool.rss_threshold = pcfg->rss_threshold;
        config->memwraptool.rss_maxlimit = pcfg->rss_maxlimit;
        config->memwraptool.heapwalk_duration = pcfg->heapwalk_duration;
        config->memwraptool.heapwalk_interval = pcfg->heapwalk_interval;
        config->rss_memory_restart_threshold_low = pcfg->rss_memory_restart_threshold_low;
        config->rss_memory_restart_threshold_high = pcfg->rss_memory_restart_threshold_high;
        config->assoc_monitor_duration = pcfg->assoc_monitor_duration;
        config->rapid_reconnect_enable = pcfg->rapid_reconnect_enable;
        config->vap_stats_feature = pcfg->vap_stats_feature;
        config->mfp_config_feature = pcfg->mfp_config_feature;
        config->force_disable_radio_feature = pcfg->force_disable_radio_feature;
        config->force_disable_radio_status = pcfg->force_disable_radio_status;
        config->fixed_wmm_params = pcfg->fixed_wmm_params;
        if (strlen(pcfg->wifi_region_code) != 0) {
            strncpy(config->wifi_region_code,pcfg->wifi_region_code,sizeof(config->wifi_region_code)-1);
        }
        config->diagnostic_enable = pcfg->diagnostic_enable;
        config->validate_ssid = pcfg->validate_ssid;
        config->device_network_mode = pcfg->device_network_mode;
        if (strlen(pcfg->normalized_rssi_list) != 0) {
            strncpy(config->normalized_rssi_list,pcfg->normalized_rssi_list,sizeof(config->normalized_rssi_list)-1);
            config->normalized_rssi_list[sizeof(config->normalized_rssi_list)-1] = '\0';
        }
        if (strlen(pcfg->snr_list) != 0) {
            strncpy(config->snr_list,pcfg->snr_list,sizeof(config->snr_list)-1);
            config->snr_list[sizeof(config->snr_list)-1] = '\0';
        }
        if (strlen(pcfg->cli_stat_list) != 0) {
            strncpy(config->cli_stat_list,pcfg->cli_stat_list,sizeof(config->cli_stat_list)-1);
            config->cli_stat_list[sizeof(config->cli_stat_list)-1] = '\0';
        }
        if (strlen(pcfg->txrx_rate_list) != 0) {
            strncpy(config->txrx_rate_list,pcfg->txrx_rate_list,sizeof(config->txrx_rate_list)-1);
            config->txrx_rate_list[sizeof(config->txrx_rate_list)-1] = '\0';
        }

        config->mgt_frame_rate_limit_enable = pcfg->mgt_frame_rate_limit_enable;
        config->mgt_frame_rate_limit = pcfg->mgt_frame_rate_limit;
        config->mgt_frame_rate_limit_window_size = pcfg->mgt_frame_rate_limit_window_size;
        config->mgt_frame_rate_limit_cooldown_time = pcfg->mgt_frame_rate_limit_cooldown_time;

        wifi_util_dbg_print(WIFI_DB,
            "%s:%d notify_wifi_changes %d prefer_private %d prefer_private_configure %d "
            "factory_reset %d tx_overflow_selfheal %d inst_wifi_client_enabled %d "
            "inst_wifi_client_reporting_period %d inst_wifi_client_mac %s "
            "inst_wifi_client_def_reporting_period %d wifi_active_msmt_enabled %d "
            "wifi_active_msmt_pktsize %d wifi_active_msmt_num_samples %d "
            "wifi_active_msmt_sample_duration %d vlan_cfg_version %d wps_pin %s "
            "bandsteering_enable %d good_rssi_threshold %d assoc_count_threshold %d "
            "assoc_gate_time %d rss_memory_restart_threshold_low %d "
            "rss_memory_restart_threshold_high %d "
            "assoc_monitor_duration %d rapid_reconnect_enable %d "
            "vap_stats_feature %d mfp_config_feature %d force_disable_radio_feature %d "
            "force_disable_radio_status %d fixed_wmm_params %d wifi_region_code %s "
            "diagnostic_enable %d validate_ssid %d device_network_mode:%d normalized_rssi_list %s "
            "snr list %s txrx_rate_list %s cli_stat_list %s mgt_frame_rate_limit_enable %d"
            "mgt_frame_rate_limit %d mgt_frame_rate_limit_window_size %d "
            "mgt_frame_rate_limit_cooldown_time %d rss_check_interval %d rss_threshold %d "
            "rss_maxlimit %d heapwalk_duration %d heapwalk_interval %d\n",
            __func__, __LINE__, config->notify_wifi_changes, config->prefer_private,
            config->prefer_private_configure, config->factory_reset, config->tx_overflow_selfheal,
            config->inst_wifi_client_enabled, config->inst_wifi_client_reporting_period,
            config->inst_wifi_client_mac, config->inst_wifi_client_def_reporting_period,
            config->wifi_active_msmt_enabled, config->wifi_active_msmt_pktsize,
            config->wifi_active_msmt_num_samples, config->wifi_active_msmt_sample_duration,
            config->vlan_cfg_version, config->wps_pin, config->bandsteering_enable,
            config->good_rssi_threshold, config->assoc_count_threshold, config->assoc_gate_time,
            config->rss_memory_restart_threshold_low, config->rss_memory_restart_threshold_high,
            config->assoc_monitor_duration, config->rapid_reconnect_enable,
            config->vap_stats_feature, config->mfp_config_feature,
            config->force_disable_radio_feature, config->force_disable_radio_status,
            config->fixed_wmm_params, config->wifi_region_code, config->diagnostic_enable,
            config->validate_ssid, config->device_network_mode, config->normalized_rssi_list,
            config->snr_list, config->txrx_rate_list, config->cli_stat_list,
            config->mgt_frame_rate_limit_enable, config->mgt_frame_rate_limit,
            config->mgt_frame_rate_limit_window_size, config->mgt_frame_rate_limit_cooldown_time,
            config->memwraptool.rss_check_interval, config->memwraptool.rss_threshold,
            config->memwraptool.rss_maxlimit, config->memwraptool.heapwalk_duration,
            config->memwraptool.heapwalk_interval);
    }
    free(pcfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_wifi_radio_config
  Parameter   : radio_name - Name of radio
  Description : Delete table_Wifi_Radio_Config entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_wifi_radio_config(char *radio_name)
{
    json_t *where;
    int ret = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "radio_name", OFUNC_EQ, radio_name);
    ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Radio_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Radio Config delete radio_name=%s ret=%d\n",__func__, __LINE__,radio_name,ret);
    if(ret != 1)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to delete table_Wifi_Radio_Config \n",__func__, __LINE__);
        return -1;
    } else {
        wifidb_print("%s:%d Deleted WIFI DB. table_Wifi_Radio_Config deleted successful. \n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_wifi_vap_info
  Parameter   : vap_name - Name of vap
  Description : Delete table_Wifi_VAP_Config entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_wifi_vap_info(char *vap_name)
{
    json_t *where;
    int ret = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_VAP_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to delete table_Wifi_VAP_Config \n",__func__, __LINE__);
        return -1;
    } else{
        wifidb_print("%s:%d Deleted WIFI DB. table_Wifi_VAP_Config deleted successful. \n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_wifi_security_config
  Parameter   : vap_name - Name of vap
  Description : Delete table_Wifi_Security_Config entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_wifi_security_config(char *vap_name)
{
    json_t *where;
    int ret = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Security_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Security  Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to delete table_Wifi_Security_Config. \n",__func__, __LINE__);
        return -1;
    } else {
        wifidb_print("%s:%d Deleted WIFI DB. table_Wifi_Security_Config table deleted successful. \n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_wifi_interworking_config
  Parameter   : vap_name - Name of vap
  Description : Delete table_Wifi_Interworking_Config entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_wifi_interworking_config(char *vap_name)
{
    json_t *where;
    int ret = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Interworking Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to delete table_Wifi_Interworking_Config \n",__func__, __LINE__);
        return -1;
    } else {
        wifidb_print("%s:%d Deleted WIFI DB. table_Wifi_Interworking_Config table deleted successful. \n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_all_wifi_vap_config
  Parameter   : void
  Description : Delete all VapConfig entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_all_wifi_vap_config()
{
    int ret = 0;
    unsigned int i = 0;
    int radio_index, num_radio = getNumberRadios();
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed due to Number of Radios %d exceeds supported %d Radios \n",__func__, 
                     __LINE__, getNumberRadios(), MAX_NUM_RADIOS);
        return -1;
    }

    for(radio_index=0; radio_index < num_radio; radio_index++)
    {
        l_vap_param_cfg = get_wifidb_vap_map(radio_index);
        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_map \n",__func__, __LINE__);
            return -1;
        }
        for(i=0; i < l_vap_param_cfg->num_vaps; i++)
        {
            ret = wifidb_delete_wifi_vap_info(l_vap_param_cfg->vap_array[i].vap_name);
            ret = wifidb_delete_wifi_interworking_config(l_vap_param_cfg->vap_array[i].vap_name);
            ret = wifidb_delete_wifi_security_config(l_vap_param_cfg->vap_array[i].vap_name);
        }
    }

    if(ret == 0)
    {
        wifidb_print("%s:%d Deleted WIFI DB. all_wifi_vap_config Deleted successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to Delete \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_preassoc_ctrl
  Parameter   : vap_name - Name of vap
  Description : Delete table_Wifi_Preassoc_Control_Config entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_preassoc_ctrl(char *vap_name)
{
    json_t *where;
    int ret = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Preassoc_Control_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to delete table_Wifi_Preassoc_Control_Config \n",__func__, __LINE__);
        return -1;
    } else{
        wifidb_print("%s:%d Deleted WIFI DB. table_Wifi_Preassoc_Control_Config deleted successful. \n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_all_wifi_preassoc_ctrl
  Parameter   : void
  Description : Delete all VapConfig entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_all_preassoc_ctrl()
{
    int ret = 0;
    unsigned int i = 0;
    int radio_index, num_radio = getNumberRadios();
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed due to Number of Radios %d exceeds supported %d Radios \n",__func__,
                     __LINE__, getNumberRadios(), MAX_NUM_RADIOS);
        return -1;
    }

    for(radio_index=0; radio_index < num_radio; radio_index++)
    {
        l_vap_param_cfg = get_wifidb_vap_map(radio_index);
        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_map \n",__func__, __LINE__);
            return -1;
        }
        for(i=0; i < l_vap_param_cfg->num_vaps; i++)
        {
            ret = wifidb_delete_preassoc_ctrl(l_vap_param_cfg->vap_array[i].vap_name);
        }
    }

    if(ret == 0)
    {
        wifidb_print("%s:%d Deleted WIFI DB. all_preassoc_ctrl Deleted successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to Delete \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_connection_ctrl
  Parameter   : vap_name - Name of vap
  Description : Delete table_Wifi_Connection_Control_Config entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_postassoc_ctrl(char *vap_name)
{
    json_t *where;
    int ret = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Connection_Control_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to delete table_Wifi_Connection_Control_Config \n",__func__, __LINE__);
        return -1;
    } else{
        wifidb_print("%s:%d Deleted WIFI DB. table_Wifi_Connection_Control_Config deleted successful. \n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_all_wifi_postassoc_ctrl
  Parameter   : void
  Description : Delete all VapConfig entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_all_postassoc_ctrl()
{
    int ret = 0;
    unsigned int i = 0;
    int radio_index, num_radio = getNumberRadios();
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed due to Number of Radios %d exceeds supported %d Radios \n",__func__,
                     __LINE__, getNumberRadios(), MAX_NUM_RADIOS);
        return -1;
    }

    for(radio_index=0; radio_index < num_radio; radio_index++)
    {
        l_vap_param_cfg = get_wifidb_vap_map(radio_index);
        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_map \n",__func__, __LINE__);
            return -1;
        }
        for(i=0; i < l_vap_param_cfg->num_vaps; i++)
        {
            ret = wifidb_delete_postassoc_ctrl(l_vap_param_cfg->vap_array[i].vap_name);
        }
    }

    if(ret == 0)
    {
        wifidb_print("%s:%d Deleted WIFI DB. all_postassoc_ctrl Deleted successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to Delete \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_connection_ctrl
  Parameter   : vap_name - Name of vap
  Description : Delete table_Wifi_Postassoc_Control_Config entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_connection_ctrl(char *vap_name)
{
    json_t *where;
    int ret = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Postassoc_Control_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to delete table_Wifi_Connection_Control_Config \n",__func__, __LINE__);
        return -1;
    } else{
        wifidb_print("%s:%d Deleted WIFI DB. table_Wifi_Postassoc_Control_Config deleted successful. \n",__func__, __LINE__);
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_delete_all_wifi_connection_ctrl
  Parameter   : void
  Description : Delete all ConnectionConfig entry from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_delete_all_connection_ctrl()
{
    int ret = 0;
    unsigned int i = 0;
    int radio_index, num_radio = getNumberRadios();
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifidb_print("%s:%d WIFI DB Delete error !!!. Failed due to Number of Radios %d exceeds supported %d Radios \n",__func__,
                     __LINE__, getNumberRadios(), MAX_NUM_RADIOS);
        return -1;
    }

    for(radio_index=0; radio_index < num_radio; radio_index++)
    {
        l_vap_param_cfg = get_wifidb_vap_map(radio_index);
        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_map \n",__func__, __LINE__);
            return -1;
        }
        for(i=0; i < l_vap_param_cfg->num_vaps; i++)
        {
            ret = wifidb_delete_connection_ctrl(l_vap_param_cfg->vap_array[i].vap_name);
        }
    }

    if(ret == 0)
    {
        wifidb_print("%s:%d Deleted WIFI DB. all_postassoc_ctrl Deleted successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB Delete error !!!. Failed to Delete \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_global_param
  Parameter   : config - wifi_global_param_t will be updated from Global cache
  Description : Get wifi_global_param_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_global_param(wifi_global_param_t *config)
{
    int ret = 0;
    wifi_mgr_t *g_wifidb;

    if (config == NULL) {
        wifidb_print("%s:%d Failed to get Global Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, &g_wifidb->global_config.global_parameters, sizeof(wifi_global_param_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return ret;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_global_config
  Parameter   : config - wifi_global_config_t will be updated from Global cache
  Description : Get wifi_global_config_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_global_config(wifi_global_config_t *config)
{
    int ret = 0;
    wifi_mgr_t *g_wifidb;
    wifi_global_config_t  *global_config = get_wifidb_wifi_global_config();

    if (config == NULL) {
        wifidb_print("%s:%d Failed to get Global Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, global_config, sizeof(wifi_global_config_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return ret;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_vap_config
  Parameter   : radio_index - Index of radio
                config - wifi_vap_info_map_t will be updated from Global cache
  Description : Get wifi_vap_info_map_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_vap_config(int radio_index,wifi_vap_info_map_t *config)
{
    int ret = 0;
    wifi_mgr_t *g_wifidb;
    wifi_vap_info_map_t *l_vap_map_param_cfg = NULL;
    l_vap_map_param_cfg = get_wifidb_vap_map(radio_index);
    if(config == NULL || l_vap_map_param_cfg == NULL)
    {
        wifidb_print("%s:%d Failed to get Wifi VAP Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    if(radio_index > (int)getNumberRadios())
    {
         wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalide radio index, Data not fount \n",__func__, __LINE__,radio_index);
         return -1;
    }
    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, l_vap_map_param_cfg,sizeof(*config));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return ret;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_vap_info
  Parameter   : vap_name - Name of vap
                config - wifi_vap_info_t will be updated from Global cache
  Description : Get wifi_vap_info_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_vap_info(char *vap_name,wifi_vap_info_t *config)
{
    int i = 0;
    wifi_mgr_t *g_wifidb;
    wifi_vap_info_t *l_vap_param_cfg = NULL;

    g_wifidb = get_wifimgr_obj();
    if(config == NULL)
    {
        wifidb_print("%s:%d Failed to Get VAP info - Null pointer \n",__func__, __LINE__);
        return -1;
    }

    i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, vap_name);
    if(i == -1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,vap_name);
        return -1;
    }
    l_vap_param_cfg = get_wifidb_vap_parameters(i);
    if(l_vap_param_cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid get_wifidb_vap_parameters \n",__func__, __LINE__,vap_name);
        return -1;
    }

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,l_vap_param_cfg,sizeof(wifi_vap_info_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return 0;

}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_security_config
  Parameter   : vap_name - Name of vap
                config - get_wifi_security_config will be updated from Global cache
  Description : Get get_wifi_security_config from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_security_config(char *vap_name, wifi_vap_security_t *config)
{
    int i = 0;
    wifi_mgr_t *g_wifidb;
    wifi_vap_security_t *l_security_cfg = NULL;

    g_wifidb = get_wifimgr_obj();
    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP info failed \n",__func__, __LINE__);
        return -1;
    }

    i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, vap_name);
    if(i == -1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,vap_name);
        return -1;
    }
    if (isVapSTAMesh(i)) {
        l_security_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(i);
        if(l_security_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter \n",__func__, __LINE__,vap_name);
            return 0;
        }
    } else {
        l_security_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(i);
        if(l_security_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_bss_security_parameter \n",__func__, __LINE__,vap_name);
            return 0;
        }
    }

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, l_security_cfg, sizeof(wifi_vap_security_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return 0;

}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_interworking_config
  Parameter   : vap_name - Name of vap
                config - wifi_InterworkingElement_t will be updated from Global cache
  Description : Get wifi_InterworkingElement_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_interworking_config(char *vap_name, wifi_InterworkingElement_t *config)
{
    int i = 0;
    wifi_mgr_t *g_wifidb;
    wifi_interworking_t *l_interworking_cfg = NULL;

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP info failed \n",__func__, __LINE__);
        return -1;
    }

    g_wifidb = get_wifimgr_obj();
    i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, vap_name);
    if(i == -1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,vap_name);
        return -1;
    }

    l_interworking_cfg = Get_wifi_object_interworking_parameter(i);
    if(l_interworking_cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_interworking_parameter \n",__func__, __LINE__,vap_name);
        return -1;
    }
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, &l_interworking_cfg->interworking, sizeof(wifi_InterworkingElement_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return 0;

}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_preassoc_ctrl_config
  Parameter   : vap_name - Name of vap
                config - wifi_preassoc_control_t will be updated from Global cache
  Description : Get wifi_preassoc_control_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_preassoc_ctrl_config(char *vap_name, wifi_preassoc_control_t *config)
{
    int i = 0;
    wifi_mgr_t *g_wifidb;
    wifi_preassoc_control_t *l_preassoc_ctrl_cfg = NULL;

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP info failed \n",__func__, __LINE__);
        return -1;
    }

    g_wifidb = get_wifimgr_obj();
    i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, vap_name);
    if(i == -1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,vap_name);
        return -1;
    }

    l_preassoc_ctrl_cfg = Get_wifi_object_preassoc_ctrl_parameter(i);
    if(l_preassoc_ctrl_cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_preassoc_ctrl_parameter \n",__func__, __LINE__,vap_name);
        return -1;
    }
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, l_preassoc_ctrl_cfg, sizeof(wifi_preassoc_control_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return 0;

}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_postassoc_ctrl_config
  Parameter   : vap_name - Name of vap
                config - wifi_postassoc_control_t will be updated from Global cache
  Description : Get wifi_postassoc_control_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_postassoc_ctrl_config(char *vap_name, wifi_postassoc_control_t *config)
{
    int i = 0;
    wifi_mgr_t *g_wifidb;
    wifi_postassoc_control_t *l_postassoc_ctrl_cfg = NULL;

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP info failed \n",__func__, __LINE__);
        return -1;
    }

    g_wifidb = get_wifimgr_obj();
    i = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, vap_name);
    if(i == -1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,vap_name);
        return -1;
    }

    l_postassoc_ctrl_cfg = Get_wifi_object_postassoc_ctrl_parameter(i);
    if(l_postassoc_ctrl_cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_postassoc_ctrl_parameter \n",__func__, __LINE__,vap_name);
        return -1;
    }
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, l_postassoc_ctrl_cfg, sizeof(wifi_postassoc_control_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return 0;

}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_preassoc_ctrl_config
  Parameter   : vap_name - Name of vap
                config   - Update wifi_preassoc_control_t to wifidb
  Description : Wrapper API for wifidb_update_preassoc_ctrl_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_preassoc_ctrl_config(char *vap_name, wifi_preassoc_control_t *config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update preassoc ctrl Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }

    ret = wifidb_update_preassoc_ctrl_config(vap_name,config);
    if(ret == 0)
    {
        wifidb_print("%s:%d Updated WIFI DB. Preassoc ctrl Config updated successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update preassoc ctrl Config \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_postassoc_ctrl_config
  Parameter   : vap_name - Name of vap
                config   - Update wifi_postassoc_control_t to wifidb
  Description : Wrapper API for wifidb_update_postassoc_ctrl_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_postassoc_ctrl_config(char *vap_name, wifi_postassoc_control_t *config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update postassoc ctrl Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }

    ret = wifidb_update_postassoc_ctrl_config(vap_name,config);
    if(ret == 0)
    {
        wifidb_print("%s:%d Updated WIFI DB. Postassoc ctrl Config updated successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update postassoc ctrl Config \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_vap_config
  Parameter   : radio_index - Index of radio
                config      - Update wifi_vap_info_map_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_vap_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_vap_config(int radio_index, wifi_vap_info_map_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. update VAP Config failed - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    ret = wifidb_update_wifi_vap_config(radio_index,config,rdk_config);
    if(ret == 0)
    {
        wifidb_print("%s:%d Updated WIFI DB. wifi VAP Config updated successfully \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update wifi VAP Config table \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_security_config
  Parameter   : vap_name - Name of vap
                config   - Update wifi_vap_security_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_security_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_security_config(char *vap_name, wifi_vap_security_t *sec)
{
    int ret = 0;

    if(sec == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Security Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }    
    ret = wifidb_update_wifi_security_config(vap_name,sec);
    if(ret == 0)
    {
    wifidb_print("%s:%d Updated WIFI DB. Security Config updated successful. \n",__func__, __LINE__);
    return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Security Config\n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_radio_config
  Parameter   : radio_index - Index of radio
                config      - wifi_radio_operationParam_t will be updated from Global cache
                feat_config - wifi_radio_feature_param_t will be updated from Global cache
  Description : Get wifi_radio_operationParam_t and wifi_radio_feature_param_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    int ret = 0;
    wifi_mgr_t *g_wifidb;
    wifi_radio_operationParam_t *l_radio_cfg = NULL;
    wifi_radio_feature_param_t *f_radio_cfg = NULL;
    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get Radio Config failed \n",__func__, __LINE__);
        return -1;
    }
    if(feat_config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get Radio Feature Config failed \n",__func__, __LINE__);
        return -1;
    }
    if(radio_index > (int)getNumberRadios())
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid radio index, Data not fount \n",__func__, __LINE__,radio_index);
        return -1;
    }
    l_radio_cfg = get_wifidb_radio_map(radio_index);
    if(l_radio_cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get Radio Config failed radio_index:%d \n",__func__, __LINE__,radio_index);
        return -1;
    }
    f_radio_cfg = get_wifidb_radio_feat_map(radio_index);
    if(f_radio_cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get Radio Feature Config failed radio_index:%d \n",__func__, __LINE__, radio_index);
        return -1;
    }

    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, l_radio_cfg, sizeof(wifi_radio_operationParam_t));
    memcpy(feat_config, f_radio_cfg, sizeof(wifi_radio_feature_param_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return ret;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_gas_config
  Parameter   : advertisement_id - ID
                config      - Update wifi_GASConfiguration_t to wifidb
  Description : Wrapper API for wifidb_update_gas_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    int ret = 0;

    if(gas_info == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Gas Config - Null pointer\n",__func__, __LINE__);
        return -1;
    }
    ret = wifidb_update_gas_config(advertisement_id,gas_info);
    if(ret == 0)
    {
        wifidb_print("%s:%d Updated WIFI DB. Gas Config updated successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Gas Config\n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_gas_config
  Parameter   : config - wifi_GASConfiguration_t will be updated from Global cache
  Description : Get wifi_GASConfiguration_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_gas_config(wifi_GASConfiguration_t *config)
{
    int ret = 0;
    wifi_mgr_t *g_wifidb;

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get gas Config failed \n",__func__, __LINE__);
        return -1;
    }
    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&g_wifidb->global_config.gas_config,sizeof(*config));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return ret;
}

char *get_data_from_json_file(char *filename)
{
    char *data = NULL;
    FILE *fileRead = NULL;
    int len;

    fileRead = fopen(filename, "r");

    if (fileRead == NULL) {
        wifi_util_error_print(WIFI_DB,"%s:%d: Error in opening JSON file \n",__func__, __LINE__);
        return NULL;
    }

    fseek(fileRead, 0, SEEK_END);
    len = ftell(fileRead);

    if (len <0) {
        wifi_util_error_print(WIFI_DB,"%s:%d: File size reads negative \n",__func__, __LINE__);
        fclose(fileRead);
        return NULL;
    }

    fseek(fileRead, 0, SEEK_SET);
    data = (char*)malloc(sizeof(char) * (len + 1));

    if (data != NULL) {
        memset(data, 0, (sizeof(char) * (len + 1)));
        if (1 != fread(data, len, 1, fileRead)) {
            free(data);
            fclose(fileRead);
            return NULL;
        }
        data[len] = '\0';
    }
    else {
        wifi_util_error_print(WIFI_DB,"%s:%d: Memory allocation failed \n",__func__, __LINE__);
        fclose(fileRead);
        return NULL;
    }

    fclose(fileRead);
    return data;
}

void get_wifi_country_code_from_bootstrap_json(char *country_code, int len)
{
    char *data = NULL;
    cJSON *json = NULL;
    char PartnerID[PARTNER_ID_LEN] = {0};

    data = get_data_from_json_file(BOOTSTRAP_INFO_FILE);

    if (data == NULL) {
        wifi_util_error_print(WIFI_DB,"%s:%d: Failed to read file \n",__func__, __LINE__);
        return;
    } else if (strlen(data) != 0) {
        json = cJSON_Parse(data);
        if (!json) {
            wifi_util_error_print(WIFI_DB,"%s:%d: json file parser error\n",__func__, __LINE__);
            free(data);
            return;
        } else {
            if (RETURN_OK == get_wificcsp_obj()->desc.get_partner_id_fn(PartnerID)) {
                if (PartnerID[0] != '\0') {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Partner = %s \n",__func__, __LINE__, PartnerID);
                    cJSON *partnerObj = cJSON_GetObjectItem(json, PartnerID);
                    if (partnerObj != NULL) {
                        cJSON *paramObj = cJSON_GetObjectItem(partnerObj, "Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code");
                        if (paramObj != NULL) {
                            char *valuestr = NULL;
                            cJSON *paramObjVal = cJSON_GetObjectItem(paramObj, "ActiveValue");
                            if (paramObjVal)
                                valuestr = paramObjVal->valuestring;
                            if (valuestr != NULL) {
                                snprintf(country_code, len, "%s", valuestr);
                            } else {
                                wifi_util_error_print(WIFI_DB,"%s:%d: ActiveValue is NULL\n", __func__, __LINE__);
                            }
                        } else {
                            wifi_util_error_print(WIFI_DB,"%s:%d: Object is NULL\n", __func__, __LINE__);
                        }
                    } else {
                        wifi_util_error_print(WIFI_DB,"%s:%d: - PARTNER ID OBJECT Value is NULL\n", __func__, __LINE__);
                    }
                }
            } else {
                wifi_util_error_print(WIFI_DB,"%s:%d: Failed to get Partner ID \n",__func__, __LINE__);
            }
            cJSON_Delete(json);
        }
        free(data);
        data = NULL;
    } else {
        wifi_util_error_print(WIFI_DB,"%s:%d: BOOTSTRAP_INFO_FILE %s is empty \n",__func__, __LINE__, BOOTSTRAP_INFO_FILE);
        free(data);
        data=NULL;
        return;
    }

    return;
}

int get_lnf_radius_server_ip(char *server_ip)
{
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;

    fp = popen("grep own_ip_addr= /etc/lnf/authserver.conf | cut -d '=' -f2 | cut -d ' ' -f2","r");
    if(fp != NULL) {
        while (fgets(value, sizeof(value), fp) != NULL) {
            strncpy(server_ip, value, strlen(value)-1);
        }
        pclose(fp);
        return RETURN_OK;
    }
    return RETURN_ERR;
}

void set_lnf_radius_server_ip(wifi_vap_security_t *l_security_cfg)
{
    char radius_server_ip[64];
    memset(radius_server_ip, 0, sizeof(radius_server_ip));

    if ((get_lnf_radius_server_ip(radius_server_ip) == RETURN_OK) &&
                (strlen(radius_server_ip) != 0)) {
        strncpy((char *)l_security_cfg->u.radius.ip, radius_server_ip, (sizeof(l_security_cfg->u.radius.ip) - 1));
        strncpy((char *)l_security_cfg->u.radius.s_ip, radius_server_ip, (sizeof(l_security_cfg->u.radius.s_ip) - 1));
    } else {
        strncpy((char *)l_security_cfg->u.radius.ip, LNF_PRIMARY_RADIUS_IP,sizeof(l_security_cfg->u.radius.ip));
        strncpy((char *)l_security_cfg->u.radius.s_ip, LNF_SECONDARY_RADIUS_IP,sizeof(l_security_cfg->u.radius.s_ip));
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_interworking_config_default
  Parameter   : vap_index - Index of vap
  Description : Update global cache with default value for wifi_InterworkingElement_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_interworking_config_default(int vapIndex,void /*wifi_InterworkingElement_t*/ *config)
{
    wifi_InterworkingElement_t interworking;
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    memset((char *)&interworking, 0, sizeof(wifi_InterworkingElement_t));
    convert_vap_index_to_name(&g_wifidb->hal_cap.wifi_prop, vapIndex,vap_name);
    interworking.interworkingEnabled = 0;
    interworking.asra = 0;
    interworking.esr = 0;
    interworking.uesa = 0;
    interworking.hessOptionPresent = 1;
    strcpy(interworking.hessid,"11:22:33:44:55:66");
    if (isVapHotspot(vapIndex))    //Xfinity hotspot vaps
    {
         interworking.accessNetworkType = 2;
    } else {
         interworking.accessNetworkType = 0;
    }

    interworking.venueOptionPresent = 1;
    interworking.venueGroup = 0;
    interworking.venueType = 0;

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, &interworking,sizeof(wifi_InterworkingElement_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_preassoc_conn_ctrl_config_default
  Parameter   : vap_index - Index of vap
  Description : Update global cache with default value for wifi_preassoc_control_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_preassoc_conn_ctrl_config_default(int vapIndex, wifi_preassoc_control_t *config)
{
    wifi_preassoc_control_t preassoc_connection_ctrl;
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    memset((char *)&preassoc_connection_ctrl, 0, sizeof(wifi_preassoc_control_t));
    convert_vap_index_to_name(&g_wifidb->hal_cap.wifi_prop, vapIndex,vap_name);
    strcpy(preassoc_connection_ctrl.rssi_up_threshold, "disabled");
    strcpy(preassoc_connection_ctrl.snr_threshold, "disabled");
    strcpy(preassoc_connection_ctrl.cu_threshold, "disabled");
    strcpy(preassoc_connection_ctrl.basic_data_transmit_rates, "disabled");
    strcpy(preassoc_connection_ctrl.operational_data_transmit_rates, "disabled");
    strcpy(preassoc_connection_ctrl.supported_data_transmit_rates, "disabled");
    strcpy(preassoc_connection_ctrl.minimum_advertised_mcs, "disabled");
    strcpy(preassoc_connection_ctrl.sixGOpInfoMinRate, "disabled");
    preassoc_connection_ctrl.time_ms = TCM_TIMEOUT_MS;
    preassoc_connection_ctrl.min_num_mgmt_frames = TCM_MIN_MGMT_FRAMES;
    strcpy(preassoc_connection_ctrl.tcm_exp_weightage, TCM_WEIGHTAGE);
    strcpy(preassoc_connection_ctrl.tcm_gradient_threshold, TCM_THRESHOLD);
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, &preassoc_connection_ctrl, sizeof(wifi_preassoc_control_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_postassoc_conn_ctrl_config_default
  Parameter   : vap_index - Index of vap
  Description : Update global cache with default value for wifi_postassoc_control_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_postassoc_conn_ctrl_config_default(int vapIndex, wifi_postassoc_control_t *config)
{
    wifi_postassoc_control_t postassoc_connection_ctrl;
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    memset((char *)&postassoc_connection_ctrl, 0, sizeof(wifi_postassoc_control_t));
    convert_vap_index_to_name(&g_wifidb->hal_cap.wifi_prop, vapIndex,vap_name);
    strcpy(postassoc_connection_ctrl.rssi_up_threshold, "disabled");
    strcpy(postassoc_connection_ctrl.sampling_interval, "7");
    strcpy(postassoc_connection_ctrl.snr_threshold, "disabled");
    strcpy(postassoc_connection_ctrl.sampling_count, "3");
    strcpy(postassoc_connection_ctrl.cu_threshold, "disabled");

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, &postassoc_connection_ctrl, sizeof(wifi_postassoc_control_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_gas_config_default
  Parameter   : void
  Description : Update global cache with default value for wifi_GASConfiguration_t
 *************************************************************************************
********************************************** ****************************************/
void wifidb_init_gas_config_default(wifi_GASConfiguration_t *config)
{
    wifi_GASConfiguration_t gas_config = {0};
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    gas_config.AdvertisementID = 0;
    gas_config.PauseForServerResponse = true;
    gas_config.ResponseTimeout = 5000;
    gas_config.ComeBackDelay = 1000;
    gas_config.ResponseBufferingTime = 1000;
    gas_config.QueryResponseLengthLimit = 127;

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&gas_config,sizeof(wifi_GASConfiguration_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_rfc_config_default
  Parameter   : void
  Description : Update global cache with default value for wifi_rfc_dml_parameters_t
 *************************************************************************************
********************************************** ****************************************/
void wifidb_init_rfc_config_default(wifi_rfc_dml_parameters_t *config)
{
    wifi_rfc_dml_parameters_t rfc_config = {0};
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    rfc_config.wifipasspoint_rfc = false;
    rfc_config.wifiinterworking_rfc = false;
    rfc_config.radiusgreylist_rfc = false;
    rfc_config.dfsatbootup_rfc = false;
    rfc_config.dfs_rfc = false;
    rfc_config.levl_enabled_rfc = false;
    rfc_config.memwraptool_app_rfc = true;
#if defined(_XB8_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_) || defined(_XER5_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_)
    rfc_config.wpa3_rfc = true;
#else
    rfc_config.wpa3_rfc = false;
#endif
#if defined(ALWAYS_ENABLE_AX_2G) || defined(NEWPLATFORM_PORT)
    rfc_config.twoG80211axEnable_rfc = true;
#else
    rfc_config.twoG80211axEnable_rfc = false;
#endif
    rfc_config.hotspot_open_2g_last_enabled = false;
    rfc_config.hotspot_open_5g_last_enabled = false;
    rfc_config.hotspot_open_6g_last_enabled = false;
    rfc_config.hotspot_secure_2g_last_enabled = false;
    rfc_config.hotspot_secure_5g_last_enabled = false;
    rfc_config.hotspot_secure_6g_last_enabled = false;
    rfc_config.wifi_offchannelscan_app_rfc = false;
    rfc_config.wifi_offchannelscan_sm_rfc = false;
    rfc_config.tcm_enabled_rfc = false;
    rfc_config.wpa3_compatibility_enable = false;
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&rfc_config,sizeof(wifi_rfc_dml_parameters_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

}

static void wifidb_global_config_upgrade()
{
    char *str = NULL;
    char strValue[256] = {0};
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

    if (g_wifidb->db_version == 0) {
        return;
    }
    if (g_wifidb->db_version < ONEWIFI_DB_VERSION_LOGINTERVAL_FLAG) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d upgrade global config, old db version %d \n", __func__, __LINE__, g_wifidb->db_version);

        memset(strValue, 0, sizeof(strValue));
        str = (char *) p_ccsp_desc->psm_get_value_fn(WhixLoginterval, strValue);
        if (str != NULL) {
            g_wifidb->global_config.global_parameters.whix_log_interval = atoi(str);
            wifi_util_dbg_print(WIFI_DB,"whix_log_interval is %d and str is %s \n", g_wifidb->global_config.global_parameters.whix_log_interval, str);
        } else {
            g_wifidb->global_config.global_parameters.whix_log_interval = DEFAULT_WHIX_LOGINTERVAL;
            wifi_util_error_print(WIFI_DB, ":%s:%d str value for whix_log_interval is null \r\n",
                __func__, __LINE__);
        }
    }

    if (g_wifidb->db_version < ONEWIFI_DB_VERSION_CHUTILITY_LOGINTERVAL_FLAG) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d upgrade global config, old db version %d \n", __func__, __LINE__, g_wifidb->db_version);

        memset(strValue, 0, sizeof(strValue));
        str = (char *) p_ccsp_desc->psm_get_value_fn(WhixChUtilityLoginterval, strValue);
        if (str != NULL) {
            g_wifidb->global_config.global_parameters.whix_chutility_loginterval = atoi(str);
            wifi_util_dbg_print(WIFI_DB,"%s:%d whix_chutility_loginterval is %d and str is %s \n", __func__, __LINE__, g_wifidb->global_config.global_parameters.whix_chutility_loginterval, str);
        } else {
             g_wifidb->global_config.global_parameters.whix_chutility_loginterval = 
                DEFAULT_WHIX_CHUTILITY_LOGINTERVAL;
            wifi_util_error_print(WIFI_DB,
                ":%s:%d str value for whix_chutility_loginterval is null \r\n", __func__, __LINE__);
        }
    }

    if (g_wifidb->db_version < ONEWIFI_DB_VERSION_RSS_MEMORY_THRESHOLD_FLAG) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d upgrade global config, old db version %d \n", __func__,
            __LINE__, g_wifidb->db_version);
        g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_low =
            RSS_MEM_THRESHOLD1_DEFAULT;
        g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_high =
            RSS_MEM_THRESHOLD2_DEFAULT;
    }

    if ((g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_low) == 0 ||
        (g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_high) == 0) {
        g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_low =
            RSS_MEM_THRESHOLD1_DEFAULT;
        g_wifidb->global_config.global_parameters.rss_memory_restart_threshold_high =
            RSS_MEM_THRESHOLD2_DEFAULT;
    }

    if (g_wifidb->db_version < ONEWIFI_DB_VERSION_MGT_FRAME_RATE_LIMIT) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d upgrade global config, old db version %d \n", __func__,
            __LINE__, g_wifidb->db_version);
        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit_enable = false;
        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit = 10;
        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit_window_size = 1;
        g_wifidb->global_config.global_parameters.mgt_frame_rate_limit_cooldown_time = 30;
    }

    if (g_wifidb->db_version < ONEWIFI_DB_VERSION_MEMWRAPTOOL_FLAG) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d upgrade global config, old db version %d \n", __func__,
            __LINE__, g_wifidb->db_version);

        g_wifidb->global_config.global_parameters.memwraptool.rss_check_interval =
            DEFAULT_RSS_CHECK_INTERVAL;
        g_wifidb->global_config.global_parameters.memwraptool.rss_threshold = DEFAULT_RSS_THRESHOLD;
        g_wifidb->global_config.global_parameters.memwraptool.rss_maxlimit = DEFAULT_RSS_MAXLIMIT;
        g_wifidb->global_config.global_parameters.memwraptool.heapwalk_duration =
            DEFAULT_HEAPWALK_DURATION;
        g_wifidb->global_config.global_parameters.memwraptool.heapwalk_interval =
            DEFAULT_HEAPWALK_INTERVAL;
        g_wifidb->global_config.global_parameters.memwraptool.enable = true;
    }
}

/************************************************************************************
*************************************************************************************
  Function    : wifidb_radio_config_upgrade
  Parameter   : config      - wifi_radio_operationParam_t updated to wifidb
              : rdk_config  - wifi_radio_feature_param_t updated to wifidb
  Description : Upgrade radio parameters to new db version
**************************************************************************************
**************************************************************************************/
static void wifidb_radio_config_upgrade(unsigned int index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *rdk_config)
{
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    unsigned int total_radios = getNumberRadios();

    if (index < 0 || index >= total_radios)
    {
        wifi_util_error_print(WIFI_DB,"%s:%d Invalid radio index\n", __func__, __LINE__);
        return;
    }

    if (g_wifidb->db_version == 0) {
        return;
    }

    if (g_wifidb->db_version < ONEWIFI_DB_VERSION_OFFCHANNELSCAN_FLAG) {
        wifi_util_info_print(WIFI_DB, "%s:%d upgrade radio config, old db version %d total radios %u\n", __func__,
        __LINE__, g_wifidb->db_version, total_radios);
        //Feature not required for 2G radio, can be added later for 5GH and 6G
        if (is_radio_band_5G(config->band)) {
            rdk_config->OffChanTscanInMsec = OFFCHAN_DEFAULT_TSCAN_IN_MSEC;
            rdk_config->OffChanNscanInSec = OFFCHAN_DEFAULT_NSCAN_IN_SEC;
            rdk_config->OffChanTidleInSec = OFFCHAN_DEFAULT_TIDLE_IN_SEC;
            rdk_config->radio_index = index;
            if(wifidb_update_wifi_radio_config(index, config, rdk_config) != RETURN_OK) {
                wifi_util_error_print(WIFI_DB,"%s:%d error in updating radio config\n", __func__,__LINE__);
                return;
            }
        } else {
            rdk_config->OffChanTscanInMsec = 0;
            rdk_config->OffChanNscanInSec = 0;
            rdk_config->OffChanTidleInSec = 0;
            rdk_config->radio_index = index;
            if(wifidb_update_wifi_radio_config(index, config, rdk_config) != RETURN_OK) {
                wifi_util_error_print(WIFI_DB,"%s:%d error in updating radio config\n", __func__,__LINE__);
                return;
            }
        }
    }

    if( g_wifidb->db_version < ONEWIFI_DB_VERSION_DFS_TIMER_RADAR_DETECT_FLAG ) {
        config->DFSTimer = DFS_DEFAULT_TIMER_IN_MIN;
        strncpy(config->radarDetected, " ", sizeof(config->radarDetected));
        wifi_util_info_print(WIFI_DB, "%s Updated DFSTimer:%d radarDetected:%s. \n", __func__, config->DFSTimer, config->radarDetected);
        if(wifidb_update_wifi_radio_config(index, config, rdk_config) != RETURN_OK) {
            wifi_util_error_print(WIFI_DB,"%s:%d error in updating radio config\n", __func__,__LINE__);
            return;
        }
    }

#ifdef CONFIG_IEEE80211BE
    if (g_wifidb->db_version < ONEWIFI_DB_VERSION_IEEE80211BE_FLAG) {
        wifi_util_info_print(WIFI_DB, "%s:%d upgrade radio=%d config, old db version: %d total radios: %u\n",
            __func__, __LINE__, index, g_wifidb->db_version, total_radios);
        if (config->band != WIFI_FREQUENCY_2_4_BAND)
            config->variant |= WIFI_80211_VARIANT_BE;
        if(wifidb_update_wifi_radio_config(index, config, rdk_config) != RETURN_OK) {
            wifi_util_error_print(WIFI_DB,"%s:%d error in updating radio config\n", __func__,__LINE__);
            return;
        }
    }
#endif /* CONFIG_IEEE80211BE */
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_vap_config_upgrade
  Parameter   : config      - wifi_vap_info_map_t updated to wifidb
              : rdk_config  - rdk_wifi_vap_info_t updated to wifidb
  Description : Upgrade vap parameters to new db version
 *************************************************************************************
********************************************** ****************************************/
static void wifidb_vap_config_upgrade(wifi_vap_info_map_t *config, rdk_wifi_vap_info_t *rdk_config)
{
    unsigned int i;
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();

    if (g_wifidb->db_version == 0) {
        return;
    }

    wifi_util_info_print(WIFI_DB, "%s:%d upgrade vap config, old db version %d\n", __func__,
        __LINE__, g_wifidb->db_version);

    for (i = 0; i < config->num_vaps; i++) {
        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_EXISTS_FLAG) {
            if (ctrl->network_mode != rdk_dev_mode_type_ext) {
                rdk_config[i].exists = true;
                wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
                    &rdk_config[i]);
            }
        }
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
        if (rdk_config[i].exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
            if (config->vap_array[i].vap_index != 2 && config->vap_array[i].vap_index != 3) {
                wifi_util_error_print(WIFI_DB,
                    "%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n", __FUNCTION__,
                    __LINE__, config->vap_array[i].vap_index);
                rdk_config[i].exists = true;
            }
#else
            wifi_util_error_print(WIFI_DB,
                "%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n", __FUNCTION__,
                __LINE__, config->vap_array[i].vap_index);
            rdk_config[i].exists = true;
#endif
        }
#endif
        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_MBO_FLAG &&
            !isVapSTAMesh(config->vap_array[i].vap_index)) {
            config->vap_array[i].u.bss_info.mbo_enabled = !isVapPrivate(
                config->vap_array[i].vap_index);
            wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
                &rdk_config[i]);
        }
        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_TCM_FLAG) {
            wifi_util_info_print(WIFI_DB, "%s:%d upgrade vap config, db version %d\n", __func__,
                __LINE__, g_wifidb->db_version);
            config->vap_array[i].u.bss_info.preassoc.time_ms = TCM_TIMEOUT_MS;
            config->vap_array[i].u.bss_info.preassoc.min_num_mgmt_frames = TCM_MIN_MGMT_FRAMES;
            strncpy(config->vap_array[i].u.bss_info.preassoc.tcm_exp_weightage, TCM_WEIGHTAGE,
                sizeof(config->vap_array[i].u.bss_info.preassoc.tcm_exp_weightage));
            strncpy(config->vap_array[i].u.bss_info.preassoc.tcm_gradient_threshold, TCM_THRESHOLD,
                sizeof(config->vap_array[i].u.bss_info.preassoc.tcm_gradient_threshold));
            wifidb_update_wifi_cac_config(config);
        }
        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_WPA3_COMP_FLAG) {
            if (config->vap_array[i].u.bss_info.security.mode == WPA3_COMPATIBILITY) {
                config->vap_array[i].u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
                config->vap_array[i].u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
                wifi_util_info_print(WIFI_DB, "%s Update security mode:%d mfp:%d \n", __func__,
                    config->vap_array[i].u.bss_info.security.mode,
                    config->vap_array[i].u.bss_info.security.mfp);
                wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
                    &rdk_config[i]);
            }
        }

        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_HOSTAP_MGMT_FRAME_CTRL_FLAG) {
#if defined(_XB7_PRODUCT_REQ_) || defined(_XB8_PRODUCT_REQ_) || defined(_XB10_PRODUCT_REQ_) || \
    defined(_SCER11BEL_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_) ||                         \
    defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_)
            if (!isVapSTAMesh(config->vap_array[i].vap_index)) {
                config->vap_array[i].u.bss_info.hostap_mgt_frame_ctrl = true;
                wifi_util_info_print(WIFI_DB,
                    "%s:%d Update hostap_mgt_frame_ctrl:%d for vap_index:%d \n", __func__, __LINE__,
                    config->vap_array[i].u.bss_info.hostap_mgt_frame_ctrl,
                    config->vap_array[i].vap_index);
                wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
                    &rdk_config[i]);
            }
#endif // defined(_XB7_PRODUCT_REQ_) || defined(_XB8_PRODUCT_REQ_) || defined(_XB10_PRODUCT_REQ_) ||
       // defined(_SCER11BEL_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_) ||
       // defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_)
        }

        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_STATS_FLAG) {
            config->vap_array[i].u.bss_info.interop_ctrl = false;
            config->vap_array[i].u.bss_info.inum_sta = 0;
            wifi_util_dbg_print(WIFI_DB,
                "%s:%d Update interop_ctrl:%d inum_sta:%d for vap_index:%d \n", __func__, __LINE__,
                config->vap_array[i].u.bss_info.interop_ctrl,config->vap_array[i].u.bss_info.inum_sta,
                config->vap_array[i].vap_index);
            wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
                &rdk_config[i]);
        }

        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_MANAGED_WIFI_FLAG) {
            config->vap_array[i].u.bss_info.am_config.npc.speed_tier =
                isVapLnfPsk(config->vap_array[i].vap_index) ? DEFAULT_MANAGED_WIFI_SPEED_TIER : 0;
            wifi_util_dbg_print(WIFI_DB, "%s:%d Update speed_tier:%d for vap_index:%d \n", __func__,
                __LINE__, config->vap_array[i].u.bss_info.am_config.npc.speed_tier,
                config->vap_array[i].vap_index);
            wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
                &rdk_config[i]);
        }

        if (g_wifidb->db_version < ONEWIFI_DB_VERSION_WPA3_T_DISABLE_FLAG) {
            wifi_vap_security_t *sec;

            if (isVapSTAMesh(config->vap_array[i].vap_index)) {
                sec = &config->vap_array[i].u.sta_info.security;
            } else {
                sec = &config->vap_array[i].u.bss_info.security;
            }

            if (sec->wpa3_transition_disable != false) {
                sec->wpa3_transition_disable = false;
                int ret = wifidb_update_wifi_security_config(config->vap_array[i].vap_name, sec);
                wifi_util_info_print(WIFI_DB, "%s:%d force change wpa3 transition"
                    " disable state to false for vap:%s ret:%d\r\n", __func__, __LINE__,
                    config->vap_array[i].vap_name, ret);
            }
        }
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_vap_config_ext
  Parameter   : config      - wifi_vap_info_map_t updated to wifidb
              : rdk_config  - rdk_wifi_vap_info_t updated to wifidb
  Description : Set vap parameters for extender mode
 *************************************************************************************
********************************************** ****************************************/
static void wifidb_vap_config_ext(wifi_vap_info_map_t *config, rdk_wifi_vap_info_t *rdk_config)
{
    unsigned int i;
    wifi_ctrl_t *ctrl = get_wifictrl_obj();

    if (ctrl->network_mode != rdk_dev_mode_type_ext) {
        return;
    }

    for (i = 0; i < config->num_vaps; i++) {
        // Override db configuration since after bootup extender VAPs don't exist
        rdk_config[i].exists = isVapSTAMesh(config->vap_array[i].vap_index);
        wifidb_update_wifi_vap_info(config->vap_array[i].vap_name, &config->vap_array[i],
            &rdk_config[i]);
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_vap_config_correction
  Parameter   : cl_vap_map_param      - wifi_vap_info_map_t updated to wifidb
  Description : vap config parameters corrections
 *************************************************************************************
********************************************** ****************************************/
void wifidb_vap_config_correction(wifi_vap_info_map_t *l_vap_map_param)
{
    unsigned int index = 0;
    wifi_vap_info_t *vap_config = NULL;
    rdk_wifi_vap_info_t *rdk_vap_config = NULL;

    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();

    for (index = 0; index < l_vap_map_param->num_vaps; index++) {
        vap_config = &l_vap_map_param->vap_array[index];

        if ((isVapPrivate(vap_config->vap_index)) &&
            (access(ONEWIFI_BSS_MAXASSOC_FLAG, F_OK) != 0) &&
            (vap_config->u.bss_info.bssMaxSta != wifi_hal_cap_obj->wifi_prop.BssMaxStaAllow)) {
            wifi_util_info_print(WIFI_DB,
                "%s:%d: Update bssMaxSta for private_vap:%d from %d to %d\r\n", __func__, __LINE__,
                vap_config->vap_index, vap_config->u.bss_info.bssMaxSta,
                wifi_hal_cap_obj->wifi_prop.BssMaxStaAllow);
            vap_config->u.bss_info.bssMaxSta = wifi_hal_cap_obj->wifi_prop.BssMaxStaAllow;

            rdk_vap_config = get_wifidb_rdk_vaps(vap_config->radio_index);
            if (rdk_vap_config == NULL) {
                wifi_util_error_print(WIFI_DB, "%s:%d: failed to get rdk vaps for radio index %d\n",
                    __func__, __LINE__, vap_config->radio_index);
            } else {
                update_wifi_vap_info(vap_config->vap_name, vap_config, rdk_vap_config);
            }
        }

        if (isVapPrivate(vap_config->vap_index) &&
            is_sec_mode_personal(vap_config->u.bss_info.security.mode)) {
#if defined(FEATURE_SUPPORT_WPS) &&  !defined(_SR213_PRODUCT_REQ_)
            if (vap_config->u.bss_info.wps.enable == false) {
                vap_config->u.bss_info.wps.enable = true;
                wifi_util_info_print(WIFI_DB, "%s:%d: force wps enabled for private_vap:%d\r\n",
                    __func__, __LINE__, vap_config->vap_index);
            }
            continue;
#endif
        }
        if (isVapLnfSecure(vap_config->vap_index) &&
            is_sec_mode_enterprise(vap_config->u.bss_info.security.mode)) {
            set_lnf_radius_server_ip(&vap_config->u.bss_info.security);
            wifi_util_info_print(WIFI_DB, "%s:%d: Primary Ip and Secondry Ip: %s , %s\n", __func__,
                __LINE__, (char *)vap_config->u.bss_info.security.u.radius.ip,
                (char *)vap_config->u.bss_info.security.u.radius.s_ip);
            continue;
        }
        if (isVapLnfPsk(vap_config->vap_index) &&
            (!vap_config->u.bss_info.mdu_enabled &&
                !strstr(vap_config->repurposed_vap_name, "managed_guest_")) &&
            vap_config->u.bss_info.enabled) {
            vap_config->u.bss_info.enabled = false;
            rdk_vap_config = get_wifidb_rdk_vaps(vap_config->radio_index);
            if (rdk_vap_config == NULL) {
                wifi_util_error_print(WIFI_DB, "%s:%d: failed to get rdk vaps for radio index %d\n",
                    __func__, __LINE__, vap_config->radio_index);
                continue;
            }
            update_wifi_vap_info(vap_config->vap_name, vap_config, rdk_vap_config);
            wifi_util_info_print(WIFI_DB,
                "%s:%d: vap_config->u.bss_info.enabled = false for the vap_name = %s\n", __func__,
                __LINE__, vap_config->vap_name);
            continue;
        }
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : evloop_func
  Parameter   : void
  Description : Init evloop which monitors wifidb for any update and triggers
                respective  callbacks
 *************************************************************************************
********************************************** ****************************************/
void *evloop_func(void *arg)
{
        wifi_db_t *g_wifidb;
	prctl(PR_SET_NAME,  __func__, 0, 0, 0);
        g_wifidb = (wifi_db_t*) get_wifidb_obj();
	ev_run(g_wifidb->wifidb_ev_loop, 0);
	return NULL;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_read_version
  Parameter   : void
  Description : read db version (before upgrade)
 *************************************************************************************
********************************************** ****************************************/
static void wifidb_read_version()
{
    int ret;
    FILE *file;
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();

    g_wifidb->db_version = 0;

    file = fopen(ONEWIFI_DB_OLD_VERSION_FILE, "r");
    if (file == NULL) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d: Failed to open %s\n", __func__, __LINE__,
            ONEWIFI_DB_OLD_VERSION_FILE);
        return;
    }

    ret = fscanf(file, "%d", &g_wifidb->db_version);
    if (ret != 1) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d: Failed to read %s\n", __func__, __LINE__,
            ONEWIFI_DB_OLD_VERSION_FILE);
    } else {
        wifi_util_dbg_print(WIFI_DB, "%s:%d: db version %d\n", __func__, __LINE__,
            g_wifidb->db_version);
    }

    fclose(file);
}

void create_onewifi_migration_flag(void)
{
    //create file
    FILE *fp = NULL;

    fp = fopen(ONEWIFI_MIGRATION_FLAG, "a+");
    if (fp != NULL) {
        fclose(fp);
        wifi_util_info_print(WIFI_DB, "%s:%d onewifi wifidb migration flag created\n", __func__, __LINE__);
    } else {
        wifi_util_info_print(WIFI_DB, "%s:%d onewifi wifidb migration flag create failure\n", __func__, __LINE__);
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : start_wifidb_func
  Parameter   : void
  Description : Init wifidb server
 *************************************************************************************
***************************************************************************************/
void *start_wifidb_func(void *arg)
{
    char cmd[1024];
    char db_file[128];
    struct stat sb;
    bool debug_option = false;
    DIR     *wifiDbDir = NULL;
    char version_str[BUFFER_LENGTH_WIFIDB] = {0};
    int  version_int = 0;
    FILE *fp = NULL;
    int i = 0;
    //bool isOvsSchemaCreate = false;
    wifi_util_info_print(WIFI_DB, "start_wifidb_func \n");
    wifi_mgr_t *g_wifidb;
    char last_reboot_reason[32];
    raw_data_t data = { 0 };

    memset(last_reboot_reason, 0, sizeof(last_reboot_reason));
    g_wifidb = get_wifimgr_obj();
    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    g_wifidb->is_db_update_required = false;

    wifiDbDir = opendir(WIFIDB_DIR);
    if(wifiDbDir){
        closedir(wifiDbDir);
    }else if(ENOENT == errno){
        if(0 != mkdir(WIFIDB_DIR, 0777)){
            wifi_util_info_print(WIFI_DB,"Failed to Create WIFIDB directory.\n");
            return NULL;
        }
    }else{
        wifi_util_info_print(WIFI_DB,"Error opening Db Configuration directory. Setting Default\n");
        return NULL;
    }
    //create a copy of ovs-db server
    sprintf(cmd, "cp /usr/sbin/ovsdb-server %s/wifidb-server", WIFIDB_RUN_DIR);
    system(cmd);
    sprintf(db_file, "%s/rdkb-wifi.db", WIFIDB_DIR);
    if (stat(db_file, &sb) != 0) {
        wifi_util_info_print(WIFI_DB, "%s:%d: Could not find rdkb database, ..creating\n", __func__,
            __LINE__);
        sprintf(cmd, "ovsdb-tool create %s %s/rdkb-wifi.ovsschema", db_file, WIFIDB_SCHEMA_DIR);
        system(cmd);

        memset(&data, 0, sizeof(raw_data_t));

        if (get_bus_descriptor()->bus_data_get_fn(&g_wifidb->ctrl.handle,
                LAST_REBOOT_REASON_NAMESPACE, &data) == bus_error_success) {
            if (data.data_type != bus_data_type_string) {
                wifi_util_error_print(WIFI_CTRL,
                    "%s:%d '%s' bus_data_get_fn failed with data_type:0x%x\n", __func__, __LINE__,
                    LAST_REBOOT_REASON_NAMESPACE, data.data_type);
                get_bus_descriptor()->bus_data_free_fn(&data);
                return NULL;
            }
            strncpy(last_reboot_reason, (char *)data.raw_data.bytes, data.raw_data_len);
            get_bus_descriptor()->bus_data_free_fn(&data);
        } else {
            get_wifi_last_reboot_reason_psm_value(last_reboot_reason);
        }
        wifi_util_info_print(WIFI_DB, "%s:%d last_reboot_reason:%s \n", __func__, __LINE__,
            last_reboot_reason);
        if ((strlen(last_reboot_reason) != 0) &&
            (strncmp(last_reboot_reason, "factory-reset", strlen("factory-reset")) != 0) &&
            (strncmp(last_reboot_reason, "kernel-panic", strlen("kernel-panic")) != 0) &&
            (strncmp(last_reboot_reason, "WPS-Factory-Reset", strlen("WPS-Factory-Reset")) != 0)) {
            create_onewifi_migration_flag();
        }
    } else {
        /*check for db-version of the db file. If db-version is less than than the OneWiFi Schema db version, then
         * Delete the exisiting schema file and create it. So that OneWiFi will update the configuration based on
         * PSM and NVRAM values
         * */

        wifi_util_info_print(WIFI_DB,"%s:%d: rdkb database already present\n", __func__, __LINE__);
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "ovsdb-tool db-version %s", db_file);
        /*Get the Existing db-version*/
        fp = popen(cmd,"r");
        if(fp != NULL) {
            while (fgets(version_str, sizeof(version_str), fp) != NULL){
                wifi_util_info_print(WIFI_DB,"%s:%d: DB Version before upgrade found\n", __func__, __LINE__);
            }
            pclose(fp);
            for(i=0;version_str[i];i++) {
                if ((version_str[i]!='.') && (isdigit(version_str[i]))) {
                    version_int=version_int*10+(version_str[i]-'0');
                }
            }
            wifi_util_info_print(WIFI_DB,"%s:%d:DB Version before upgrade %d\n", __func__, __LINE__, version_int);
            g_wifidb->db_version = version_int;

            if (version_int < ONEWIFI_SCHEMA_DEF_VERSION) {
                /*version less than OneWiFi default version
                 * so, Delete the db file and re-create the schema file
                 */
                if (remove(db_file) == 0) {
                    wifi_util_info_print(WIFI_DB,"%s:%d: %s file deleted succesfully\n", __func__, __LINE__, db_file);
                }
                wifi_util_info_print(WIFI_DB,"%s:%d: creating the new DB file\n", __func__, __LINE__);
                sprintf(cmd, "ovsdb-tool create %s %s/rdkb-wifi.ovsschema", db_file, WIFIDB_SCHEMA_DIR);
                system(cmd);
                g_wifidb->is_db_update_required = true;
                create_onewifi_migration_flag();
            }
        }

        if (g_wifidb->is_db_update_required == false) {
            sprintf(cmd,"ovsdb-tool convert %s %s/rdkb-wifi.ovsschema",db_file,WIFIDB_SCHEMA_DIR);
            wifi_util_info_print(WIFI_DB,"%s:%d: rdkb database check for version upgrade/downgrade %s \n", __func__, __LINE__,cmd);
            system(cmd);
        }
    }

    sprintf(cmd, "%s/wifidb-server %s --remote=punix:%s/wifidb.sock %s --unixctl=%s/wifi.ctl --log-file=/dev/null --detach", WIFIDB_RUN_DIR, db_file, WIFIDB_RUN_DIR, (debug_option == true)?"--verbose=dbg":"", WIFIDB_RUN_DIR);

    system(cmd);
    wifi_util_info_print(WIFI_DB, "start_wifidb_func done\n");
    return NULL;
}

//moved wifi_db.c code moved here for abstract the db functions.
void rdk_wifi_dbg_print(int level, char *format, ...)
{
    char buff[2048] = {0};
    va_list list;
    static FILE *fpg = NULL;

    if ((access("/nvram/rdkWifiDbg", R_OK)) != 0) {
        return;
    }

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    if (fpg == NULL) {
        fpg = fopen("/tmp/rdkWifi", "a+");
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

int wifidb_get_factory_reset_data(bool *data)
{
	return 0;
}

int wifidb_set_factory_reset_data(bool data)
{
	return 0;
}

int wifidb_del_interworking_entry()
{
    return 0;
}

int wifidb_check_wmm_params()
{
    return 0;
}

int wifidb_get_reset_hotspot_required(bool *req)
{
    return 0;
}

int wifidb_set_reset_hotspot_required(bool req)
{
    return 0;
}

void rdk_wifi_radio_get_status(uint8_t r_index, bool *status)
{
    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    rdk_wifi_dbg_print(1, "wifidb radio get status %s\n", __FUNCTION__);
    wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);
    *status = radio_vap_map.enable;
}

void rdk_wifi_radio_get_autochannel_status(uint8_t r_index, bool *autochannel_status)
{
    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    rdk_wifi_dbg_print(1, "wifidb radio get auto channel status %s\n", __FUNCTION__);
    wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);
    *autochannel_status = radio_vap_map.autoChannelEnabled;
}

void rdk_wifi_radio_get_frequency_band(uint8_t r_index, char *band)
{
    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);
    if ( radio_vap_map.band == 1 )
    {
        strcpy(band, "2.4GHz");
    }
    else if ( radio_vap_map.band == 2 )
    {
        strcpy(band, "5GHz");
    }
}

void rdk_wifi_radio_get_dcs_status(uint8_t r_index, bool *dcs_status)
{
    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    rdk_wifi_dbg_print(1, "wifidb radio get dcs status %s\n", __FUNCTION__);
    wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);
    *dcs_status = radio_vap_map.DCSEnabled;
}

void rdk_wifi_radio_get_channel(uint8_t r_index, ULONG *channel)
{
    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);
    *channel = radio_vap_map.channel;
}

void rdk_wifi_radio_get_channel_bandwidth(uint8_t r_index, ULONG *channel_bandwidth)
{
    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);
    *channel_bandwidth = radio_vap_map.channelWidth;
}

void rdk_wifi_radio_get_operating_standards(uint8_t r_index, char *buf)
{

    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);

        if (radio_vap_map.variant & WIFI_80211_VARIANT_A )
        {
            strcat(buf, "a");
        }
        
        if (radio_vap_map.variant & WIFI_80211_VARIANT_B )
        {
            if (strlen(buf) != 0)
            {
                strcat(buf, ",b");
            }
            else
            {
                strcat(buf, "b");
            }
        }
        
        if (radio_vap_map.variant & WIFI_80211_VARIANT_G )
        {
            if (strlen(buf) != 0)
            {
                strcat(buf, ",g");
            }
            else
            {
                strcat(buf, "g");
            }
        }
        
        if (radio_vap_map.variant & WIFI_80211_VARIANT_N )
        {
            if (strlen(buf) != 0)
            {
                strcat(buf, ",n");
            }
            else
            {
                strcat(buf, "n");
            }
        }

        if (radio_vap_map.variant & WIFI_80211_VARIANT_AC )
        {
            if (strlen(buf) != 0)
            {
                strcat(buf, ",ac");
            }
            else
            {
                strcat(buf, "ac");
            }
        }

        if (radio_vap_map.variant & WIFI_80211_VARIANT_AX )
        {
            if (strlen(buf) != 0)
            {
                strcat(buf, ",ax");
            }
            else
            {
                strcat(buf, "ax");
            }
        }
#ifdef CONFIG_IEEE80211BE
        if (radio_vap_map.variant & WIFI_80211_VARIANT_BE )
        {
            if (strlen(buf) != 0)
            {
                strcat(buf, ",be");
            }
            else
            {
                strcat(buf, "be");
            }
        }
#endif /* CONFIG_IEEE80211BE */
}

int rdk_wifi_vap_get_from_index(int wlanIndex, wifi_vap_info_t *vap_map,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    int retDbGet;
    char l_vap_name[32];
    memset(l_vap_name, 0, sizeof(l_vap_name));
    memset(vap_map, 0 ,sizeof(wifi_vap_info_t));
    memset(rdk_vap_info, 0, sizeof(rdk_wifi_vap_info_t));

    retDbGet = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, wlanIndex, l_vap_name);
    if(retDbGet == RETURN_ERR)
    {
        rdk_wifi_dbg_print(1, "wifidb vap name info get failure\n");
        return retDbGet;
    }
    retDbGet = wifidb_get_wifi_vap_info(l_vap_name, vap_map, rdk_vap_info);
    if(retDbGet != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "wifidb vap info get failure\n");
    }
    else
    {
        rdk_wifi_dbg_print(1, "Get wifiDb_vap_parameter vap_index:%d:: l_vap_name = %s \n", wlanIndex, l_vap_name);
    }
    return retDbGet;
}

int rdk_wifi_vap_update_from_index(int wlanIndex, wifi_vap_info_t *vap_map,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    int retDbSet = RETURN_OK;
    char l_vap_name[32];
    memset(l_vap_name, 0, sizeof(l_vap_name));

    retDbSet = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, wlanIndex, l_vap_name);
    if(retDbSet == RETURN_ERR)
    {
        rdk_wifi_dbg_print(1, "wifidb vap name info get failure\n");
        return retDbSet;
    }

    retDbSet = wifidb_update_wifi_vap_info(l_vap_name, vap_map, rdk_vap_info);
    if(retDbSet != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "wifidb vap info set failure\n");
    }
    else
    {
        rdk_wifi_dbg_print(1, "Set wifiDb_vap_parameter success...vap_index:%d: vap_name: = %s\n", wlanIndex, l_vap_name);
    }
    return retDbSet;
}

int rdk_wifi_vap_security_get_from_index(int wlanIndex, wifi_vap_security_t *sec)
{
    rdk_wifi_dbg_print(1, "Enter vap security get from index\n");
    int retDbGet = RETURN_OK;
    char l_vap_name[32];
    memset(l_vap_name, 0, sizeof(l_vap_name));
    memset(sec, 0 ,sizeof(wifi_vap_security_t));

    retDbGet = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, wlanIndex, l_vap_name);
    if(retDbGet == RETURN_ERR)
    {
        rdk_wifi_dbg_print(1, "wifidb vap name info get failure\n");
        return retDbGet;
    }

    retDbGet = wifidb_get_wifi_security_config(l_vap_name, sec);
    if(retDbGet != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "wifidb vap security info get failure\n");
    }
    else
    {
        rdk_wifi_dbg_print(1, "Get wifiDb_vap_security_parameter vap_index:%d:: l_vap_name = %s \n", wlanIndex, l_vap_name);
    }
    return retDbGet;
}

int rdk_wifi_vap_security_update_from_index(int wlanIndex, wifi_vap_security_t *sec)
{
    rdk_wifi_dbg_print(1, "Enter vap security update from index\n");
    int retDbSet = RETURN_OK;
    char l_vap_name[32];
    memset(l_vap_name, 0, sizeof(l_vap_name));

    retDbSet = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, wlanIndex, l_vap_name);
    if(retDbSet == RETURN_ERR)
    {
        rdk_wifi_dbg_print(1, "wifidb vap name info get failure\n");
        return retDbSet;
    }

    retDbSet = wifidb_update_wifi_security_config(l_vap_name, sec); 
    if(retDbSet != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "wifidb vap info set failure\n");
    }
    else
    {
        rdk_wifi_dbg_print(1, "Set wifiDb_vap_security_parameter...vap_index:%d: vap_name: = %s\n", wlanIndex, l_vap_name);
    }
    return retDbSet;
}

int rdk_wifi_SetRapidReconnectThresholdValue(int wlanIndex, int rapidReconnThresholdValue)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    vap_map.u.bss_info.rapidReconnThreshold = rapidReconnThresholdValue;
    rdk_wifi_dbg_print(1, "wifidb vap info set rapidReconnThresholdValue %d\n", rapidReconnThresholdValue);
    ret = rdk_wifi_vap_update_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    return ret;
}

int rdk_wifi_GetRapidReconnectThresholdValue(int wlanIndex, int *rapidReconnThresholdValue)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    if(ret != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "rdk wifi vap get index failure :%s\n",__FUNCTION__);
	return ret;
    }
    *rapidReconnThresholdValue = vap_map.u.bss_info.rapidReconnThreshold;
    rdk_wifi_dbg_print(1, "wifidb vap info get rapidReconnThresholdValue %d\n", *rapidReconnThresholdValue);
    return ret;
}

int rdk_wifi_SetRapidReconnectEnable(int wlanIndex, bool reconnectCountEnable)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    vap_map.u.bss_info.rapidReconnectEnable = reconnectCountEnable;
    rdk_wifi_dbg_print(1, "wifidb vap info set reconnectEnable %d\n", reconnectCountEnable);
    ret = rdk_wifi_vap_update_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    return ret;
}

int rdk_wifi_GetRapidReconnectEnable(int wlanIndex, bool *reconnectCountEnable)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    if(ret != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "rdk wifi vap get index failure :%s\n",__FUNCTION__);
	return ret;
    }
    *reconnectCountEnable = vap_map.u.bss_info.rapidReconnectEnable;
    rdk_wifi_dbg_print(1, "wifidb vap info get reconnectEnable %d\n", *reconnectCountEnable);
    return ret;
}

int rdk_wifi_SetNeighborReportActivated(int wlanIndex, bool bNeighborReportActivated)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    vap_map.u.bss_info.nbrReportActivated = bNeighborReportActivated;
    rdk_wifi_dbg_print(1, "wifidb vap info set nbrReportActivated %d\n", bNeighborReportActivated);
    ret = rdk_wifi_vap_update_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    return ret;
}

int rdk_wifi_GetNeighborReportActivated(int wlanIndex, bool *bNeighborReportActivated)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    if(ret != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "rdk wifi vap get index failure :%s\n",__FUNCTION__);
	return ret;
    }
    *bNeighborReportActivated = vap_map.u.bss_info.nbrReportActivated;
    rdk_wifi_dbg_print(1, "wifidb vap info get nbrReportActivated %d\n", *bNeighborReportActivated);
    return ret;
}

int rdk_wifi_ApSetStatsEnable(int wlanIndex, bool bValue)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    vap_map.u.bss_info.vapStatsEnable = bValue;
    rdk_wifi_dbg_print(1, "wifidb vap info set vapStatsEnable %d\n", bValue);
    ret = rdk_wifi_vap_update_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    return ret;
}

int rdk_wifi_ApGetStatsEnable(int wlanIndex, bool *bValue)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    if(ret != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "rdk wifi vap get index failure :%s\n",__FUNCTION__);
	return ret;
    }
    *bValue = vap_map.u.bss_info.vapStatsEnable;
    rdk_wifi_dbg_print(1, "wifidb vap info get vapStatsEnable %d\n", *bValue);
    return ret;
}

int rdk_wifi_setBSSTransitionActivated(int wlanIndex, bool BSSTransitionActivated)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    vap_map.u.bss_info.bssTransitionActivated = BSSTransitionActivated;
    rdk_wifi_dbg_print(1, "wifidb vap info set BSSTransitionActivated %d\n", BSSTransitionActivated);
    ret = rdk_wifi_vap_update_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    return ret;
}

int rdk_wifi_getBSSTransitionActivated(int wlanIndex, bool *BSSTransitionActivated)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    if(ret != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "rdk wifi vap get index failure :%s\n",__FUNCTION__);
	return ret;
    }
    *BSSTransitionActivated = vap_map.u.bss_info.bssTransitionActivated;
    rdk_wifi_dbg_print(1, "wifidb vap info get BSSTransitionActivated %d\n", *BSSTransitionActivated);
    return ret;
}

int rdk_wifi_GetApMacFilterMode(int wlanIndex, int *mode)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    if(ret != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "rdk wifi vap get index failure :%s\n",__FUNCTION__);
	return ret;
    }
    *mode = vap_map.u.bss_info.mac_filter_mode;
    rdk_wifi_dbg_print(1, "wifidb vap info get mac_filter_mode %d\n", *mode);
    return ret;
}

int rdk_wifi_SetApMacFilterMode(int wlanIndex, int mode)
{
    int ret = RETURN_OK;
    wifi_vap_info_t vap_map;
    rdk_wifi_vap_info_t rdk_vap_info;
    ret = rdk_wifi_vap_get_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    vap_map.u.bss_info.mac_filter_mode = mode;
    rdk_wifi_dbg_print(1, "wifidb vap info set mac_filter_mode %d\n", mode);
    ret = rdk_wifi_vap_update_from_index(wlanIndex, &vap_map, &rdk_vap_info);
    return ret;
}

int rdk_wifi_radio_get_BeaconInterval(uint8_t r_index, int *BeaconInterval)
{
    int ret = RETURN_OK;

    wifi_radio_operationParam_t radio_vap_map;
    wifi_radio_feature_param_t radio_feat;
    memset(&radio_vap_map, 0, sizeof(radio_vap_map));
    memset(&radio_feat, 0, sizeof(radio_feat));

    ret = wifidb_get_wifi_radio_config(r_index, &radio_vap_map, &radio_feat);
    if(ret == RETURN_OK)
    {
       rdk_wifi_dbg_print(1, "wifidb radio beacon info get success %s: r_index:%d\n", __FUNCTION__, r_index);
       *BeaconInterval = radio_vap_map.beaconInterval;
    }
    else
    {
       rdk_wifi_dbg_print(1, "wifidb radio beacon info get failure %s r_index:%d\n", __FUNCTION__, r_index);
    }
    return ret;
}

int rdk_wifi_radio_get_parameters(uint8_t r_index, wifi_radio_operationParam_t *radio_vap_map, wifi_radio_feature_param_t *radio_feat)
{
    int ret = RETURN_OK;
    memset(radio_vap_map, 0, sizeof(wifi_radio_operationParam_t));
    memset(radio_feat, 0, sizeof(wifi_radio_feature_param_t));

    ret = wifidb_get_wifi_radio_config(r_index, radio_vap_map, radio_feat);
    if(ret == RETURN_OK)
    {
       rdk_wifi_dbg_print(1, "wifidb radio info get success %s r_index:%d\n", __FUNCTION__, r_index);
    }
    else
    {
       rdk_wifi_dbg_print(1, "wifidb radio info get failure %s r_index:%d\n", __FUNCTION__, r_index);
    }
    return ret;
}

int update_wifidb_vap_bss_param(uint8_t vap_index, wifi_front_haul_bss_t *pcfg)
{
    uint8_t l_radio_index = 0, l_vap_index = 0;
    char l_vap_name[32];
    int ret;
    rdk_wifi_vap_info_t *l_rdk_vaps;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vap_index, &l_radio_index, &l_vap_index);
    wifi_vap_info_t *l_vap_maps = get_wifidb_vap_parameters(l_radio_index);
    if(l_vap_maps == NULL || l_vap_index >= getNumberVAPsPerRadio(l_radio_index))
    {

        rdk_wifi_dbg_print(1, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, l_radio_index, vap_index);
        return RETURN_ERR;
    }
    memcpy(&l_vap_maps->u.bss_info, pcfg, sizeof(wifi_front_haul_bss_t));

    l_rdk_vaps = get_wifidb_rdk_vaps(l_radio_index);
    if (l_rdk_vaps == NULL)
    {
        rdk_wifi_dbg_print(1, "%s: failed to get rdk vaps for radio index %d\n", __FUNCTION__,
            l_radio_index);
        return RETURN_ERR;
    }

    convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vap_index, l_vap_name);
    ret = update_wifi_vap_info(l_vap_name, l_vap_maps, l_rdk_vaps);
    if(ret != RETURN_OK)
    {
        rdk_wifi_dbg_print(1, "wifidb vap info update failure %s vap_index:%d\n", __FUNCTION__, vap_index);
	return RETURN_ERR;
    }
    return RETURN_OK;
}

#if 0
int ovsdb_get_radio_params(unsigned int radio_index, wifi_radio_operationParam_t *params)
{
    if (radio_index == 0) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->operatingClass = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_G;
    } else if (radio_index == 1) {
        params->band = WIFI_FREQUENCY_5_BAND;
        params->operatingClass = 1;
        params->channel = 36;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_A;
    } else if (radio_index == 2) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->operatingClass = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_N;
    } else if (radio_index == 3) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->operatingClass = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_N;
    }

    params->autoChannelEnabled = false;
    params->csa_beacon_count = 0;
    params->countryCode = wifi_countrycode_US;
    params->beaconInterval = 100;
    params->dtimPeriod = 2;
    return 0;
}
int ovsdb_get_vap_info_map(unsigned int real_index, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    wifi_vap_info_t *params;
    params = &map->vap_array[0];
    memset((unsigned char *)params, 0, sizeof(wifi_vap_info_t));
    //params->radio_index = real_index;
    params->radio_index = radio_index;
    if (radio_index == 0) {
        map->num_vaps = 1;
        params->vap_index = 0;
        params->vap_mode = wifi_vap_mode_ap;
        strcpy(params->vap_name, "private_ssid_2g");
        strcpy(params->bridge_name, "br0");
        strcpy(params->u.bss_info.ssid, "wifi_test_private_2");
        params->u.bss_info.enabled = true;
        params->u.bss_info.showSsid = true;
        params->u.bss_info.isolation = true;
        params->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
        params->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        strcpy(params->u.bss_info.security.u.key.key, INVALID_KEY);
        params->u.sta_info.scan_params.period = 10;
        params->u.bss_info.bssMaxSta = 20;
    } else if (radio_index == 1) {
        map->num_vaps = 1;
        params->vap_index = 1;
        params->vap_mode = wifi_vap_mode_ap;
        strcpy(params->vap_name, "private_ssid_5g");
        strcpy(params->bridge_name, "br1");
        strcpy(params->u.sta_info.ssid, "wifi_test_private_5");
        params->u.bss_info.enabled = true;
        params->u.bss_info.showSsid = true;
        params->u.bss_info.isolation = true;
        params->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
        params->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        strcpy(params->u.bss_info.security.u.key.key, INVALID_KEY);
        params->u.sta_info.scan_params.period = 10;
        params->u.bss_info.bssMaxSta = 20;
    } else if (radio_index == 2) {
        map->num_vaps = 1;
        params->vap_index = 2;
        params->vap_mode = wifi_vap_mode_ap;
        strcpy(params->vap_name, "private_ssid_2g");
        strcpy(params->bridge_name, "br2");
        strcpy(params->u.bss_info.ssid, "wifi_test_private_2");
        params->u.bss_info.enabled = true;
        params->u.bss_info.showSsid = true;
        params->u.bss_info.isolation = true;
        params->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
        params->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        strcpy(params->u.bss_info.security.u.key.key, INVALID_KEY);
        params->u.bss_info.bssMaxSta = 20;
    } else if (radio_index == 3) {
	map->num_vaps = 1;
        params->vap_index = 3;
        params->vap_mode = wifi_vap_mode_sta;
        strcpy(params->vap_name, "backhaul_ssid_2g");
        strcpy(params->bridge_name, "br3");
	strcpy(params->u.sta_info.ssid, "wifi_test_private_2");
        params->u.sta_info.scan_params.period = 10;
        params->u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
        params->u.sta_info.security.encr = wifi_encryption_aes_tkip;
        strcpy(params->u.sta_info.security.u.key.key, INVALID_KEY);
    }
    return 0;
}
#endif//ONE_WIFI

void wifidb_print(char *format, ...)
{
    char buff[256 * 1024] = {0};
    va_list list;
    FILE *fpg = NULL;

    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    fpg = fopen("/rdklogs/logs/wifiDb.txt", "a+");
    if (fpg == NULL) {
        return;
    }
    fputs(buff, fpg);
    fflush(fpg);
    fclose(fpg);
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_rfc_config
  Parameter   : rfc_id     - ID of rfc structure
                rfc_param - rfc info to be updated to wifidb
  Description : Update RFC Config structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_rfc_config(UINT rfc_id, wifi_rfc_dml_parameters_t *rfc_param)
{
    struct schema_Wifi_Rfc_Config cfg, *pcfg;
    
    json_t *where;
    bool update = false;
    int count;
    int ret;
    char index[4] = {0};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if (rfc_param == NULL) {
        wifi_util_error_print(WIFI_DB, "%s:%d: rfc_param is NULL\n", __func__, __LINE__);
        return -1;
    }

    sprintf(index,"%d",rfc_id);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "rfc_id", OFUNC_EQ, index);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Rfc_Config, where, &count);
    if ((count != 0) && (pcfg != NULL)) {
        wifidb_print("%s:%d Updated WIFI DB. Found %d records with key: %d in Wifi RFCConfig table \n",__func__, __LINE__, count, rfc_id);
        memcpy(&cfg, pcfg, sizeof(struct schema_Wifi_Rfc_Config));
        update = true;
        free(pcfg);
    }
    cfg.wifipasspoint_rfc = rfc_param->wifipasspoint_rfc;
    cfg.wifiinterworking_rfc = rfc_param->wifiinterworking_rfc;
    cfg.radiusgreylist_rfc = rfc_param->radiusgreylist_rfc;
    cfg.dfsatbootup_rfc = rfc_param->dfsatbootup_rfc;
    cfg.dfs_rfc = rfc_param->dfs_rfc;
    cfg.wpa3_rfc = rfc_param->wpa3_rfc;
    cfg.memwraptool_app_rfc = rfc_param->memwraptool_app_rfc;
    cfg.levl_enabled_rfc = rfc_param->levl_enabled_rfc;
    cfg.twoG80211axEnable_rfc = rfc_param->twoG80211axEnable_rfc;
    cfg.hotspot_open_2g_last_enabled = rfc_param->hotspot_open_2g_last_enabled;
    cfg.hotspot_open_5g_last_enabled = rfc_param->hotspot_open_5g_last_enabled;
    cfg.hotspot_open_6g_last_enabled = rfc_param->hotspot_open_6g_last_enabled;
    cfg.hotspot_secure_2g_last_enabled = rfc_param->hotspot_secure_2g_last_enabled;
    cfg.hotspot_secure_5g_last_enabled = rfc_param->hotspot_secure_5g_last_enabled;
    cfg.hotspot_secure_6g_last_enabled = rfc_param->hotspot_secure_6g_last_enabled;
    cfg.wifi_offchannelscan_app_rfc = rfc_param->wifi_offchannelscan_app_rfc;
    cfg.wifi_offchannelscan_sm_rfc = rfc_param->wifi_offchannelscan_sm_rfc;
    cfg.tcm_enabled_rfc = rfc_param->tcm_enabled_rfc;
    cfg.wpa3_compatibility_enable = rfc_param->wpa3_compatibility_enable;
    if (update == true) {
        where = onewifi_ovsdb_tran_cond(OCLM_STR, "rfc_id", OFUNC_EQ, index); 
        ret = onewifi_ovsdb_table_update_where(g_wifidb->wifidb_sock_path, &table_Wifi_Rfc_Config, where, &cfg);
        if (ret == -1) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi Rfc Config table \n",__func__, __LINE__);
            return -1;
        } else if (ret == 0) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: nothing to update table_Wifi_Rfc_Config table\n", __func__, __LINE__);
        } else {
            wifidb_print("%s:%d Updated WIFI DB. Wifi Rfc Config table updated successful. \n",__func__, __LINE__);
        }
    } else {
        strcpy(cfg.rfc_id,index);
        if (onewifi_ovsdb_table_upsert_simple(g_wifidb->wifidb_sock_path, &table_Wifi_Rfc_Config, 
                                  SCHEMA_COLUMN(Wifi_Rfc_Config, rfc_id),
                                  cfg.rfc_id,
                                  &cfg, NULL) == false) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to insert in table_Wifi_RFC_config \n",__func__, __LINE__);
            return -1;
        } else {
            wifidb_print("%s:%d Updated WIFI DB. Insert in table_Wifi_RFC_Config table successful \n",__func__, __LINE__);
        }
    }
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_gas_config
  Parameter   : advertisement_id     - ID of gas_config structure
                gas_info - gas_info to be updated to wifidb
  Description : Update gas_info structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    struct schema_Wifi_GAS_Config cfg, *pcfg;
    
    json_t *where;
    bool update = false;
    int count;
    int ret;
    char index[4] = {0};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    sprintf(index,"%d",advertisement_id);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "advertisement_id", OFUNC_EQ, index);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, where, &count);
    if ((count != 0) && (pcfg != NULL)) {
        wifidb_print("%s:%d Updated WIFI DB. Found %d records with key: %d in Wifi GAS table \n",__func__, __LINE__, count, advertisement_id);
        memcpy(&cfg, pcfg, sizeof(struct schema_Wifi_GAS_Config));
        update = true;
        free(pcfg);
    }

    cfg.pause_for_server_response = gas_info->PauseForServerResponse;
    cfg.response_timeout = gas_info->ResponseTimeout;
    cfg.comeback_delay = gas_info->ComeBackDelay;
    cfg.response_buffering_time = gas_info->ResponseBufferingTime;
    cfg.query_responselength_limit = gas_info->QueryResponseLengthLimit;
    if (update == true) {
        where = onewifi_ovsdb_tran_cond(OCLM_STR, "advertisement_id", OFUNC_EQ, index); 
        ret = onewifi_ovsdb_table_update_where(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, where, &cfg);
        if (ret == -1) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi GAS Config table \n",__func__, __LINE__);
            return -1;
        } else if (ret == 0) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: nothing to update table_Wifi_GAS_Config table\n", __func__, __LINE__);
        } else {
            wifidb_print("%s:%d Updated WIFI DB. Wifi GAS Config table updated successful. \n",__func__, __LINE__);
        }
    } else {
        strcpy(cfg.advertisement_id,index);
        if (onewifi_ovsdb_table_upsert_simple(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, 
                                  SCHEMA_COLUMN(Wifi_GAS_Config, advertisement_id),
                                  cfg.advertisement_id,
                                  &cfg, NULL) == false) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to insert in table_Wifi_GAS_Config \n",__func__, __LINE__);
            return -1;
        } else {
            wifidb_print("%s:%d Updated WIFI DB. Insert in table_Wifi_GAS_Config table successful \n",__func__, __LINE__);
        }
    }
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_gas_config
  Parameter   : advertisement_id     - ID of gas_config structure
                gas_info -  wifi_GASConfiguration_t to be updated with wifidb
  Description : Get wifi_GASConfiguration_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    struct schema_Wifi_GAS_Config  *pcfg;
    json_t *where;
    int count;
    char index[4] = {0};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    sprintf(index,"%d",advertisement_id);
    where = onewifi_ovsdb_tran_cond(OCLM_STR, "advertisement_id", OFUNC_EQ, index);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, where, &count);
    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_GAS_Config not found, entry count=%d \n",__func__, __LINE__, count);
        return -1;
    }
    gas_info->AdvertisementID = atoi(pcfg->advertisement_id);
    gas_info->PauseForServerResponse = pcfg->pause_for_server_response;
    gas_info->ResponseTimeout = pcfg->response_timeout;
    gas_info->ComeBackDelay = pcfg->comeback_delay;
    gas_info->ResponseBufferingTime = pcfg->response_buffering_time;
    gas_info->QueryResponseLengthLimit = pcfg->query_responselength_limit;
    free(pcfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_wifi_vap_info
  Parameter   : vap_name     - Name of vap
                config      - wifi_vap_info_t will be updated with wifidb
  Description : Get wifi_vap_info_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_wifi_vap_info(char *vap_name, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    struct schema_Wifi_VAP_Config *pcfg;
    json_t *where;
    int count = 0;
    unsigned int index = 0;
    uint8_t vap_index = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if(config == NULL)
    {
        wifidb_print("%s:%d Failed to Get VAP info - Null pointer \n",__func__, __LINE__);
        return RETURN_ERR;
    }

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_VAP_Config, where, &count);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config get vap_name=%s count=%d\n",__func__, __LINE__,vap_name,count);
    if((pcfg == NULL) || (count== 0))
    {
        wifidb_print("%s:%d Table table_Wifi_VAP_Config table not found, entry count=%d \n",__func__, __LINE__,count);
        return RETURN_ERR;
    }
    if(pcfg != NULL)
    {

        wifi_util_dbg_print(WIFI_DB,
            "%s:%d: VAP Config radio_name=%s vap_name=%s ssid=%s enabled=%d "
            "ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d "
            "bss_max_sta=%d bss_transition_activated=%d nbr_report_activated=%d "
            "rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d "
            "mac_filter_enabled=%d mac_filter_mode=%d  mac_addr_acl_enabled=%d wmm_enabled=%d "
            "anqp_parameters=%s hs2Parameters=%s uapsd_enabled=%d beacon_rate=%d bridge_name=%s "
            "wmm_noack=%d wep_key_length=%d bss_hotspot=%d wps_push_button=%d "
            "wps_config_methods=%d wps_enabled=%d beacon_rate_ctl=%s network_initiated_greylist=%d "
            "repurposed_vap_name=%s connected_building_enabled=%d hostap_mgt_frame_ctrl=%d "
            "mbo_enabled=%d interop_ctrl=%d inum_sta=%d \n",
            __func__, __LINE__, pcfg->radio_name, pcfg->vap_name, pcfg->ssid, pcfg->enabled,
            pcfg->ssid_advertisement_enabled, pcfg->isolation_enabled, pcfg->mgmt_power_control,
            pcfg->bss_max_sta, pcfg->bss_transition_activated, pcfg->nbr_report_activated,
            pcfg->rapid_connect_enabled, pcfg->rapid_connect_threshold, pcfg->vap_stats_enable,
            pcfg->mac_filter_enabled, pcfg->mac_filter_mode, pcfg->mac_addr_acl_enabled,
            pcfg->wmm_enabled, pcfg->anqp_parameters, pcfg->hs2_parameters, pcfg->uapsd_enabled,
            pcfg->beacon_rate, pcfg->bridge_name, pcfg->wmm_noack, pcfg->wep_key_length,
            pcfg->bss_hotspot, pcfg->wps_push_button, pcfg->wps_config_methods, pcfg->wps_enabled,
            pcfg->beacon_rate_ctl, pcfg->network_initiated_greylist, pcfg->repurposed_vap_name,
            pcfg->connected_building_enabled, pcfg->hostap_mgt_frame_ctrl, pcfg->mbo_enabled, pcfg->interop_ctrl, pcfg->inum_sta);

        if((convert_radio_name_to_index(&index,pcfg->radio_name))!=0)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid radio name \n",__func__, __LINE__,pcfg->radio_name);
            return RETURN_ERR;
        }
        config->radio_index = index ;
        config->vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, pcfg->vap_name);
        if ((int)config->vap_index < 0) {
            wifi_util_error_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,pcfg->vap_name);
            return RETURN_ERR;
        }
        strncpy(config->vap_name, pcfg->vap_name,(sizeof(config->vap_name)-1));
        vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, pcfg->vap_name);
        if ((int)vap_index < 0) {
            wifi_util_error_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,pcfg->vap_name);
            return RETURN_ERR;
        }
        if (isVapLnfPsk(vap_index) && pcfg->mdu_enabled) {
            if (strlen(pcfg->repurposed_bridge_name) != 0) {
                strncpy(config->bridge_name, pcfg->repurposed_bridge_name,(sizeof(config->bridge_name)-1));
                strncpy(config->repurposed_bridge_name, pcfg->bridge_name, (sizeof(config->repurposed_bridge_name)-1));
            }
        }
        else {
            if (strlen(pcfg->bridge_name) != 0) {
                strncpy(config->bridge_name, pcfg->bridge_name,(sizeof(config->bridge_name)-1));
            } else {
                get_vap_interface_bridge_name(config->vap_index, config->bridge_name);
            }
        }

        if (strlen(pcfg->repurposed_vap_name) != 0) {
            strncpy(config->repurposed_vap_name, pcfg->repurposed_vap_name, (strlen(pcfg->repurposed_vap_name) + 1));
        }
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
        if(pcfg->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
            if(vap_index != 2 && vap_index != 3) {
                wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
                pcfg->exists = true;
            }
#else
            wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
            pcfg->exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
        }
#endif /* defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)*/
        rdk_config->exists = pcfg->exists;

        if (isVapSTAMesh(vap_index)) {
            if (strlen(pcfg->ssid) != 0) {
                strncpy(config->u.sta_info.ssid, pcfg->ssid, (sizeof(config->u.sta_info.ssid)-1));
            }
            config->u.sta_info.enabled = pcfg->enabled;
            config->u.sta_info.scan_params.period = pcfg->period;
            config->u.sta_info.scan_params.channel.channel = pcfg->channel;
            config->u.sta_info.scan_params.channel.band = pcfg->freq_band;
        } else {
            if(strlen(pcfg->ssid) != 0) {
                strncpy(config->u.bss_info.ssid,pcfg->ssid,(sizeof(config->u.bss_info.ssid)-1));
            }
            config->u.bss_info.enabled = pcfg->enabled;
            config->u.bss_info.showSsid = pcfg->ssid_advertisement_enabled;
            config->u.bss_info.isolation = pcfg->isolation_enabled;
            config->u.bss_info.mgmtPowerControl = pcfg->mgmt_power_control;
            config->u.bss_info.bssMaxSta = pcfg->bss_max_sta;
            config->u.bss_info.bssTransitionActivated = pcfg->bss_transition_activated;
            config->u.bss_info.nbrReportActivated = pcfg->nbr_report_activated;
            config->u.bss_info.network_initiated_greylist = pcfg->network_initiated_greylist;
            config->u.bss_info.connected_building_enabled = pcfg->connected_building_enabled;
            config->u.bss_info.mdu_enabled = pcfg->mdu_enabled;
            config->u.bss_info.am_config.npc.speed_tier = pcfg->speed_tier;
            wifi_util_info_print(WIFI_DB,"%s:%d: speed_tier %d and mdu_enabled %d\n",__func__, __LINE__,config->u.bss_info.am_config.npc.speed_tier, config->u.bss_info.mdu_enabled);
            config->u.bss_info.rapidReconnectEnable = pcfg->rapid_connect_enabled;
            config->u.bss_info.rapidReconnThreshold = pcfg->rapid_connect_threshold;
            config->u.bss_info.vapStatsEnable = pcfg->vap_stats_enable;
            config->u.bss_info.mac_filter_enable = pcfg->mac_filter_enabled;
            config->u.bss_info.mac_filter_mode = pcfg->mac_filter_mode;
            config->u.bss_info.wmm_enabled = pcfg->wmm_enabled;
            if (strlen(pcfg->anqp_parameters) != 0) {
                strncpy((char *)config->u.bss_info.interworking.anqp.anqpParameters, (char *)pcfg->anqp_parameters,(sizeof(config->u.bss_info.interworking.anqp.anqpParameters)-1));
            }
            if (strlen(pcfg->hs2_parameters) != 0) {
                strncpy((char *)config->u.bss_info.interworking.passpoint.hs2Parameters,(char *)pcfg->hs2_parameters,(sizeof(config->u.bss_info.interworking.passpoint.hs2Parameters)-1));
            }
            config->u.bss_info.UAPSDEnabled = pcfg->uapsd_enabled;
            config->u.bss_info.beaconRate = pcfg->beacon_rate;
            config->u.bss_info.wmmNoAck = pcfg->wmm_noack;
            config->u.bss_info.wepKeyLength = pcfg->wep_key_length;
            config->u.bss_info.bssHotspot = pcfg->bss_hotspot;
#if defined(FEATURE_SUPPORT_WPS)
            config->u.bss_info.wpsPushButton = pcfg->wps_push_button;
            config->u.bss_info.wps.methods = pcfg->wps_config_methods;
            config->u.bss_info.wps.enable = pcfg->wps_enabled;
#endif
            if (strlen(pcfg->beacon_rate_ctl) != 0) {
                strncpy(config->u.bss_info.beaconRateCtl, pcfg->beacon_rate_ctl,(sizeof(config->u.bss_info.beaconRateCtl)-1));
            }
            config->u.bss_info.hostap_mgt_frame_ctrl = pcfg->hostap_mgt_frame_ctrl;
            config->u.bss_info.interop_ctrl = pcfg->interop_ctrl;
            config->u.bss_info.inum_sta = pcfg->inum_sta;
            config->u.bss_info.mbo_enabled = pcfg->mbo_enabled;
        }
    }
    free(pcfg);
    return RETURN_OK;
}

int wifidb_get_wifi_security_config_old_mode(char *vap_name, int vap_index)
{
    struct schema_Wifi_Security_Config  *pcfg;
    json_t *where;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    int count, sec_mode_old = 0;

    where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = onewifi_ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Security_Config, where, &count);

    if (pcfg == NULL) {
        wifidb_print("%s:%d Table table_Wifi_Security_Config table not found, entry count=%d \n",__func__, __LINE__, count);
        return wifi_security_mode_wpa2_personal;
    }
    sec_mode_old = (isVapPrivate(vap_index) && !pcfg->security_mode) ? wifi_security_mode_wpa2_personal : pcfg->security_mode;

    return sec_mode_old;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_security_config
  Parameter   : vap_name     - Name of vap
                config      - wifi_vap_security_t will be updated to wifidb
  Description : Update wifi_vap_security_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_security_config(char *vap_name, wifi_vap_security_t *sec)
{
    struct schema_Wifi_Security_Config cfg_sec;
    char *filter_vapsec[] = {"-",NULL};
    char address[BUFFER_LENGTH_WIFIDB] = {0};
#ifndef NEWPLATFORM_PORT
    wifi_security_psm_param_t psm_security_cfg;
    memset(&psm_security_cfg, 0, sizeof(psm_security_cfg));
#endif // NEWPLATFORM_PORT
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    int vap_index = 0;
    memset(&cfg_sec,0,sizeof(cfg_sec));
    if(sec == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Security Config table - Null pointer \n",__func__, __LINE__);
        return RETURN_ERR;
    }
    vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop,vap_name);
    if (vap_index < 0) {
        wifi_util_error_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,vap_name);
        return RETURN_ERR;
    }
    cfg_sec.security_mode = sec->mode;
    if( sec->mode == WPA3_COMPATIBILITY ) {
	cfg_sec.security_mode = wifidb_get_wifi_security_config_old_mode(vap_name, vap_index);
	wifi_util_info_print(WIFI_DB,"%s:%d: security_mode:%d \n",__func__, __LINE__, cfg_sec.security_mode);
    }
    cfg_sec.encryption_method = sec->encr;
    convert_security_mode_integer_to_string(sec->mfp,(char *)&cfg_sec.mfp_config);
    strncpy(cfg_sec.vap_name,vap_name,(sizeof(cfg_sec.vap_name)-1));
    cfg_sec.rekey_interval = sec->rekey_interval;
    cfg_sec.strict_rekey = sec->strict_rekey;
    cfg_sec.eapol_key_timeout = sec->eapol_key_timeout;
    cfg_sec.eapol_key_retries = sec->eapol_key_retries;
    cfg_sec.eap_identity_req_timeout = sec->eap_identity_req_timeout;
    cfg_sec.eap_identity_req_retries = sec->eap_identity_req_retries;
    cfg_sec.eap_req_timeout = sec->eap_req_timeout;
    cfg_sec.eap_req_retries = sec->eap_req_retries;
    cfg_sec.disable_pmksa_caching = sec->disable_pmksa_caching;
    cfg_sec.wpa3_transition_disable = sec->wpa3_transition_disable;
    cfg_sec.security_mode_new = sec->mode;

    if (!security_mode_support_radius(sec->mode))
    {
        strncpy(cfg_sec.radius_server_ip,"",sizeof(cfg_sec.radius_server_ip)-1);
        cfg_sec.radius_server_port = 0;
        strncpy(cfg_sec.radius_server_key, "",sizeof(cfg_sec.radius_server_key)-1);
        strncpy(cfg_sec.secondary_radius_server_ip,"",sizeof(cfg_sec.secondary_radius_server_ip)-1);
        cfg_sec.secondary_radius_server_port = 0;
        strncpy(cfg_sec.secondary_radius_server_key, "",sizeof(cfg_sec.secondary_radius_server_key)-1);
        cfg_sec.key_type = sec->u.key.type;
        strncpy(cfg_sec.keyphrase,sec->u.key.key,sizeof(cfg_sec.keyphrase)-1);
        cfg_sec.max_auth_attempts = 0;
        cfg_sec.blacklist_table_timeout = 0;
        cfg_sec.identity_req_retry_interval = 0;
        cfg_sec.server_retries = 0;
        strncpy(cfg_sec.das_ip,"",sizeof(cfg_sec.das_ip)-1);
        cfg_sec.das_port = 0;
        strncpy(cfg_sec.das_key, "",sizeof(cfg_sec.das_key)-1);
    }
    else
    {
        strncpy(cfg_sec.radius_server_ip,(char *)sec->u.radius.ip,sizeof(cfg_sec.radius_server_ip)-1);
        cfg_sec.radius_server_port = (int)sec->u.radius.port;
        strncpy(cfg_sec.radius_server_key, sec->u.radius.key,sizeof(cfg_sec.radius_server_key)-1);
        strncpy(cfg_sec.secondary_radius_server_ip,(char *)sec->u.radius.s_ip,sizeof(cfg_sec.secondary_radius_server_ip)-1);
        cfg_sec.secondary_radius_server_port =(int)sec->u.radius.s_port;
        strncpy(cfg_sec.secondary_radius_server_key, sec->u.radius.s_key,sizeof(cfg_sec.secondary_radius_server_key)-1);
        cfg_sec.key_type = 0;
        strncpy(cfg_sec.keyphrase,"",sizeof(cfg_sec.keyphrase)-1);
        cfg_sec.max_auth_attempts = (int)sec->u.radius.max_auth_attempts;
        cfg_sec.blacklist_table_timeout = (int)sec->u.radius.blacklist_table_timeout;
        cfg_sec.identity_req_retry_interval = (int)sec->u.radius.identity_req_retry_interval;
        cfg_sec.server_retries = (int)sec->u.radius.server_retries;
	getIpStringFromAdrress(address,&sec->u.radius.dasip);
	strncpy(cfg_sec.das_ip,address,sizeof(cfg_sec.das_ip)-1);
        cfg_sec.das_port = sec->u.radius.dasport;
        strncpy(cfg_sec.das_key,sec->u.radius.daskey,sizeof(cfg_sec.das_key)-1);
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Update table_Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d"
            "rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d mfg=%s cfg_key_type=%d cfg_vap_name=%s rekey_interval = %d strict_rekey  = %d"
            "eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d"
            "eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d "
            "das_ip = %s das_port=%d wpa3_transition_disable=%d security_mode_new=%d \n",__func__, __LINE__,cfg_sec.security_mode,cfg_sec.encryption_method,
            cfg_sec.radius_server_ip, cfg_sec.radius_server_port,cfg_sec.secondary_radius_server_ip,cfg_sec.secondary_radius_server_port,cfg_sec.mfp_config,
            cfg_sec.key_type, cfg_sec.vap_name,cfg_sec.rekey_interval,cfg_sec.strict_rekey,cfg_sec.eapol_key_timeout,cfg_sec.eapol_key_retries, cfg_sec.eap_identity_req_timeout,
            cfg_sec.eap_identity_req_retries,cfg_sec.eap_req_timeout,cfg_sec.eap_req_retries,cfg_sec.disable_pmksa_caching,cfg_sec.max_auth_attempts, cfg_sec.blacklist_table_timeout,
            cfg_sec.identity_req_retry_interval,cfg_sec.server_retries,cfg_sec.das_ip,cfg_sec.das_port,cfg_sec.wpa3_transition_disable, cfg_sec.security_mode_new);

    if(onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_Security_Config,&cfg_sec,false,filter_vapsec,SCHEMA_TABLE(Wifi_VAP_Config),onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name),vap_name),SCHEMA_COLUMN(Wifi_VAP_Config,security)) == false)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi Security Config table\n",__func__, __LINE__);
    }
    else
    {
        wifidb_print("%s:%d Updated WIFI DB. Wifi Security Config table updated successful. \n",__func__, __LINE__);
#if ONEWIFI_DML_SUPPORT
#ifndef NEWPLATFORM_PORT
        wifidml_desc_t *p_desc = &get_wifidml_obj()->desc;
        psm_security_cfg.vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
        strncpy(psm_security_cfg.mfp, cfg_sec.mfp_config, sizeof(psm_security_cfg.mfp)-1);
        p_desc->push_data_to_ssp_queue_fn(&psm_security_cfg, sizeof(wifi_security_psm_param_t), ssp_event_type_psm_write, security_config);
#endif // NEWPLATFORM_PORT
#endif
    }
    return RETURN_OK;
}


/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_macfilter_config
  Parameter   : macfilter_key     - vap_name-device_mac
                config          - acl_entry_t with device details
  Description : Update macfilter entry to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_macfilter_config(char *macfilter_key, acl_entry_t *config, bool add)
{
    struct schema_Wifi_MacFilter_Config cfg_mac;
    char *filter_mac[] = {"-", NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    char tmp_mac_str[18];
    char concat_string[128];
    char buff[50];
    char *saveptr = NULL;
    char *vap_name = NULL;
    json_t *where;
    int ret = 0;
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    wifi_mac_entry_param_t l_mac_entry;
    memset(&l_mac_entry, 0, sizeof(l_mac_entry));
    str_tolower(macfilter_key);
    memset(buff, 0, sizeof(buff));
    snprintf(buff,sizeof(buff),"%s",macfilter_key);
  
    vap_name = strtok_r(buff,"-",&saveptr);
    if (!add) {
        where = onewifi_ovsdb_tran_cond(OCLM_STR, "macfilter_key", OFUNC_EQ, macfilter_key);
        ret = onewifi_ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_MacFilter_Config, where);
        l_mac_entry.vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
        wifidb_print("%s:%d vap_name:%s key:%s\n",__func__, __LINE__, vap_name, macfilter_key);
        memset(tmp_mac_str, 0, sizeof(tmp_mac_str));
        to_mac_str(config->mac, tmp_mac_str);
        str_tolower(tmp_mac_str);
        strncpy(l_mac_entry.device_name, config->device_name, sizeof(l_mac_entry.device_name)-1);
        strncpy(l_mac_entry.mac, tmp_mac_str, sizeof(l_mac_entry.mac)-1);
#if ONEWIFI_DML_SUPPORT
#ifndef NEWPLATFORM_PORT
        wifidml_desc_t *p_desc = &get_wifidml_obj()->desc;
        p_desc->push_data_to_ssp_queue_fn(&l_mac_entry, sizeof(l_mac_entry), ssp_event_type_psm_write, mac_config_delete);
#endif // NEWPLATFORM_PORT
#endif

        if (ret != 1) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to delete table_Wifi_MacFilter_Config\n",__func__, __LINE__);
            return -1;
        }
        wifidb_print("%s:%d Updated WIFI DB. Deleted entry and updated Wifi_MacFilter Config table successfully\n",__func__, __LINE__);
    } else {

        memset(tmp_mac_str, 0, sizeof(tmp_mac_str));
        memset(concat_string, 0, sizeof(concat_string));

        memset(&cfg_mac, 0, sizeof(cfg_mac));
        if (config == NULL) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to update MacFilter Config \n",__func__, __LINE__);
            return -1;
        }

        to_mac_str(config->mac, tmp_mac_str);
        str_tolower(tmp_mac_str);
        strncpy(cfg_mac.device_mac, tmp_mac_str, sizeof(cfg_mac.device_mac)-1);
        strncpy(cfg_mac.device_name, config->device_name, sizeof(cfg_mac.device_name)-1);
        cfg_mac.reason = config->reason;
        cfg_mac.expiry_time = config->expiry_time;
        //concat for macfilter_key.
        strncpy(cfg_mac.macfilter_key, macfilter_key, sizeof(cfg_mac.macfilter_key));
        wifi_util_dbg_print(WIFI_DB,"%s:%d: updating table wifi_macfilter_config table entry is device_mac %s, device_name %s,macfilter_key %s reason %d and expiry_time %d\n", __func__, __LINE__, cfg_mac.device_mac, cfg_mac.device_name, cfg_mac.macfilter_key,cfg_mac.reason,cfg_mac.expiry_time);

        l_mac_entry.vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
        if (l_mac_entry.vap_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Unable to get vap index for vap_name %s\n", __func__, __LINE__, vap_name);
            return -1;
        }
        l_rdk_vap_array = get_wifidb_rdk_vap_info(l_mac_entry.vap_index);
        if (l_rdk_vap_array ==  NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Unable to find vap_array for vap_index %d\n", __func__, __LINE__, l_mac_entry.vap_index);
            return -1;
        }
        l_mac_entry.acl_map = l_rdk_vap_array->acl_map;
        strncpy(l_mac_entry.device_name, cfg_mac.device_name, sizeof(l_mac_entry.device_name)-1);
        strncpy(l_mac_entry.mac, cfg_mac.device_mac, sizeof(l_mac_entry.mac)-1);
#if ONEWIFI_DML_SUPPORT
#ifndef NEWPLATFORM_PORT
        wifidml_desc_t *p_desc = &get_wifidml_obj()->desc;
        p_desc->push_data_to_ssp_queue_fn(&l_mac_entry, sizeof(l_mac_entry), ssp_event_type_psm_write, mac_config_add);
#endif // NEWPLATFORM_PORT
#endif
        if (onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path, &table_Wifi_MacFilter_Config, &cfg_mac, false, filter_mac, SCHEMA_TABLE(Wifi_VAP_Config), onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name), vap_name), SCHEMA_COLUMN(Wifi_VAP_Config, mac_filter)) ==  false) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi_MacFilter Config table \n",__func__, __LINE__);
        }
        else {
            wifidb_print("%s:%d Updated WIFI DB. Wifi_MacFilter Config table updated successful\n",__func__, __LINE__);
        }
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_passpoint_config
  Parameter   : vap_name     - Name of vap
                config      - wifi_InterworkingElement_t
  Description : Update passpoint config to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_passpoint_config(char *vap_name, wifi_interworking_t *config)
{
    struct schema_Wifi_Passpoint_Config cfg_passpoint;
//     char *filter_passpoint[] = {"-",NULL};
    wifi_db_t *g_wifidb;
   g_wifidb = (wifi_db_t*) get_wifidb_obj();
    memset(&cfg_passpoint,0,sizeof(cfg_passpoint));
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Passpoint update for vap name=%s\n",__func__, __LINE__,vap_name);
    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null config - Passpoint update failed \n",__func__, __LINE__);
        return -1;
    }
    wifi_passpoint_settings_t *cpass = &(config->passpoint);
    const char *p_json = get_passpoint_json_by_vap_name(vap_name);
    if(p_json == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null p_json - passpoint update failed \n",__func__, __LINE__);
        return -1;
    }
    cJSON *p_root = cJSON_Parse(p_json);
    if(p_root == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unable to parse json  - passpoint update failed \n",__func__, __LINE__);
        return -1;
    }
    cfg_passpoint.enable = cpass->enable;
    cfg_passpoint.group_addressed_forwarding_disable = cpass->gafDisable;
    cfg_passpoint.p2p_cross_connect_disable = cpass->p2pDisable;
    if( ((unsigned int)cpass->capabilityInfoLength < (sizeof(cfg_passpoint.capability_element)-1)) &&
        ((unsigned int)cpass->capabilityInfoLength < sizeof(cpass->capabilityInfo.capabilityList)) ){
        cfg_passpoint.capability_length = cpass->capabilityInfoLength;
        memcpy(&cfg_passpoint.capability_element, cpass->capabilityInfo.capabilityList, cpass->capabilityInfoLength);
    }
    cfg_passpoint.nai_home_realm_length = cpass->realmInfoLength;
    cJSON *nai_home_anqp_j = cJSON_GetObjectItem(p_root, "NAIHomeRealmANQPElement");
    if(nai_home_anqp_j != NULL) {
        char *tstr = cJSON_Print(nai_home_anqp_j);
        strncpy(cfg_passpoint.nai_home_realm_element, tstr, sizeof(cfg_passpoint.nai_home_realm_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is%s\n",__func__, __LINE__, strlen(tstr), tstr,nai_home_anqp_j->valuestring);
        cJSON_free(tstr);
    }
    cfg_passpoint.operator_friendly_name_length = cpass->opFriendlyNameInfoLength;
    cJSON *op_f_j = cJSON_GetObjectItem(p_root, "OperatorFriendlyNameANQPElement");
    if(op_f_j != NULL) {
        char *tstr = cJSON_Print(op_f_j);
        strncpy(cfg_passpoint.operator_friendly_name_element, tstr, sizeof(cfg_passpoint.operator_friendly_name_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is%s\n",__func__, __LINE__, strlen(tstr), tstr,op_f_j->valuestring);
        cJSON_free(tstr);
    }
    cfg_passpoint.connection_capability_length = cpass->connCapabilityLength;
    cJSON *cc_j = cJSON_GetObjectItem(p_root, "ConnectionCapabilityListANQPElement");
    if(cc_j != NULL) {
        char *tstr = cJSON_Print(cc_j);
        strncpy(cfg_passpoint.connection_capability_element, tstr, sizeof(cfg_passpoint.connection_capability_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is%s\n",__func__, __LINE__, strlen(tstr), tstr,cc_j->valuestring);
        cJSON_free(tstr);
    }
    cJSON_Delete(p_root);
    strncpy(cfg_passpoint.vap_name, vap_name,(sizeof(cfg_passpoint.vap_name)-1));
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Update Wifi_Passpoint_Config table vap_name=%s Enable=%d gafDisable=%d p2pDisable=%d capability_length=%d nai_home_realm_length=%d operator_friendly_name_length=%d connection_capability_length=%d \n",__func__, __LINE__,cfg_passpoint.vap_name,cfg_passpoint.enable,cfg_passpoint.group_addressed_forwarding_disable,cfg_passpoint.p2p_cross_connect_disable,cfg_passpoint.capability_length,cfg_passpoint.nai_home_realm_length,cfg_passpoint.operator_friendly_name_length,cfg_passpoint.connection_capability_length);
    if(onewifi_ovsdb_table_upsert_simple(g_wifidb->wifidb_sock_path, &table_Wifi_Passpoint_Config, SCHEMA_COLUMN(Wifi_Passpoint_Config, vap_name), vap_name, &cfg_passpoint, NULL) == false)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update Wifi_Passpoint_Config table\n",__func__, __LINE__);
    }
    else
    {
        reset_passpoint_json(vap_name);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: update table Wifi_Passpoint_Config table successful\n",__func__, __LINE__);
     }
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_anqp_config
  Parameter   : vap_name     - Name of vap
                config      - wifi_InterworkingElement_t
  Description : Update anqp config to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_anqp_config(char *vap_name, wifi_interworking_t *config)
{
    struct schema_Wifi_Anqp_Config cfg_anqp;
//    char *filter_anqp[] = {"-",NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    memset(&cfg_anqp,0,sizeof(cfg_anqp));
    wifi_util_dbg_print(WIFI_DB,"%s:%d:anqp update for vap name=%s\n",__func__, __LINE__,vap_name);
    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null config - Anqp update failed \n",__func__, __LINE__);
        return -1;
    }
    wifi_anqp_settings_t *canqp = &(config->anqp);
    const char *p_json = get_anqp_json_by_vap_name(vap_name);
    if(p_json == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null p_json - Anqp update failed \n",__func__, __LINE__);
        return -1;
    }
    cJSON *p_root = cJSON_Parse(p_json);
    if(p_root == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unable to parse json  - Anqp update failed \n",__func__, __LINE__);
        return -1;
    }
    if( ((unsigned int)canqp->capabilityInfoLength < (sizeof(cfg_anqp.capability_element)-1)) &&
        ((unsigned int)canqp->capabilityInfoLength < sizeof(canqp->capabilityInfo.capabilityList)) ){
        cfg_anqp.capability_length = canqp->capabilityInfoLength;
        memcpy(&cfg_anqp.capability_element, canqp->capabilityInfo.capabilityList, canqp->capabilityInfoLength);
    }
    cfg_anqp.venue_name_length = canqp->venueInfoLength;
    cJSON *venueInfo_j = cJSON_GetObjectItem(p_root, "VenueNameANQPElement");
    if(venueInfo_j != NULL) {
        char *tstr = cJSON_Print(venueInfo_j);
        strncpy(cfg_anqp.venue_name_element, tstr, sizeof(cfg_anqp.venue_name_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is%s\n",__func__, __LINE__, strlen(tstr), tstr,cfg_anqp.venue_name_element);
        cJSON_free(tstr);
    }
    cfg_anqp.domain_name_length = canqp->domainInfoLength;
    cJSON *dom_j = cJSON_GetObjectItem(p_root, "DomainANQPElement");
    if(dom_j != NULL) {
        char *tstr = cJSON_Print(dom_j);
        strncpy(cfg_anqp.domain_name_element, tstr, sizeof(cfg_anqp.domain_name_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is%s\n",__func__, __LINE__, strlen(tstr), tstr,cfg_anqp.domain_name_element);
        cJSON_free(tstr);
    }
    cfg_anqp.roaming_consortium_length = canqp->roamInfoLength;
    cJSON *roam_j = cJSON_GetObjectItem(p_root, "RoamingConsortiumANQPElement");
    if(roam_j != NULL) {
        char *tstr = cJSON_Print(roam_j);
        strncpy(cfg_anqp.roaming_consortium_element, tstr, sizeof(cfg_anqp.roaming_consortium_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is%s\n",__func__, __LINE__, strlen(tstr), tstr,cfg_anqp.domain_name_element);
        cJSON_free(tstr);
    }
    cfg_anqp.nai_realm_length = canqp->realmInfoLength;
    cJSON *realm_j = cJSON_GetObjectItem(p_root, "NAIRealmANQPElement");
    if(realm_j != NULL) {
        char *tstr = cJSON_Print(realm_j);
        strncpy(cfg_anqp.nai_realm_element, tstr, sizeof(cfg_anqp.nai_realm_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is %s\n",__func__, __LINE__, strlen(tstr), tstr,cfg_anqp.nai_realm_element);
        cJSON_free(tstr);
    } else {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unable to get NAIRealmANQPElement\n",__func__, __LINE__);
    }
    cfg_anqp.gpp_cellular_length = canqp->gppInfoLength;
    cJSON *gpp_j = cJSON_GetObjectItem(p_root, "3GPPCellularANQPElement");
    if(gpp_j != NULL) {
        char *tstr = cJSON_Print(gpp_j);
        strncpy(cfg_anqp.gpp_cellular_element, tstr, sizeof(cfg_anqp.gpp_cellular_element)-1);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: len: %d, tstr: %s and its value is%s\n",__func__, __LINE__, strlen(tstr), tstr,cfg_anqp.gpp_cellular_element);
        cJSON_free(tstr);
    }
    cfg_anqp.ipv4_address_type = 0;
    cfg_anqp.ipv6_address_type = 0;
    cJSON *addr_j = cJSON_GetObjectItem(p_root, "IPAddressTypeAvailabilityANQPElement");
    if(addr_j != NULL) {
        cJSON *addr_j_ip4 = cJSON_GetObjectItem(addr_j, "IPv4AddressType");
        if(addr_j_ip4 != NULL) { cfg_anqp.ipv4_address_type = cJSON_GetNumberValue(addr_j_ip4); }
        cJSON *addr_j_ip6 = cJSON_GetObjectItem(addr_j, "IPv6AddressType");
        if(addr_j_ip6 != NULL) { cfg_anqp.ipv6_address_type = cJSON_GetNumberValue(addr_j_ip6); }
    }
    cJSON_Delete(p_root);
    strncpy(cfg_anqp.vap_name, vap_name,(sizeof(cfg_anqp.vap_name)-1));
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Update Wifi_Anqp_Config table vap_name=%s capability_length=%d nai_realm_length=%d venue_name_length=%d domain_name_length=%d roaming_consortium_length=%d gpp_cellular_length=%d\n",__func__, __LINE__,cfg_anqp.vap_name,cfg_anqp.capability_length,cfg_anqp.nai_realm_length,cfg_anqp.domain_name_length,cfg_anqp.roaming_consortium_length,cfg_anqp.gpp_cellular_length);
    if(onewifi_ovsdb_table_upsert_simple(g_wifidb->wifidb_sock_path, &table_Wifi_Anqp_Config, SCHEMA_COLUMN(Wifi_Anqp_Config, vap_name), vap_name, &cfg_anqp, NULL) == false)
    {
        reset_anqp_json(vap_name);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update Wifi_Anqp_Config table\n",__func__, __LINE__);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: update table Wifi_Anqp_Config table successful\n",__func__, __LINE__);
    }
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_global_config
  Parameter   : config - Update wifi_global_param_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_global_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_global_config(wifi_global_param_t *config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Global Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    ret = wifidb_update_wifi_global_config(config);
    if(ret == 0)
    {
        wifidb_print("%s:%d Updated WIFI DB. Global Config table updated successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Global Config\n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_vap_info
  Parameter   : vap_name - Name of vap
                config   - Update wifi_vap_info_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_vap_info
 *************************************************************************************
**************************************************************************************/
int update_wifi_vap_info(char *vap_name,wifi_vap_info_t *config,rdk_wifi_vap_info_t *rdk_config)
{
    int ret = RETURN_OK;

    if(config == NULL || rdk_config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update VAP info - Null pointer \n",__func__, __LINE__);
        return RETURN_ERR;
    } 
    ret = wifidb_update_wifi_vap_info(vap_name,config,rdk_config);
    if(ret == RETURN_OK)
    {
        wifidb_print("%s:%d Updated WIFI DB. Vap Info updated successful. \n",__func__, __LINE__);
        return RETURN_OK;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update VAP info \n",__func__, __LINE__);
    return RETURN_ERR;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_interworking_config
  Parameter   : vap_name - Name of vap
                config   - Update wifi_InterworkingElement_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_interworking_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_interworking_config(char *vap_name, wifi_interworking_t *config)
{
    int ret = 0;
    wifi_InterworkingElement_t configure;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update interworking Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }

    configure = config->interworking;
    ret = wifidb_update_wifi_interworking_config(vap_name, &configure);
    if(ret == 0)
    {
        wifidb_print("%s:%d Updated WIFI DB. interworking Config updated successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update interworking Config \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : update_wifi_radio_config
  Parameter   : radio_index - Index of radio
                config      - Update wifi_radio_operationParam_t and wifi_radio_feature_param_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_radio_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Radio Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    if (feat_config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Radio Feature Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }
    ret = wifidb_update_wifi_radio_config(radio_index,config,feat_config);
    if(ret == 0)
    {
        wifidb_print("%s:%d Updated WIFI DB. Radio Config updated successful. \n",__func__, __LINE__);
        return 0;
    }
    wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Radio Config \n",__func__, __LINE__);
    return -1;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_radio_config_default
  Parameter   : radio_index - Index of radio
  Description : Update global cache with default value for wifi_radio_operationParam_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_radio_config_default(int radio_index,wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    int band;
    char country_code[COUNTRY_CODE_LEN] = {0};
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_radio_operationParam_t cfg;
    wifi_countrycode_type_t country_code_val;
    wifi_radio_feature_param_t Fcfg;
    memset(&Fcfg,0,sizeof(Fcfg));
    memset(&cfg,0,sizeof(cfg));

    wifi_radio_capabilities_t radio_capab = g_wifidb->hal_cap.wifi_prop.radiocap[radio_index];

    if (convert_radio_index_to_freq_band(&rdk_wifi_get_hal_capability_map()->wifi_prop, radio_index,
        &band) == RETURN_ERR)
    {
        wifi_util_error_print(WIFI_DB,"%s:%d Failed to convert radio index %d to band, use default\n", __func__,
            __LINE__, radio_index);
        cfg.band = WIFI_FREQUENCY_2_4_BAND;
    }
    else
    {
        cfg.band = band;
    }

    cfg.enable = true;

    switch (cfg.band) {
        case WIFI_FREQUENCY_2_4_BAND:
            cfg.operatingClass = 81;
            cfg.channel = 1;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
#if defined(_XER5_PRODUCT_REQ_)
            cfg.variant = WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AX;
#else
            cfg.variant = WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N;
#endif
#if defined (NEWPLATFORM_PORT) || defined (_GREXT02ACTS_PRODUCT_REQ_)
            cfg.variant |= WIFI_80211_VARIANT_AX;
#endif /* NEWPLATFORM_PORT */
#if defined (_PP203X_PRODUCT_REQ_) || defined (_GREXT02ACTS_PRODUCT_REQ_)
            cfg.beaconInterval = 200;
#endif
            break;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
            cfg.operatingClass = 128;
#if defined (_PP203X_PRODUCT_REQ_) || defined (_GREXT02ACTS_PRODUCT_REQ_)
            cfg.beaconInterval = 200;
#endif
            cfg.channel = 44;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
#if defined (_PP203X_PRODUCT_REQ_)
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC;
            cfg.DfsEnabled = true;
#else
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX;
#endif

#ifdef CONFIG_IEEE80211BE
            cfg.variant |= WIFI_80211_VARIANT_BE;
#endif /* CONFIG_IEEE80211BE */
            break;
        case WIFI_FREQUENCY_5H_BAND:
            cfg.operatingClass = 128;
            cfg.channel = 157;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
#if defined (_PP203X_PRODUCT_REQ_) || defined (_GREXT02ACTS_PRODUCT_REQ_)
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC;
            cfg.beaconInterval = 200;
            cfg.DfsEnabled = true;
#else
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX;
#endif

#ifdef CONFIG_IEEE80211BE
            cfg.variant |= WIFI_80211_VARIANT_BE;
#endif /* CONFIG_IEEE80211BE */
            break;
        case WIFI_FREQUENCY_6_BAND:
            cfg.operatingClass = 131;
            cfg.channel = 5;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_160MHZ;
            cfg.variant = WIFI_80211_VARIANT_AX;

#ifdef CONFIG_IEEE80211BE
            cfg.variant |= WIFI_80211_VARIANT_BE;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_320MHZ;
#endif /* CONFIG_IEEE80211BE */
            break;
        default:
            wifi_util_error_print(WIFI_DB,"%s:%d radio index %d, invalid band %d\n", __func__,
            __LINE__, radio_index, cfg.band);
            break;
    }

    for (int i=0; i<radio_capab.channel_list[0].num_channels; i++)
    {
        cfg.channel_map[i].ch_number = radio_capab.channel_list[0].channels_list[i];
        if ( (cfg.band == WIFI_FREQUENCY_5_BAND || cfg.band == WIFI_FREQUENCY_5L_BAND || cfg.band == WIFI_FREQUENCY_5H_BAND ) && ((radio_capab.channel_list[0].channels_list[i] >= 52) && (radio_capab.channel_list[0].channels_list[i] <= 144))) {
            cfg.channel_map[i].ch_state = CHAN_STATE_DFS_NOP_FINISHED;
        } else {
            cfg.channel_map[i].ch_state = CHAN_STATE_AVAILABLE;
        }
    }
    cfg.autoChannelEnabled = true;
    for(int i=0 ;i<MAX_NUM_CHANNELBANDWIDTH_SUPPORTED;i++)
    {
        cfg.channels_per_bandwidth[i].num_channels_list = 0;
        memset(cfg.channels_per_bandwidth[i].channels_list,0,sizeof(cfg.channels_per_bandwidth[i].channels_list));
        cfg.channels_per_bandwidth[i].chanwidth = 0;
    }
    cfg.acs_keep_out_reset = false;
    cfg.csa_beacon_count = 100;
    country_code_val = wifi_countrycode_US;
    if (wifi_hal_get_default_country_code(country_code) < 0) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: unable to get default country code setting a US\n", __func__, __LINE__);
    } else {
        if (country_code_conversion(&country_code_val, country_code, sizeof(country_code), STRING_TO_ENUM) < 0) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: unable to convert country string\n", __func__, __LINE__);
        }
    }
    cfg.countryCode = country_code_val;
    cfg.operatingEnvironment = wifi_operating_env_indoor;
    cfg.dtimPeriod = 1;
    if (cfg.beaconInterval == 0) {
        cfg.beaconInterval = 100;
    }
    cfg.fragmentationThreshold = 2346;
    cfg.transmitPower = 100;
    cfg.rtsThreshold = 2347;
    cfg.guardInterval = wifi_guard_interval_auto;
    cfg.ctsProtection = false;
    cfg.obssCoex = true;
    cfg.stbcEnable = true;
    cfg.greenFieldEnable = false;
    cfg.userControl = 0;
    cfg.adminControl = 0;
    cfg.chanUtilThreshold = 90;
    cfg.chanUtilSelfHealEnable = 0;
    cfg.EcoPowerDown = false;
    cfg.factoryResetSsid = 0;
    if ((is_device_type_sr213() == true) && (WIFI_FREQUENCY_2_4_BAND == cfg.band)) {
        cfg.basicDataTransmitRates = WIFI_BITRATE_1MBPS | WIFI_BITRATE_2MBPS |
            WIFI_BITRATE_5_5MBPS | WIFI_BITRATE_11MBPS;
    } else {
        cfg.basicDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_24MBPS;
    }
    cfg.operationalDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_18MBPS | WIFI_BITRATE_24MBPS | WIFI_BITRATE_36MBPS | WIFI_BITRATE_48MBPS | WIFI_BITRATE_54MBPS;
    Fcfg.radio_index = radio_index;
    cfg.DFSTimer = DFS_DEFAULT_TIMER_IN_MIN;
    strncpy(cfg.radarDetected, " ", sizeof(cfg.radarDetected));
    if (is_radio_band_5G(cfg.band)) {
        Fcfg.OffChanTscanInMsec = OFFCHAN_DEFAULT_TSCAN_IN_MSEC;
        Fcfg.OffChanNscanInSec = OFFCHAN_DEFAULT_NSCAN_IN_SEC;
        Fcfg.OffChanTidleInSec = OFFCHAN_DEFAULT_TIDLE_IN_SEC;
    } else {
        Fcfg.OffChanTscanInMsec = 0;
        Fcfg.OffChanNscanInSec = 0;
        Fcfg.OffChanTidleInSec = 0;
    }

    for (int j = 0; j < MAX_AMSDU_TID; j++) {
        cfg.amsduTid[j] = FALSE;
    }

#if defined(_XB10_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_)
    if (cfg.band == WIFI_FREQUENCY_6_BAND) {
        for (int i = 0; i < 5; i++)
        {
            cfg.amsduTid[i] = TRUE;
        }
    } else {
        for (int i = 0; i < 4; i++)
        {
            cfg.amsduTid[i] = TRUE;
        }
    }
#elif defined(_XB8_PRODUCT_REQ_)
    cfg.amsduTid[0] = TRUE;
    if (cfg.band == WIFI_FREQUENCY_6_BAND) {
        cfg.amsduTid[4] = TRUE;
    }
#endif

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Tscan:%lu Nscan:%lu Nidle:%lu\n", __func__, __LINE__, Fcfg.OffChanTscanInMsec, Fcfg.OffChanNscanInSec, Fcfg.OffChanTidleInSec);
    /* Call the function to update the operating classes based on Country code and Radio */
    update_radio_operating_classes(&cfg);
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
    memcpy(feat_config, &Fcfg, sizeof(Fcfg));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_vap_config_default
  Parameter   : vap_index - Index of vap
  Description : Update global cache with default value for wifi_vap_info_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_vap_config_default(int vap_index, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_hal_capability_t *wifi_hal_cap_obj = &g_wifidb->hal_cap;
    unsigned int vap_array_index;
    unsigned int found = 0;
    wifi_vap_info_t cfg;
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};
#ifdef FEATURE_SUPPORT_WPS
    char wps_pin[128] = {0};
#endif
    char password[128] = {0};
    char radius_key[128] = {0};
    char ssid[128] = {0};
    int band;
    bool exists = true;

    memset(&cfg,0,sizeof(cfg));

    for (vap_array_index = 0; vap_array_index < getTotalNumberVAPs(); vap_array_index++)
    {
        if (wifi_hal_cap_obj->wifi_prop.interface_map[vap_array_index].index == (unsigned int)vap_index) {
            found = 1;
            break;
        }
    }
    if (!found) {
        wifi_util_error_print(WIFI_DB,"%s:%d: vap_index %d, not found\n",__func__, __LINE__, vap_index);
        return RETURN_OK;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d: vap_array_index %d vap_index %d vap_name %s\n",__func__, __LINE__, vap_array_index, vap_index,
                                        wifi_hal_cap_obj->wifi_prop.interface_map[vap_array_index].vap_name);
    
    cfg.vap_index = vap_index;
    strncpy(cfg.bridge_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[vap_array_index].bridge_name, sizeof(cfg.bridge_name)-1);
    strncpy(vap_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[vap_array_index].vap_name, sizeof(vap_name)-1);
    strncpy(cfg.vap_name, vap_name, sizeof(cfg.vap_name)-1);
    cfg.radio_index = wifi_hal_cap_obj->wifi_prop.interface_map[vap_array_index].rdk_radio_index;
    convert_radio_index_to_freq_band(&wifi_hal_cap_obj->wifi_prop, cfg.radio_index, &band);

    if (isVapSTAMesh(vap_index)) {
        cfg.vap_mode = wifi_vap_mode_sta;
        if (band == WIFI_FREQUENCY_6_BAND) {
            cfg.u.sta_info.security.mode = wifi_security_mode_wpa3_personal;
            cfg.u.sta_info.security.wpa3_transition_disable = false;
            cfg.u.sta_info.security.mfp = wifi_mfp_cfg_required;
            cfg.u.sta_info.security.u.key.type = wifi_security_key_type_sae;
        } else {
#if defined(NEWPLATFORM_PORT)
                cfg.u.sta_info.security.mode = wifi_security_mode_wpa3_transition;
                cfg.u.sta_info.security.wpa3_transition_disable = false;
                cfg.u.sta_info.security.mfp = wifi_mfp_cfg_optional;
                cfg.u.sta_info.security.u.key.type = wifi_security_key_type_psk_sae;
#else
                cfg.u.sta_info.security.mfp = wifi_mfp_cfg_disabled;
                cfg.u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
#endif
        }
        cfg.u.sta_info.security.encr = wifi_encryption_aes;
        cfg.u.sta_info.enabled = false;
        cfg.u.sta_info.scan_params.period = 10;
        memset(ssid, 0, sizeof(ssid));
        if (wifi_hal_get_default_ssid(ssid, vap_index) == 0) {
            strcpy(cfg.u.sta_info.ssid, ssid);
        } else {
            strcpy(cfg.u.sta_info.ssid, vap_name);
        }
        memset(password, 0, sizeof(password));
        if (wifi_hal_get_default_keypassphrase(password,vap_index) == 0) {
            strcpy(cfg.u.sta_info.security.u.key.key, password);
        } else {
            strcpy(cfg.u.sta_info.security.u.key.key, INVALID_KEY);
        }
        if ((strlen(cfg.u.sta_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(cfg.u.sta_info.security.u.key.key) > MAX_PWD_LEN)) {
            wifi_util_error_print(WIFI_DB, "%s:%d: Incorrect password length %d for vap '%s'\n", __func__, __LINE__, strlen(cfg.u.sta_info.security.u.key.key), vap_name);
            strncpy(cfg.u.sta_info.security.u.key.key, INVALID_KEY, sizeof(cfg.u.sta_info.security.u.key.key));
        }

        cfg.u.sta_info.scan_params.channel.band = band;

        switch(band) {
            case WIFI_FREQUENCY_2_4_BAND:
                cfg.u.sta_info.scan_params.channel.channel = 1;
                break;
            case WIFI_FREQUENCY_5_BAND:
            case WIFI_FREQUENCY_5L_BAND:
                cfg.u.sta_info.scan_params.channel.channel = 44;
                break;
            case WIFI_FREQUENCY_5H_BAND:
                cfg.u.sta_info.scan_params.channel.channel = 157;
                break;
            case WIFI_FREQUENCY_6_BAND:
                cfg.u.sta_info.scan_params.channel.channel = 5;
                break;
            default:
                wifi_util_error_print(WIFI_DB,"%s:%d invalid band %d\n", __func__, __LINE__, band);
                break;
        }

        cfg.u.sta_info.conn_status = wifi_connection_status_disabled;
        memset(&cfg.u.sta_info.bssid, 0, sizeof(cfg.u.sta_info.bssid));
    } else {
        cfg.u.bss_info.wmm_enabled = true;
        cfg.u.bss_info.mbo_enabled = true;
        if (isVapHotspot(vap_index)) {
            cfg.u.bss_info.isolation  = 1;
        } else {
            cfg.u.bss_info.isolation  = 0;
        }
#ifndef NEWPLATFORM_PORT
        cfg.u.bss_info.bssTransitionActivated = false;
        cfg.u.bss_info.nbrReportActivated = false;
#else
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.bssTransitionActivated = true;
            cfg.u.bss_info.nbrReportActivated = true;
        } else {
            cfg.u.bss_info.bssTransitionActivated = false;
            cfg.u.bss_info.nbrReportActivated = false;
        }
#endif
        cfg.u.bss_info.network_initiated_greylist = false;
        cfg.u.bss_info.connected_building_enabled = false;
        cfg.u.bss_info.mdu_enabled = false;
        if (isVapLnfPsk(vap_index)) {
            cfg.u.bss_info.am_config.npc.speed_tier = DEFAULT_MANAGED_WIFI_SPEED_TIER;
        }
        else {
            cfg.u.bss_info.am_config.npc.speed_tier = 0;
        }
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.vapStatsEnable = true;
            cfg.u.bss_info.wpsPushButton = 0;
#ifdef FEATURE_SUPPORT_WPS
            cfg.u.bss_info.wps.enable = true;
#else
            cfg.u.bss_info.wps.enable = false;
#endif
            cfg.u.bss_info.rapidReconnectEnable = true;
        } else {
            cfg.u.bss_info.vapStatsEnable = false;
            cfg.u.bss_info.rapidReconnectEnable = false;
        }
        cfg.u.bss_info.rapidReconnThreshold = 180;
        if (isVapMeshBackhaul(vap_index)) {
            cfg.u.bss_info.mac_filter_enable = true;
            cfg.u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
        } else {
            cfg.u.bss_info.mac_filter_enable = false;
        }
        cfg.u.bss_info.UAPSDEnabled = true;
        cfg.u.bss_info.wmmNoAck = false;
        cfg.u.bss_info.wepKeyLength = 128;
        cfg.u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        if (isVapHotspotOpen(vap_index)) {
            cfg.u.bss_info.bssHotspot = true;
            if (band == WIFI_FREQUENCY_6_BAND) {
                cfg.u.bss_info.security.mode = wifi_security_mode_enhanced_open;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_required;
                cfg.u.bss_info.security.encr = wifi_encryption_aes;
            }
            else {
                cfg.u.bss_info.security.mode = wifi_security_mode_none;
            }
        } else if (isVapHotspotSecure(vap_index)) {
            cfg.u.bss_info.bssHotspot = true;
            if (band == WIFI_FREQUENCY_6_BAND) {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa3_enterprise;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_required;
            }
            else {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
            }
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
        } else if (isVapLnfSecure (vap_index)) {
            cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
        } else if (isVapPrivate(vap_index))  {
            if (band == WIFI_FREQUENCY_6_BAND) {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                cfg.u.bss_info.security.wpa3_transition_disable = false;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_required;
                cfg.u.bss_info.security.u.key.type = wifi_security_key_type_sae;
            } else {
#if defined(_XB8_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_) || defined(_XER5_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_)
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
                cfg.u.bss_info.security.wpa3_transition_disable = false;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_optional;
                cfg.u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
#else
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
#endif
            }
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
            cfg.u.bss_info.bssHotspot = false;
            cfg.u.bss_info.mbo_enabled = false;
        } else  {
            if (band == WIFI_FREQUENCY_6_BAND) {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                cfg.u.bss_info.security.wpa3_transition_disable = false;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_required;
                cfg.u.bss_info.security.u.key.type = wifi_security_key_type_sae;
            } else {
#if defined(NEWPLATFORM_PORT)
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
                cfg.u.bss_info.security.wpa3_transition_disable = false;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_optional;
                cfg.u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
#else
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
#endif
            }
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
            cfg.u.bss_info.bssHotspot = false;
        }
        cfg.u.bss_info.beaconRate = WIFI_BITRATE_6MBPS;
        strncpy(cfg.u.bss_info.beaconRateCtl,"6Mbps",sizeof(cfg.u.bss_info.beaconRateCtl)-1);
        cfg.vap_mode = wifi_vap_mode_ap;
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.showSsid = true;
#ifdef FEATURE_SUPPORT_WPS
            cfg.u.bss_info.wps.methods = WIFI_ONBOARDINGMETHODS_PUSHBUTTON;
            memset(wps_pin, 0, sizeof(wps_pin));
            if ((wifi_hal_get_default_wps_pin(wps_pin) == RETURN_OK) && ((strlen(wps_pin) != 0))) {
                strcpy(cfg.u.bss_info.wps.pin, wps_pin);
            } else {
                wifi_util_error_print(WIFI_DB, "%s:%d: Incorrect wps pin for vap '%s'\n", __func__,
                    __LINE__, vap_name);
                strcpy(cfg.u.bss_info.wps.pin, "12345678");
            }
#endif
        } else if (isVapHotspot(vap_index)) {
            cfg.u.bss_info.showSsid = true;
        } else {
            cfg.u.bss_info.showSsid = false;
        }

#if defined(_XER5_PRODUCT_REQ_) || defined(_XB10_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_)
        if (isVapLnfSecure(vap_index) || isVapPrivate(vap_index)) {
             cfg.u.bss_info.enabled = true; 
        }
#else
        if ((vap_index == 2) || isVapLnfSecure(vap_index) || isVapPrivate(vap_index)) {
             cfg.u.bss_info.enabled = true;
        }
#endif
#if defined(_SKY_HUB_COMMON_PRODUCT_REQ_)
#ifndef _SCER11BEL_PRODUCT_REQ_
        if (isVapXhs(vap_index)) {
            cfg.u.bss_info.enabled = false;
        }
#endif
        if (isVapLnfPsk(vap_index)) {
            cfg.u.bss_info.enabled = false;
        }
#if defined(_SR213_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_)
        cfg.u.bss_info.bssMaxSta = wifi_hal_cap_obj->wifi_prop.BssMaxStaAllow;
#else
        cfg.u.bss_info.bssMaxSta = BSS_MAX_NUM_STA_SKY;
#endif //_SR213_PRODUCT_REQ_

#else
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.bssMaxSta = wifi_hal_cap_obj->wifi_prop.BssMaxStaAllow;
        } else if (is_device_type_cbr2() && isVapHotspot(vap_index)) {
            cfg.u.bss_info.bssMaxSta = BSS_MAX_NUM_STA_HOTSPOT_CBRV2;
        } else if (isVapHotspot(vap_index)) {
            cfg.u.bss_info.bssMaxSta = BSS_MAX_NUM_STA_HOTSPOT_XB;
        } else {
            cfg.u.bss_info.bssMaxSta = BSS_MAX_NUM_STA_COMMON;
        }
        wifi_util_dbg_print(WIFI_DB, "%s:%d vap_index:%d bssMaxSta:%d\n", __func__, __LINE__,
            vap_index, cfg.u.bss_info.bssMaxSta);
#endif //_SKY_HUB_COMMON_PRODUCT_REQ_

#if defined(_XB7_PRODUCT_REQ_) || defined(_XB8_PRODUCT_REQ_) || defined(_XB10_PRODUCT_REQ_) || \
    defined(_SCER11BEL_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_) ||                         \
    defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_)
        if (!isVapSTAMesh(vap_index)) {
            cfg.u.bss_info.hostap_mgt_frame_ctrl = true;
            wifi_util_info_print(WIFI_DB, "%s:%d vap_index:%d hostap_mgt_frame_ctrl:%d\n", __func__,
                __LINE__, vap_index, cfg.u.bss_info.hostap_mgt_frame_ctrl);
        }
#endif // defined(_XB7_PRODUCT_REQ_) || defined(_XB8_PRODUCT_REQ_) || defined(_XB10_PRODUCT_REQ_) ||
       // defined(_SCER11BEL_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_) ||
       // defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_)
        cfg.u.bss_info.interop_ctrl = false;
        cfg.u.bss_info.inum_sta = 0;
        wifi_util_dbg_print(WIFI_DB, "%s:%d vap_index:%d interop_ctrl:%d inum_sta:%d \n", __func__,
            __LINE__, vap_index, cfg.u.bss_info.interop_ctrl, cfg.u.bss_info.inum_sta);

        memset(ssid, 0, sizeof(ssid));

        if (wifi_hal_get_default_ssid(ssid, vap_index) == 0) {
            strcpy(cfg.u.bss_info.ssid, ssid);

        } else {
           strcpy(cfg.u.bss_info.ssid, vap_name);
        }

        memset(password, 0, sizeof(password));
        if (wifi_hal_get_default_keypassphrase(password,vap_index) == 0) {
            strcpy(cfg.u.bss_info.security.u.key.key, password);
        } else {
            strcpy(cfg.u.bss_info.security.u.key.key, INVALID_KEY);
        }

        if (isVapLnfSecure(vap_index)) {
            cfg.u.bss_info.enabled = true;
            cfg.u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            strcpy(cfg.u.bss_info.security.u.radius.identity, "lnf_radius_identity");
            cfg.u.bss_info.security.u.radius.port = 1812;
            if (wifi_hal_get_default_radius_key(radius_key,vap_index) == 0) {
                strcpy(cfg.u.bss_info.security.u.radius.key, radius_key);
                strcpy(cfg.u.bss_info.security.u.radius.s_key, radius_key);
            }
            else {
                strcpy(cfg.u.bss_info.security.u.radius.key, INVALID_KEY);
                strcpy(cfg.u.bss_info.security.u.radius.s_key, INVALID_KEY);
            }
            memset(cfg.u.bss_info.security.u.radius.ip,0,sizeof(cfg.u.bss_info.security.u.radius.ip));
            cfg.u.bss_info.security.u.radius.s_port = 1812;
            memset(cfg.u.bss_info.security.u.radius.s_ip,0,sizeof(cfg.u.bss_info.security.u.radius.s_ip));
            set_lnf_radius_server_ip(&cfg.u.bss_info.security);
            wifi_util_info_print(WIFI_DB,"Primary Ip and Secondry Ip: %s , %s\n", (char *)cfg.u.bss_info.security.u.radius.ip, (char *)cfg.u.bss_info.security.u.radius.s_ip);
        }

        char str[600] = {0};
        snprintf(str,sizeof(str),"%s"," { \"ANQP\":{ \"IPAddressTypeAvailabilityANQPElement\":{ \"IPv6AddressType\":0, \"IPv4AddressType\":0}, \"DomainANQPElement\":{\"DomainName\":[]}, \"NAIRealmANQPElement\":{\"Realm\":[]}, \"3GPPCellularANQPElement\":{ \"GUD\":0, \"PLMN\":[]}, \"RoamingConsortiumANQPElement\": { \"OI\": []}, \"VenueNameANQPElement\": { \"VenueInfo\": []}}}");
        snprintf((char *)cfg.u.bss_info.interworking.anqp.anqpParameters,sizeof(cfg.u.bss_info.interworking.anqp.anqpParameters),"%s",str);
        memset(str,0,sizeof(str));
        snprintf(str,sizeof(str),"%s","{ \"Passpoint\":{ \"PasspointEnable\":false, \"NAIHomeRealmANQPElement\":{\"Realms\":[]}, \"OperatorFriendlyNameANQPElement\":{\"Name\":[]}, \"ConnectionCapabilityListANQPElement\":{\"ProtoPort\":[]}, \"GroupAddressedForwardingDisable\":true, \"P2pCrossConnectionDisable\":false}}");
        snprintf((char *)cfg.u.bss_info.interworking.passpoint.hs2Parameters,sizeof(cfg.u.bss_info.interworking.passpoint.hs2Parameters),"%s",str);

        if ((!security_mode_support_radius(cfg.u.bss_info.security.mode)) &&
                cfg.u.bss_info.security.mode != wifi_security_mode_none && 
                cfg.u.bss_info.security.mode != wifi_security_mode_enhanced_open) {
            if ((strlen(cfg.u.bss_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(cfg.u.bss_info.security.u.key.key) > MAX_PWD_LEN)) {
                wifi_util_error_print(WIFI_DB, "%s:%d: Incorrect password length %d for vap '%s'\n", __func__, __LINE__, strlen(cfg.u.bss_info.security.u.key.key), vap_name);
                strncpy(cfg.u.bss_info.security.u.key.key, INVALID_KEY, sizeof(cfg.u.bss_info.security.u.key.key));
            }
        }
#if defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_PP203X_PRODUCT_REQ_) || defined (_GREXT02ACTS_PRODUCT_REQ_) //NEED _SCER11BEL_PRODUCT_REQ_ XER10 is GW..  STA is NOT needed ????
        //Disabling all vaps except STA Vaps by default in XLE
        cfg.u.bss_info.enabled = false;
        exists = false;
#endif //_WNXL11BWL_PRODUCT_REQ_ , _PP203X_PRODUCT_REQ_ , _GREXT02ACTS_PRODUCT_REQ_
    }

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
    if(exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
        if(vap_index != 2 && vap_index != 3) {
            wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
            exists = true;
        }
#else
        wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
        exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
    }
#endif /* !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)*/
    rdk_config->exists = exists;
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_global_config_default
  Parameter   : void
  Description : Update global cache with default value for wifi_global_param_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_global_config_default(wifi_global_param_t *config)
{
    wifi_global_param_t cfg;
    char temp[32], tempBuf[MAX_BUF_SIZE];
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    memset(&cfg,0,sizeof(cfg));

    cfg.notify_wifi_changes = true;
    cfg.prefer_private =  false;
    cfg.prefer_private_configure = true;
    cfg.tx_overflow_selfheal = false;
    cfg.vlan_cfg_version = 2;

    cfg.bandsteering_enable = false;
    cfg.good_rssi_threshold = -65;
    cfg.assoc_count_threshold = 0;
    cfg.assoc_gate_time  = 0;
    cfg.whix_log_interval = DEFAULT_WHIX_LOGINTERVAL;
    cfg.whix_chutility_loginterval = DEFAULT_WHIX_CHUTILITY_LOGINTERVAL;
    cfg.memwraptool.rss_check_interval = DEFAULT_RSS_CHECK_INTERVAL;
    cfg.memwraptool.rss_threshold = DEFAULT_RSS_THRESHOLD;
    cfg.memwraptool.rss_maxlimit = DEFAULT_RSS_MAXLIMIT;
    cfg.memwraptool.heapwalk_duration = DEFAULT_HEAPWALK_DURATION;
    cfg.memwraptool.heapwalk_interval = DEFAULT_HEAPWALK_INTERVAL;
    cfg.memwraptool.enable = true;
    cfg.rss_memory_restart_threshold_low = 81920;
    cfg.rss_memory_restart_threshold_high = 112640;
    cfg.assoc_monitor_duration = 0;
    cfg.rapid_reconnect_enable = true;
    cfg.vap_stats_feature =  true;
    cfg.mfp_config_feature = false;
    cfg.force_disable_radio_feature = false;
    cfg.force_disable_radio_status = false;
    cfg.fixed_wmm_params = 3;
    memset(temp, 0, sizeof(temp));
    if (wifi_hal_get_default_country_code(temp) < 0) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: unable to get default country code setting a USI\n", __func__, __LINE__);
        strncpy(cfg.wifi_region_code, "USI",sizeof(cfg.wifi_region_code)-1);
    } else {
        snprintf(cfg.wifi_region_code, sizeof(cfg.wifi_region_code), "%sI", temp);
    }
    cfg.inst_wifi_client_enabled = false;
    cfg.inst_wifi_client_reporting_period = 0;
    cfg.inst_wifi_client_def_reporting_period = 0;
    cfg.wifi_active_msmt_enabled = false;
    cfg.wifi_active_msmt_pktsize = 1470;
    cfg.wifi_active_msmt_num_samples = 5;
    cfg.wifi_active_msmt_sample_duration = 400;
    cfg.diagnostic_enable = false;
    cfg.validate_ssid = true;
    cfg.factory_reset = 0;
    strncpy(cfg.wps_pin, DEFAULT_WPS_PIN, sizeof(cfg.wps_pin)-1);
    memset(temp, '\0', sizeof(temp));
    memset(tempBuf, '\0', MAX_BUF_SIZE);
    for (UINT i = 0; i < getNumberRadios(); i++) {
        snprintf(temp, sizeof(temp), "%d,", getPrivateApFromRadioIndex(i)+1);
        strncat(tempBuf, temp, strlen(temp));
    }
    tempBuf[strlen(tempBuf)-1] = '\0';
    strncpy(cfg.normalized_rssi_list, tempBuf, sizeof(cfg.normalized_rssi_list)-1);
    cfg.normalized_rssi_list[sizeof(cfg.normalized_rssi_list)-1] = '\0';
    strncpy(cfg.snr_list, tempBuf, sizeof(cfg.snr_list)-1);
    cfg.snr_list[sizeof(cfg.snr_list)-1] = '\0';
    strncpy(cfg.cli_stat_list, tempBuf, sizeof(cfg.cli_stat_list)-1);
    cfg.cli_stat_list[sizeof(cfg.cli_stat_list)-1] = '\0';
    strncpy(cfg.txrx_rate_list, tempBuf, sizeof(cfg.txrx_rate_list)-1);
    cfg.txrx_rate_list[sizeof(cfg.txrx_rate_list)-1] = '\0';

    cfg.mgt_frame_rate_limit_enable = false;
    cfg.mgt_frame_rate_limit = 10;
    cfg.mgt_frame_rate_limit_window_size = 1;
    cfg.mgt_frame_rate_limit_cooldown_time = 30;

#ifdef ONEWIFI_DEFAULT_NETWORKING_MODE
    cfg.device_network_mode = ONEWIFI_DEFAULT_NETWORKING_MODE;
#else
    cfg.device_network_mode = rdk_dev_mode_type_gw;
#endif

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_default_value
  Parameter   : void
  Description : Update global cache with default values
 *************************************************************************************
********************************************** ****************************************/
void wifidb_init_default_value()
{
    int r_index = 0;
    int vap_index = 0;
    int num_radio = getNumberRadios();
    wifi_radio_operationParam_t *l_radio_cfg = NULL;
    wifi_radio_feature_param_t *f_radio_cfg = NULL;
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;
    mac_address_t temp_mac_address[MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO];
    int l_vap_index = 0;

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifi_util_dbg_print(WIFI_DB,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return;
    }

    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    for (r_index = 0; r_index < num_radio; r_index++)
    {
        l_radio_cfg = get_wifidb_radio_map(r_index);
        if(l_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_map \n",__func__, __LINE__,index);
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
            return;
        }
        f_radio_cfg = get_wifidb_radio_feat_map(r_index);
        if(f_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_feat_map \n",__func__, __LINE__, r_index);
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
            return;
        }
        l_vap_param_cfg = get_wifidb_vap_map(r_index);

        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_parameters \n",__func__, __LINE__);
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
            return;
        }
        memset(l_radio_cfg, 0, sizeof(wifi_radio_operationParam_t));
        memset(f_radio_cfg, 0, sizeof(wifi_radio_feature_param_t));
        for (vap_index = 0; vap_index < MAX_NUM_VAP_PER_RADIO; vap_index++)
        {
            l_vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, l_vap_param_cfg->vap_array[vap_index].vap_name);
            
            if (l_vap_index == RETURN_ERR) {
                continue;
            }

            memset(&temp_mac_address[l_vap_index], 0, sizeof(temp_mac_address[l_vap_index]));

            //Copy the vap's interface mac address to temporary array before the memset, to avoid loosing the
            //interface mac
            if (isVapSTAMesh(l_vap_index) == TRUE) {
                memcpy(&temp_mac_address[l_vap_index], l_vap_param_cfg->vap_array[vap_index].u.sta_info.mac, sizeof(temp_mac_address[l_vap_index]));
            } else {
                memcpy(&temp_mac_address[l_vap_index], l_vap_param_cfg->vap_array[vap_index].u.bss_info.bssid, sizeof(temp_mac_address[l_vap_index]));
            }

            memset(&l_vap_param_cfg->vap_array[vap_index].u.sta_info, 0, sizeof(wifi_back_haul_sta_t));
            memset(&l_vap_param_cfg->vap_array[vap_index].u.bss_info, 0, sizeof(wifi_front_haul_bss_t));
            memset(&l_vap_param_cfg->vap_array[vap_index].bridge_name, 0, WIFI_BRIDGE_NAME_LEN);
            memset(&l_vap_param_cfg->vap_array[vap_index].vap_mode, 0, sizeof(wifi_vap_mode_t));
        }
    }
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    for (r_index = 0; r_index < num_radio; r_index++)
    {
        l_radio_cfg = get_wifidb_radio_map(r_index);
        if(l_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_map \n",__func__, __LINE__,index);
            return;
        }
        f_radio_cfg = get_wifidb_radio_feat_map(r_index);
        if(f_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_feat_map \n",__func__, __LINE__, r_index);
            return;
        }
        wifidb_init_radio_config_default(r_index, l_radio_cfg, f_radio_cfg);
    }

    for (UINT index = 0; index < getTotalNumberVAPs(); index++)
    {
        vap_index = VAP_INDEX(g_wifidb->hal_cap, index);
        wifi_vap_info_t *vapInfo = getVapInfo(vap_index);
        if (vapInfo == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: VAP info for VAP index %d not found\n", __func__, __LINE__, vap_index);
            continue;
        }
        rdk_wifi_vap_info_t *rdkVapInfo = getRdkVapInfo(vap_index);
        if (rdkVapInfo == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: rdk VAP info for VAP index %d not found\n",
                __func__, __LINE__, vap_index);
            continue;
        }
        wifidb_init_vap_config_default(vap_index, vapInfo, rdkVapInfo);
        wifidb_init_interworking_config_default(vap_index, &vapInfo->u.bss_info.interworking.interworking);
        wifidb_init_preassoc_conn_ctrl_config_default(vap_index, &vapInfo->u.bss_info.preassoc);
        wifidb_init_postassoc_conn_ctrl_config_default(vap_index, &vapInfo->u.bss_info.postassoc);

      //As wifidb_init_vap_config_default() does memcpy of wifi_vap_info_t structure
      //so here we are restoring the interface mac into wifi_vap_info_t from temporary array
        if (isVapSTAMesh(vap_index) == TRUE) {
            memcpy(vapInfo->u.sta_info.mac, &temp_mac_address[vap_index], sizeof(vapInfo->u.sta_info.mac));
        } else {
            memcpy(vapInfo->u.bss_info.bssid, &temp_mac_address[vap_index], sizeof(vapInfo->u.bss_info.bssid));
        }
    }

    wifidb_init_global_config_default(&g_wifidb->global_config.global_parameters);
    wifidb_reset_macfilter_hashmap();
    wifidb_init_gas_config_default(&g_wifidb->global_config.gas_config);
    wifidb_init_rfc_config_default(&g_wifidb->rfc_dml_parameters);
    wifi_util_info_print(WIFI_DB,"%s:%d Wifi db update completed\n",__func__, __LINE__);

}

static int get_ap_mac_by_vap_index(wifi_vap_info_map_t *hal_vap_info_map, int vap_index,  mac_address_t mac)
{
    unsigned int j = 0;

    for (j = 0; j < hal_vap_info_map->num_vaps; j++) {
        if ((int)hal_vap_info_map->vap_array[j].vap_index == vap_index) {
            memcpy(mac, hal_vap_info_map->vap_array[j].u.bss_info.bssid, sizeof(mac_address_t));
            return RETURN_OK;
        }
    }
    wifi_util_error_print(WIFI_DB, "%s:%d vap_info not found for vap_index value: %d\n"
        ,__FUNCTION__, __LINE__, vap_index);
    return RETURN_ERR;
}

static int wifidb_vap_config_update_mld_mac()
{
    wifi_vap_info_map_t  hal_vap_info_map;
    wifi_vap_info_map_t *mgr_vap_info_map = NULL;
    mac_address_t mlo_mac = {0};
    mac_address_t zero_mac = {0};
    unsigned char *mld_addr_map[MAX_NUM_RADIOS] = {0};
    unsigned int r_idx=0;
    unsigned int i = 0;
    unsigned int k = 0;
    int ret = RETURN_OK;

    for (i = 0; i < MLD_UNIT_COUNT; i++) {
        memset(mld_addr_map, 0, sizeof(mld_addr_map));
        memset(mlo_mac, 0, sizeof(mac_address_t));

        wifi_util_info_print(WIFI_DB, "%s:%d: Updating MLO MAC for mld_unit %d\r\n", __func__, __LINE__, i);

        for (r_idx=0; r_idx < getNumberRadios(); r_idx++) {
            memset(&hal_vap_info_map, 0, sizeof(hal_vap_info_map));
            /* wifi_hal_getRadioVapInfoMap is used  to get the macaddress of wireless interfaces */
            ret = wifi_hal_getRadioVapInfoMap(r_idx, &hal_vap_info_map);
            if (ret != RETURN_OK) {
                wifi_util_error_print(WIFI_DB, "%s:%d wifi_hal_getRadioVapInfoMap failed for radio: %d\n",__FUNCTION__, __LINE__, r_idx);
                return ret;
            }
            /* vap map with loaded DB - find the main mlo vap */
            mgr_vap_info_map = get_wifidb_vap_map(r_idx);
            if (mgr_vap_info_map == NULL) {
                wifi_util_error_print(WIFI_DB, "%s:%d get_wifidb_vap_map failed for radio: %d\n",__FUNCTION__, __LINE__, r_idx);
                return RETURN_ERR;
            }
            for (k = 0; k < mgr_vap_info_map->num_vaps; k++) {
                wifi_vap_info_t *vap_config = &mgr_vap_info_map->vap_array[k];
                wifi_mld_common_info_t *mld_info = NULL;

                if (isVapSTAMesh(vap_config->vap_index)) {
                    continue;
                }

                mld_info = &vap_config->u.bss_info.mld_info.common_info;
                if (i == 0) { /* Initialise all vap's mld_mac with interface mac */
                    get_ap_mac_by_vap_index(&hal_vap_info_map, vap_config->vap_index, mld_info->mld_addr);
                }

                if (mld_info->mld_enable && mld_info->mld_id == i) {
                    mld_addr_map[r_idx] = mld_info->mld_addr; /* store mld_addr ptr to be updated later */
                    if(mld_info->mld_link_id == 0) { /* check if the link is main MLO link */
                        get_ap_mac_by_vap_index(&hal_vap_info_map, vap_config->vap_index, mlo_mac);
                    }
                }
            }
        }

        if (memcmp(mlo_mac, zero_mac, sizeof(mac_address_t)) == 0) {
            continue;
        }

        for (r_idx = 0; r_idx < getNumberRadios(); r_idx++) {
            if (mld_addr_map[r_idx] != NULL) {
                memcpy(mld_addr_map[r_idx], mlo_mac, sizeof(mac_address_t));
            }
        }
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : init_wifidb_data
  Parameter   : void
  Description : Init global cache with wifidb persistant data
 *************************************************************************************
********************************************** ****************************************/
void init_wifidb_data()
{
    static bool db_param_init = false;
    if (db_param_init == true) {
        wifi_util_info_print(WIFI_DB, "%s:%d db params already initialized\r\n",__func__, __LINE__);
        return;
    }

    FILE *file = NULL;
    int r_index = 0;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    int num_radio = getNumberRadios();
    rdk_wifi_vap_info_t *l_rdk_vap_param_cfg;
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;
    wifi_radio_operationParam_t *l_radio_cfg = NULL;
    wifi_radio_feature_param_t *f_radio_cfg = NULL;
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();
    char country_code[COUNTRY_CODE_LEN] = {0};

    wifi_util_info_print(WIFI_DB,"%s:%d No of radios %d\n",__func__, __LINE__,getNumberRadios());

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_DB,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return;
    }
    wifidb_init_default_value();

    if ((access(ONEWIFI_FR_REBOOT_FLAG, F_OK) == 0) && (access(ONEWIFI_FR_WIFIDB_RESET_DONE_FLAG, F_OK) != 0)) {
        wifidb_update_rfc_config(0, rfc_param);
        get_wifi_country_code_from_bootstrap_json(country_code, COUNTRY_CODE_LEN);
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        for (r_index = 0; r_index < num_radio; r_index++) {
            l_radio_cfg = get_wifidb_radio_map(r_index);
            if(l_radio_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: invalid get_wifidb_radio_map \n",__func__, __LINE__);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            l_rdk_vap_param_cfg = get_wifidb_rdk_vaps(r_index);
            if (l_rdk_vap_param_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: invalid get_wifidb_rdk_vaps \n",__func__, __LINE__);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            l_vap_param_cfg = get_wifidb_vap_map(r_index);
            if(l_vap_param_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: invalid get_wifidb_vap_map \n",__func__, __LINE__);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            f_radio_cfg = get_wifidb_radio_feat_map(r_index);
            if(f_radio_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_feat_map \n",__func__, __LINE__, r_index);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            if (country_code[0] != 0) {
                char radio_country_code[COUNTRY_CODE_LEN] = {0};
                wifi_countrycode_type_t r_country_code;
                snprintf(radio_country_code, COUNTRY_CODE_LEN, "%s", country_code);
                if (country_code_conversion(&r_country_code, radio_country_code, COUNTRY_CODE_LEN, STRING_TO_ENUM) < 0) {
                    wifi_util_error_print(WIFI_DB,"%s:%d: unable to convert country string %s\n", __func__, __LINE__, radio_country_code);
                } else {
                    if (l_radio_cfg->countryCode != r_country_code) {
                        l_radio_cfg->countryCode = r_country_code;
                    }
                }
            }
            wifidb_update_wifi_radio_config(r_index, l_radio_cfg, f_radio_cfg);
            wifidb_update_wifi_vap_config(r_index, l_vap_param_cfg, l_rdk_vap_param_cfg);

            wifidb_update_wifi_cac_config(l_vap_param_cfg);
        }
        if (country_code[0] != 0) {
            if (strcmp(country_code, g_wifidb->global_config.global_parameters.wifi_region_code) != 0) {
                strncpy(g_wifidb->global_config.global_parameters.wifi_region_code, country_code, sizeof(g_wifidb->global_config.global_parameters.wifi_region_code));
            }
        }
        if (wifidb_update_wifi_global_config(&g_wifidb->global_config.global_parameters) != RETURN_OK) {
            wifi_util_error_print(WIFI_DB,"%s:%d error in updating global config\n", __func__,__LINE__);
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
            return;
        }
        wifidb_update_gas_config(g_wifidb->global_config.gas_config.AdvertisementID, &g_wifidb->global_config.gas_config);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        remove_onewifi_factory_reset_reboot_flag();
        create_onewifi_fr_wifidb_reset_done_flag();
        wifi_util_info_print(WIFI_DB,"%s:%d FactoryReset done. wifidb updated with default values.\n",__func__, __LINE__);
    }
    else {
        dbwritten = true;
        if (wifidb_get_rfc_config(0,rfc_param) != 0) {
            wifi_util_error_print(WIFI_DB,"%s:%d: Error getting RFC config\n",__func__, __LINE__);
        }
#ifdef ALWAYS_ENABLE_AX_2G
        wifidb_update_rfc_config(0, rfc_param);
#endif
        get_wifi_country_code_from_bootstrap_json(country_code, COUNTRY_CODE_LEN);
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        for (r_index = 0; r_index < num_radio; r_index++) {
            l_vap_param_cfg = get_wifidb_vap_map(r_index);
            if(l_vap_param_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: invalid get_wifidb_vap_map \n",__func__, __LINE__);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            l_rdk_vap_param_cfg = get_wifidb_rdk_vaps(r_index);
            if (l_rdk_vap_param_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: invalid get_wifidb_rdk_vaps \n",__func__, __LINE__);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            l_radio_cfg = get_wifidb_radio_map(r_index);
            if(l_radio_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: invalid get_wifidb_radio_map \n",__func__, __LINE__);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            f_radio_cfg = get_wifidb_radio_feat_map(r_index);
            if(f_radio_cfg == NULL) {
                wifi_util_error_print(WIFI_DB,"%s:%d: %d invalid get_wifidb_radio_feat_map \n",__func__, __LINE__, r_index);
                pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                return;
            }
            wifidb_get_wifi_radio_config(r_index, l_radio_cfg, f_radio_cfg);
            if (wifidb_get_wifi_vap_config(r_index, l_vap_param_cfg, l_rdk_vap_param_cfg) == -1) {
                wifidb_print("%s:%d wifidb_get_wifi_vap_config failed\n",__func__, __LINE__);
                wifidb_update_wifi_vap_config(r_index, l_vap_param_cfg, l_rdk_vap_param_cfg);
            }

            wifidb_vap_config_correction(l_vap_param_cfg);

            if (country_code[0] != 0) {
                char radio_country_code[COUNTRY_CODE_LEN] = {0};
                wifi_countrycode_type_t r_country_code;
                strncpy(radio_country_code, country_code, sizeof(radio_country_code) - 1);
                if (country_code_conversion(&r_country_code, radio_country_code, COUNTRY_CODE_LEN, STRING_TO_ENUM) < 0) {
                        wifi_util_dbg_print(WIFI_DB,"%s:%d: unable to convert country string, country_code = %s\n", __func__, __LINE__,radio_country_code);
                } else {
                    if (l_radio_cfg->countryCode != r_country_code) {
                        l_radio_cfg->countryCode = r_country_code;
                        wifidb_update_wifi_radio_config(r_index, l_radio_cfg, f_radio_cfg);
                    }
                }
            }
            wifidb_radio_config_upgrade(r_index, l_radio_cfg, f_radio_cfg);
            wifidb_vap_config_upgrade(l_vap_param_cfg, l_rdk_vap_param_cfg);
            if (l_radio_cfg->EcoPowerDown == false) {
                wifidb_vap_config_ext(l_vap_param_cfg, l_rdk_vap_param_cfg);
            }

            for (unsigned int i = 0; i < l_vap_param_cfg->num_vaps; i++) {
                uint8_t vap_index= convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, l_vap_param_cfg->vap_array[i].vap_name);
                if ((int)vap_index < 0) {
                    wifi_util_error_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,l_vap_param_cfg->vap_array[i].vap_name);
                    continue;
                }
                if (isVapHotspot(vap_index)) {
                    wifidb_get_preassoc_ctrl_config(l_vap_param_cfg->vap_array[i].vap_name, &l_vap_param_cfg->vap_array[i].u.bss_info.preassoc);
                    wifidb_get_postassoc_ctrl_config(l_vap_param_cfg->vap_array[i].vap_name, &l_vap_param_cfg->vap_array[i].u.bss_info.postassoc);
                }
            }
        }

        /* This is system-wide (file) flag. Hence, open the file after number of radio loop only in reboot case */
        file = fopen(ONEWIFI_BSS_MAXASSOC_FLAG, "a");
        if (file != NULL) {
            wifi_util_info_print(WIFI_DB, "%s:%d: File %s created\n", __func__, __LINE__, ONEWIFI_BSS_MAXASSOC_FLAG);
            /* This is one time operation occurs during migration from non-fix to fix build to support max station */
            fclose(file);
        } else {
            wifi_util_error_print(WIFI_DB, "%s:%d: Failed to open %s\n", __func__, __LINE__, ONEWIFI_BSS_MAXASSOC_FLAG);
            /* Continue after logging the system error. */
        }

        wifidb_get_wifi_macfilter_config();
        wifidb_get_wifi_global_config(&g_wifidb->global_config.global_parameters);
        wifidb_get_gas_config(g_wifidb->global_config.gas_config.AdvertisementID,&g_wifidb->global_config.gas_config);
        if (country_code[0] != 0) {
            if (strcmp(country_code, g_wifidb->global_config.global_parameters.wifi_region_code) != 0) {
                strncpy(g_wifidb->global_config.global_parameters.wifi_region_code, country_code, sizeof(g_wifidb->global_config.global_parameters.wifi_region_code));
            }
        }
        wifidb_global_config_upgrade();
        if (wifidb_update_wifi_global_config(&g_wifidb->global_config.global_parameters) != RETURN_OK) {
            wifi_util_error_print(WIFI_DB,"%s:%d error in updating global config\n", __func__,__LINE__);
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
            return;
        }
        wifidb_vap_config_update_mld_mac();
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }

    wifi_util_info_print(WIFI_DB,"%s:%d Wifi data init complete\n",__func__, __LINE__);
    db_param_init = true;
    dbwritten = true;
}

/************************************************************************************
 ************************************************************************************
  Function    : start_wifidb_monitor
  Parameter   : void
  Description : Init wifidb monitors which triggers respective  callbacks on modification
 *************************************************************************************
********************************************** ****************************************/
int start_wifidb_monitor()
{
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Radio_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_VAP_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Security_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Interworking_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_GAS_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Preassoc_Control_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Postassoc_Control_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Rfc_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Global_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Passpoint_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Anqp_Config, true);
    return 0;
}


/************************************************************************************
 ************************************************************************************
  Function    : init_wifidb_tables
  Parameter   : void
  Description : Init wifidb table and wifidb server connection
 *************************************************************************************
********************************************** ****************************************/
int init_wifidb_tables()
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if (is_db_consolidated()) {
        g_wifidb->wifidb_fd = -1;
        g_wifidb->wifidb_wfd = -1;
        wifidb_read_version();
    }

    unsigned int attempts = 0;
    g_wifidb->wifidb_ev_loop = ev_loop_new(0);
    if (!g_wifidb->wifidb_ev_loop) {
        wifi_util_error_print(WIFI_DB,"%s:%d: Could not find default target_loop\n", __func__, __LINE__);
        return -1;
    }
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Device_Config, device_mac);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Security_Config,vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Interworking_Config, vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Preassoc_Control_Config, vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Postassoc_Control_Config, vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Connection_Control_Config, vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_GAS_Config, advertisement_id);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_VAP_Config, vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Radio_Config, radio_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_MacFilter_Config, macfilter_key);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Rfc_Config, rfc_id);
    ONEWIFI_OVSDB_TABLE_INIT_NO_KEY(Wifi_Global_Config);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Passpoint_Config, vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Anqp_Config, vap_name);
    //connect to wifidb with sock path
    if (is_db_consolidated()) {
        snprintf(g_wifidb->wifidb_sock_path, sizeof(g_wifidb->wifidb_sock_path), WIFIDB_CONSOLIDATED_PATH);
    } else {
        snprintf(g_wifidb->wifidb_sock_path, sizeof(g_wifidb->wifidb_sock_path), "%s/wifidb.sock", WIFIDB_RUN_DIR);
    }
    // XXX: attemps == 3 sometimes is reached on XE2. Should be refactored
    while (attempts < 5) {
        if ((g_wifidb->wifidb_fd = onewifi_ovsdb_conn(g_wifidb->wifidb_sock_path)) < 0) {
            wifi_util_error_print(WIFI_DB,"%s:%d:Failed to connect to wifidb at %s\n",
                __func__, __LINE__, g_wifidb->wifidb_sock_path);
            attempts++;
            sleep(1);
            if (attempts == 5) {
                return -1;
            }
        } else {
            break;
        }
    }
    wifi_util_info_print(WIFI_DB,"%s:%d:Connection to wifidb at %s successful\n",
            __func__, __LINE__, g_wifidb->wifidb_sock_path);
    //init evloop for wifidb
    if (onewifi_ovsdb_init_loop(g_wifidb->wifidb_fd, &g_wifidb->wifidb_ev_io, g_wifidb->wifidb_ev_loop) == false) 
    {
        wifi_util_error_print(WIFI_DB,"%s:%d: Could not find default target_loop\n", __func__, __LINE__);
        return -1;
    }
    //create thread to receive notification for wifidb server
    pthread_create(&g_wifidb->evloop_thr_id, &attr, evloop_func, NULL);
    return 0;
}


/************************************************************************************
 ************************************************************************************
  Function    : start_wifidb_func
  Parameter   : void
  Description : Init wifidb 
 *************************************************************************************
***************************************************************************************/
int start_wifidb()
{
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    g_wifidb->wifidb_fd = -1;
    g_wifidb->wifidb_wfd = -1;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );

    pthread_create(&g_wifidb->wifidb_thr_id, &attr, start_wifidb_func, NULL);

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_cleanup
  Parameter   : void
  Description : Close all openned file pointers
 *************************************************************************************
***************************************************************************************/
void wifidb_cleanup()
{
    wifi_db_t *g_wifidb;
    g_wifidb = get_wifidb_obj();
    if (g_wifidb->wifidb_fd >= 0)
    {
        close(g_wifidb->wifidb_fd);
    }
    if (g_wifidb->wifidb_wfd >= 0)
    {
        close(g_wifidb->wifidb_wfd);
    }
}

void init_wifidb(void)
{
    if (!is_db_consolidated()) {
        start_wifidb();
    }
    init_wifidb_tables();
    //init_wifidb_data();//TBD
    start_wifidb_monitor();
}

int wifi_db_update_global_config(wifi_global_param_t *global_cfg)
{
    char *str = NULL;
    char strValue[256] = {0};
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

    memset(global_cfg, 0, sizeof(wifi_global_param_t));
    get_wifidb_obj()->desc.init_global_config_default_fn(global_cfg);

    memset(strValue, 0, sizeof(strValue));
#ifndef NEWPLATFORM_PORT
    str = p_ccsp_desc->psm_get_value_fn(WiFivAPStatsFeatureEnable, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &global_cfg->vap_stats_feature);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->vap_stats_feature; is %d and str is %s\n", global_cfg->vap_stats_feature, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for vap_stats_feature:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WifiVlanCfgVersion, strValue);
    if (str != NULL) {
        global_cfg->vlan_cfg_version = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->vlan_cfg_version is %d and str is %s and atoi(str) is %d\n", global_cfg->vlan_cfg_version, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for vlan_cfg_version:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(PreferPrivate, strValue);
    if (str != NULL) {
        global_cfg->prefer_private = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->prefer_private is %d and str is %s and atoi(str) is %d\n", global_cfg->prefer_private, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for prefer_private:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(NotifyWiFiChanges, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &global_cfg->notify_wifi_changes);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->notify_wifi_changes is %d and str is %s\n", global_cfg->notify_wifi_changes, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for notify_wifi_changes:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(DiagnosticEnable, strValue);
    if (str != NULL) {
        global_cfg->diagnostic_enable = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->diagnostic_enable is %d and str is %s and atoi(str) is %d\n", global_cfg->diagnostic_enable, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for diagnostic_enable:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(GoodRssiThreshold, strValue);
    if (str != NULL) {
        global_cfg->good_rssi_threshold = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->good_rssi_threshold is %d and str is %s and atoi(str) is %d\n", global_cfg->good_rssi_threshold, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for good_rssi_threshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(AssocCountThreshold, strValue);
    if (str != NULL) {
        global_cfg->assoc_count_threshold = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->assoc_count_threshold is %d and str is %s and atoi(str) is %d\n", global_cfg->assoc_count_threshold, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for assoc_count_threshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(AssocMonitorDuration, strValue);
    if (str != NULL) {
        global_cfg->assoc_monitor_duration = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->assoc_monitor_duration is %d and str is %s and atoi(str) is %d\n", global_cfg->assoc_monitor_duration, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for assoc_monitor_duration:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(AssocGateTime, strValue);
    if (str != NULL) {
        global_cfg->assoc_gate_time = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->assoc_gate_time is %d and str is %s and atoi(str) is %d\n", global_cfg->assoc_gate_time, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for assoc_gate_time:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WhixLoginterval, strValue);
    if (str != NULL) {
        global_cfg->whix_log_interval = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->whix_log_interval is %d and str is %s and atoi(str) is %d\n", global_cfg->whix_log_interval, str, atoi(str));
    } else {
        global_cfg->whix_log_interval = DEFAULT_WHIX_LOGINTERVAL;
        wifi_util_error_print(WIFI_MGR,":%s:%d str value for whix_log_interval is null \n", __func__, __LINE__);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WhixChUtilityLoginterval, strValue);
    if (str != NULL) {
        global_cfg->whix_chutility_loginterval = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"%s:%d global_cfg->whix_chutility_log_interval is %d and str is %s and atoi(str) is %d\n", __func__, __LINE__, global_cfg->whix_chutility_loginterval, str, atoi(str));
    } else {
        global_cfg->whix_chutility_loginterval = DEFAULT_WHIX_CHUTILITY_LOGINTERVAL;
        wifi_util_error_print(WIFI_MGR,":%s:%d str value for whix_chutility_loginterval is null \n", __func__, __LINE__);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(RapidReconnectIndicationEnable, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &global_cfg->rapid_reconnect_enable);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->rapid_reconnect_enable is %d and str is %s\n", global_cfg->rapid_reconnect_enable, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for rapid_reconnect_enable:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(FeatureMFPConfig, strValue);
    if (str != NULL) {
        global_cfg->mfp_config_feature = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->mfp_config_feature is %d and str is %s and atoi(str) is %d\n", global_cfg->mfp_config_feature, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for mfp_config_feature:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WiFiTxOverflowSelfheal, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &global_cfg->tx_overflow_selfheal);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->tx_overflow_selfheal is %d and str is %s\n", global_cfg->tx_overflow_selfheal, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for tx_overflow_selfheal:%s \r\n", __func__, __LINE__, str);    
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WiFiForceDisableWiFiRadio, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &global_cfg->force_disable_radio_feature);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->force_disable_radio_feature is %d and str is %s\n", global_cfg->force_disable_radio_feature, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for force_disable_radio_feature:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WiFiForceDisableRadioStatus, strValue);
    if (str != NULL) {
        global_cfg->force_disable_radio_status = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->force_disable_radio_status is %d and str is %s and atoi(str) is %d\n", global_cfg->force_disable_radio_status, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for force_disable_radio_status:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(ValidateSSIDName, strValue);
    if (str != NULL) {
        global_cfg->validate_ssid = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->validate_ssid is %d and str is %s and atoi(str) is %d\n", global_cfg->validate_ssid, str, atoi(str));
    }  else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for validate_ssid:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(FixedWmmParams, strValue);
    if (str != NULL) {
        global_cfg->fixed_wmm_params = atoi(strValue);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->fixed_wmm_params is %d and str is %s and atoi(str) is %d\n", global_cfg->fixed_wmm_params, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for fixed_wmm_params:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
#endif // NEWPLATFORM_PORT
    str = p_ccsp_desc->psm_get_value_fn(TR181_WIFIREGION_Code, strValue);
    if (str != NULL) {
        strcpy(global_cfg->wifi_region_code, str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_region_code is %s and str is %s \n", global_cfg->wifi_region_code, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_region_code:%s \r\n", __func__, __LINE__, str);
    }

#ifndef NEWPLATFORM_PORT
    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WpsPin, strValue);
    if (str != NULL) {
        // global_cfg->wps_pin = atoi(str);
	strcpy(global_cfg->wps_pin, str);
        wifi_util_dbg_print(WIFI_MGR,
	"global_cfg->wps_pin is %s and str is %s and atoi(str) is %d\n", global_cfg->wps_pin,
         str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR, ":%s:%d str value for wps_pin:%s \r\n", __func__, __LINE__,
            str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(PreferPrivateConfigure, strValue);
    if (str != NULL) {
        global_cfg->prefer_private_configure = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->prefer_private_configure is %d and str is %s and atoi(str) is %d\n", global_cfg->prefer_private_configure, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for prefer_private_configure:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(FactoryReset, strValue);
    if (str != NULL) {
        global_cfg->factory_reset = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->factory_reset is %d and str is %s and atoi(str) is %d\n", global_cfg->factory_reset, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for factory_reset:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(BandSteer_Enable, strValue);
    if (str != NULL) {
        global_cfg->bandsteering_enable = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->bandsteering_enable is %d and str is %s and atoi(str) is %d\n", global_cfg->bandsteering_enable, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for bandsteering_enable:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(InstWifiClientEnabled, strValue);
    if (str != NULL) {
        global_cfg->inst_wifi_client_enabled = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_enabled is %d and str is %s and atoi(str) is %d\n", global_cfg->inst_wifi_client_enabled, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_enabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(InstWifiClientReportingPeriod, strValue);
    if (str != NULL) {
        global_cfg->inst_wifi_client_reporting_period = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_reporting_period is %d and str is %s and atoi(str) is %d\n", global_cfg->inst_wifi_client_reporting_period, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_reporting_period:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(InstWifiClientMacAddress, strValue);
    if (str != NULL) {
        str_to_mac_bytes(str, global_cfg->inst_wifi_client_mac);
        //strncpy(global_cfg->inst_wifi_client_mac,str,sizeof(global_cfg->inst_wifi_client_mac)-1);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_mac is %s and str is %s \r\n", global_cfg->inst_wifi_client_mac, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_mac:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(InstWifiClientDefReportingPeriod, strValue);
    if (str != NULL) {
        global_cfg->inst_wifi_client_def_reporting_period = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->inst_wifi_client_def_reporting_period is %d and str is %s and atoi(str) is %d\n", global_cfg->inst_wifi_client_def_reporting_period, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for inst_wifi_client_def_reporting_period:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WiFiActiveMsmtEnabled, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, &global_cfg->wifi_active_msmt_enabled);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_enabled is %d and str is %s\r\n", global_cfg->wifi_active_msmt_enabled, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_enabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WiFiActiveMsmtPktSize, strValue);
    if (str != NULL) {
        global_cfg->wifi_active_msmt_pktsize = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_pktsize is %d and str is %s and atoi(str) is %d\n", global_cfg->wifi_active_msmt_pktsize, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_pktsize:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WiFiActiveMsmtNumberOfSample, strValue);
    if (str != NULL) {
        global_cfg->wifi_active_msmt_num_samples = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_num_samples is %d and str is %s and atoi(str) is %d\n", global_cfg->wifi_active_msmt_num_samples, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_num_samples:%s \r\n", __func__, __LINE__, str);
    }

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WiFiActiveMsmtSampleDuration, strValue);
    if (str != NULL) {
        global_cfg->wifi_active_msmt_sample_duration = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"global_cfg->wifi_active_msmt_sample_duration is %d and str is %s and atoi(str) is %d\n", global_cfg->wifi_active_msmt_sample_duration, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,":%s:%d str value for wifi_active_msmt_sample_duration:%s \r\n", __func__, __LINE__, str);
    }
#endif // NEWPLATFORM_PORT

    if (get_wifidb_obj()->desc.update_wifi_global_cfg_fn(global_cfg) != RETURN_OK) {
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
    char recName[256] = {0};
    char strValue[256] = {0};
    char *l_strValue = NULL;
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

    memset(recName, '\0', sizeof(recName));
    snprintf(recName, sizeof(recName), MacFilterList, instance_number);
    memset(strValue, 0, sizeof(strValue));
    wifi_util_dbg_print(WIFI_MGR, "%s:%d  recName: %s instance_number:%d\n",__func__, __LINE__, recName, instance_number);
    l_strValue = p_ccsp_desc->psm_get_value_fn(recName, l_strValue);
    if ((l_strValue != NULL) && (strlen(l_strValue) > 0))
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
        wifi_util_dbg_print(WIFI_MGR, "%s:%d PSM maclist get failure mac list data:%s\n",__func__, __LINE__, l_strValue);
    }

    return RETURN_ERR;
}

void get_radio_params_from_psm(unsigned int radio_index, wifi_radio_operationParam_t *radio_cfg, wifi_radio_feature_param_t *radio_feat_cfg)
{
    char *str = NULL;
    char recName[256] = {0};
    char strValue[256] = {0};
    unsigned int instance_number = radio_index + 1;
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

    memset(radio_cfg, 0, sizeof(wifi_radio_operationParam_t));
    memset(radio_feat_cfg, 0, sizeof(wifi_radio_feature_param_t));
    get_wifidb_obj()->desc.init_radio_config_default_fn((instance_number - 1), radio_cfg, radio_feat_cfg);


#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
    //5GH and 6G can be added later after support is added
    if (is_radio_band_5G(radio_cfg->band)) {
        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), Tscan, instance_number);
        str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
        if (str != NULL) {
            radio_feat_cfg->OffChanTscanInMsec = atoi(str);
            wifi_util_dbg_print(WIFI_MGR,"radio_feat_cfg->OffChanTscanInMsec is %d and str is %s and atoi(str) is %d\n", radio_feat_cfg->OffChanTscanInMsec, str, atoi(str));
        } else {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for Tscan:%s \r\n", __func__, __LINE__, str);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), Nscan, instance_number);
        str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
        if (str != NULL) {
            radio_feat_cfg->OffChanNscanInSec = atoi(str);
            wifi_util_dbg_print(WIFI_MGR,"radio_feat_cfg->OffChanNscanInSec is %d and str is %s and atoi(str) is %d\n", radio_feat_cfg->OffChanNscanInSec, str, atoi(str));
        } else {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for Nscan:%s \r\n", __func__, __LINE__, str);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), Tidle, instance_number);
        str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
        if (str != NULL) {
            radio_feat_cfg->OffChanTidleInSec = atoi(str);
            wifi_util_dbg_print(WIFI_MGR,"radio_feat_cfg->OffChanTidleInSec is %d and str is %s and atoi(str) is %d\n", radio_feat_cfg->OffChanTidleInSec, str, atoi(str));
        } else {
            wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for Tidle:%s \r\n", __func__, __LINE__, str);
        }
    }
#endif //FEATURE_OFF_CHANNEL_SCAN_5G

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), CTSProtection, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->ctsProtection = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->ctsProtection is %d and str is %s and atoi(str) is %d\n", radio_cfg->ctsProtection, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for ctsProtection:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BeaconInterval, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->beaconInterval = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->beaconInterval is %d and str is %s and atoi(str) is %d\n", radio_cfg->beaconInterval, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for beaconInterval:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), DTIMInterval, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->dtimPeriod = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->dtimPeriod is %d and str is %s and atoi(str) is %d\n", radio_cfg->dtimPeriod, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for dtimPeriod:%s \r\n", __func__, __LINE__,str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), FragThreshold, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->fragmentationThreshold = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->fragmentationThreshold is %d and str is %s and atoi(str) is %d\n", radio_cfg->fragmentationThreshold, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for fragmentationThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), RTSThreshold, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->rtsThreshold = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->rtsThreshold is %d and str is %s and atoi(str) is %d\n", radio_cfg->rtsThreshold, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for rtsThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), ObssCoex, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->obssCoex = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->obssCoex is %d and str is %s and atoi(str) is %d\n", radio_cfg->obssCoex, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for obssCoex:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), STBCEnable, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->stbcEnable = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->stbcEnable is %d and str is %s and atoi(str) is %d\n", radio_cfg->stbcEnable, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for stbcEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), GuardInterval, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->guardInterval = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->guardInterval is %d and str is %s and atoi(str) is %d\n", radio_cfg->guardInterval, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for guardInterval:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), GreenField, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->greenFieldEnable = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->greenFieldEnable is %d and str is %s and atoi(str) is %d\n", radio_cfg->greenFieldEnable, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for greenFieldEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), TransmitPower, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->transmitPower = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->transmitPower is %d and str is %s and atoi(str) is %d\n", radio_cfg->transmitPower, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for transmitPower:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), UserControl, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->userControl = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->userControl is %d and str is %s and atoi(str) is %d\n", radio_cfg->userControl, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for userControl:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), AdminControl, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->adminControl = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->adminControl is %d and str is %s and atoi(str) is %d\n", radio_cfg->adminControl, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for adminControl:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), MeasuringRateRd, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->radioStatsMeasuringRate = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->chanUtilThreshold is %d and str is %s and ansc_atoi-str is %d\n", radio_cfg->chanUtilThreshold, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for radioStatsMeasuringRate:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), MeasuringIntervalRd, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->radioStatsMeasuringInterval = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->radioStatsMeasuringInterval is %d and str is %s and atoi(str) is %d\n", radio_cfg->radioStatsMeasuringInterval, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for radioStatsMeasuringInterval:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), SetChanUtilThreshold, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->chanUtilThreshold = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->chanUtilThreshold is %d and str is %s and ansc_atoi-str is %d\n", radio_cfg->chanUtilThreshold, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for chanUtilThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), SetChanUtilSelfHealEnable, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        radio_cfg->chanUtilSelfHealEnable = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"radio_cfg->chanUtilSelfHealEnable is %d and str is %s and atoi(str) is %d\n", radio_cfg->chanUtilSelfHealEnable, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: str value for chanUtilSelfHealEnable:%s \r\n", __func__, __LINE__, str);
    }

    nvram_get_radio_enable_status(&radio_cfg->enable, radio_index);

    wifi_util_info_print(WIFI_MGR,"radio_cfg->enable:%d for radio index:%d\n", radio_cfg->enable, radio_index);
}

void get_radio_params_from_db(unsigned int radio_index,wifi_radio_operationParam_t *radio_cfg)
{
    wifi_channelBandwidth_t channelWidth = 0;
    if(platform_get_channel_bandwidth(radio_index,&channelWidth)!=0)
    {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: failed to get channel bandwidth from vendor db \r\n", __func__, __LINE__);
    }
    if(channelWidth)
    {
        radio_cfg->channelWidth = channelWidth;
        wifi_util_dbg_print(WIFI_MGR,"%s:%d:%u  successful value to get channel bandwidth from vendor db \r\n", __func__, __LINE__,radio_cfg->channelWidth);
    }
    else
    {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d:channelWidth is getting wrong value \n", __func__, __LINE__);
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
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

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
        str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
        if (str != NULL) {
            strcpy(temp_psm_mac_param->device_name, str);
            wifi_util_dbg_print(WIFI_MGR,"psm get device_name is %s\r\n", str);
        } else {
            wifi_util_dbg_print(WIFI_MGR,"[Failure] psm record_name: %s\n", recName);
        }

        memset(recName, 0, sizeof(recName));
        memset(strValue, 0, sizeof(strValue));
        snprintf(recName, sizeof(recName), MacFilter, instance_number, index);
        str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
        if (str != NULL) {
            str_to_mac_bytes(str, temp_psm_mac_param->mac);
            wifi_util_dbg_print(WIFI_MGR,"psm get mac is %s\n", str);
            str_tolower(str);
            wifi_util_dbg_print(WIFI_MGR,"psm get mac after lower is %s\n", str);
            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", l_vap_name, str);
            get_wifidb_obj()->desc.update_wifi_macfilter_config_fn(macfilterkey, temp_psm_mac_param, true);
        } else {
            wifi_util_dbg_print(WIFI_MGR,"[Failure] psm record_name: %s\n", recName);
        }
        free(temp_psm_mac_param);
        total_entry--;
    }
}

int get_vap_params_from_psm(unsigned int vap_index, wifi_vap_info_t *vap_config,
    rdk_wifi_vap_info_t *rdk_vap_config)
{
    wifi_front_haul_bss_t *bss_cfg;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    char *str = NULL;
    char recName[256] = {0};
    char strValue[256] = {0};
    unsigned int instance_number = vap_index + 1;
    int ret = -1;
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

    memset(vap_config, 0, sizeof(wifi_vap_info_t));
    get_wifidb_obj()->desc.init_vap_config_default_fn((instance_number - 1), vap_config, rdk_vap_config);
    if (isVapSTAMesh(vap_config->vap_index)) {
        return RETURN_ERR;
    }
    bss_cfg = &vap_config->u.bss_info;

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), WmmEnable, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->wmm_enabled = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->wmm_enabled is %d and str is %s and atoi(str) is %d\n", bss_cfg->wmm_enabled, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for wmm_enabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), UAPSDEnable, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->UAPSDEnabled = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->UAPSDEnabled is %d and str is %s and atoi(str) is %d\n", bss_cfg->UAPSDEnabled, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for UAPSDEnabled:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), vAPStatsEnable, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, (bool *)&bss_cfg->vapStatsEnable);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->vapStatsEnable is %d and str is %s\n", bss_cfg->vapStatsEnable, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for vapStatsEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), WmmNoAck, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->wmmNoAck = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->wmmNoAck is %d and str is %s and atoi(str) is %d\n", bss_cfg->wmmNoAck, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for wmmNoAck:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BssMaxNumSta, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        if ((isVapPrivate(vap_config->vap_index)) && (atoi(str) == 0)) {
            bss_cfg->bssMaxSta = wifi_mgr->hal_cap.wifi_prop.BssMaxStaAllow;
            wifi_util_info_print(WIFI_MGR, "wrong max clients configured in psm, changing max associated clients to %d on vap:%d\n", wifi_mgr->hal_cap.wifi_prop.BssMaxStaAllow, vap_index);
        } else {
            bss_cfg->bssMaxSta = atoi(str);
        }
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->bssMaxSta is %d and str is %s and atoi(str) is %d\n", bss_cfg->bssMaxSta, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for bssMaxSta:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), MacFilterMode, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        unsigned int mf_mode = atoi(str);
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
        wifi_util_info_print(WIFI_MGR,"bss_cfg->mac_filter_mode is %d and str is %s and atoi(str) is %d\n", bss_cfg->mac_filter_mode, str, atoi(str));
    } else {
        wifi_util_error_print(WIFI_MGR,"%s:%d mac_filter_mode not found for:%s\r\n", __func__, __LINE__, recName);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), ApIsolationEnable, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->isolation = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->isolation is %d and str is %s and atoi(str) is %d\n", bss_cfg->isolation, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for isolation:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BSSTransitionActivated, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, (bool *)&bss_cfg->bssTransitionActivated);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->bssTransitionActivated is %d and str is %s\n", bss_cfg->bssTransitionActivated, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for bssTransitionActivated:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BssHotSpot, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->bssHotspot = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->bssHotspot is %d and str is %s and atoi(str) is %d\n", bss_cfg->bssHotspot, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for bssHotspot:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
#ifdef FEATURE_SUPPORT_WPS
    snprintf(recName, sizeof(recName), WpsPushButton, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->wpsPushButton = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->wpsPushButton is %d and str is %s and atoi(str) is %d\n", bss_cfg->wpsPushButton, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d str value for wpsPushButton:%s \r\n", __func__,__LINE__, str);
    }
#endif

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), RapidReconnThreshold, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->rapidReconnThreshold = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->rapidReconnThreshold is %d and str is %s and atoi(str) is %d\n", bss_cfg->rapidReconnThreshold, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for rapidReconnThreshold:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), RapidReconnCountEnable, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        bss_cfg->rapidReconnectEnable = atoi(str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->rapidReconnectEnable is %d and str is %s and atoi(str) is %d\n", bss_cfg->rapidReconnectEnable, str, atoi(str));
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for rapidReconnectEnable:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), NeighborReportActivated, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        convert_ascii_string_to_bool(str, (bool *)&bss_cfg->nbrReportActivated);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->nbrReportActivated is %d and str is %s\n", bss_cfg->nbrReportActivated, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for nbrReportActivated:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), ApMFPConfig, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    int security_mfp = 0;
    if (str != NULL) {
        convert_security_mode_string_to_integer((int *)&security_mfp, str);
        wifi_util_dbg_print(WIFI_MGR,"cfg->mfp is %d and str is %s\n", security_mfp, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for mfp:%s \r\n", __func__, __LINE__, str);
    }

    memset(recName, 0, sizeof(recName));
    memset(strValue, 0, sizeof(strValue));
    snprintf(recName, sizeof(recName), BeaconRateCtl, instance_number);
    str = p_ccsp_desc->psm_get_value_fn(recName, strValue);
    if (str != NULL) {
        strcpy(bss_cfg->beaconRateCtl,str);
        wifi_util_dbg_print(WIFI_MGR,"bss_cfg->beaconRateCtl is %s and str is %s \r\n", bss_cfg->beaconRateCtl, str);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d str value for beaconRateCtl:%s \r\n", __func__, __LINE__, str);
    }

    ret = nvram_get_current_ssid(bss_cfg->ssid, (instance_number - 1));
    if ((ret != 0 ) && isVapPrivate(vap_config->vap_index)) {
        wifi_util_info_print(WIFI_MGR,"%s:%d nvram_get_current_ssid failed for private vapindex :%d \n", __func__, __LINE__, vap_config->vap_index);
        sleep(5);
        ret = nvram_get_current_ssid(bss_cfg->ssid, (instance_number - 1));
        wifi_util_info_print(WIFI_MGR,"%s:%d nvram_get_current_ssid ret value after sleep  :%d \n", __func__, __LINE__, ret);
    }
    nvram_get_vap_enable_status(&bss_cfg->enabled, (instance_number - 1));

    int security_mode = bss_cfg->security.mode;
    if (nvram_get_current_security_mode(&security_mode, (instance_number - 1)) == 0) {
        /* use defaults if security and mfp do not match the specs */
        if (((security_mode == wifi_security_mode_wpa3_personal) ||
             (security_mode == wifi_security_mode_enhanced_open)) &&
            (security_mfp != wifi_mfp_cfg_required)) {
            wifi_util_error_print(WIFI_MGR, "%s:%d Using default security mode 0x%x and MFP %d for %s\n", \
                                  __func__, __LINE__, bss_cfg->security.mode, bss_cfg->security.mfp, vap_config->vap_name);
        } else if ((security_mode == wifi_security_mode_wpa3_transition) && (security_mfp != wifi_mfp_cfg_optional)) {
            wifi_util_error_print(WIFI_MGR, "%s:%d Using default security mode 0x%x and MFP %d for %s\n", \
                                  __func__, __LINE__, bss_cfg->security.mode, bss_cfg->security.mfp, vap_config->vap_name);
        } else {
            bss_cfg->security.mode = security_mode;
            bss_cfg->security.mfp = security_mfp;
        }
    } else {
        wifi_util_error_print(WIFI_MGR, "%s:%d - Error getting security mode from NVRAM. Using default security mode 0x%x and mfp %d for $%s\n", __func__, __LINE__, bss_cfg->security.mode, bss_cfg->security.mfp, vap_config->vap_name);
    }

    wifi_security_modes_t mode = bss_cfg->security.mode;
    if ((mode == wifi_security_mode_wpa_enterprise) || (mode == wifi_security_mode_wpa2_enterprise ) || (mode == wifi_security_mode_wpa3_enterprise) || (mode == wifi_security_mode_wpa_wpa2_enterprise)) {
        //TBD
    } else {
        ret = nvram_get_current_password(bss_cfg->security.u.key.key, (instance_number - 1));
        if ((ret != 0 ) && isVapPrivate(vap_config->vap_index)) {
            wifi_util_info_print(WIFI_MGR,"%s:%d nvram_get_current_password failed for private vapindex :%d \n", __func__, __LINE__, vap_config->vap_index);
            sleep(5);
            ret = nvram_get_current_password(bss_cfg->security.u.key.key, (instance_number - 1));
            wifi_util_info_print(WIFI_MGR,"%s:%d nvram_get_current_password ret value after sleep  :%d \n", __func__, __LINE__, ret);
       }
    }

    if (nvram_get_mgmt_frame_power_control(vap_index, &bss_cfg->mgmtPowerControl) == RETURN_OK) {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d bss_cfg->mgmtPowerControl is %d for VAP Index %d\n", __func__, __LINE__, bss_cfg->mgmtPowerControl, vap_index);
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d wifi_hal_get_mgmt_frame_power_control(VAP_index %d) failed\n", __func__, __LINE__, vap_index);
    }

    return RETURN_OK;
}

int wifi_db_update_radio_config()
{
    wifi_radio_operationParam_t radio_cfg;
    wifi_radio_feature_param_t radio_feat_cfg;
    unsigned int radio_index;
    int retval=0;

    for(radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        memset(&radio_cfg, 0, sizeof(wifi_radio_operationParam_t));
        memset(&radio_feat_cfg, 0, sizeof(wifi_radio_feature_param_t));

        /* read values from psm and update db */
#ifndef NEWPLATFORM_PORT
        get_radio_params_from_psm(radio_index, &radio_cfg, &radio_feat_cfg);
#endif // NEWPLATFORM_PORT
        get_radio_params_from_db(radio_index, &radio_cfg);
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: %u ****success to get bandwidth value in wifi db\n",__func__, __LINE__,radio_cfg.channelWidth);

        retval = get_wifidb_obj()->desc.update_radio_cfg_fn(radio_index, &radio_cfg, &radio_feat_cfg);
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
#ifndef NEWPLATFORM_PORT
    wifi_vap_info_t vap_cfg;
    rdk_wifi_vap_info_t rdk_vap_cfg;
    int retval;
    unsigned int mac_index_list[128];
    unsigned int total_mac_list;
    char strValue[256] = {0};
    wifi_mgr_t *mgr = get_wifimgr_obj();

    memset(mac_index_list, 0, sizeof(mac_index_list));

    /* read values from psm and update db */
    for (unsigned int index = 0; index < getTotalNumberVAPs(); index++) {
        unsigned int vap_index;

        vap_index = VAP_INDEX(mgr->hal_cap, index);
        get_vap_params_from_psm(vap_index, &vap_cfg, &rdk_vap_cfg);

        if (!isVapHotspot(vap_index) && !isVapSTAMesh(vap_index)) {
            if (get_total_mac_list_from_psm((vap_index + 1), &total_mac_list, strValue) == RETURN_OK) {
                mac_list_entry_update_data(strValue, mac_index_list);
                get_psm_mac_list_entry((vap_index + 1), vap_cfg.vap_name, total_mac_list, mac_index_list);
            }
        }

        retval = get_wifidb_obj()->desc.update_wifi_vap_info_fn(vap_cfg.vap_name, &vap_cfg, &rdk_vap_cfg);
        if (retval != 0) {
            wifi_util_error_print(WIFI_MGR,"%s:%d: Failed to update vap config in wifi db\n",__func__, __LINE__);
        } else {
            wifi_util_info_print(WIFI_MGR,"%s:%d: Successfully updated vap config in wifidb \r\n",__func__, __LINE__);
        }

        if (isVapSTAMesh(vap_cfg.vap_index)) {
            retval = get_wifidb_obj()->desc.update_wifi_security_config_fn(vap_cfg.vap_name, &vap_cfg.u.sta_info.security);
        } else {
            retval = get_wifidb_obj()->desc.update_wifi_security_config_fn(vap_cfg.vap_name, &vap_cfg.u.bss_info.security);
        }
        if (retval != 0) {
            wifi_util_error_print(WIFI_MGR,"%s:%d: Failed to update vap_%s security config in wifi db\n",__func__, __LINE__, vap_cfg.vap_name);
        } else {
            wifi_util_info_print(WIFI_MGR,"%s:%d: Successfully updated security vap_%s config in wifidb \r\n",__func__, __LINE__, vap_cfg.vap_name);
        }
    }
#endif // NEWPLATFORM_PORT
    return RETURN_OK;
}

int wifi_db_update_psm_values()
{
    int retval;
    wifi_global_param_t global_config;
    memset(&global_config, 0, sizeof(global_config));

    retval = wifi_db_update_global_config(&global_config);
    wifi_util_info_print(WIFI_MGR,"%s:%d: Global config update %d\n",__func__, __LINE__,retval);

    retval = wifi_db_update_radio_config();

    wifi_util_info_print(WIFI_MGR,"%s:%d: Radio config update %d\n",__func__, __LINE__,retval);

    retval = wifi_db_update_vap_config();

    wifi_util_info_print(WIFI_MGR,"%s:%d: Vap config update %d\n",__func__, __LINE__,retval);
    return retval;
}

//static void bus_subscription_handler(bus_handle_t handle, bus_event_t *event,
static void bus_subscription_handler(char *event_name, raw_data_t *p_data, void *userData)
{
    (void)p_data;
    (void)userData;
    wifi_util_dbg_print(WIFI_MGR,"%s:%d bus_subscription_handler:%s\n", __func__, __LINE__, event_name);
}

int wifi_mgr_bus_subsription(bus_handle_t *handle)
{
    int rc;
    char *component_name = "WifiMgr";

    rc = get_bus_descriptor()->bus_open_fn(handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n",
	 __func__, __LINE__, component_name, rc);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_MGR, "%s:%d bus open success\n", __func__, __LINE__);
    if (get_bus_descriptor()->bus_event_subs_fn(handle, LAST_REBOOT_REASON_NAMESPACE,
            bus_subscription_handler, NULL, 0) != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d bus event:%s subscribe failed\n", __FUNCTION__,
            __LINE__, LAST_REBOOT_REASON_NAMESPACE);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d bus: bus event:%s subscribe success\n", __FUNCTION__,
            __LINE__, LAST_REBOOT_REASON_NAMESPACE);
    }

    return RETURN_OK;
}

int get_wifi_db_psm_enable_status(bool *wifi_psm_db_enabled)
{
    char *str = NULL;
    char strValue[256] = {0};
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(WIFI_PSM_DB_NAMESPACE, strValue);
    if (str != NULL) {
        *wifi_psm_db_enabled = atoi(str);
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
    wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;

    memset(strValue, 0, sizeof(strValue));
    str = p_ccsp_desc->psm_get_value_fn(LAST_REBOOT_REASON_NAMESPACE, strValue);
    if (str != NULL) {
        strcpy(last_reboot_reason, str);
        wifi_util_dbg_print(WIFI_MGR,"str is %s and last_reboot_reason is %s\n", str, last_reboot_reason);
    } else {
        wifi_util_error_print(WIFI_MGR,"%s:%d last_reboot_reason:%s \r\n", __func__, __LINE__, last_reboot_reason);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_all_param_from_psm_and_set_into_db(void)
{
    char inactive_firmware[64] = { 0 };
    wifi_util_info_print(WIFI_MGR, "%s \n", __func__);
    /*      check for psm-db(Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-PSM-DB.Enable) and
    **      last reboot reason(Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason)
    **      if psm-db is false and last reboot reason if not factory-reset,
    **      then update wifi-db with values from psm */
    wifi_util_info_print(WIFI_MGR, "%s \n", __func__);
    if (is_device_type_xb7() == true || is_device_type_xb8() == true ||
        is_device_type_vbvxb10() == true || is_device_type_vbvxb9() == true || is_device_type_sercommxb10() == true ||
        is_device_type_scxer10() == true || is_device_type_sr213() == true ||
        is_device_type_cmxb7() == true || is_device_type_cbr2() == true ||
        is_device_type_vbvxer5() == true || is_device_type_xle() == true) {
        bool wifi_psm_db_enabled = false;
        char last_reboot_reason[32];
        raw_data_t data;

        memset(&data, 0, sizeof(raw_data_t));
        memset(last_reboot_reason, 0, sizeof(last_reboot_reason));

        bus_handle_t handle = { 0 };
        if (wifi_mgr_bus_subsription(&handle) == RETURN_OK) {
            if (get_bus_descriptor()->bus_data_get_fn(&handle, WIFI_PSM_DB_NAMESPACE, &data) ==
                bus_error_success) {
                if (data.data_type != bus_data_type_boolean) {
                    wifi_util_error_print(WIFI_CTRL,
                        "%s:%d '%s' bus_data_get_fn failed with data_type:0x%x\n", __func__,
                        __LINE__, WIFI_PSM_DB_NAMESPACE, data.data_type);
                    return 0;
                }
                wifi_psm_db_enabled = data.raw_data.b;
                get_wifi_db_psm_enable_status(&wifi_psm_db_enabled);
            }
            memset(&data, 0, sizeof(raw_data_t));
            if (get_bus_descriptor()->bus_data_get_fn(&handle, LAST_REBOOT_REASON_NAMESPACE,
                    &data) == bus_error_success) {
                if (data.data_type != bus_data_type_string) {
                    wifi_util_error_print(WIFI_CTRL,
                        "%s:%d '%s' bus_data_get_fn failed with data_type:0x%x\n", __func__,
                        __LINE__, LAST_REBOOT_REASON_NAMESPACE, data.data_type);
                    get_bus_descriptor()->bus_data_free_fn(&data);
                    return 0;
                }
                strncpy(last_reboot_reason, (char *)data.raw_data.bytes, data.raw_data_len);
                get_bus_descriptor()->bus_data_free_fn(&data);
            }
        } else {
            get_wifi_db_psm_enable_status(&wifi_psm_db_enabled);
            get_wifi_last_reboot_reason_psm_value(last_reboot_reason);
        }

        wifi_util_info_print(WIFI_MGR, "%s psm:%d last_reboot_reason:%s \n", __func__,
            wifi_psm_db_enabled, last_reboot_reason);

        memset(&data, 0, sizeof(raw_data_t));

        if (get_bus_descriptor()->bus_data_get_fn(&handle, INACTIVE_FIRMWARE_NAMESPACE, &data) ==
            bus_error_success) {
            if (data.data_type != bus_data_type_string) {
                wifi_util_error_print(WIFI_CTRL,
                    "%s:%d '%s' bus_data_get_fn failed with data_type:0x%x\n", __func__, __LINE__,
                    LAST_REBOOT_REASON_NAMESPACE, data.data_type);
                get_bus_descriptor()->bus_data_free_fn(&data);
                return 0;
            }
            strncpy(inactive_firmware, (char *)data.raw_data.bytes,
                (sizeof(inactive_firmware) - 1));
            if (access(ONEWIFI_DB_CONSOLIDATED_FLAG, F_OK) != 0) {
                if (((strncmp(last_reboot_reason, "Software_upgrade", strlen("Software_upgrade")) ==
                         0) ||
                        (strncmp(last_reboot_reason, "Forced_Software_upgrade",
                             strlen("Forced_Software_upgrade")) == 0)) &&
                    is_db_upgrade_required(inactive_firmware)) {

                    wifi_util_info_print(WIFI_MGR, "ONEWIFI_MIGRATION_FLAG is created\n");
                }
            }
            get_bus_descriptor()->bus_data_free_fn(&data);
        }

        if ((access(ONEWIFI_MIGRATION_FLAG, F_OK) == 0)) {
            int retval;
            retval = wifi_db_update_psm_values();
            if (retval == RETURN_OK) {
                wifi_util_info_print(WIFI_MGR, "%s updated WIFI DB from psm\n", __func__);
            } else {
                wifi_util_error_print(WIFI_MGR, "%s: failed to update WIFI DB from psm\n",
                    __func__);
                return RETURN_ERR;
            }
            sleep(1);
            remove_onewifi_factory_reset_flag();
            remove_onewifi_migration_flag();
            wifi_util_info_print(WIFI_MGR, "%s FactoryReset flag removed  \n", __func__);
        }

        if (wifi_psm_db_enabled == true) {
            wifi_ccsp_desc_t *p_ccsp_desc = &get_wificcsp_obj()->desc;
            p_ccsp_desc->psm_set_value_fn(WIFI_PSM_DB_NAMESPACE, "false");
        }
        if ((strncmp(last_reboot_reason, "factory-reset", strlen("factory-reset")) == 0) ||
            (strncmp(last_reboot_reason, "WPS-Factory-Reset", strlen("WPS-Factory-Reset")) == 0) ||
            (strncmp(last_reboot_reason, "CM_variant_change", strlen("CM_variant_change")) == 0)) {
            create_onewifi_factory_reset_flag();
            create_onewifi_factory_reset_reboot_flag();
            wifi_util_info_print(WIFI_MGR, "%s FactoryReset is done \n", __func__);
        }
    }

    get_wifidb_obj()->desc.init_data_fn();

    // Set Wifi Global Parameters
    init_wifi_global_config();

    wifi_util_info_print(WIFI_MGR, "%s Done\n", __func__);
    return RETURN_OK;
}
#endif //ONEWIFI_DB_SUPPORT
