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
#if DML_SUPPORT
#include "wifi_monitor.h"
#include "plugin_main_apis.h"
#endif // DML_SUPPORT
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#if DML_SUPPORT
#include <sysevent/sysevent.h>
#endif // DML_SUPPORT
#include <cJSON.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "cJSON.h"
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
#include "wifi_ctrl.h"
#include "wifi_util.h"
#include "wifi_mgr.h"
#if DML_SUPPORT
#include "ssp_loop.h"
#else
#include <opensync/ow_sta_security.h>
#endif // DML_SUPPORT

#define MAX_BUF_SIZE 128
#define ONEWIFI_DB_VERSION_EXISTS_FLAG 100017
#define ONEWIFI_DB_OLD_VERSION_FILE "/tmp/wifi_db_old_version"

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
#if DML_SUPPORT
ovsdb_table_t table_Wifi_Rfc_Config;
#endif // DML_SUPPORT

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
#if DML_SUPPORT
/************************************************************************************
 ************************************************************************************
  Function    : callback_Wifi_Rfc_Config
  Parameter   : mon     - Type of modification
                old_rec - schema_Wifi_Rfc_Config  holds value before modification
                new_rec - schema_Wifi_Rfc_Config  holds value after modification
  Description : Callback function called when Wifi_Rfc_Config modified in wifidb
 *************************************************************************************
 *************************************************************************************/
void callback_Wifi_Rfc_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Rfc_Config *old_rec,
        struct schema_Wifi_Rfc_Config *new_rec)
{
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();

    if (mon->mon_type == OVSDB_UPDATE_DEL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__); 
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY)) {
     
        wifi_util_dbg_print(WIFI_DB,"%s:%d:RFC Config New/Modify \n", __func__, __LINE__);
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        strcpy(rfc_param->rfc_id,new_rec->rfc_id);
        rfc_param->wifipasspoint_rfc = new_rec->wifipasspoint_rfc;
        rfc_param->wifiinterworking_rfc =  new_rec->wifiinterworking_rfc;
        rfc_param->radiusgreylist_rfc = new_rec->radiusgreylist_rfc;
        rfc_param->dfsatbootup_rfc = new_rec->dfsatbootup_rfc;
        rfc_param->dfs_rfc = new_rec->dfs_rfc;
        rfc_param->wpa3_rfc  = new_rec->wpa3_rfc;
        rfc_param->ow_core_thread_rfc  = new_rec->ow_core_thread_rfc;
        rfc_param->twoG80211axEnable_rfc  = new_rec->twoG80211axEnable_rfc;
        rfc_param->hotspot_open_2g_last_enabled  = new_rec->hotspot_open_2g_last_enabled;
        rfc_param->hotspot_open_5g_last_enabled  = new_rec->hotspot_open_5g_last_enabled;
        rfc_param->hotspot_secure_2g_last_enabled  = new_rec->hotspot_secure_2g_last_enabled;
        rfc_param->hotspot_secure_5g_last_enabled  = new_rec->hotspot_secure_5g_last_enabled;
        rfc_param->mgmt_frame_rbus_enabled_rfc =  new_rec->mgmt_frame_rbus_enabled_rfc;

        wifi_util_dbg_print(WIFI_DB,"%s:%d wifipasspoint_rfc=%d wifiinterworking_rfc=%d radiusgreylist_rfc=%d dfsatbootup_rfc=%d dfs_rfc=%d wpa3_rfc=%d ow_core_thread_rfc=%d twoG80211axEnable_rfc=%d hotspot_open_2g_last_enabled=%d hotspot_open_5g_last_enabled=%d hotspot_secure_2g_last_enabled=%d hotspot_secure_2g_last_enabled=%d mgmt_frame_rbus_enabled_rfc=%d rfc_id=%s\n", __func__, __LINE__,rfc_param->wifipasspoint_rfc,rfc_param->wifiinterworking_rfc,rfc_param->radiusgreylist_rfc,rfc_param->dfsatbootup_rfc, rfc_param->dfs_rfc ,rfc_param->wpa3_rfc,rfc_param->ow_core_thread_rfc,rfc_param->twoG80211axEnable_rfc,rfc_param->hotspot_open_2g_last_enabled,rfc_param->hotspot_open_5g_last_enabled,rfc_param->hotspot_secure_2g_last_enabled,rfc_param->hotspot_secure_5g_last_enabled,rfc_param->mgmt_frame_rbus_enabled_rfc,rfc_param->rfc_id);
       pthread_mutex_unlock(&g_wifidb->data_cache_lock);

	}
}
#endif // DML_SUPPORT
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
#if DML_SUPPORT
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();
#endif // DML_SUPPORT

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

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
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalide get_wifidb_radio_map \n",__func__, __LINE__,index);
            return ;
        }
        wifidb_init_radio_config_default(index, l_radio_cfg);
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
         wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalide radio index, Data not fount \n",__func__, __LINE__,index);
         return ;
        }
        l_radio_cfg = get_wifidb_radio_map(index);
        if(l_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalide get_wifidb_radio_map \n",__func__, __LINE__,index);
            return ;
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
#if DML_SUPPORT
        l_radio_cfg->DfsEnabledBootup = rfc_param->dfsatbootup_rfc;
#endif // DML_SUPPORT
        l_radio_cfg->dtimPeriod = new_rec->dtim_period;
        if (new_rec->beacon_interval != 0) {
            l_radio_cfg->beaconInterval = new_rec->beacon_interval;
        }
        l_radio_cfg->operatingClass = new_rec->operating_class;
        l_radio_cfg->basicDataTransmitRates = new_rec->basic_data_transmit_rate;
        l_radio_cfg->operationalDataTransmitRates = new_rec->operational_data_transmit_rate;
        l_radio_cfg->fragmentationThreshold = new_rec->fragmentation_threshold;
        l_radio_cfg->guardInterval = new_rec->guard_interval;
        l_radio_cfg->transmitPower = new_rec->transmit_power;
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d OperatingEnviroment=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d, radio_stats_measuring_rate = %d, radio_stats_measuring_interval = %d, cts_protection %d, obss_coex= %d, stbc_enable= %d, greenfield_enable= %d, user_control= %d, admin_control= %d,chan_util_threshold= %d, chan_util_selfheal_enable= %d, eco_power_down= %d \n",__func__, __LINE__,l_radio_cfg->enable,l_radio_cfg->band,l_radio_cfg->autoChannelEnabled,l_radio_cfg->channel,l_radio_cfg->channelWidth,l_radio_cfg->variant,l_radio_cfg->csa_beacon_count,l_radio_cfg->countryCode,l_radio_cfg->operatingEnvironment,l_radio_cfg->DCSEnabled,l_radio_cfg->numSecondaryChannels,new_rec->secondary_channels_list,l_radio_cfg->dtimPeriod,l_radio_cfg->beaconInterval,l_radio_cfg->operatingClass,l_radio_cfg->basicDataTransmitRates,l_radio_cfg->operationalDataTransmitRates,l_radio_cfg->fragmentationThreshold,l_radio_cfg->guardInterval,l_radio_cfg->transmitPower,l_radio_cfg->rtsThreshold,l_radio_cfg->factoryResetSsid,l_radio_cfg->radioStatsMeasuringInterval,l_radio_cfg->radioStatsMeasuringInterval,l_radio_cfg->ctsProtection,l_radio_cfg->obssCoex,l_radio_cfg->stbcEnable,l_radio_cfg->greenFieldEnable,l_radio_cfg->userControl,l_radio_cfg->adminControl,l_radio_cfg->chanUtilThreshold,l_radio_cfg->chanUtilSelfHealEnable, l_radio_cfg->EcoPowerDown);
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

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

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
                return;
            }
        } else {
            l_security_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(i);
            if(l_security_cfg == NULL)
            {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid Get_wifi_object_bss_security_parameter \n",__func__, __LINE__,old_rec->vap_name);
                return;
            }
        }
        memset(l_security_cfg, 0, sizeof(wifi_vap_security_t));
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(&g_wifidb->hal_cap.wifi_prop, old_rec->vap_name);
        if(vap_index == -1)
        {
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
        }

        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        l_security_cfg->mode = new_rec->security_mode;
        l_security_cfg->encr = new_rec->encryption_method;

        convert_security_mode_string_to_integer((int *)&l_security_cfg->mfp,(char *)&new_rec->mfp_config);
        l_security_cfg->rekey_interval = new_rec->rekey_interval;
        l_security_cfg->strict_rekey = new_rec->strict_rekey;
        l_security_cfg->eapol_key_timeout = new_rec->eapol_key_timeout;
        l_security_cfg->eapol_key_retries = new_rec->eapol_key_retries;
        l_security_cfg->eap_identity_req_timeout = new_rec->eap_identity_req_timeout;
        l_security_cfg->eap_identity_req_retries = new_rec->eap_identity_req_retries;
        l_security_cfg->eap_req_timeout = new_rec->eap_req_timeout;
        l_security_cfg->eap_req_retries = new_rec->eap_req_retries;
        l_security_cfg->disable_pmksa_caching = new_rec->disable_pmksa_caching;
        if ((!security_mode_support_radius(l_security_cfg->mode)) && (!isVapHotspotOpen(i))) 
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d r_ser_key=%s rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d rs_ser_key=%s mfg=%s cfg_key_type=%d keyphrase=%s vap_name=%s rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,new_rec->security_mode,new_rec->encryption_method,new_rec->radius_server_ip,new_rec->radius_server_port,new_rec->radius_server_key,new_rec->secondary_radius_server_ip,new_rec->secondary_radius_server_port,new_rec->secondary_radius_server_key,new_rec->mfp_config,new_rec->key_type,new_rec->keyphrase,new_rec->vap_name,new_rec->rekey_interval,new_rec->strict_rekey,new_rec->eapol_key_timeout,new_rec->eapol_key_retries,new_rec->eap_identity_req_timeout,new_rec->eap_identity_req_retries,new_rec->eap_req_timeout,new_rec->eap_req_retries,new_rec->disable_pmksa_caching,new_rec->max_auth_attempts,new_rec->blacklist_table_timeout,new_rec->identity_req_retry_interval,new_rec->server_retries,new_rec->das_ip,new_rec->das_port,new_rec->das_key);
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

        l_rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
        if (l_rdk_vap_info == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: Failed to get rdk vap info for index %d\n",
                __func__, __LINE__, vap_index);
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        l_rdk_vap_info->exists = new_rec->exists;
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);

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
            if (strlen(new_rec->bridge_name) != 0){
                strncpy(l_vap_param_cfg->bridge_name, new_rec->bridge_name,(sizeof(l_vap_param_cfg->bridge_name)-1));
            } else {
                get_vap_interface_bridge_name(vap_index, l_vap_param_cfg->bridge_name);
            }
            l_bss_param_cfg->wmmNoAck = new_rec->wmm_noack;
            l_bss_param_cfg->wepKeyLength = new_rec->wep_key_length;
            l_bss_param_cfg->bssHotspot = new_rec->bss_hotspot;
            l_bss_param_cfg->wpsPushButton = new_rec->wps_push_button;
            l_bss_param_cfg->wps.methods = new_rec->wps_config_methods;
            l_bss_param_cfg->wps.enable = new_rec->wps_enabled;
            if (strlen(new_rec->beacon_rate_ctl) != 0) {
                strncpy(l_bss_param_cfg->beaconRateCtl, new_rec->beacon_rate_ctl,(sizeof(l_bss_param_cfg->beaconRateCtl)-1));
            }

            wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config radio_name=%s vap_name=%s ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  mac_addr_acl_enabled =%d wmm_enabled=%d anqp_parameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d wps_config_methods = %d wps_enabled = %d beacon_rate_ctl =%s mfp_config = %s  network_initiated_greylist = %d exists=%d\n",__func__, __LINE__,new_rec->radio_name,new_rec->vap_name,new_rec->ssid,new_rec->enabled,new_rec->ssid_advertisement_enabled,new_rec->isolation_enabled,new_rec->mgmt_power_control,new_rec->bss_max_sta,new_rec->bss_transition_activated,new_rec->nbr_report_activated,new_rec->rapid_connect_enabled,new_rec->rapid_connect_threshold,new_rec->vap_stats_enable,new_rec->mac_filter_enabled,new_rec->mac_filter_mode,new_rec->mac_addr_acl_enabled,new_rec->wmm_enabled,new_rec->anqp_parameters,new_rec->hs2_parameters,new_rec->uapsd_enabled,new_rec->beacon_rate,new_rec->bridge_name,new_rec->wmm_noack, new_rec->wep_key_length, new_rec->bss_hotspot,new_rec->wps_push_button, new_rec->wps_config_methods, new_rec->wps_enabled, new_rec->beacon_rate_ctl, new_rec->mfp_config, new_rec->network_initiated_greylist, new_rec->exists);
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
        g_wifidb->global_config.global_parameters.vlan_cfg_version = new_rec->vlan_cfg_version;
        if (strlen(new_rec->wps_pin) != 0) {
            strncpy(g_wifidb->global_config.global_parameters.wps_pin,new_rec->wps_pin,sizeof(g_wifidb->global_config.global_parameters.wps_pin)-1);
        } else {
            strcpy(g_wifidb->global_config.global_parameters.wps_pin, DEFAULT_WPS_PIN);
        }
        g_wifidb->global_config.global_parameters.bandsteering_enable = new_rec->bandsteering_enable;
        g_wifidb->global_config.global_parameters.good_rssi_threshold = new_rec->good_rssi_threshold;
        g_wifidb->global_config.global_parameters.assoc_count_threshold = new_rec->assoc_count_threshold;
        g_wifidb->global_config.global_parameters.assoc_gate_time = new_rec->assoc_gate_time;
        g_wifidb->global_config.global_parameters.assoc_monitor_duration = new_rec->assoc_monitor_duration;
        g_wifidb->global_config.global_parameters.rapid_reconnect_enable = new_rec->rapid_reconnect_enable;
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d  notify_wifi_changes %d  prefer_private %d  prefer_private_configure %d  factory_reset %d  tx_overflow_selfheal %d  inst_wifi_client_enabled %d  inst_wifi_client_reporting_period %d  inst_wifi_client_mac = %s inst_wifi_client_def_reporting_period %d  wifi_active_msmt_enabled %d  wifi_active_msmt_pktsize %d  wifi_active_msmt_num_samples %d  wifi_active_msmt_sample_duration %d  vlan_cfg_version %d  wps_pin = %s bandsteering_enable %d  good_rssi_threshold %d  assoc_count_threshold %d  assoc_gate_time %d  assoc_monitor_duration %d  rapid_reconnect_enable %d  vap_stats_feature %d  mfp_config_feature %d  force_disable_radio_feature %d  force_disable_radio_status %d  fixed_wmm_params %d  wifi_region_code %s diagnostic_enable %d  validate_ssid %d device_network_mode:%d normalized_rssi_list %s snr_list %s cli_stat_list %s txrx_rate_list %s\r\n", __func__, __LINE__, new_rec->notify_wifi_changes,new_rec->prefer_private,new_rec->prefer_private_configure,new_rec->factory_reset,new_rec->tx_overflow_selfheal,new_rec->inst_wifi_client_enabled,new_rec->inst_wifi_client_reporting_period,new_rec->inst_wifi_client_mac, new_rec->inst_wifi_client_def_reporting_period,new_rec->wifi_active_msmt_enabled,new_rec->wifi_active_msmt_pktsize,new_rec->wifi_active_msmt_num_samples,new_rec->wifi_active_msmt_sample_duration,new_rec->vlan_cfg_version,new_rec->wps_pin, new_rec->bandsteering_enable,new_rec->good_rssi_threshold,new_rec->assoc_count_threshold,new_rec->assoc_gate_time,new_rec->assoc_monitor_duration,new_rec->rapid_reconnect_enable,new_rec->vap_stats_feature,new_rec->mfp_config_feature,new_rec->force_disable_radio_feature,new_rec->force_disable_radio_status,new_rec->fixed_wmm_params,new_rec->wifi_region_code,new_rec->diagnostic_enable,new_rec->validate_ssid, new_rec->device_network_mode, new_rec->normalized_rssi_list, new_rec->snr_list, new_rec->cli_stat_list, new_rec->txrx_rate_list);
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

#if DML_SUPPORT
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
    cfg.ow_core_thread_rfc = rfc_param->ow_core_thread_rfc;
    cfg.twoG80211axEnable_rfc = rfc_param->twoG80211axEnable_rfc;
    cfg.hotspot_open_2g_last_enabled = rfc_param->hotspot_open_2g_last_enabled;
    cfg.hotspot_open_5g_last_enabled = rfc_param->hotspot_open_5g_last_enabled;
    cfg.hotspot_open_6g_last_enabled = rfc_param->hotspot_open_6g_last_enabled;
    cfg.hotspot_secure_2g_last_enabled = rfc_param->hotspot_secure_2g_last_enabled;
    cfg.hotspot_secure_5g_last_enabled = rfc_param->hotspot_secure_5g_last_enabled;
    cfg.hotspot_secure_6g_last_enabled = rfc_param->hotspot_secure_6g_last_enabled;
    cfg.mgmt_frame_rbus_enabled_rfc = rfc_param->mgmt_frame_rbus_enabled_rfc;

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
#endif // DML_SUPPORT

#if DML_SUPPORT
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
    rfc_info->ow_core_thread_rfc = pcfg->ow_core_thread_rfc;
    rfc_info->twoG80211axEnable_rfc = pcfg->twoG80211axEnable_rfc;
    rfc_info->hotspot_open_2g_last_enabled= pcfg->hotspot_open_2g_last_enabled;
    rfc_info->hotspot_open_5g_last_enabled= pcfg->hotspot_open_5g_last_enabled;
    rfc_info->hotspot_open_6g_last_enabled= pcfg->hotspot_open_6g_last_enabled;
    rfc_info->hotspot_secure_2g_last_enabled= pcfg->hotspot_secure_2g_last_enabled;
    rfc_info->hotspot_secure_2g_last_enabled= pcfg->hotspot_secure_5g_last_enabled;
    rfc_info->hotspot_secure_6g_last_enabled= pcfg->hotspot_secure_6g_last_enabled;
    rfc_info->mgmt_frame_rbus_enabled_rfc = pcfg->mgmt_frame_rbus_enabled_rfc;
    free(pcfg);
    return 0;
}
#endif // DML_SUPPORT

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
  Description : update wifi_radio_operationParam_t structure to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config)
{
    struct schema_Wifi_Radio_Config cfg;
    char name[BUFFER_LENGTH_WIFIDB] = {0};
    char *insert_filter[] = {"-",SCHEMA_COLUMN(Wifi_Radio_Config,vap_configs),NULL};
    unsigned int i = 0;
    int k = 0;
    int len = 0;
    char channel_list[BUFFER_LENGTH_WIFIDB] = {0};
    len = sizeof(channel_list)-1;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    memset(&cfg,0,sizeof(cfg));
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Update Radio Config for radio_index=%d \n",__func__, __LINE__,radio_index);
    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifidb_print("%s:%d Failed to update Radio Config for radio_index %d \n",__func__, __LINE__,radio_index);
        return -1;
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

    for(i=0;i<(config->numSecondaryChannels);i++)
    {
        if(k >= (len-1))
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi_Radio_Config table Maximum size reached for secondary_channels_list\n",__func__, __LINE__);
            break;
        }
        snprintf(channel_list+k,sizeof(channel_list)-k,"%d,",config->channelSecondary[i]);
        wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi_Radio_Config table Channel list %s %d\t",__func__, __LINE__,channel_list,strlen(channel_list));
        k = strlen(channel_list);
    }
    strncpy(cfg.secondary_channels_list,channel_list,sizeof(cfg.secondary_channels_list)-1);
    cfg.num_secondary_channels = config->numSecondaryChannels;
    strncpy(cfg.radio_name,name,sizeof(cfg.radio_name)-1);

    wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d  radio_stats_measuring_rate = %d   radio_stats_measuring_interval = %d cts_protection = %d obss_coex = %d  stbc_enable = %d  greenfield_enable = %d user_control = %d  admin_control = %d  chan_util_threshold = %d  chan_util_selfheal_enable = %d  eco_power_down = %d\n",__func__, __LINE__,config->enable,config->band,config->autoChannelEnabled,config->channel,config->channelWidth,config->variant,config->csa_beacon_count,config->countryCode,config->DCSEnabled,config->numSecondaryChannels,cfg.secondary_channels_list,config->dtimPeriod,config->beaconInterval,config->operatingClass,config->basicDataTransmitRates,config->operationalDataTransmitRates,config->fragmentationThreshold,config->guardInterval,config->transmitPower,config->rtsThreshold,config->factoryResetSsid,config->radioStatsMeasuringRate,config->radioStatsMeasuringInterval,config->ctsProtection,config->obssCoex,config->stbcEnable,config->greenFieldEnable,config->userControl,config->adminControl,config->chanUtilThreshold,config->chanUtilSelfHealEnable,config->EcoPowerDown);
    if(onewifi_ovsdb_table_upsert_f(g_wifidb->wifidb_sock_path,&table_Wifi_Radio_Config,&cfg,false,insert_filter) == false)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to insert Wifi_Radio_Config table \n",__func__, __LINE__);
        return -1;
    }
    else
    {
        wifidb_print("%s:%d Updated WIFI DB. Insert Wifi_Radio_Config table completed successful. \n",__func__, __LINE__);
#if DML_SUPPORT
        push_data_to_ssp_queue(config, sizeof(wifi_radio_operationParam_t), ssp_event_type_psm_write, radio_config);
#endif // DML_SUPPORT
    }

    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_wifi_radio_config
  Parameter   : radio_index - Radio index
                config      - wifi_radio_operationParam_t to be updated from wifidb
  Description : Get wifi_radio_operationParam_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config)
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
#if DML_SUPPORT
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();
#endif // DML_SUPPORT

    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifidb_print("%s:%d Failed to Get Radio Config \n",__func__, __LINE__);
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
        config->channel = cfg->channel;
        config->channelWidth = cfg->channel_width;
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
#if DML_SUPPORT
    config->DfsEnabledBootup = rfc_param->dfsatbootup_rfc;
#endif // DML_SUPPORT
    config->dtimPeriod = cfg->dtim_period;
    if (cfg->beacon_interval != 0) {
        config->beaconInterval = cfg->beacon_interval;
    }
    config->operatingClass = cfg->operating_class;
    config->basicDataTransmitRates = cfg->basic_data_transmit_rate;
    config->operationalDataTransmitRates = cfg->operational_data_transmit_rate;
    config->fragmentationThreshold = cfg->fragmentation_threshold;
    config->guardInterval = cfg->guard_interval;
    config->transmitPower = cfg->transmit_power;
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

    wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d operatingEnvironment=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d, radio_stats_measuring_rate = %d, radio_stats_measuring_interval = %d, cts_protection %d, obss_coex= %d, stbc_enable= %d, greenfield_enable= %d, user_control= %d, admin_control= %d,chan_util_threshold= %d, chan_util_selfheal_enable= %d, eco_power_down=%d \n",__func__, __LINE__,config->enable,config->band,config->autoChannelEnabled,config->channel,config->channelWidth,config->variant,config->csa_beacon_count,config->countryCode,config->operatingEnvironment,config->DCSEnabled,config->numSecondaryChannels,cfg->secondary_channels_list,config->dtimPeriod,config->beaconInterval,config->operatingClass,config->basicDataTransmitRates,config->operationalDataTransmitRates,config->fragmentationThreshold,config->guardInterval,config->transmitPower,config->rtsThreshold,config->factoryResetSsid,config->radioStatsMeasuringInterval,config->radioStatsMeasuringInterval,config->ctsProtection,config->obssCoex,config->stbcEnable,config->greenFieldEnable,config->userControl,config->adminControl,config->chanUtilThreshold,config->chanUtilSelfHealEnable, config->EcoPowerDown);
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
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s vap_name is invalid\n",__func__, __LINE__,vap_name);
                continue;
            }
            config->vap_array[vap_index].radio_index = radio_index;
            l_vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
            if (l_vap_index < 0) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s vap_name is invalid\n",__func__, __LINE__,vap_name);
                continue;
            }
            config->vap_array[vap_index].vap_index = l_vap_index;
            wifidb_get_wifi_vap_info(vap_name,&config->vap_array[vap_index],&rdk_config[vap_index]);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %svap name vap_index=%d radio_ondex=%d\n",__func__, __LINE__,vap_name,vap_index,radio_index);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_VAP_Config verify count=%d\n",__func__, __LINE__,vap_count);
            wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config Row=%d radio_name=%s radioindex=%d vap_name=%s vap_index=%d ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  wmm_enabled=%d anqpParameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d wps_config_methods=%d wps_enabled = %d beacon_rate_ctl =%s network_initiated_greylist=%d exists=%d\n",__func__, __LINE__,i,name,config->vap_array[vap_index].radio_index,config->vap_array[vap_index].vap_name,config->vap_array[vap_index].vap_index,config->vap_array[vap_index].u.bss_info.ssid,config->vap_array[vap_index].u.bss_info.enabled,config->vap_array[vap_index].u.bss_info.showSsid ,config->vap_array[vap_index].u.bss_info.isolation,config->vap_array[vap_index].u.bss_info.mgmtPowerControl,config->vap_array[vap_index].u.bss_info.bssMaxSta,config->vap_array[vap_index].u.bss_info.bssTransitionActivated,config->vap_array[vap_index].u.bss_info.nbrReportActivated,config->vap_array[vap_index].u.bss_info.rapidReconnectEnable,config->vap_array[vap_index].u.bss_info.rapidReconnThreshold,config->vap_array[vap_index].u.bss_info.vapStatsEnable,config->vap_array[vap_index].u.bss_info.mac_filter_enable,config->vap_array[vap_index].u.bss_info.mac_filter_mode,config->vap_array[vap_index].u.bss_info.wmm_enabled,config->vap_array[vap_index].u.bss_info.interworking.anqp.anqpParameters,config->vap_array[vap_index].u.bss_info.interworking.passpoint.hs2Parameters,config->vap_array[vap_index].u.bss_info.UAPSDEnabled,config->vap_array[vap_index].u.bss_info.beaconRate,config->vap_array[vap_index].bridge_name,config->vap_array[vap_index].u.bss_info.wmmNoAck,config->vap_array[vap_index].u.bss_info.wepKeyLength,config->vap_array[vap_index].u.bss_info.bssHotspot,config->vap_array[vap_index].u.bss_info.wpsPushButton, config->vap_array[vap_index].u.bss_info.wps.methods, config->vap_array[vap_index].u.bss_info.wps.enable, config->vap_array[vap_index].u.bss_info.beaconRateCtl, config->vap_array[vap_index].u.bss_info.network_initiated_greylist, rdk_config[vap_index].exists);

            wifidb_get_interworking_config(vap_name,&config->vap_array[vap_index].u.bss_info.interworking.interworking);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Interworking_Config table vap_name=%s Enable=%d accessNetworkType=%d internetAvailable=%d asra=%d esr=%d uesa=%d hess_present=%d hessid=%s venueGroup=%d venueType=%d \n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.bss_info.interworking.interworking.interworkingEnabled,config->vap_array[vap_index].u.bss_info.interworking.interworking.accessNetworkType,config->vap_array[vap_index].u.bss_info.interworking.interworking.internetAvailable,config->vap_array[vap_index].u.bss_info.interworking.interworking.asra,config->vap_array[vap_index].u.bss_info.interworking.interworking.esr,config->vap_array[vap_index].u.bss_info.interworking.interworking.uesa,config->vap_array[vap_index].u.bss_info.interworking.interworking.hessOptionPresent,config->vap_array[vap_index].u.bss_info.interworking.interworking.hessid,config->vap_array[vap_index].u.bss_info.interworking.interworking.venueGroup,config->vap_array[vap_index].u.bss_info.interworking.interworking.venueType);


            if (isVapSTAMesh(l_vap_index)) {
                wifidb_get_wifi_security_config(vap_name,&config->vap_array[vap_index].u.sta_info.security);

                if ((!security_mode_support_radius(config->vap_array[vap_index].u.sta_info.security.mode))) {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table sec type=%d  sec key=%s \n",__func__, __LINE__,config->vap_array[vap_index].u.sta_info.security.u.key.type,config->vap_array[vap_index].u.sta_info.security.u.key.key,config->vap_array[vap_index].u.sta_info.security.u.key.type,config->vap_array[vap_index].u.sta_info.security.u.key.key);
                } else {
                    getIpStringFromAdrress(address,&config->vap_array[vap_index].u.sta_info.security.u.radius.dasip);
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table radius server ip =%s  port =%d sec key=%s Secondary radius server ip=%s port=%d key=%s max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,config->vap_array[vap_index].u.sta_info.security.u.radius.ip,config->vap_array[vap_index].u.sta_info.security.u.radius.port,config->vap_array[vap_index].u.sta_info.security.u.radius.key,config->vap_array[vap_index].u.sta_info.security.u.radius.s_ip,config->vap_array[vap_index].u.sta_info.security.u.radius.s_port,config->vap_array[vap_index].u.sta_info.security.u.radius.s_key,config->vap_array[vap_index].u.sta_info.security.u.radius.max_auth_attempts,config->vap_array[vap_index].u.sta_info.security.u.radius.blacklist_table_timeout,config->vap_array[vap_index].u.sta_info.security.u.radius.identity_req_retry_interval,config->vap_array[vap_index].u.sta_info.security.u.radius.server_retries,address,config->vap_array[vap_index].u.sta_info.security.u.radius.dasport,config->vap_array[vap_index].u.sta_info.security.u.radius.daskey);
                }
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table vap_name=%s Sec_mode=%d enc_mode=%d mfg_config=%d rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d \n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.sta_info.security.mode,config->vap_array[vap_index].u.sta_info.security.encr,config->vap_array[vap_index].u.sta_info.security.mfp,config->vap_array[vap_index].u.sta_info.security.rekey_interval,config->vap_array[vap_index].u.sta_info.security.strict_rekey,config->vap_array[vap_index].u.sta_info.security.eapol_key_timeout,config->vap_array[vap_index].u.sta_info.security.eapol_key_retries,config->vap_array[vap_index].u.sta_info.security.eap_identity_req_timeout,config->vap_array[vap_index].u.sta_info.security.eap_identity_req_retries,config->vap_array[vap_index].u.sta_info.security.eap_req_timeout,config->vap_array[vap_index].u.sta_info.security.eap_req_retries,config->vap_array[vap_index].u.sta_info.security.disable_pmksa_caching);
            } else {
                wifidb_get_wifi_security_config(vap_name,&config->vap_array[vap_index].u.bss_info.security);

                if ((!security_mode_support_radius(config->vap_array[vap_index].u.bss_info.security.mode))&& (!isVapHotspotOpen(vap_index))) {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table sec type=%d  sec key=%s \n",__func__, __LINE__,config->vap_array[vap_index].u.bss_info.security.u.key.type,config->vap_array[vap_index].u.bss_info.security.u.key.key,config->vap_array[vap_index].u.bss_info.security.u.key.type,config->vap_array[vap_index].u.bss_info.security.u.key.key);
                } else {
                    getIpStringFromAdrress(address,&config->vap_array[vap_index].u.bss_info.security.u.radius.dasip);
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table radius server ip =%s  port =%d sec key=%s Secondary radius server ip=%s port=%d key=%s max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,config->vap_array[vap_index].u.bss_info.security.u.radius.ip,config->vap_array[vap_index].u.bss_info.security.u.radius.port,config->vap_array[vap_index].u.bss_info.security.u.radius.key,config->vap_array[vap_index].u.bss_info.security.u.radius.s_ip,config->vap_array[vap_index].u.bss_info.security.u.radius.s_port,config->vap_array[vap_index].u.bss_info.security.u.radius.s_key,config->vap_array[vap_index].u.bss_info.security.u.radius.max_auth_attempts,config->vap_array[vap_index].u.bss_info.security.u.radius.blacklist_table_timeout,config->vap_array[vap_index].u.bss_info.security.u.radius.identity_req_retry_interval,config->vap_array[vap_index].u.bss_info.security.u.radius.server_retries,address,config->vap_array[vap_index].u.bss_info.security.u.radius.dasport,config->vap_array[vap_index].u.bss_info.security.u.radius.daskey);
                }
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table vap_name=%s Sec_mode=%d enc_mode=%d mfg_config=%d rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d \n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.bss_info.security.mode,config->vap_array[vap_index].u.bss_info.security.encr,config->vap_array[vap_index].u.bss_info.security.mfp,config->vap_array[vap_index].u.bss_info.security.rekey_interval,config->vap_array[vap_index].u.bss_info.security.strict_rekey,config->vap_array[vap_index].u.bss_info.security.eapol_key_timeout,config->vap_array[vap_index].u.bss_info.security.eapol_key_retries,config->vap_array[vap_index].u.bss_info.security.eap_identity_req_timeout,config->vap_array[vap_index].u.bss_info.security.eap_identity_req_retries,config->vap_array[vap_index].u.bss_info.security.eap_req_timeout,config->vap_array[vap_index].u.bss_info.security.eap_req_retries,config->vap_array[vap_index].u.bss_info.security.disable_pmksa_caching);
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
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

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
    
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d r_ser_key=%s rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d rs_ser_key=%s mfg=%s cfg_key_type=%d keyphrase=%s vap_name=%s rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,pcfg->security_mode,pcfg->encryption_method,pcfg->radius_server_ip,pcfg->radius_server_port,pcfg->radius_server_key,pcfg->secondary_radius_server_ip,pcfg->secondary_radius_server_port,pcfg->secondary_radius_server_key,pcfg->mfp_config,pcfg->key_type,pcfg->keyphrase,pcfg->vap_name,pcfg->rekey_interval,pcfg->strict_rekey,pcfg->eapol_key_timeout,pcfg->eapol_key_retries,pcfg->eap_identity_req_timeout,pcfg->eap_identity_req_retries,pcfg->eap_req_timeout,pcfg->eap_req_retries,pcfg->disable_pmksa_caching,pcfg->max_auth_attempts,pcfg->blacklist_table_timeout,pcfg->identity_req_retry_interval,pcfg->server_retries,pcfg->das_ip,pcfg->das_port,pcfg->das_key);
    
    if ((band == WIFI_FREQUENCY_6_BAND)  && (pcfg->security_mode != wifi_security_mode_wpa3_personal && \
      pcfg->security_mode != wifi_security_mode_wpa3_enterprise &&  pcfg->security_mode != wifi_security_mode_enhanced_open)) {
        sec->mode = wifi_security_mode_wpa3_personal;
        sec->encr = wifi_encryption_aes;
        wifi_util_error_print(WIFI_DB, "%s:%d Invalid Security mode for 6G %d\n", __func__, __LINE__, pcfg->security_mode);
    } else {
        sec->mode = pcfg->security_mode;
        sec->encr = pcfg->encryption_method;
    }

    convert_security_mode_string_to_integer((int *)&sec->mfp,(char *)&pcfg->mfp_config);
    if ((sec->mode == wifi_security_mode_wpa3_transition) && (sec->mfp != wifi_mfp_cfg_optional)) {
        wifi_util_error_print(WIFI_DB, "%s:%d Invalid MFP Config\n", __func__, __LINE__);
        sec->mfp = wifi_mfp_cfg_optional;
    } else if (((sec->mode == wifi_security_mode_wpa3_enterprise) || (sec->mode == wifi_security_mode_wpa3_personal)) && (sec->mfp != wifi_mfp_cfg_required)) {
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
    if ((!security_mode_support_radius(sec->mode)) && (!isVapHotspotOpen(vap_index))) {
        sec->u.key.type = pcfg->key_type;
        strncpy(sec->u.key.key,pcfg->keyphrase,sizeof(sec->u.key.key)-1);
    }
    else {
        if (strlen(pcfg->radius_server_ip) != 0) {
            strncpy((char *)sec->u.radius.ip,pcfg->radius_server_ip,sizeof(sec->u.radius.ip)-1);
        }
        sec->u.radius.port = pcfg->radius_server_port;
        if (strlen(pcfg->radius_server_key) != 0) {
            strncpy(sec->u.radius.key,pcfg->radius_server_key,sizeof(sec->u.radius.key)-1);
        }
        if (strlen(pcfg->secondary_radius_server_ip) != 0) {
            strncpy((char *)sec->u.radius.s_ip,pcfg->secondary_radius_server_ip,sizeof(sec->u.radius.s_ip)-1);
        }
        sec->u.radius.s_port = pcfg->secondary_radius_server_port;
        if (strlen(pcfg->secondary_radius_server_key) != 0) {
            strncpy(sec->u.radius.s_key,pcfg->secondary_radius_server_key,sizeof(sec->u.radius.s_key)-1);
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

        wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config radio_name=%s vap_name=%s ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  mac_addr_acl_enabled =%d wmm_enabled=%d anqp_parameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d wps_config_methods=%d wps_enabled = %d beacon_rate_ctl =%s network_initiated_greylist=%d \n",__func__, __LINE__,pcfg->radio_name,pcfg->vap_name,pcfg->ssid,pcfg->enabled,pcfg->ssid_advertisement_enabled,pcfg->isolation_enabled,pcfg->mgmt_power_control,pcfg->bss_max_sta,pcfg->bss_transition_activated,pcfg->nbr_report_activated,pcfg->rapid_connect_enabled,pcfg->rapid_connect_threshold,pcfg->vap_stats_enable,pcfg->mac_filter_enabled,pcfg->mac_filter_mode,pcfg->mac_addr_acl_enabled,pcfg->wmm_enabled,pcfg->anqp_parameters,pcfg->hs2_parameters,pcfg->uapsd_enabled,pcfg->beacon_rate,pcfg->bridge_name,pcfg->wmm_noack,pcfg->wep_key_length,pcfg->bss_hotspot,pcfg->wps_push_button, pcfg->wps_config_methods, pcfg->wps_enabled, pcfg->beacon_rate_ctl, pcfg->network_initiated_greylist);


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
        if (strlen(pcfg->bridge_name) != 0) {
            strncpy(config->bridge_name, pcfg->bridge_name,(sizeof(config->bridge_name)-1));
        } else {
            get_vap_interface_bridge_name(config->vap_index, config->bridge_name);
        }

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
            config->u.bss_info.wpsPushButton = pcfg->wps_push_button;
            config->u.bss_info.wps.methods = pcfg->wps_config_methods;
            config->u.bss_info.wps.enable = pcfg->wps_enabled;
            if (strlen(pcfg->beacon_rate_ctl) != 0) {
                strncpy(config->u.bss_info.beaconRateCtl, pcfg->beacon_rate_ctl,(sizeof(config->u.bss_info.beaconRateCtl)-1));
            }
        }
    }
    free(pcfg);
    return RETURN_OK;
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
    wifi_security_psm_param_t psm_security_cfg;
    memset(&psm_security_cfg, 0, sizeof(psm_security_cfg));
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

    if ((!security_mode_support_radius(sec->mode)) && (!isVapHotspotOpen(vap_index)))
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
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Update table_Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d r_ser_key=%s rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d rs_ser_key=%s mfg=%s cfg_key_type=%d cfg_sec_keyphrase=%s cfg_vap_name=%s rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,cfg_sec.security_mode,cfg_sec.encryption_method,cfg_sec.radius_server_ip,cfg_sec.radius_server_port,cfg_sec.radius_server_key,cfg_sec.secondary_radius_server_ip,cfg_sec.secondary_radius_server_port,cfg_sec.secondary_radius_server_key,cfg_sec.mfp_config,cfg_sec.key_type,cfg_sec.keyphrase,cfg_sec.vap_name,cfg_sec.rekey_interval,cfg_sec.strict_rekey,cfg_sec.eapol_key_timeout,cfg_sec.eapol_key_retries,cfg_sec.eap_identity_req_timeout,cfg_sec.eap_identity_req_retries,cfg_sec.eap_req_timeout,cfg_sec.eap_req_retries,cfg_sec.disable_pmksa_caching,cfg_sec.max_auth_attempts,cfg_sec.blacklist_table_timeout,cfg_sec.identity_req_retry_interval,cfg_sec.server_retries,cfg_sec.das_ip,cfg_sec.das_port,cfg_sec.das_key);

    if(onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_Security_Config,&cfg_sec,false,filter_vapsec,SCHEMA_TABLE(Wifi_VAP_Config),onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name),vap_name),SCHEMA_COLUMN(Wifi_VAP_Config,security)) == false)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi Security Config table\n",__func__, __LINE__);
    }
    else
    {
#if DML_SUPPORT
        wifidb_print("%s:%d Updated WIFI DB. Wifi Security Config table updated successful. \n",__func__, __LINE__);
        psm_security_cfg.vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
        strncpy(psm_security_cfg.mfp, cfg_sec.mfp_config, sizeof(psm_security_cfg.mfp)-1);
        push_data_to_ssp_queue(&psm_security_cfg, sizeof(wifi_security_psm_param_t), ssp_event_type_psm_write, security_config);
#endif // DML_SUPPORT
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
#if DML_SUPPORT
        push_data_to_ssp_queue(&l_mac_entry, sizeof(l_mac_entry), ssp_event_type_psm_write, mac_config_delete);
#endif // DML_SUPPORT

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
#if DML_SUPPORT
        push_data_to_ssp_queue(&l_mac_entry, sizeof(l_mac_entry), ssp_event_type_psm_write, mac_config_add);
#endif // DML_SUPPORT
        if (onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path, &table_Wifi_MacFilter_Config, &cfg_mac, false, filter_mac, SCHEMA_TABLE(Wifi_VAP_Config), onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name), vap_name), SCHEMA_COLUMN(Wifi_VAP_Config, mac_filter)) ==  false) {
            wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Wifi_MacFilter Config table \n",__func__, __LINE__);
        }
        else {
            wifidb_print("%s:%d Updated WIFI DB. Wifi_MacFilter Config table updated successful\n",__func__, __LINE__);
        }
    }

    return 0;
}


extern const char* get_passpoint_json_by_vap_name(const char* vap_name);
extern const char* get_anqp_json_by_vap_name(const char* vap_name);
extern void reset_passpoint_json(const char* vap_name);
extern void reset_anqp_json(const char* vap_name);

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
    strncpy(cfg.bridge_name, config->bridge_name,(sizeof(cfg.bridge_name)-1));
    l_vap_index = convert_vap_name_to_index(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, config->vap_name);
    if (l_vap_index < 0) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Unable to get vap index for vap_name %s\n", __func__, __LINE__, config->vap_name);
            return RETURN_ERR;
    }

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
        cfg.wps_push_button = config->u.bss_info.wpsPushButton;
        cfg.wps_config_methods = config->u.bss_info.wps.methods;
        cfg.wps_enabled = config->u.bss_info.wps.enable;
        strncpy(cfg.beacon_rate_ctl,config->u.bss_info.beaconRateCtl,sizeof(cfg.beacon_rate_ctl)-1);
        strncpy(cfg.mfp_config,"Disabled",sizeof(cfg.mfp_config)-1);

        wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config update data cfg.radio_name=%s cfg.radio_name=%s cfg.ssid=%s cfg.enabled=%d cfg.advertisement=%d cfg.isolation_enabled=%d cfg.mgmt_power_control=%d cfg.bss_max_sta =%d cfg.bss_transition_activated=%d cfg.nbr_report_activated=%d cfg.rapid_connect_enabled=%d cfg.rapid_connect_threshold=%d cfg.vap_stats_enable=%d cfg.mac_filter_enabled =%d cfg.mac_filter_mode=%d cfg.wmm_enabled=%d anqp_parameters=%s hs2_parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s cfg.wmm_noack = %d cfg.wep_key_length = %d   cfg.bss_hotspot =  %d cfg.wps_push_button =  %d cfg.wps_config_methods=%d cfg.wps_enabled=%d cfg.beacon_rate_ctl = %s cfg.mfp_config =%s network_initiated_greylist=%d exists=%d\n",__func__, __LINE__,cfg.radio_name,cfg.vap_name,cfg.ssid,cfg.enabled,cfg.ssid_advertisement_enabled,cfg.isolation_enabled,cfg.mgmt_power_control,cfg.bss_max_sta,cfg.bss_transition_activated,cfg.nbr_report_activated,cfg.rapid_connect_enabled,cfg.rapid_connect_threshold,cfg.vap_stats_enable,cfg.mac_filter_enabled,cfg.mac_filter_mode,cfg.wmm_enabled,cfg.anqp_parameters,cfg.hs2_parameters,cfg.uapsd_enabled,cfg.beacon_rate,cfg.bridge_name,cfg.wmm_noack, cfg.wep_key_length, cfg.bss_hotspot, cfg.wps_push_button, cfg.wps_config_methods, cfg.wps_enabled, cfg.beacon_rate_ctl, cfg.mfp_config, cfg.network_initiated_greylist, cfg.exists);
    }
    if(onewifi_ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_VAP_Config,&cfg,false,filter_vap,SCHEMA_TABLE(Wifi_Radio_Config),(onewifi_ovsdb_where_simple(SCHEMA_COLUMN(Wifi_Radio_Config,radio_name),radio_name)),SCHEMA_COLUMN(Wifi_Radio_Config,vap_configs)) == false)
    {
      wifidb_print("%s:%d WIFI DB update error !!!. Failed to update table_Wifi_VAP_Config table\n",__func__, __LINE__);
    }
    else
    {
        wifidb_print("%s:%d Updated WIFI DB. table_Wifi_VAP_Config table updated successful\n",__func__, __LINE__);
#if DML_SUPPORT
        push_data_to_ssp_queue(config, sizeof(wifi_vap_info_t), ssp_event_type_psm_write, vap_config);
#endif // DML_SUPPORT
    }
    return RETURN_OK;
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
    cfg.vlan_cfg_version = config->vlan_cfg_version;
    strncpy(cfg.wps_pin,config->wps_pin,sizeof(cfg.wps_pin)-1);
    cfg.bandsteering_enable = config->bandsteering_enable;
    cfg.good_rssi_threshold = config->good_rssi_threshold;
    cfg.assoc_count_threshold = config->assoc_count_threshold;
    cfg.assoc_gate_time = config->assoc_gate_time;
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

#if DML_SUPPORT
    push_data_to_ssp_queue(config, sizeof(wifi_global_param_t), ssp_event_type_psm_write, global_config);
#endif // DML_SUPPORT
    wifi_util_dbg_print(WIFI_DB,"\n %s:%d  notify_wifi_changes %d  prefer_private %d  prefer_private_configure %d  factory_reset %d  tx_overflow_selfheal %d  inst_wifi_client_enabled %d  inst_wifi_client_reporting_period %d  inst_wifi_client_mac = %s inst_wifi_client_def_reporting_period %d  wifi_active_msmt_enabled %d  wifi_active_msmt_pktsize %d  wifi_active_msmt_num_samples %d  wifi_active_msmt_sample_duration %d  vlan_cfg_version %d  wps_pin = %s bandsteering_enable %d  good_rssi_threshold %d  assoc_count_threshold %d  assoc_gate_time %d  assoc_monitor_duration %d  rapid_reconnect_enable %d  vap_stats_feature %d  mfp_config_feature %d  force_disable_radio_feature %d  force_disable_radio_status %d  fixed_wmm_params %d  wifi_region_code %s diagnostic_enable %d  validate_ssid %d device_network_mode:%d normalized_rssi_list %s snr_list %s cli_stat_list %s txrx_rate_list %s\r\n", __func__, __LINE__, config->notify_wifi_changes,config->prefer_private,config->prefer_private_configure,config->factory_reset,config->tx_overflow_selfheal,config->inst_wifi_client_enabled,config->inst_wifi_client_reporting_period,config->inst_wifi_client_mac, config->inst_wifi_client_def_reporting_period,config->wifi_active_msmt_enabled,config->wifi_active_msmt_pktsize,config->wifi_active_msmt_num_samples,config->wifi_active_msmt_sample_duration,config->vlan_cfg_version,config->wps_pin, config->bandsteering_enable,config->good_rssi_threshold,config->assoc_count_threshold,config->assoc_gate_time,config->assoc_monitor_duration,config->rapid_reconnect_enable,config->vap_stats_feature,config->mfp_config_feature,config->force_disable_radio_feature,config->force_disable_radio_status,config->fixed_wmm_params,config->wifi_region_code,config->diagnostic_enable,config->validate_ssid, config->device_network_mode,config->normalized_rssi_list,config->snr_list,config->cli_stat_list,config->txrx_rate_list);

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
        if (strlen(pcfg->wps_pin) != 0) {
            strncpy(config->wps_pin,pcfg->wps_pin,sizeof(config->wps_pin)-1);
        } else {
            strcpy(config->wps_pin, DEFAULT_WPS_PIN);
        }
        config->bandsteering_enable = pcfg->bandsteering_enable;
        config->good_rssi_threshold = pcfg->good_rssi_threshold;
        config->assoc_count_threshold = pcfg->assoc_count_threshold;
        config->assoc_gate_time = pcfg->assoc_gate_time;
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

        wifi_util_dbg_print(WIFI_DB,"%s:%d  notify_wifi_changes %d  prefer_private %d  prefer_private_configure %d  factory_reset %d  tx_overflow_selfheal %d  inst_wifi_client_enabled %d  inst_wifi_client_reporting_period %d  inst_wifi_client_mac = %s inst_wifi_client_def_reporting_period %d  wifi_active_msmt_enabled %d  wifi_active_msmt_pktsize %d  wifi_active_msmt_num_samples %d  wifi_active_msmt_sample_duration %d  vlan_cfg_version %d  wps_pin = %s bandsteering_enable %d  good_rssi_threshold %d  assoc_count_threshold %d  assoc_gate_time %d  assoc_monitor_duration %d  rapid_reconnect_enable %d  vap_stats_feature %d  mfp_config_feature %d  force_disable_radio_feature %d  force_disable_radio_status %d  fixed_wmm_params %d  wifi_region_code %s diagnostic_enable %d  validate_ssid %d device_network_mode:%d normalized_rssi_list %s snr list %s txrx_rate_list %s cli_stat_list %s\r\n", __func__, __LINE__, config->notify_wifi_changes,config->prefer_private,config->prefer_private_configure,config->factory_reset,config->tx_overflow_selfheal,config->inst_wifi_client_enabled,config->inst_wifi_client_reporting_period,config->inst_wifi_client_mac, config->inst_wifi_client_def_reporting_period,config->wifi_active_msmt_enabled,config->wifi_active_msmt_pktsize,config->wifi_active_msmt_num_samples,config->wifi_active_msmt_sample_duration,config->vlan_cfg_version,config->wps_pin, config->bandsteering_enable,config->good_rssi_threshold,config->assoc_count_threshold,config->assoc_gate_time,config->assoc_monitor_duration,config->rapid_reconnect_enable,config->vap_stats_feature,config->mfp_config_feature,config->force_disable_radio_feature,config->force_disable_radio_status,config->fixed_wmm_params,config->wifi_region_code,config->diagnostic_enable,config->validate_ssid, config->device_network_mode,config->normalized_rssi_list, config->snr_list, config->txrx_rate_list, config->cli_stat_list);

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
  Function    : update_wifi_interworking_config
  Parameter   : vap_name - Name of vap
                config   - Update wifi_InterworkingElement_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_interworking_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_interworking_config(char *vap_name, wifi_InterworkingElement_t *config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update interworking Config - Null pointer \n",__func__, __LINE__);
        return -1;
    }    
    ret = wifidb_update_wifi_interworking_config(vap_name,config);
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
                config      - Update wifi_radio_operationParam_t to wifidb
  Description : Wrapper API for wifidb_update_wifi_radio_config
 *************************************************************************************
**************************************************************************************/
int update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifidb_print("%s:%d WIFI DB update error !!!. Failed to update Radio Config - Null pointer \n",__func__, __LINE__);
        return -1;
    } 
    ret = wifidb_update_wifi_radio_config(radio_index,config);
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
  Function    : get_wifi_radio_config
  Parameter   : radio_index - Index of radio
                config      - wifi_radio_operationParam_t will be updated from Global cache
  Description : Get wifi_radio_operationParam_t from Global cache
 *************************************************************************************
**************************************************************************************/
int get_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config)
{
    int ret = 0;
    wifi_mgr_t *g_wifidb;
    wifi_radio_operationParam_t *l_radio_cfg = NULL;

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get Radio Config failed \n",__func__, __LINE__);
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
    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config, l_radio_cfg, sizeof(wifi_radio_operationParam_t));
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

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_radio_config_default
  Parameter   : radio_index - Index of radio
  Description : Update global cache with default value for wifi_radio_operationParam_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_radio_config_default(int radio_index,wifi_radio_operationParam_t *config)
{
    int band;
    char country_code[4] = {0};
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_radio_operationParam_t cfg;
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
            cfg.op_class = 12;
            cfg.channel = 1;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
            cfg.variant = WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N;
            break;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
            cfg.op_class = 1;
#if defined (_PP203X_PRODUCT_REQ_)
            cfg.beaconInterval = 200;
#endif 
            cfg.channel = 44;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
#if defined (_PP203X_PRODUCT_REQ_)
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC;
#else
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX;
#endif
            break;
        case WIFI_FREQUENCY_5H_BAND:
            cfg.op_class = 3;
            cfg.channel = 157;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
#if defined (_PP203X_PRODUCT_REQ_)
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC;
            cfg.beaconInterval = 200;
#else
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX;
#endif
            break;
        case WIFI_FREQUENCY_6_BAND:
            cfg.op_class = 131;
            cfg.channel = 197;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_160MHZ;
            cfg.variant = WIFI_80211_VARIANT_AX;
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
    cfg.csa_beacon_count = 100;
    cfg.countryCode = wifi_countrycode_US;
    if (wifi_hal_get_default_country_code(country_code) < 0) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: unable to get default country code setting a US\n", __func__, __LINE__);
    } else {
        if (country_code_conversion(&cfg.countryCode, country_code, sizeof(country_code), STRING_TO_ENUM) < 0) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: unable to convert country string\n", __func__, __LINE__);
        }
    }
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
    cfg.stbcEnable = false;
    cfg.greenFieldEnable = false;
    cfg.userControl = 0;
    cfg.adminControl = 0;
    cfg.chanUtilThreshold = 90;
    cfg.chanUtilSelfHealEnable = 0;
    cfg.EcoPowerDown = false;
    cfg.factoryResetSsid = 0;
    cfg.basicDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_24MBPS;
    cfg.operationalDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_18MBPS | WIFI_BITRATE_24MBPS | WIFI_BITRATE_36MBPS | WIFI_BITRATE_48MBPS | WIFI_BITRATE_54MBPS;
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
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
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();
    unsigned int vap_array_index;
    unsigned int found = 0;
    wifi_vap_info_t cfg;
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};
    char wps_pin[128] = {0};
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d: vap_index %d, not found\n",__func__, __LINE__, vap_index);
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
            cfg.u.sta_info.security.wpa3_transition_disable = true;
            cfg.u.sta_info.security.mfp = wifi_mfp_cfg_required;
            cfg.u.sta_info.security.u.key.type = wifi_security_key_type_sae;
        } else {
            cfg.u.sta_info.security.mfp = wifi_mfp_cfg_disabled;
            cfg.u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
        }
        cfg.u.sta_info.security.encr = wifi_encryption_aes;
        cfg.u.sta_info.enabled = false;
        cfg.u.sta_info.scan_params.period = 10;
        memset(ssid, 0, sizeof(ssid));
#ifdef CCSP_WIFI_HAL
        if (wifi_hal_get_default_ssid(ssid, vap_index) == 0) {
#else
        if (ow_sta_security_default_ssid_get(ssid,vap_index,sizeof(ssid)) == 0) {
#endif
            strcpy(cfg.u.sta_info.ssid, ssid);
        } else {
            strcpy(cfg.u.sta_info.ssid, vap_name);
        }
        memset(password, 0, sizeof(password));
#ifdef CCSP_WIFI_HAL
        if (wifi_hal_get_default_keypassphrase(password,vap_index) == 0) {
#else 
        if (ow_sta_security_default_keypassphrase_get(password,vap_index,sizeof(password)) == 0) {
#endif
            strcpy(cfg.u.sta_info.security.u.key.key, password);
        } else {
            strcpy(cfg.u.sta_info.security.u.key.key, INVALID_KEY);
        }
        
        cfg.u.bss_info.bssMaxSta = 75;
        cfg.u.sta_info.scan_params.channel.band =band;

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
                cfg.u.sta_info.scan_params.channel.channel = 197;
                break;
            default:
                wifi_util_error_print(WIFI_DB,"%s:%d invalid band %d\n", __func__, __LINE__, band);
                break;
        }

        cfg.u.sta_info.conn_status = wifi_connection_status_disabled;
        memset(&cfg.u.sta_info.bssid, 0, sizeof(cfg.u.sta_info.bssid));
    } else {
        cfg.u.bss_info.wmm_enabled = true;
        if (isVapHotspot(vap_index)) {
            cfg.u.bss_info.isolation  = 1;
        } else {
            cfg.u.bss_info.isolation  = 0;
        }
        cfg.u.bss_info.bssTransitionActivated = false;
        cfg.u.bss_info.nbrReportActivated = false;
        cfg.u.bss_info.network_initiated_greylist = false;
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.vapStatsEnable = true;
            cfg.u.bss_info.wpsPushButton = 0;
            cfg.u.bss_info.wps.enable = true;
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
                cfg.u.bss_info.security.encr = wifi_encryption_none;
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
                cfg.u.bss_info.security.wpa3_transition_disable = true;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_required;
                cfg.u.bss_info.security.u.key.type = wifi_security_key_type_sae;
            } else {
#if defined(_XB8_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_)
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
        } else  {
            if (band == WIFI_FREQUENCY_6_BAND) {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                cfg.u.bss_info.security.wpa3_transition_disable = true;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_required;
                cfg.u.bss_info.security.u.key.type = wifi_security_key_type_sae;
            } else {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            }
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
            cfg.u.bss_info.bssHotspot = false;
        }
        cfg.u.bss_info.beaconRate = WIFI_BITRATE_6MBPS;
        strncpy(cfg.u.bss_info.beaconRateCtl,"6Mbps",sizeof(cfg.u.bss_info.beaconRateCtl)-1);
        cfg.vap_mode = wifi_vap_mode_ap;
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.showSsid = true;
            cfg.u.bss_info.wps.methods = WIFI_ONBOARDINGMETHODS_PUSHBUTTON;
            memset(wps_pin, 0, sizeof(wps_pin));
            if (wifi_hal_get_default_wps_pin(wps_pin) == RETURN_OK) {
                strcpy(cfg.u.bss_info.wps.pin, wps_pin);
            } else {
                strcpy(cfg.u.bss_info.wps.pin, "12345678");
            }
        }
        else if (isVapHotspot(vap_index)) {
            cfg.u.bss_info.showSsid = true;
        } else {
            cfg.u.bss_info.showSsid = false;
        }
        if ((vap_index == 2) || isVapLnf(vap_index) || isVapPrivate(vap_index)) {
             cfg.u.bss_info.enabled = true;
        }
#if defined(_SKY_HUB_COMMON_PRODUCT_REQ_)
        if (isVapXhs(vap_index)) {
            cfg.u.bss_info.enabled = false;
        }
        cfg.u.bss_info.bssMaxSta = 64;
#else
        cfg.u.bss_info.bssMaxSta = 75;
#endif
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
                wifi_util_dbg_print(WIFI_DB,"radius_key %s\n",radius_key);
                strcpy(cfg.u.bss_info.security.u.radius.key, radius_key);
                strcpy(cfg.u.bss_info.security.u.radius.s_key, radius_key);
            }
            else {
                strcpy(cfg.u.bss_info.security.u.radius.key, INVALID_KEY);
                strcpy(cfg.u.bss_info.security.u.radius.s_key, INVALID_KEY);
            }
            memset(cfg.u.bss_info.security.u.radius.ip,0,sizeof(cfg.u.bss_info.security.u.radius.ip));
            strncpy((char *)cfg.u.bss_info.security.u.radius.ip, "192.168.106.254",sizeof(cfg.u.bss_info.security.u.radius.ip));
            cfg.u.bss_info.security.u.radius.s_port = 1812;
            memset(cfg.u.bss_info.security.u.radius.s_ip,0,sizeof(cfg.u.bss_info.security.u.radius.s_ip));
            strncpy((char *)cfg.u.bss_info.security.u.radius.s_ip, "192.168.106.254",sizeof(cfg.u.bss_info.security.u.radius.s_ip));
            wifi_util_dbg_print(WIFI_DB,"Primary Ip and Secondry Ip: %s , %s\n", (char *)cfg.u.bss_info.security.u.radius.ip, (char *)cfg.u.bss_info.security.u.radius.s_ip);
        }

        char str[600] = {0};
        snprintf(str,sizeof(str),"%s"," { \"ANQP\":{ \"IPAddressTypeAvailabilityANQPElement\":{ \"IPv6AddressType\":0, \"IPv4AddressType\":0}, \"DomainANQPElement\":{\"DomainName\":[]}, \"NAIRealmANQPElement\":{\"Realm\":[]}, \"3GPPCellularANQPElement\":{ \"GUD\":0, \"PLMN\":[]}, \"RoamingConsortiumANQPElement\": { \"OI\": []}, \"VenueNameANQPElement\": { \"VenueInfo\": []}}}");
        snprintf((char *)cfg.u.bss_info.interworking.anqp.anqpParameters,sizeof(cfg.u.bss_info.interworking.anqp.anqpParameters),"%s",str);
        memset(str,0,sizeof(str));
        snprintf(str,sizeof(str),"%s","{ \"Passpoint\":{ \"PasspointEnable\":false, \"NAIHomeRealmANQPElement\":{\"Realms\":[]}, \"OperatorFriendlyNameANQPElement\":{\"Name\":[]}, \"ConnectionCapabilityListANQPElement\":{\"ProtoPort\":[]}, \"GroupAddressedForwardingDisable\":true, \"P2pCrossConnectionDisable\":false}}");
        snprintf((char *)cfg.u.bss_info.interworking.passpoint.hs2Parameters,sizeof(cfg.u.bss_info.interworking.passpoint.hs2Parameters),"%s",str);

#if defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_PP203X_PRODUCT_REQ_)
        //Disabling all vaps except STA Vaps by default in XLE
        cfg.u.bss_info.enabled = false;
        exists = false;
#endif //_WNXL11BWL_PRODUCT_REQ_ , _PP203X_PRODUCT_REQ_
    }

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
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
    char temp[8], tempBuf[MAX_BUF_SIZE];
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
    cfg.assoc_monitor_duration = 0;
    cfg.rapid_reconnect_enable = true;
    cfg.vap_stats_feature =  true;
    cfg.mfp_config_feature = false;
    cfg.force_disable_radio_feature = false;
    cfg.force_disable_radio_status = false;
    cfg.fixed_wmm_params = 3;
    memset(temp, 0, 8);
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
    memset(temp, '\0', 8);
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
  Function    : wifidb_init_interworking_config_default
  Parameter   : vap_index - Index of vap
  Description : Update global cache with default value for wifi_InterworkingElement_t
 *************************************************************************************
********************************************** ****************************************/
int wifidb_init_interworking_config_default(int vapIndex,wifi_InterworkingElement_t *config)
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

#if DML_SUPPORT
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
#if defined(_XB8_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_)
    rfc_config.wpa3_rfc = true;
#else
    rfc_config.wpa3_rfc = false;
#endif
    rfc_config.ow_core_thread_rfc = false;
    rfc_config.twoG80211axEnable_rfc = false;
    rfc_config.hotspot_open_2g_last_enabled = false;
    rfc_config.hotspot_open_5g_last_enabled = false;
    rfc_config.hotspot_secure_2g_last_enabled = false;
    rfc_config.hotspot_secure_5g_last_enabled = false;
    rfc_config.mgmt_frame_rbus_enabled_rfc = false;

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&rfc_config,sizeof(wifi_rfc_dml_parameters_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

}
#endif

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
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;
    mac_address_t temp_mac_address[MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO];
    int l_vap_index = 0;

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifi_util_dbg_print(WIFI_DB,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return ;
    }

    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    for (r_index = 0; r_index < num_radio; r_index++)
    {
        l_radio_cfg = get_wifidb_radio_map(r_index);
        if(l_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalide get_wifidb_radio_map \n",__func__, __LINE__,index);
            return ;
        }
        l_vap_param_cfg = get_wifidb_vap_map(r_index);
        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_parameters \n",__func__, __LINE__);
            return ;
        }
        memset(l_radio_cfg, 0, sizeof(wifi_radio_operationParam_t));

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
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %d invalide get_wifidb_radio_map \n",__func__, __LINE__,index);
            return ;
        }
        wifidb_init_radio_config_default(r_index, l_radio_cfg);
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
#if DML_SUPPORT
    wifidb_init_rfc_config_default(&g_wifidb->rfc_dml_parameters);
#endif
    wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi db update completed\n",__func__, __LINE__);

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
  Function    : init_wifidb_data
  Parameter   : void
  Description : Init global cache with wifidb persistant data
 *************************************************************************************
********************************************** ****************************************/
void init_wifidb_data()
{
    static bool db_param_init = false;
    if (db_param_init == true) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d db params already initialized\r\n",__func__, __LINE__);
        return;
    }

    int r_index = 0;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    int num_radio = getNumberRadios();
    rdk_wifi_vap_info_t *l_rdk_vap_param_cfg;
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;
    wifi_radio_operationParam_t *l_radio_cfg = NULL;
#if DML_SUPPORT
    wifi_rfc_dml_parameters_t *rfc_param = get_wifi_db_rfc_parameters();
#endif // DML_SUPPORT

    wifi_util_dbg_print(WIFI_DB,"%s:%d No of radios %d\n",__func__, __LINE__,getNumberRadios());

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifi_util_dbg_print(WIFI_DB,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return ;
    }
    wifidb_init_default_value();
#if DML_SUPPORT
    if (wifidb_get_rfc_config(0,rfc_param) != 0) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Error getting RFC config\n",__func__, __LINE__);
    }
#endif // DML_SUPPORT
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    for (r_index = 0; r_index < num_radio; r_index++)
    {
        l_vap_param_cfg = get_wifidb_vap_map(r_index);
        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: invalid get_wifidb_vap_map \n",__func__, __LINE__);
            return;
        }
        l_rdk_vap_param_cfg = get_wifidb_rdk_vaps(r_index);
        if (l_rdk_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: invalid get_wifidb_rdk_vaps \n",__func__, __LINE__);
            return;
        }
        l_radio_cfg = get_wifidb_radio_map(r_index);
        if(l_radio_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: invalid get_wifidb_radio_map \n",__func__, __LINE__);
            return;
        }
        wifidb_get_wifi_radio_config(r_index, l_radio_cfg);
        if (wifidb_get_wifi_vap_config(r_index, l_vap_param_cfg, l_rdk_vap_param_cfg) == -1) {
            wifidb_print("%s:%d wifidb_get_wifi_vap_config failed\n",__func__, __LINE__);
            wifidb_update_wifi_vap_config(r_index, l_vap_param_cfg, l_rdk_vap_param_cfg);
        }

        wifidb_vap_config_upgrade(l_vap_param_cfg, l_rdk_vap_param_cfg);
        wifidb_vap_config_ext(l_vap_param_cfg, l_rdk_vap_param_cfg);
    }
    wifidb_get_wifi_macfilter_config();
    wifidb_get_wifi_global_config(&g_wifidb->global_config.global_parameters);
    wifidb_get_gas_config(g_wifidb->global_config.gas_config.AdvertisementID,&g_wifidb->global_config.gas_config);
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi data init complete\n",__func__, __LINE__);
    db_param_init = true;
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
        g_wifidb = (wifi_db_t*) get_wifidb_obj();
	ev_run(g_wifidb->wifidb_ev_loop, 0);
	return NULL;
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
#if DML_SUPPORT
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Rfc_Config, true);
#endif // DML_SUPPORT
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Global_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Passpoint_Config, true);
    ONEWIFI_OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Anqp_Config, true);
    return 0;
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
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_GAS_Config, advertisement_id);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_VAP_Config, vap_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Radio_Config, radio_name);
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_MacFilter_Config, macfilter_key);
#if DML_SUPPORT
    ONEWIFI_OVSDB_TABLE_INIT(Wifi_Rfc_Config, rfc_id);
#endif // DML_SUPPORT
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
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    g_wifidb->is_db_update_required = false;

    wifiDbDir = opendir(WIFIDB_DIR);
    if(wifiDbDir){
        closedir(wifiDbDir);
    }else if(ENOENT == errno){
        if(0 != mkdir(WIFIDB_DIR, 0777)){
            wifi_util_dbg_print(WIFI_DB,"Failed to Create WIFIDB directory.\n");
            return NULL;
        }
    }else{
        wifi_util_dbg_print(WIFI_DB,"Error opening Db Configuration directory. Setting Default\n");
        return NULL;
    }
    //create a copy of ovs-db server
    sprintf(cmd, "cp /usr/sbin/ovsdb-server %s/wifidb-server", WIFIDB_RUN_DIR);
    system(cmd);
    sprintf(db_file, "%s/rdkb-wifi.db", WIFIDB_DIR);
    if (stat(db_file, &sb) != 0) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Could not find rdkb database, ..creating\n", __func__, __LINE__);
        sprintf(cmd, "ovsdb-tool create %s %s/rdkb-wifi.ovsschema", db_file, WIFIDB_SCHEMA_DIR);
        system(cmd);
    } else {
        /*check for db-version of the db file. If db-version is less than than the OneWiFi Schema db version, then
         * Delete the exisiting schema file and create it. So that OneWiFi will update the configuration based on
         * PSM and NVRAM values
         * */

        wifi_util_dbg_print(WIFI_DB,"%s:%d: rdkb database already present\n", __func__, __LINE__);
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "ovsdb-tool db-version %s", db_file);
        /*Get the Existing db-version*/
        fp = popen(cmd,"r");
        if(fp != NULL) {
            while (fgets(version_str, sizeof(version_str), fp) != NULL){
                wifi_util_dbg_print(WIFI_DB,"%s:%d: DB Version before upgrade found\n", __func__, __LINE__);
            }
            pclose(fp);
            for(i=0;version_str[i];i++) {
                if ((version_str[i]!='.') && (isdigit(version_str[i]))) {
                    version_int=version_int*10+(version_str[i]-'0');
                }
            }
            wifi_util_dbg_print(WIFI_DB,"%s:%d:DB Version before upgrade %d\n", __func__, __LINE__, version_int);
            g_wifidb->db_version = version_int;

            if (version_int < ONEWIFI_SCHEMA_DEF_VERSION) {
                /*version less than OneWiFi default version
                 * so, Delete the db file and re-create the schema file
                 */
                if (remove(db_file) == 0) {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: %s file deleted succesfully\n", __func__, __LINE__, db_file);
                }
                wifi_util_dbg_print(WIFI_DB,"%s:%d: creating the new DB file\n", __func__, __LINE__);
                sprintf(cmd, "ovsdb-tool create %s %s/rdkb-wifi.ovsschema", db_file, WIFIDB_SCHEMA_DIR);
                system(cmd);
                g_wifidb->is_db_update_required = true;
            }
        }

        if (g_wifidb->is_db_update_required == false) {
            sprintf(cmd,"ovsdb-tool convert %s %s/rdkb-wifi.ovsschema",db_file,WIFIDB_SCHEMA_DIR);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: rdkb database check for version upgrade/downgrade %s \n", __func__, __LINE__,cmd);
            system(cmd);
        }
    }

    sprintf(cmd, "%s/wifidb-server %s --remote=punix:%s/wifidb.sock %s --unixctl=%s/wifi.ctl --log-file=/dev/null --detach", WIFIDB_RUN_DIR, db_file, WIFIDB_RUN_DIR, (debug_option == true)?"--verbose=dbg":"", WIFIDB_RUN_DIR);

    system(cmd);
    return NULL;
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

