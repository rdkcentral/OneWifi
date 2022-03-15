#include "wifi_data_plane.h"
#include "wifi_monitor.h"
#include "plugin_main_apis.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#include "ansc_status.h"
#include <sysevent/sysevent.h>
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

ovsdb_table_t table_Wifi_Radio_Config;
ovsdb_table_t table_Wifi_VAP_Config;
ovsdb_table_t table_Wifi_Security_Config;
ovsdb_table_t table_Wifi_Device_Config;
ovsdb_table_t table_Wifi_Interworking_Config;
ovsdb_table_t table_Wifi_GAS_Config;
ovsdb_table_t table_Wifi_Global_Config;
ovsdb_table_t table_Wifi_MacFilter_Config;

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
    char *tmp, *ptr;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_radio_operationParam_t *l_radio_cfg = NULL;

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        if(old_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Radio config update failed \n",__func__, __LINE__);
            return;
        }
        if((convert_radio_name_to_index(&index,old_rec->radio_name))!=0)
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
        if((convert_radio_name_to_index(&index,new_rec->radio_name))!=0)
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
        l_radio_cfg->band = new_rec->freq_band;
        l_radio_cfg->autoChannelEnabled = new_rec->auto_channel_enabled;
        l_radio_cfg->channel = new_rec->channel;
        l_radio_cfg->channelWidth = new_rec->channel_width;
        l_radio_cfg->variant = new_rec->hw_mode;
        l_radio_cfg->csa_beacon_count = new_rec->csa_beacon_count;
        l_radio_cfg->countryCode = new_rec->country;
        l_radio_cfg->DCSEnabled = new_rec->dcs_enabled;
        l_radio_cfg->dtimPeriod = new_rec->dtim_period;
        l_radio_cfg->beaconInterval = new_rec->beacon_interval;
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d, radio_stats_measuring_rate = %d, radio_stats_measuring_interval = %d, cts_protection %d, obss_coex= %d, stbc_enable= %d, greenfield_enable= %d, user_control= %d, admin_control= %d,chan_util_threshold= %d, chan_util_selfheal_enable= %d \n",__func__, __LINE__,l_radio_cfg->enable,l_radio_cfg->band,l_radio_cfg->autoChannelEnabled,l_radio_cfg->channel,l_radio_cfg->channelWidth,l_radio_cfg->variant,l_radio_cfg->csa_beacon_count,l_radio_cfg->countryCode,l_radio_cfg->DCSEnabled,l_radio_cfg->numSecondaryChannels,new_rec->secondary_channels_list,l_radio_cfg->dtimPeriod,l_radio_cfg->beaconInterval,l_radio_cfg->operatingClass,l_radio_cfg->basicDataTransmitRates,l_radio_cfg->operationalDataTransmitRates,l_radio_cfg->fragmentationThreshold,l_radio_cfg->guardInterval,l_radio_cfg->transmitPower,l_radio_cfg->rtsThreshold,l_radio_cfg->factoryResetSsid,l_radio_cfg->radioStatsMeasuringInterval,l_radio_cfg->radioStatsMeasuringInterval,l_radio_cfg->ctsProtection,l_radio_cfg->obssCoex,l_radio_cfg->stbcEnable,l_radio_cfg->greenFieldEnable,l_radio_cfg->userControl,l_radio_cfg->adminControl,l_radio_cfg->chanUtilThreshold,l_radio_cfg->chanUtilSelfHealEnable);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
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

        i = convert_vap_name_to_index(old_rec->vap_name);
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
        vap_index = convert_vap_name_to_index(old_rec->vap_name);
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

        i = convert_vap_name_to_index(new_rec->vap_name);
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
            }
        }

	pthread_mutex_lock(&g_wifidb->data_cache_lock);
        l_security_cfg->mode = new_rec->security_mode;
        l_security_cfg->encr = new_rec->encryption_method;

	convert_security_mode_string_to_integer(&l_security_cfg->mfp,&new_rec->mfp_config);
        l_security_cfg->rekey_interval = new_rec->rekey_interval;
	l_security_cfg->strict_rekey = new_rec->strict_rekey;
        l_security_cfg->eapol_key_timeout = new_rec->eapol_key_timeout;
        l_security_cfg->eapol_key_retries = new_rec->eapol_key_retries;
        l_security_cfg->eap_identity_req_timeout = new_rec->eap_identity_req_timeout;
        l_security_cfg->eap_identity_req_retries = new_rec->eap_identity_req_retries;
        l_security_cfg->eap_req_timeout = new_rec->eap_req_timeout;
        l_security_cfg->eap_req_retries = new_rec->eap_req_retries;
        l_security_cfg->disable_pmksa_caching = new_rec->disable_pmksa_caching;
        if(!security_mode_support_radius(l_security_cfg->mode))
        {
            l_security_cfg->u.key.type = new_rec->key_type;
            strncpy(l_security_cfg->u.key.key,new_rec->keyphrase,sizeof(l_security_cfg->u.key.key)-1);
        }
        else
        {
            strncpy((char *)l_security_cfg->u.radius.ip,(char *)new_rec->radius_server_ip,sizeof(l_security_cfg->u.radius.ip)-1);

	    strncpy((char *)l_security_cfg->u.radius.s_ip,new_rec->secondary_radius_server_ip,sizeof(l_security_cfg->u.radius.s_ip)-1);
            l_security_cfg->u.radius.port = new_rec->radius_server_port;
            strncpy(l_security_cfg->u.radius.key,new_rec->radius_server_key,sizeof(l_security_cfg->u.radius.key)-1);
            l_security_cfg->u.radius.s_port = new_rec->secondary_radius_server_port;
            strncpy(l_security_cfg->u.radius.s_key,new_rec->secondary_radius_server_key,sizeof(l_security_cfg->u.radius.s_key)-1);
            l_security_cfg->u.radius.max_auth_attempts = new_rec->max_auth_attempts;
            l_security_cfg->u.radius.blacklist_table_timeout = new_rec->blacklist_table_timeout;
            l_security_cfg->u.radius.identity_req_retry_interval = new_rec->identity_req_retry_interval;
            l_security_cfg->u.radius.server_retries = new_rec->server_retries;
	    getIpAddressFromString(new_rec->das_ip,&l_security_cfg->u.radius.dasip);
            l_security_cfg->u.radius.dasport = new_rec->das_port;
            strncpy(l_security_cfg->u.radius.daskey,new_rec->das_key,sizeof(l_security_cfg->u.radius.daskey)-1);
        }
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d r_ser_key=%s rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d rs_ser_key=%s mfg=%s cfg_key_type=%d keyphrase=%s vap_name=%s rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,new_rec->security_mode,new_rec->encryption_method,new_rec->radius_server_ip,new_rec->radius_server_port,new_rec->radius_server_key,new_rec->secondary_radius_server_ip,new_rec->secondary_radius_server_port,new_rec->secondary_radius_server_key,new_rec->mfp_config,new_rec->key_type,new_rec->keyphrase,new_rec->vap_name,new_rec->rekey_interval,new_rec->strict_rekey,new_rec->eapol_key_timeout,new_rec->eapol_key_retries,new_rec->eap_identity_req_timeout,new_rec->eap_identity_req_retries,new_rec->eap_req_timeout,new_rec->eap_req_retries,new_rec->disable_pmksa_caching,new_rec->max_auth_attempts,new_rec->blacklist_table_timeout,new_rec->identity_req_retry_interval,new_rec->server_retries,new_rec->das_ip,new_rec->das_port,new_rec->das_key);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(new_rec->vap_name);
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
        i =convert_vap_name_to_array_index(old_rec->vap_name);
        if(i == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
        vap_index = convert_vap_name_to_index(old_rec->vap_name);
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

        i = convert_vap_name_to_index(new_rec->vap_name);
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
        strncpy(l_interworking_cfg->interworking.hessid, new_rec->hessid, sizeof(l_interworking_cfg->interworking.hessid)-1);
        l_interworking_cfg->interworking.venueGroup = new_rec->venue_group;
        l_interworking_cfg->interworking.venueType = new_rec->venue_type;
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Update Wifi_Interworking_Config table vap_name=%s Enable=%d access_network_type=%d internet=%d asra=%d esr=%d uesa=%d hess_present=%d hessid=%s venue_group=%d venue_type=%d",__func__, __LINE__,new_rec->vap_name,new_rec->enable,new_rec->access_network_type,new_rec->internet,new_rec->asra,new_rec->esr,new_rec->uesa,new_rec->hess_option_present,new_rec->hessid,new_rec->venue_group,new_rec->venue_type); 
	pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        vap_index = convert_vap_name_to_index(new_rec->vap_name);
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
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_front_haul_bss_t *l_bss_param_cfg = NULL;
    wifi_back_haul_sta_t *l_sta_param_cfg = NULL;
    wifi_vap_info_t *l_vap_param_cfg = NULL;
    wifi_vap_info_map_t *l_vap_param_map_cfg = NULL;

    wifi_util_dbg_print(WIFI_DB,"%s:%d\n", __func__, __LINE__);

    if (mon->mon_type == OVSDB_UPDATE_DEL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Delete\n", __func__, __LINE__);
        vap_index = convert_vap_name_to_index(old_rec->vap_name);
        if(vap_index == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,old_rec->vap_name);
            return;
        }
        if((convert_radio_name_to_index(&radio_index,old_rec->radio_name))!=0)
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
        
	wifidb_init_vap_config_default(vap_index,l_vap_param_map_cfg->vap_array[(vap_index/2)]);
    }
    else if ((mon->mon_type == OVSDB_UPDATE_NEW) || (mon->mon_type == OVSDB_UPDATE_MODIFY))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:New/Modify %d\n", __func__, __LINE__,mon->mon_type);
        if(new_rec == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Null pointer Vap config update failed \n",__func__, __LINE__);
            return;
        }

        if((convert_radio_name_to_index(&radio_index,new_rec->radio_name))!=0)
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

	vap_index = convert_vap_name_to_index(new_rec->vap_name);
        if(vap_index == -1)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,new_rec->vap_name);
            return;
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
            l_vap_param_cfg->vap_index = convert_vap_name_to_index(new_rec->vap_name);
            strncpy(l_vap_param_cfg->vap_name, new_rec->vap_name,(sizeof(l_vap_param_cfg->vap_name)-1));
            strncpy(l_vap_param_cfg->bridge_name, new_rec->bridge_name,(sizeof(l_vap_param_cfg->bridge_name)-1));
	    strncpy((char *)l_sta_param_cfg->ssid, new_rec->ssid, (sizeof(l_sta_param_cfg->ssid) - 1));
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
	    l_vap_param_cfg->vap_index = convert_vap_name_to_index(new_rec->vap_name);
            strncpy(l_vap_param_cfg->vap_name, new_rec->vap_name,(sizeof(l_vap_param_cfg->vap_name)-1));
            strncpy(l_bss_param_cfg->ssid,new_rec->ssid,(sizeof(l_bss_param_cfg->ssid)-1));
            l_bss_param_cfg->enabled = new_rec->enabled;
            l_bss_param_cfg->showSsid = new_rec->ssid_advertisement_enabled;
            l_bss_param_cfg->isolation = new_rec->isolation_enabled;
            l_bss_param_cfg->mgmtPowerControl = new_rec->mgmt_power_control;
            l_bss_param_cfg->bssMaxSta = new_rec->bss_max_sta;
            l_bss_param_cfg->bssTransitionActivated = new_rec->bss_transition_activated;
            l_bss_param_cfg->nbrReportActivated = new_rec->nbr_report_activated;
            l_bss_param_cfg->rapidReconnectEnable = new_rec->rapid_connect_enabled;
            l_bss_param_cfg->rapidReconnThreshold = new_rec->rapid_connect_threshold;
            l_bss_param_cfg->vapStatsEnable = new_rec->vap_stats_enable;
            l_bss_param_cfg->mac_filter_enable = new_rec->mac_filter_enabled;
            l_bss_param_cfg->mac_filter_mode = new_rec->mac_filter_mode;
            l_bss_param_cfg->wmm_enabled = new_rec->wmm_enabled;
            strncpy((char *)l_bss_param_cfg->interworking.anqp.anqpParameters,new_rec->anqp_parameters,(sizeof(l_bss_param_cfg->interworking.anqp.anqpParameters)-1));
            strncpy((char *)l_bss_param_cfg->interworking.passpoint.hs2Parameters,new_rec->hs2_parameters,(sizeof(l_bss_param_cfg->interworking.passpoint.hs2Parameters)-1));
            l_bss_param_cfg->UAPSDEnabled = new_rec->uapsd_enabled;
            l_bss_param_cfg->beaconRate = new_rec->beacon_rate;
            strncpy(l_vap_param_cfg->bridge_name, new_rec->bridge_name,(sizeof(l_vap_param_cfg->bridge_name)-1));
            l_bss_param_cfg->wmmNoAck = new_rec->wmm_noack;
            l_bss_param_cfg->wepKeyLength = new_rec->wep_key_length;
            l_bss_param_cfg->bssHotspot = new_rec->bss_hotspot;
            l_bss_param_cfg->wpsPushButton = new_rec->wps_push_button;
            strncpy(l_bss_param_cfg->beaconRateCtl, new_rec->beacon_rate_ctl,(sizeof(l_bss_param_cfg->beaconRateCtl)-1));

            wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config radio_name=%s vap_name=%s ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  mac_addr_acl_enabled =%d wmm_enabled=%d anqp_parameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d beacon_rate_ctl =%s mfp_config = %s\n",__func__, __LINE__,new_rec->radio_name,new_rec->vap_name,new_rec->ssid,new_rec->enabled,new_rec->ssid_advertisement_enabled,new_rec->isolation_enabled,new_rec->mgmt_power_control,new_rec->bss_max_sta,new_rec->bss_transition_activated,new_rec->nbr_report_activated,new_rec->rapid_connect_enabled,new_rec->rapid_connect_threshold,new_rec->vap_stats_enable,new_rec->mac_filter_enabled,new_rec->mac_filter_mode,new_rec->mac_addr_acl_enabled,new_rec->wmm_enabled,new_rec->anqp_parameters,new_rec->hs2_parameters,new_rec->uapsd_enabled,new_rec->beacon_rate,new_rec->bridge_name,new_rec->wmm_noack, new_rec->wep_key_length, new_rec->bss_hotspot,new_rec->wps_push_button, new_rec->beacon_rate_ctl, new_rec->mfp_config);
	    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        }
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Unknown\n", __func__, __LINE__);
    }
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
	ad_id = atoi(new_rec->advertisement_id);
        g_wifidb->global_config.gas_config.AdvertisementID = ad_id;
        g_wifidb->global_config.gas_config.PauseForServerResponse = new_rec->pause_for_server_response;
        g_wifidb->global_config.gas_config.ResponseTimeout =  new_rec->response_timeout;
        g_wifidb->global_config.gas_config.ComeBackDelay = new_rec->comeback_delay;
        g_wifidb->global_config.gas_config.ResponseBufferingTime = new_rec->response_buffering_time;
        g_wifidb->global_config.gas_config.QueryResponseLengthLimit = new_rec->query_responselength_limit;   
        
        wifi_util_dbg_print(WIFI_DB,"%s:%d advertisement_id=%d pause_for_server_response=%d response_timeout=%d comeback_delay=%d response_buffering_time=%d query_responselength_limit=%d\n", __func__, __LINE__,g_wifidb->global_config.gas_config.AdvertisementID,g_wifidb->global_config.gas_config.PauseForServerResponse,g_wifidb->global_config.gas_config.ResponseTimeout, g_wifidb->global_config.gas_config.ComeBackDelay,g_wifidb->global_config.gas_config.ResponseBufferingTime,g_wifidb->global_config.gas_config.QueryResponseLengthLimit);
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
        strncpy(g_wifidb->global_config.global_parameters.wps_pin,new_rec->wps_pin,sizeof(g_wifidb->global_config.global_parameters.wps_pin)-1);
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
        strncpy(g_wifidb->global_config.global_parameters.wifi_region_code,new_rec->wifi_region_code,sizeof(g_wifidb->global_config.global_parameters.wifi_region_code)-1);
        g_wifidb->global_config.global_parameters.diagnostic_enable = new_rec->diagnostic_enable;
        g_wifidb->global_config.global_parameters.validate_ssid = new_rec->validate_ssid;
        wifi_util_dbg_print(WIFI_DB,"%s:%d  notify_wifi_changes %d  prefer_private %d  prefer_private_configure %d  factory_reset %d  tx_overflow_selfheal %d  inst_wifi_client_enabled %d  inst_wifi_client_reporting_period %d  inst_wifi_client_mac = %s inst_wifi_client_def_reporting_period %d  wifi_active_msmt_enabled %d  wifi_active_msmt_pktsize %d  wifi_active_msmt_num_samples %d  wifi_active_msmt_sample_duration %d  vlan_cfg_version %d  wps_pin = %s bandsteering_enable %d  good_rssi_threshold %d  assoc_count_threshold %d  assoc_gate_time %d  assoc_monitor_duration %d  rapid_reconnect_enable %d  vap_stats_feature %d  mfp_config_feature %d  force_disable_radio_feature %d  force_disable_radio_status %d  fixed_wmm_params %d  wifi_region_code %s diagnostic_enable %d  validate_ssid %d \n", __func__, __LINE__, new_rec->notify_wifi_changes,new_rec->prefer_private,new_rec->prefer_private_configure,new_rec->factory_reset,new_rec->tx_overflow_selfheal,new_rec->inst_wifi_client_enabled,new_rec->inst_wifi_client_reporting_period,new_rec->inst_wifi_client_mac, new_rec->inst_wifi_client_def_reporting_period,new_rec->wifi_active_msmt_enabled,new_rec->wifi_active_msmt_pktsize,new_rec->wifi_active_msmt_num_samples,new_rec->wifi_active_msmt_sample_duration,new_rec->vlan_cfg_version,new_rec->wps_pin, new_rec->bandsteering_enable,new_rec->good_rssi_threshold,new_rec->assoc_count_threshold,new_rec->assoc_gate_time,new_rec->assoc_monitor_duration,new_rec->rapid_reconnect_enable,new_rec->vap_stats_feature,new_rec->mfp_config_feature,new_rec->force_disable_radio_feature,new_rec->force_disable_radio_status,new_rec->fixed_wmm_params,new_rec->wifi_region_code,new_rec->diagnostic_enable,new_rec->validate_ssid);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
    else
    {
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

    where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &count);
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
		where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    	ret = ovsdb_table_update_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &cfg);
		if (ret == -1) {
			wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update table_Wifi_Interworking_Config table\n", 
				__func__, __LINE__);
			return -1;
		} else if (ret == 0) {
			wifi_util_dbg_print(WIFI_DB,"%s:%d: nothing to update table_Wifi_Interworking_Config table\n", 
				__func__, __LINE__);
		} else {
			wifi_util_dbg_print(WIFI_DB,"%s:%d: update to table_Wifi_Interworking_Config table successful\n", 
				__func__, __LINE__);
		}
	} else {
    	if (ovsdb_table_insert(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, &cfg) == false) {
			wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to insert in table_Wifi_Interworking_Config\n", 
				__func__, __LINE__);
			return -1;
		} else {
			wifi_util_dbg_print(WIFI_DB,"%s:%d: insert in table_Wifi_Interworking_Config table successful\n", 
				__func__, __LINE__);
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
    where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &count);
    if (pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table not table_Wifi_Interworking_Config not found\n",__func__, __LINE__);
        return -1;
    }
    interworking->interworkingEnabled = pcfg->enable;
    interworking->accessNetworkType = pcfg->access_network_type;
    interworking->internetAvailable = pcfg->internet;
    interworking->asra = pcfg->asra;
    interworking->esr = pcfg->esr;
    interworking->uesa = pcfg->uesa;
    interworking->hessOptionPresent = pcfg->hess_option_present;
    strncpy(interworking->hessid, pcfg->hessid, sizeof(interworking->hessid)-1);
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
    char *vap_name[] = {"private_ssid_2g", "private_ssid_5g", "iot_ssid_2g", "iot_ssid_5g", "hotspot_open_2g", "hotspot_open_5g", "lnf_psk_2g", "lnf_psk_5g", "hotspot_secure_2g", "hotspot_secure_5g"};
    
    char output[4096];
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    wifi_util_dbg_print(WIFI_DB,"WIFIDB JSON\nname:Open_vSwitch, version:1.00.000\n");
    wifi_util_dbg_print(WIFI_DB,"table: Wifi_Interworking_Config \n");
    for (i=0; i < 10; i++) {
        where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name[i]);
        pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where, &count);
    
        if ((pcfg == NULL) || (!count)) {
            continue;
        }
        json_t *data_base = ovsdb_table_to_json(&table_Wifi_Interworking_Config, pcfg);
        if(data_base) {
            memset(output,0,sizeof(output));
            if(json_get_str(data_base,output, sizeof(output))) {
                wifi_util_dbg_print(WIFI_DB,"key: %s\nCount: %d\n%s\n",
                   vap_name[i],count,output);
            } else {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Unable to print Row\n",
                   __func__, __LINE__);
            }
        }

        free(pcfg);
        pcfg = NULL;
    }
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
    where = ovsdb_tran_cond(OCLM_STR, "advertisement_id", OFUNC_EQ, index);
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, where, &count);
    if ((count != 0) && (pcfg != NULL)) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Found %d records with key: %d in Wifi GAS table\n", 
    	__func__, __LINE__, count, advertisement_id);
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
        where = ovsdb_tran_cond(OCLM_STR, "advertisement_id", OFUNC_EQ, index); 
        ret = ovsdb_table_update_where(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, where, &cfg);
	if (ret == -1) {
	    wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update table_Wifi_GAS_Config table\n", 
		__func__, __LINE__);
	    return -1;
	} else if (ret == 0) {
	    wifi_util_dbg_print(WIFI_DB,"%s:%d: nothing to update table_Wifi_GAS_Config table\n", 
		__func__, __LINE__);
	} else {
	    wifi_util_dbg_print(WIFI_DB,"%s:%d: update to table_Wifi_GAS_Config table successful\n", 
		__func__, __LINE__);
	}
    } else {
	strcpy(cfg.advertisement_id,index);
        if (ovsdb_table_upsert_simple(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, 
                                  SCHEMA_COLUMN(Wifi_GAS_Config, advertisement_id),
                                  cfg.advertisement_id,
                                  &cfg, NULL) == false) {
	    wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to insert in table_Wifi_GAS_Config\n", 
		__func__, __LINE__);
	    return -1;
	} else {
	    wifi_util_dbg_print(WIFI_DB,"%s:%d: insert in table_Wifi_GAS_Config table successful\n", 
		__func__, __LINE__);
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
    where = ovsdb_tran_cond(OCLM_STR, "advertisement_id", OFUNC_EQ, index);
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_GAS_Config, where, &count);
    if (pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table table_Wifi_GAS_Config not found\n",__func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Radio Config update failed \n",__func__, __LINE__);
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
    cfg.dcs_enabled = config->DCSEnabled;
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

    wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d  radio_stats_measuring_rate = %d   radio_stats_measuring_interval = %d cts_protection = %d obss_coex = %d  stbc_enable = %d  greenfield_enable = %d user_control = %d  admin_control = %d  chan_util_threshold = %d  chan_util_selfheal_enable = %d  \n",__func__, __LINE__,config->enable,config->band,config->autoChannelEnabled,config->channel,config->channelWidth,config->variant,config->csa_beacon_count,config->countryCode,config->DCSEnabled,config->numSecondaryChannels,cfg.secondary_channels_list,config->dtimPeriod,config->beaconInterval,config->operatingClass,config->basicDataTransmitRates,config->operationalDataTransmitRates,config->fragmentationThreshold,config->guardInterval,config->transmitPower,config->rtsThreshold,config->factoryResetSsid,config->radioStatsMeasuringRate,config->radioStatsMeasuringInterval,config->ctsProtection,config->obssCoex,config->stbcEnable,config->greenFieldEnable,config->userControl,config->adminControl,config->chanUtilThreshold,config->chanUtilSelfHealEnable);

    if(ovsdb_table_upsert_f(g_wifidb->wifidb_sock_path,&table_Wifi_Radio_Config,&cfg,false,insert_filter) == false)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to insert Wifi_Radio_Config table\n",__func__, __LINE__);
	return -1;
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Insert Wifi_Radio_Config table complete\n",__func__, __LINE__);
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
    char *tmp, *ptr;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get Radio Config  failed \n",__func__, __LINE__);
        return -1;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Get radio config for index=%d radio_name=%s \n",__func__, __LINE__,radio_index,name);
    where = ovsdb_tran_cond(OCLM_STR, "radio_name", OFUNC_EQ, name);
    cfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Radio_Config, where, &count);
    if(cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table not table_Wifi_Radio_Config not found\n",__func__, __LINE__);
        return -1;
    }
    config->enable = cfg->enabled;
    config->band = cfg->freq_band;
    config->autoChannelEnabled = cfg->auto_channel_enabled;
    config->channel = cfg->channel;
    config->channelWidth = cfg->channel_width;
    config->variant = cfg->hw_mode;
    config->csa_beacon_count = cfg->csa_beacon_count;
    config->countryCode = cfg->country;
    config->DCSEnabled = cfg->dcs_enabled;
    config->dtimPeriod = cfg->dtim_period;
    config->beaconInterval = cfg->beacon_interval;
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

    wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%s dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d factory_reset_ssid = %d, radio_stats_measuring_rate = %d, radio_stats_measuring_interval = %d, cts_protection %d, obss_coex= %d, stbc_enable= %d, greenfield_enable= %d, user_control= %d, admin_control= %d,chan_util_threshold= %d, chan_util_selfheal_enable= %d \n",__func__, __LINE__,config->enable,config->band,config->autoChannelEnabled,config->channel,config->channelWidth,config->variant,config->csa_beacon_count,config->countryCode,config->DCSEnabled,config->numSecondaryChannels,cfg->secondary_channels_list,config->dtimPeriod,config->beaconInterval,config->operatingClass,config->basicDataTransmitRates,config->operationalDataTransmitRates,config->fragmentationThreshold,config->guardInterval,config->transmitPower,config->rtsThreshold,config->factoryResetSsid,config->radioStatsMeasuringInterval,config->radioStatsMeasuringInterval,config->ctsProtection,config->obssCoex,config->stbcEnable,config->greenFieldEnable,config->userControl,config->adminControl,config->chanUtilThreshold,config->chanUtilSelfHealEnable);
    free(cfg);
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_get_wifi_vap_config
  Parameter   : radio_index - Radio index
                config      - wifi_vap_info_map_t to be updated from wifidb
  Description : Get wifi_vap_info_map_t structure from wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_get_wifi_vap_config(int radio_index,wifi_vap_info_map_t *config)
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get VAP Config failed \n",__func__, __LINE__);
        return -1;
    }

    where = ovsdb_tran_cond(OCLM_STR, "radio_name", OFUNC_EQ, name);
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_VAP_Config, where, &vap_count);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config get index=%d radio_name=%s \n",__func__, __LINE__,radio_index,name);
    if((pcfg == NULL) || (vap_count== 0))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_VAP_Config not found count=%d\n",__func__, __LINE__,vap_count);
        return -1;
    }
    for (i = 0; i < vap_count; i++)
    {
        if(pcfg != NULL)
        {

            strncpy(vap_name,(pcfg+i)->vap_name,sizeof(vap_name));
	    vap_index = convert_vap_name_to_array_index(vap_name);
	    if(vap_index == -1)
            {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: %s vap_name is invalid\n",__func__, __LINE__,vap_name);
		continue;
            }
            config->vap_array[vap_index].radio_index = radio_index;
            config->vap_array[vap_index].vap_index = convert_vap_name_to_index(vap_name);
            wifidb_get_wifi_vap_info(vap_name,&config->vap_array[vap_index]);
	    wifi_util_dbg_print(WIFI_DB,"%s:%d: %svap name vap_index=%d radio_ondex=%d\n",__func__, __LINE__,vap_name,vap_index,radio_index);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_VAP_Config verify count=%d\n",__func__, __LINE__,vap_count);
            wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config Row=%d radio_name=%s radioindex=%d vap_name=%s vap_index=%d ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  wmm_enabled=%d anqpParameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d beacon_rate_ctl =%s \n",__func__, __LINE__,i,name,config->vap_array[vap_index].radio_index,config->vap_array[vap_index].vap_name,config->vap_array[vap_index].vap_index,config->vap_array[vap_index].u.bss_info.ssid,config->vap_array[vap_index].u.bss_info.enabled,config->vap_array[vap_index].u.bss_info.showSsid ,config->vap_array[vap_index].u.bss_info.isolation,config->vap_array[vap_index].u.bss_info.mgmtPowerControl,config->vap_array[vap_index].u.bss_info.bssMaxSta,config->vap_array[vap_index].u.bss_info.bssTransitionActivated,config->vap_array[vap_index].u.bss_info.nbrReportActivated,config->vap_array[vap_index].u.bss_info.rapidReconnectEnable,config->vap_array[vap_index].u.bss_info.rapidReconnThreshold,config->vap_array[vap_index].u.bss_info.vapStatsEnable,config->vap_array[vap_index].u.bss_info.mac_filter_enable,config->vap_array[vap_index].u.bss_info.mac_filter_mode,config->vap_array[vap_index].u.bss_info.wmm_enabled,config->vap_array[vap_index].u.bss_info.interworking.anqp.anqpParameters,config->vap_array[vap_index].u.bss_info.interworking.passpoint.hs2Parameters,config->vap_array[vap_index].u.bss_info.UAPSDEnabled,config->vap_array[vap_index].u.bss_info.beaconRate,config->vap_array[vap_index].bridge_name,config->vap_array[vap_index].u.bss_info.wmmNoAck,config->vap_array[vap_index].u.bss_info.wepKeyLength,config->vap_array[vap_index].u.bss_info.bssHotspot,config->vap_array[vap_index].u.bss_info.wpsPushButton,config->vap_array[vap_index].u.bss_info.beaconRateCtl);//config->vap_array[vap_index].u.bss_info.mfp_config);

            wifidb_get_interworking_config(vap_name,&config->vap_array[vap_index].u.bss_info.interworking.interworking);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Interworking_Config table vap_name=%s Enable=%d accessNetworkType=%d internetAvailable=%d asra=%d esr=%d uesa=%d hess_present=%d hessid=%s venueGroup=%d venueType=%d \n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.bss_info.interworking.interworking.interworkingEnabled,config->vap_array[vap_index].u.bss_info.interworking.interworking.accessNetworkType,config->vap_array[vap_index].u.bss_info.interworking.interworking.internetAvailable,config->vap_array[vap_index].u.bss_info.interworking.interworking.asra,config->vap_array[vap_index].u.bss_info.interworking.interworking.esr,config->vap_array[vap_index].u.bss_info.interworking.interworking.uesa,config->vap_array[vap_index].u.bss_info.interworking.interworking.hessOptionPresent,config->vap_array[vap_index].u.bss_info.interworking.interworking.hessid,config->vap_array[vap_index].u.bss_info.interworking.interworking.venueGroup,config->vap_array[vap_index].u.bss_info.interworking.interworking.venueType);

            l_vap_index = convert_vap_name_to_index(vap_name);
            if (isVapSTAMesh(l_vap_index)) {
                wifidb_get_wifi_security_config(vap_name,&config->vap_array[vap_index].u.sta_info.security);

                if (!security_mode_support_radius(config->vap_array[vap_index].u.sta_info.security.mode)) {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table sec type=%d  sec key=%s \n",__func__, __LINE__,config->vap_array[vap_index].u.sta_info.security.u.key.type,config->vap_array[vap_index].u.sta_info.security.u.key.key,config->vap_array[vap_index].u.sta_info.security.u.key.type,config->vap_array[vap_index].u.sta_info.security.u.key.key);
                } else {
                    getIpStringFromAdrress(address,&config->vap_array[vap_index].u.sta_info.security.u.radius.dasip);
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table radius server ip =%s  port =%d sec key=%s Secondary radius server ip=%s port=%d key=%s max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,config->vap_array[vap_index].u.sta_info.security.u.radius.ip,config->vap_array[vap_index].u.sta_info.security.u.radius.port,config->vap_array[vap_index].u.sta_info.security.u.radius.key,config->vap_array[vap_index].u.sta_info.security.u.radius.s_ip,config->vap_array[vap_index].u.sta_info.security.u.radius.s_port,config->vap_array[vap_index].u.sta_info.security.u.radius.s_key,config->vap_array[vap_index].u.sta_info.security.u.radius.max_auth_attempts,config->vap_array[vap_index].u.sta_info.security.u.radius.blacklist_table_timeout,config->vap_array[vap_index].u.sta_info.security.u.radius.identity_req_retry_interval,config->vap_array[vap_index].u.sta_info.security.u.radius.server_retries,address,config->vap_array[vap_index].u.sta_info.security.u.radius.dasport,config->vap_array[vap_index].u.sta_info.security.u.radius.daskey);
                }
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table vap_name=%s Sec_mode=%d enc_mode=%d mfg_config=%d rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d \n",__func__, __LINE__,vap_name,config->vap_array[vap_index].u.sta_info.security.mode,config->vap_array[vap_index].u.sta_info.security.encr,config->vap_array[vap_index].u.sta_info.security.mfp,config->vap_array[vap_index].u.sta_info.security.rekey_interval,config->vap_array[vap_index].u.sta_info.security.strict_rekey,config->vap_array[vap_index].u.sta_info.security.eapol_key_timeout,config->vap_array[vap_index].u.sta_info.security.eapol_key_retries,config->vap_array[vap_index].u.sta_info.security.eap_identity_req_timeout,config->vap_array[vap_index].u.sta_info.security.eap_identity_req_retries,config->vap_array[vap_index].u.sta_info.security.eap_req_timeout,config->vap_array[vap_index].u.sta_info.security.eap_req_retries,config->vap_array[vap_index].u.sta_info.security.disable_pmksa_caching);
            } else {
	        wifidb_get_wifi_security_config(vap_name,&config->vap_array[vap_index].u.bss_info.security);

                if (!security_mode_support_radius(config->vap_array[vap_index].u.bss_info.security.mode)) {
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
int wifidb_update_wifi_vap_config(int radio_index, wifi_vap_info_map_t *config)
{
    unsigned int i = 0;
    uint8_t vap_index = 0;
    char name[BUFFER_LENGTH_WIFIDB];

    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config update for radio index=%d No of Vaps=%d\n",__func__, __LINE__,radio_index,config->num_vaps);
    if((config == NULL) || (convert_radio_to_name(radio_index,name)!=0))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer VAP Config update failed \n",__func__, __LINE__);
        return -1;
    }
    for(i=0;i<config->num_vaps;i++)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Update radio=%s vap name=%s \n",__func__, __LINE__,name,config->vap_array[i].vap_name);
        wifidb_update_wifi_vap_info(config->vap_array[i].vap_name,&config->vap_array[i]);
        vap_index = convert_vap_name_to_index(config->vap_array[i].vap_name);
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
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if(sec == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Get table_Wifi_Security_Config failed \n",__func__, __LINE__);
        return -1;
    }

    where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_Security_Config, where, &count);
    if (pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table not table_Wifi_Security_Config not found\n",__func__, __LINE__);
        return -1;
    }
     wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table Sec_mode=%d enc_mode=%d r_ser_ip=%s r_ser_port=%d r_ser_key=%s rs_ser_ip=%s rs_ser_ip sec_rad_ser_port=%d rs_ser_key=%s mfg=%s cfg_key_type=%d keyphrase=%s vap_name=%s rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,pcfg->security_mode,pcfg->encryption_method,pcfg->radius_server_ip,pcfg->radius_server_port,pcfg->radius_server_key,pcfg->secondary_radius_server_ip,pcfg->secondary_radius_server_port,pcfg->secondary_radius_server_key,pcfg->mfp_config,pcfg->key_type,pcfg->keyphrase,pcfg->vap_name,pcfg->rekey_interval,pcfg->strict_rekey,pcfg->eapol_key_timeout,pcfg->eapol_key_retries,pcfg->eap_identity_req_timeout,pcfg->eap_identity_req_retries,pcfg->eap_req_timeout,pcfg->eap_req_retries,pcfg->disable_pmksa_caching,pcfg->max_auth_attempts,pcfg->blacklist_table_timeout,pcfg->identity_req_retry_interval,pcfg->server_retries,pcfg->das_ip,pcfg->das_port,pcfg->das_key);

    sec->mode = pcfg->security_mode;
    sec->encr = pcfg->encryption_method;
    convert_security_mode_string_to_integer(&sec->mfp,&pcfg->mfp_config);
    sec->rekey_interval = pcfg->rekey_interval;
    sec->strict_rekey = pcfg->strict_rekey;
    sec->eapol_key_timeout = pcfg->eapol_key_timeout;
    sec->eapol_key_retries = pcfg->eapol_key_retries;
    sec->eap_identity_req_timeout = pcfg->eap_identity_req_timeout;
    sec->eap_identity_req_retries = pcfg->eap_identity_req_retries;
    sec->eap_req_timeout = pcfg->eap_req_timeout;
    sec->eap_req_retries = pcfg->eap_req_retries;
    sec->disable_pmksa_caching = pcfg->disable_pmksa_caching;
    if(!security_mode_support_radius(sec->mode))
    {
        sec->u.key.type = pcfg->key_type;
        strncpy(sec->u.key.key,pcfg->keyphrase,sizeof(sec->u.key.key)-1);
    }
    else
    {
        strncpy((char *)sec->u.radius.ip,pcfg->radius_server_ip,sizeof(sec->u.radius.ip)-1);
        sec->u.radius.port = pcfg->radius_server_port;
        strncpy(sec->u.radius.key,pcfg->radius_server_key,sizeof(sec->u.radius.key)-1);
        strncpy((char *)sec->u.radius.s_ip,pcfg->secondary_radius_server_ip,sizeof(sec->u.radius.s_ip)-1);
        sec->u.radius.s_port = pcfg->secondary_radius_server_port;
        strncpy(sec->u.radius.s_key,pcfg->secondary_radius_server_key,sizeof(sec->u.radius.s_key)-1);
        sec->u.radius.max_auth_attempts = pcfg->max_auth_attempts;
        sec->u.radius.blacklist_table_timeout = pcfg->blacklist_table_timeout;
        sec->u.radius.identity_req_retry_interval = pcfg->identity_req_retry_interval;
        sec->u.radius.server_retries = pcfg->server_retries;
	getIpAddressFromString(pcfg->das_ip,&sec->u.radius.dasip);
        sec->u.radius.dasport = pcfg->das_port;
        strncpy(sec->u.radius.daskey,pcfg->das_key,sizeof(sec->u.radius.daskey)-1);
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
int wifidb_get_wifi_vap_info(char *vap_name,wifi_vap_info_t *config)
{
    struct schema_Wifi_VAP_Config *pcfg;
    json_t *where;
    int count = 0;
    int index = 0;
    uint8_t vap_index = 0;
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP info failed \n",__func__, __LINE__);
        return -1;
    }

    where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_VAP_Config, where, &count);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config get vap_name=%s count=%d\n",__func__, __LINE__,vap_name,count);
    if((pcfg == NULL) || (count== 0))
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_VAP_Config not found count=%d\n",__func__, __LINE__,count);
        return -1;
    }
    if(pcfg != NULL)
    {

        wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config radio_name=%s vap_name=%s ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  mac_addr_acl_enabled =%d wmm_enabled=%d anqp_parameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d beacon_rate_ctl =%s  \n",__func__, __LINE__,pcfg->radio_name,pcfg->vap_name,pcfg->ssid,pcfg->enabled,pcfg->ssid_advertisement_enabled,pcfg->isolation_enabled,pcfg->mgmt_power_control,pcfg->bss_max_sta,pcfg->bss_transition_activated,pcfg->nbr_report_activated,pcfg->rapid_connect_enabled,pcfg->rapid_connect_threshold,pcfg->vap_stats_enable,pcfg->mac_filter_enabled,pcfg->mac_filter_mode,pcfg->mac_addr_acl_enabled,pcfg->wmm_enabled,pcfg->anqp_parameters,pcfg->hs2_parameters,pcfg->uapsd_enabled,pcfg->beacon_rate,pcfg->bridge_name,pcfg->wmm_noack,pcfg->wep_key_length,pcfg->bss_hotspot,pcfg->wps_push_button,pcfg->beacon_rate_ctl);//pcfg->mfp_config);


        if((convert_radio_name_to_index(&index,pcfg->radio_name))!=0)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid radio name \n",__func__, __LINE__,pcfg->radio_name);
	    return -1;
        }
        config->radio_index = index ;
	config->vap_index = convert_vap_name_to_index(pcfg->vap_name);
        strncpy(config->vap_name, pcfg->vap_name,(sizeof(config->vap_name)-1));
        vap_index = convert_vap_name_to_index(pcfg->vap_name);
        if (strlen(pcfg->bridge_name) != 0) {
            strncpy(config->bridge_name, pcfg->bridge_name,(sizeof(config->bridge_name)-1));
        } else {
            get_vap_interface_bridge_name(config->vap_index, config->bridge_name);
        }
        if (isVapSTAMesh(vap_index)) {
            strncpy(config->u.sta_info.ssid, pcfg->ssid, (sizeof(config->u.sta_info.ssid)-1));
	    config->u.sta_info.enabled = pcfg->enabled;
	    config->u.sta_info.scan_params.period = pcfg->period;
	    config->u.sta_info.scan_params.channel.channel = pcfg->channel;
	    config->u.sta_info.scan_params.channel.band = pcfg->freq_band;
        } else {
            strncpy(config->u.bss_info.ssid,pcfg->ssid,(sizeof(config->u.bss_info.ssid)-1));
            config->u.bss_info.enabled = pcfg->enabled;
            config->u.bss_info.showSsid = pcfg->ssid_advertisement_enabled;
            config->u.bss_info.isolation = pcfg->isolation_enabled;
            config->u.bss_info.mgmtPowerControl = pcfg->mgmt_power_control;
            config->u.bss_info.bssMaxSta = pcfg->bss_max_sta;
            config->u.bss_info.bssTransitionActivated = pcfg->bss_transition_activated;
            config->u.bss_info.nbrReportActivated = pcfg->nbr_report_activated;
            config->u.bss_info.rapidReconnectEnable = pcfg->rapid_connect_enabled;
            config->u.bss_info.rapidReconnThreshold = pcfg->rapid_connect_threshold;
            config->u.bss_info.vapStatsEnable = pcfg->vap_stats_enable;
            config->u.bss_info.mac_filter_enable = pcfg->mac_filter_enabled;
            config->u.bss_info.mac_filter_mode = pcfg->mac_filter_mode;
            config->u.bss_info.wmm_enabled = pcfg->wmm_enabled;
            strncpy((char *)config->u.bss_info.interworking.anqp.anqpParameters, (char *)pcfg->anqp_parameters,(sizeof(config->u.bss_info.interworking.anqp.anqpParameters)-1));
            strncpy((char *)config->u.bss_info.interworking.passpoint.hs2Parameters,(char *)pcfg->hs2_parameters,(sizeof(config->u.bss_info.interworking.passpoint.hs2Parameters)-1));
            config->u.bss_info.UAPSDEnabled = pcfg->uapsd_enabled;
            config->u.bss_info.beaconRate = pcfg->beacon_rate;
            config->u.bss_info.wmmNoAck = pcfg->wmm_noack;
            config->u.bss_info.wepKeyLength = pcfg->wep_key_length;
            config->u.bss_info.bssHotspot = pcfg->bss_hotspot;
            config->u.bss_info.wpsPushButton = pcfg->wps_push_button;
            strncpy(config->u.bss_info.beaconRateCtl, pcfg->beacon_rate_ctl,(sizeof(config->u.bss_info.beaconRateCtl)-1));
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Interworking update failed \n",__func__, __LINE__);
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

    if(ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_Interworking_Config,&cfg_interworking,false,filter_vapinterworking,SCHEMA_TABLE(Wifi_VAP_Config),ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name),vap_name),SCHEMA_COLUMN(Wifi_VAP_Config,interworking)) == false)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update Wifi_Interworking_Config table\n",__func__, __LINE__);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:  update table Wifi_Interworking_Config table successful\n",__func__, __LINE__);
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
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();

    memset(&cfg_sec,0,sizeof(cfg_sec));
    if(sec == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Security Config update failed \n",__func__, __LINE__);
        return -1;
    }
    cfg_sec.security_mode = sec->mode;
    cfg_sec.encryption_method = sec->encr;
    convert_security_mode_integer_to_string(sec->mfp,&cfg_sec.mfp_config);
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

    if(!security_mode_support_radius(sec->mode))
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

    if(ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_Security_Config,&cfg_sec,false,filter_vapsec,SCHEMA_TABLE(Wifi_VAP_Config),ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name),vap_name),SCHEMA_COLUMN(Wifi_VAP_Config,security)) == false)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update table_Wifi_Security_Config table\n",__func__, __LINE__);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:  update table_Wifi_Security_Config table successful\n",__func__, __LINE__);
    }

    return 0;
}

static char *to_mac_str    (mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

static void to_mac_bytes   (mac_addr_str_t key, mac_address_t bmac) {
   unsigned int mac[6];
    sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
             &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
   bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
   bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_update_wifi_macfilter_config
  Parameter   : macfilter_key     - vap_name-device_mac
                config          - acl_entry_t with device details
  Description : Update macfilter entry to wifidb
 *************************************************************************************
**************************************************************************************/
int wifidb_update_wifi_macfilter_config(char *macfilter_key, acl_entry_t *config, acl_action action)
{
    struct schema_Wifi_MacFilter_Config cfg_mac;
    char *filter_mac[] = {"-", NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    char tmp_mac_str[18];
    char concat_string[128];
    json_t *where;
    int ret = 0;

    if (action == acl_action_del) {
        where = ovsdb_tran_cond(OCLM_STR, "macfilter_key", OFUNC_EQ, macfilter_key);
        ret = ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_MacFilter_Config, where);
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Table Deleting failed\n", __func__, __LINE__);
            return -1;
        }
    } else if (action == acl_action_add) {

        memset(tmp_mac_str, 0, sizeof(tmp_mac_str));
        memset(concat_string, 0, sizeof(concat_string));

        memset(&cfg_mac, 0, sizeof(cfg_mac));
        if (config == NULL) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d:MacFilter Config update failed \n",__func__, __LINE__);
            return -1;
        }

        to_mac_str(config->mac, tmp_mac_str);
        strncpy(cfg_mac.device_mac, tmp_mac_str, sizeof(cfg_mac.device_mac)-1);
        strncpy(cfg_mac.device_name, config->device_name, sizeof(cfg_mac.device_name)-1);

        //concat for macfilter_key.
        strncpy(cfg_mac.macfilter_key, macfilter_key, sizeof(cfg_mac.macfilter_key));
        wifi_util_dbg_print(WIFI_DB,"%s:%d: updating table wifi_macfilter_config table entry is device_mac %s, device_name %s,macfilter_key %s\n", __func__, __LINE__, cfg_mac.device_mac, cfg_mac.device_name, cfg_mac.macfilter_key);

        if (ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path, &table_Wifi_MacFilter_Config, &cfg_mac, false, filter_mac, SCHEMA_TABLE(Wifi_VAP_Config), ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VAP_Config,vap_name), macfilter_key), SCHEMA_COLUMN(Wifi_VAP_Config, mac_filter)) ==  false) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update table_Wifi_MacFilter_Config table\n", __func__, __LINE__);
        }
        else {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: updated table_Wifi_MacFilter_Config table\n", __func__, __LINE__);
        }

    } else {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: No Update on wifidb\n", __func__, __LINE__);
    }

    return 0;
}

void wifidb_reset_macfilter_hashmap()
{
    acl_entry_t *tmp_acl_entry = NULL, *acl_entry = NULL;
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    unsigned int itr, itrj;
    mac_addr_str_t mac_str;

    for (itr = 0; itr < getNumberRadios(); itr++) {
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
            l_rdk_vap_array = get_wifidb_rdk_vap_info(itrj);

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
    }

    return;
}
 
void wifidb_get_wifi_macfilter_config()
{
    struct schema_Wifi_MacFilter_Config *pcfg;
    int count, itr;
    char *ptr_t, *tmp, *tmp_vap_name, delim[2] = "-";
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    wifi_db_t *g_wifidb;
    acl_entry_t *tmp_acl_entry = NULL;
    mac_address_t mac;
    unsigned int vap_index;

    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, &table_Wifi_MacFilter_Config, NULL, &count);
    if (pcfg == NULL) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table table_Wifi_MacFilter_Config has no entry\n", __func__, __LINE__);
        return;
    }

    for (itr = 0; (itr < count) && (pcfg != NULL); itr++) {
        tmp = strdup(pcfg->macfilter_key);
        if (tmp != NULL) {
            tmp_vap_name = strtok_r(tmp, delim, &ptr_t);
            vap_index = convert_vap_name_to_index(tmp_vap_name);
            free(tmp);
        } else {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: NULL Pointer \n", __func__, __LINE__);
            return;
        }

        l_rdk_vap_array = get_wifidb_rdk_vap_info(vap_index);

        if (l_rdk_vap_array->acl_map != NULL) {
            tmp_acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            if (tmp_acl_entry == NULL) {
                wifi_util_dbg_print(WIFI_DB,"%s:%d: NULL Pointer \n", __func__, __LINE__);
                return;
            }
            memset(tmp_acl_entry, 0, sizeof(acl_entry_t));

            to_mac_bytes(pcfg->device_mac, mac);
            memcpy(tmp_acl_entry->mac, mac, sizeof(mac_address_t));

            tmp_acl_entry->acl_action_type = acl_action_none;
            strncpy(tmp_acl_entry->device_name, pcfg->device_name, strlen(pcfg->device_name)+1);

            hash_map_put(l_rdk_vap_array->acl_map, strdup(pcfg->device_mac), tmp_acl_entry);
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
int wifidb_update_wifi_vap_info(char *vap_name,wifi_vap_info_t *config)
{
    struct schema_Wifi_VAP_Config cfg;
    char *filter_vap[] = {"-",SCHEMA_COLUMN(Wifi_VAP_Config,security),SCHEMA_COLUMN(Wifi_VAP_Config,interworking),SCHEMA_COLUMN(Wifi_VAP_Config,mac_filter),NULL};
    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t*) get_wifidb_obj();
    char radio_name[BUFFER_LENGTH_WIFIDB] = {0};
    int radio_index = 0;
    int l_vap_index = 0;
    memset(&cfg,0,sizeof(cfg));
    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config update failed \n",__func__, __LINE__);
        return -1;
    }
    radio_index = convert_vap_name_to_radio_array_index(vap_name);
    if((convert_radio_to_name(radio_index,radio_name))!=0)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Config update failed Invalid radio index %d vap_name=%s\n",__func__, __LINE__,radio_index,vap_name);
        return -1;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Update radio=%s vap name=%s \n",__func__, __LINE__,radio_name,config->vap_name);
    strncpy(cfg.radio_name,radio_name,sizeof(cfg.radio_name)-1);
    strncpy(cfg.vap_name, config->vap_name,(sizeof(cfg.vap_name)-1));
    strncpy(cfg.bridge_name, config->bridge_name,(sizeof(cfg.bridge_name)-1));
    l_vap_index = convert_vap_name_to_index(config->vap_name);
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
        strncpy(cfg.beacon_rate_ctl,config->u.bss_info.beaconRateCtl,sizeof(cfg.beacon_rate_ctl)-1);
        strncpy(cfg.mfp_config,"Disabled",sizeof(cfg.mfp_config)-1);

        wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config update data cfg.radio_name=%s cfg.radio_name=%s cfg.ssid=%s cfg.enabled=%d cfg.advertisement=%d cfg.isolation_enabled=%d cfg.mgmt_power_control=%d cfg.bss_max_sta =%d cfg.bss_transition_activated=%d cfg.nbr_report_activated=%d cfg.rapid_connect_enabled=%d cfg.rapid_connect_threshold=%d cfg.vap_stats_enable=%d cfg.mac_filter_enabled =%d cfg.mac_filter_mode=%d cfg.wmm_enabled=%d anqp_parameters=%s hs2_parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s cfg.wmm_noack = %d cfg.wep_key_length = %d   cfg.bss_hotspot =  %d cfg.wps_push_button =  %d cfg.beacon_rate_ctl = %s cfg.mfp_config =%s  \n",__func__, __LINE__,cfg.radio_name,cfg.vap_name,cfg.ssid,cfg.enabled,cfg.ssid_advertisement_enabled,cfg.isolation_enabled,cfg.mgmt_power_control,cfg.bss_max_sta,cfg.bss_transition_activated,cfg.nbr_report_activated,cfg.rapid_connect_enabled,cfg.rapid_connect_threshold,cfg.vap_stats_enable,cfg.mac_filter_enabled,cfg.mac_filter_mode,cfg.wmm_enabled,cfg.anqp_parameters,cfg.hs2_parameters,cfg.uapsd_enabled,cfg.beacon_rate,cfg.bridge_name,cfg.wmm_noack, cfg.wep_key_length, cfg.bss_hotspot, cfg.wps_push_button, cfg.beacon_rate_ctl, cfg.mfp_config);
    }

    if(ovsdb_table_upsert_with_parent(g_wifidb->wifidb_sock_path,&table_Wifi_VAP_Config,&cfg,false,filter_vap,SCHEMA_TABLE(Wifi_Radio_Config),(ovsdb_where_simple(SCHEMA_COLUMN(Wifi_Radio_Config,radio_name),radio_name)),SCHEMA_COLUMN(Wifi_Radio_Config,vap_configs)) == false)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: failed to update table_Wifi_VAP_Config table\n",__func__, __LINE__);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:  update table_Wifi_VAP_Config table successful\n",__func__, __LINE__);
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

        jrow  = ovsdb_sync_select_where(g_wifidb->wifidb_sock_path,SCHEMA_TABLE(Wifi_Global_Config),where);
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
        where = (json_t *)ovsdb_tran_cond(key_type, key_name, OFUNC_EQ, key);
        pcfg = ovsdb_table_select_where(g_wifidb->wifidb_sock_path, table, where, &count);

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
        ret = ovsdb_table_upsert_f(g_wifidb->wifidb_sock_path, table,cfg,false,filter);
    } else {
        where = ovsdb_tran_cond(key_type, key_name, OFUNC_EQ, key);
        ret = ovsdb_table_update_where_f(g_wifidb->wifidb_sock_path, table,where, cfg,filter);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Global Config update failed \n",__func__, __LINE__);
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
    
    if (wifidb_update_table_entry(NULL,NULL,OCLM_UUID,&table_Wifi_Global_Config,&cfg,filter_global) <= 0) 
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
    }
    else
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d  notify_wifi_changes %d  prefer_private %d  prefer_private_configure %d  factory_reset %d  tx_overflow_selfheal %d  inst_wifi_client_enabled %d  inst_wifi_client_reporting_period %d  inst_wifi_client_mac = %s inst_wifi_client_def_reporting_period %d  wifi_active_msmt_enabled %d  wifi_active_msmt_pktsize %d  wifi_active_msmt_num_samples %d  wifi_active_msmt_sample_duration %d  vlan_cfg_version %d  wps_pin = %s bandsteering_enable %d  good_rssi_threshold %d  assoc_count_threshold %d  assoc_gate_time %d  assoc_monitor_duration %d  rapid_reconnect_enable %d  vap_stats_feature %d  mfp_config_feature %d  force_disable_radio_feature %d  force_disable_radio_status %d  fixed_wmm_params %d  wifi_region_code %s diagnostic_enable %d  validate_ssid %d \n", __func__, __LINE__, config->notify_wifi_changes,config->prefer_private,config->prefer_private_configure,config->factory_reset,config->tx_overflow_selfheal,config->inst_wifi_client_enabled,config->inst_wifi_client_reporting_period,config->inst_wifi_client_mac, config->inst_wifi_client_def_reporting_period,config->wifi_active_msmt_enabled,config->wifi_active_msmt_pktsize,config->wifi_active_msmt_num_samples,config->wifi_active_msmt_sample_duration,config->vlan_cfg_version,config->wps_pin, config->bandsteering_enable,config->good_rssi_threshold,config->assoc_count_threshold,config->assoc_gate_time,config->assoc_monitor_duration,config->rapid_reconnect_enable,config->vap_stats_feature,config->mfp_config_feature,config->force_disable_radio_feature,config->force_disable_radio_status,config->fixed_wmm_params,config->wifi_region_code,config->diagnostic_enable,config->validate_ssid);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get global Config failed \n",__func__, __LINE__);
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
        strncpy(config->wps_pin,pcfg->wps_pin,sizeof(config->wps_pin)-1);
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
        strncpy(config->wifi_region_code,pcfg->wifi_region_code,sizeof(config->wifi_region_code)-1);
        config->diagnostic_enable = pcfg->diagnostic_enable;
        config->validate_ssid = pcfg->validate_ssid;
        wifi_util_dbg_print(WIFI_DB,"%s:%d  notify_wifi_changes %d  prefer_private %d  prefer_private_configure %d  factory_reset %d  tx_overflow_selfheal %d  inst_wifi_client_enabled %d  inst_wifi_client_reporting_period %d  inst_wifi_client_mac = %s inst_wifi_client_def_reporting_period %d  wifi_active_msmt_enabled %d  wifi_active_msmt_pktsize %d  wifi_active_msmt_num_samples %d  wifi_active_msmt_sample_duration %d  vlan_cfg_version %d  wps_pin = %s bandsteering_enable %d  good_rssi_threshold %d  assoc_count_threshold %d  assoc_gate_time %d  assoc_monitor_duration %d  rapid_reconnect_enable %d  vap_stats_feature %d  mfp_config_feature %d  force_disable_radio_feature %d  force_disable_radio_status %d  fixed_wmm_params %d  wifi_region_code %s diagnostic_enable %d  validate_ssid %d \n", __func__, __LINE__, config->notify_wifi_changes,config->prefer_private,config->prefer_private_configure,config->factory_reset,config->tx_overflow_selfheal,config->inst_wifi_client_enabled,config->inst_wifi_client_reporting_period,config->inst_wifi_client_mac, config->inst_wifi_client_def_reporting_period,config->wifi_active_msmt_enabled,config->wifi_active_msmt_pktsize,config->wifi_active_msmt_num_samples,config->wifi_active_msmt_sample_duration,config->vlan_cfg_version,config->wps_pin, config->bandsteering_enable,config->good_rssi_threshold,config->assoc_count_threshold,config->assoc_gate_time,config->assoc_monitor_duration,config->rapid_reconnect_enable,config->vap_stats_feature,config->mfp_config_feature,config->force_disable_radio_feature,config->force_disable_radio_status,config->fixed_wmm_params,config->wifi_region_code,config->diagnostic_enable,config->validate_ssid);
    
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

    where = ovsdb_tran_cond(OCLM_STR, "radio_name", OFUNC_EQ, radio_name);
    ret = ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Radio_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Radio Config delete radio_name=%s ret=%d\n",__func__, __LINE__,radio_name,ret);
    if(ret != 1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_Radio_Config delete failed\n",__func__, __LINE__);
        return -1;
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

    where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_VAP_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_VAP_Config delete failed\n",__func__, __LINE__);
        return -1;
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

    where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Security_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Security  Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_Security_Config delete failed\n",__func__, __LINE__);
        return -1;
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

    where = ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_name);
    ret = ovsdb_table_delete_where(g_wifidb->wifidb_sock_path, &table_Wifi_Interworking_Config, where);
    wifi_util_dbg_print(WIFI_DB,"%s:%d: Interworking Config delete vap_name=%s ret=%d\n",__func__, __LINE__,vap_name,ret);
    if(ret != 1)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: table_Wifi_Interworking_Config delete failed\n",__func__, __LINE__);
        return -1;
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
        wifi_util_dbg_print(WIFI_DB,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d deleted successfully\n",__func__, __LINE__);
        return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer update VAP Config failed \n",__func__, __LINE__);
        return -1;
    }
    ret = wifidb_update_wifi_global_config(config);
    if(ret == 0)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
        return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get global Config failed \n",__func__, __LINE__);
        return -1;
    }
    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&g_wifidb->global_config.global_parameters,sizeof(*config));
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

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get global Config failed \n",__func__, __LINE__);
        return -1;
    }
    g_wifidb = get_wifimgr_obj();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,global_config,sizeof(*config));
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP Config failed \n",__func__, __LINE__);
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

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP info failed \n",__func__, __LINE__);
        return -1;
    }

    i = convert_vap_name_to_index(vap_name);
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

    g_wifidb = get_wifimgr_obj();
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

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Get VAP info failed \n",__func__, __LINE__);
        return -1;
    }

    i = convert_vap_name_to_index(vap_name);
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

    g_wifidb = get_wifimgr_obj();
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

    i = convert_vap_name_to_index(vap_name);
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
    g_wifidb = get_wifimgr_obj();
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
int update_wifi_vap_config(int radio_index, wifi_vap_info_map_t *config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer update VAP Config failed \n",__func__, __LINE__);
        return -1;
    }
    ret = wifidb_update_wifi_vap_config(radio_index,config);
    if(ret == 0)
    {
	wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
	return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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
int update_wifi_vap_info(char *vap_name,wifi_vap_info_t *config)
{
    int ret = 0;

    if(config == NULL)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Update VAP info failed \n",__func__, __LINE__);
        return -1;
    } 
    ret = wifidb_update_wifi_vap_info(vap_name,config);
    if(ret == 0)
    {
	wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
	return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Update Security Config failed \n",__func__, __LINE__);
        return -1;
    }    
    ret = wifidb_update_wifi_security_config(vap_name,sec);
    if(ret == 0)
    {
	wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
	return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Update interworking Config failed \n",__func__, __LINE__);
        return -1;
    }    
    ret = wifidb_update_wifi_interworking_config(vap_name,config);
    if(ret == 0)
    {
	wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
	return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer Update Radio Config failed \n",__func__, __LINE__);
        return -1;
    } 
    ret = wifidb_update_wifi_radio_config(radio_index,config);
    if(ret == 0)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
	return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d:Null pointer update Gas Config failed \n",__func__, __LINE__);
        return -1;
    }
    ret = wifidb_update_gas_config(advertisement_id,gas_info);
    if(ret == 0)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d updated successfully\n",__func__, __LINE__);
        return 0;
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d failed\n",__func__, __LINE__);
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
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_radio_operationParam_t cfg;
    memset(&cfg,0,sizeof(cfg));
    char radio_name[BUFFER_LENGTH_WIFIDB] = {0};

    if (convert_radio_to_name(radio_index,radio_name) != 0)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Radio Config update failed \n",__func__, __LINE__);
        return -1;
    }
    strncpy(g_wifidb->radio_config[radio_index].name,radio_name,sizeof(g_wifidb->radio_config[radio_index].name)-1);
    if (radio_index  == 0) {
        cfg.band = WIFI_FREQUENCY_2_4_BAND;
        cfg.op_class = 12;
        cfg.channel = 1;
        cfg.channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        cfg.variant = WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AX;
        g_wifidb->radio_config[radio_index].vaps.radio_index = 0;
        g_wifidb->radio_config[radio_index].vaps.num_vaps = 8;
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[0].vap_index = 0;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[0].vap_name, "private_ssid_2g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[1].vap_index = 2;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[1].vap_name, "iot_ssid_2g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[2].vap_index = 4;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[2].vap_name, "hotspot_open_2g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[3].vap_index = 6;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[3].vap_name, "lnf_psk_2g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[4].vap_index = 8;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[4].vap_name, "hotspot_secure_2g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[5].vap_index = 10;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[5].vap_name, "lnf_radius_2g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[6].vap_index = 12;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[6].vap_name, "mesh_backhaul_2g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[7].vap_index = 14;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[7].vap_name, "mesh_sta_2g");
    } else if (radio_index  == 1) {
        cfg.band = WIFI_FREQUENCY_5_BAND;
        cfg.op_class = 1;
        cfg.channel = 36;
        cfg.channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX;
        g_wifidb->radio_config[radio_index].vaps.radio_index = 1;
        g_wifidb->radio_config[radio_index].vaps.num_vaps = 8;
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[0].vap_index = 1;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[0].vap_name, "private_ssid_5g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[1].vap_index = 3;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[1].vap_name, "iot_ssid_5g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[2].vap_index = 5;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[2].vap_name, "hotspot_open_5g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[3].vap_index = 7;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[3].vap_name, "lnf_psk_5g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[4].vap_index = 9;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[4].vap_name, "hotspot_secure_5g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[5].vap_index = 11;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[5].vap_name, "lnf_radius_5g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[6].vap_index = 13;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[6].vap_name, "mesh_backhaul_5g");
        g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[7].vap_index = 15;
        strcpy((char *)g_wifidb->radio_config[radio_index].vaps.rdk_vap_array[7].vap_name, "mesh_sta_5g");
    }

    cfg.enable = true;
    cfg.autoChannelEnabled = true;
    cfg.csa_beacon_count = 100;
    cfg.countryCode = wifi_countrycode_US;
    cfg.dtimPeriod = 2;
    cfg.beaconInterval = 100;
    cfg.fragmentationThreshold = 2346;
    cfg.transmitPower = 100;
    cfg.rtsThreshold = 2347;
    cfg.guardInterval = wifi_guard_interval_auto;
    cfg.ctsProtection = false;
    cfg.obssCoex = true;
    cfg.stbcEnable = true;
    cfg.greenFieldEnable = false;
    cfg.userControl = 1;
    cfg.adminControl = 254;
    cfg.chanUtilThreshold = 90;
    cfg.chanUtilSelfHealEnable = 0;
    cfg.factoryResetSsid = 0;
    cfg.basicDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_24MBPS;
    cfg.operationalDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_18MBPS;
    cfg.basicDataTransmitRates = WIFI_BITRATE_DEFAULT;
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_default_wifi_password
  Parameter   : passwod - Default password for private_ssid_2g and private_ssid_5g
  Description : Get password value from /tmp/factory_nvram.data
 *************************************************************************************
**************************************************************************************/
int get_default_wifi_password(char *password)
{

    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;
    fp = popen("grep \"Default WIFI Password:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");

    if(fp != NULL) {
        while (fgets(value, sizeof(value), fp) != NULL){
            wifi_util_dbg_print(WIFI_DB,"Default password is found \n");
        }
        pclose(fp);
        strncpy(password,value,strlen(value)-1);
        wifi_util_dbg_print(WIFI_DB,"Default wifi password is %s and length is %d\n",password,strlen(password));
        return RETURN_OK;
    }
    return RETURN_ERR;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifidb_init_rdk_vap_config_default
  Parameter   : vap_index - Index of vap
  Description : Update rdk wifi vap global cache with default value for rdk_wifi_vap_map_t
 *************************************************************************************
**************************************************************************************/
int wifidb_init_rdk_vap_config_default(int vap_instance, rdk_wifi_vap_map_t *config)
{
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    uint8_t radio_index = 0, vap_index = 0;
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};

    convert_vap_index_to_name(vap_instance, vap_name);
    get_vap_and_radio_index_from_vap_instance(vap_instance, &radio_index, &vap_index);

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    config->radio_index = radio_index;
    config->rdk_vap_array[vap_index].vap_index = vap_instance;
    strncpy((char *)config->rdk_vap_array[vap_index].vap_name, (char *)vap_name, sizeof(config->rdk_vap_array[vap_index].vap_name)-1);
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
int wifidb_init_vap_config_default(int vap_index,wifi_vap_info_t *config)
{
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_vap_info_t cfg;
    char vap_name[BUFFER_LENGTH_WIFIDB] = {0};
    char vap_password[BUFFER_LENGTH_WIFIDB] = {0};
    int r_index = 0;
    int vap_array_index = 0;

    memset(&cfg,0,sizeof(cfg));
    const char *vap_bridge[] = {"brlan0", "brlan0", "brlan1", "brlan1", "brlan2", "brlan3", "br106", "br106", "brlan4", "brlan5", "br106", "br106", "brlan112", "brlan113", "brlan1", "brlan1"};

    convert_vap_index_to_name(vap_index,vap_name);
    strncpy(cfg.vap_name,vap_name,sizeof(cfg.vap_name)-1);
    
    if ((vap_index == 14) || (vap_index == 15)) {
        cfg.vap_index = vap_index;
	if (cfg.vap_index%2==0) {
            r_index = 0;
        } else {
            r_index = 1;
        }
        cfg.radio_index = r_index;
        cfg.vap_mode = wifi_vap_mode_sta;
        cfg.u.sta_info.enabled = false;
        strncpy(cfg.u.sta_info.ssid, vap_name, sizeof(cfg.u.sta_info.ssid)-1);
        cfg.u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
        cfg.u.sta_info.security.encr = wifi_encryption_aes_tkip;
        strcpy(cfg.u.sta_info.security.u.key.key, "123456789");
        snprintf(cfg.bridge_name, sizeof(cfg.bridge_name), vap_bridge[vap_index]);
        cfg.u.sta_info.scan_params.period = 10;
        if (r_index == 0) {
            cfg.u.sta_info.scan_params.channel.channel = 3;
            cfg.u.sta_info.scan_params.channel.band = WIFI_FREQUENCY_2_4_BAND;
        } else if (r_index == 1) {
            cfg.u.sta_info.scan_params.channel.channel = 36;
            cfg.u.sta_info.scan_params.channel.band = WIFI_FREQUENCY_5_BAND;
        }
        memset(&cfg.u.sta_info.bssid, 0, sizeof(cfg.u.sta_info.bssid));
	cfg.u.bss_info.beaconRate = WIFI_BITRATE_6MBPS;
    } else {
        strncpy(cfg.u.bss_info.ssid,vap_name,sizeof(cfg.u.bss_info.ssid)-1);
        cfg.u.bss_info.wmm_enabled = true;
        if (vap_index == 4 || vap_index == 5 || vap_index == 8 || vap_index == 9) {
            cfg.u.bss_info.bssMaxSta = 5;
            cfg.u.bss_info.isolation  = 1;
        } else {
            cfg.u.bss_info.bssMaxSta = 30;
            cfg.u.bss_info.isolation  = 0;
        }
        cfg.u.bss_info.bssTransitionActivated = false;
        cfg.u.bss_info.nbrReportActivated = false;
        if (vap_index == 0 || vap_index == 1) {
            cfg.u.bss_info.vapStatsEnable = true;
            cfg.u.bss_info.wpsPushButton = 1;
	    cfg.u.bss_info.wps.enable = true;
            cfg.u.bss_info.rapidReconnectEnable = true;
        } else {
            cfg.u.bss_info.vapStatsEnable = false;
            cfg.u.bss_info.rapidReconnectEnable = false;
        }
        cfg.u.bss_info.rapidReconnThreshold = 180;
        cfg.u.bss_info.mac_filter_enable = false;
        cfg.u.bss_info.UAPSDEnabled = true;
        cfg.u.bss_info.wmmNoAck = true;
        cfg.u.bss_info.wepKeyLength = 128;
        if (vap_index == 4 || vap_index == 5) {
            cfg.u.bss_info.bssHotspot = true;
            cfg.u.bss_info.security.mode = wifi_security_mode_none;
            cfg.u.bss_info.security.encr = wifi_encryption_none;
        } else if (vap_index == 8 || vap_index == 9) {
	    cfg.u.bss_info.bssHotspot = true;
            cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
            cfg.u.bss_info.security.encr = wifi_encryption_aes_tkip;
            strcpy(cfg.u.bss_info.security.u.key.key, "123456789");
        } else if (vap_index == 10 || vap_index == 11) {
            cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
            cfg.u.bss_info.security.encr = wifi_encryption_aes_tkip;
            strcpy(cfg.u.bss_info.security.u.key.key, "123456789");
        } else if (vap_index == 0 || vap_index == 1)  {
            cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
            memset(vap_password, 0, sizeof(vap_password));
            if (get_default_wifi_password(vap_password) == RETURN_OK) {
                wifi_util_dbg_print(WIFI_DB,"private vap_password is %s and length is %d\n",vap_password,strlen(vap_password));
                strcpy(cfg.u.bss_info.security.u.key.key, vap_password);
            } else {
                strcpy(cfg.u.bss_info.security.u.key.key, "123456789");
            }

            cfg.u.bss_info.bssHotspot = false;
        } else {
            cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            cfg.u.bss_info.security.encr = wifi_encryption_aes_tkip;
            strcpy(cfg.u.bss_info.security.u.key.key, "123456789");
            cfg.u.bss_info.bssHotspot = false;
        }
        cfg.u.bss_info.beaconRate = WIFI_BITRATE_6MBPS;
        strncpy(cfg.u.bss_info.beaconRateCtl,"6Mbps",sizeof(cfg.u.bss_info.beaconRateCtl)-1);
        cfg.u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        snprintf(cfg.u.bss_info.wps.pin, sizeof(cfg.u.bss_info.wps.pin), "123456");
        cfg.vap_index = vap_index;
        vap_array_index = convert_vap_name_to_array_index(cfg.vap_name);
        if (vap_array_index == -1) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: %s invalid vap name \n",__func__, __LINE__,cfg.vap_name);
            return -1;
        }
        if (cfg.vap_index%2==0) {
            r_index = 0;
        } else {
            r_index = 1;
        }
        cfg.radio_index = r_index;
        cfg.vap_mode = wifi_vap_mode_ap;
        if ((vap_index == 0) || (vap_index == 1)) {
	    memset(vap_name, 0, sizeof(vap_name));
            if (get_ssid_from_device_mac(vap_name) == RETURN_OK) {
	        strncpy(cfg.u.bss_info.ssid, vap_name, sizeof(cfg.u.bss_info.ssid)-1);
	    }
            cfg.u.bss_info.enabled = true;
        } else {
            cfg.u.bss_info.enabled = false;
        }
        cfg.u.bss_info.showSsid = true;
        snprintf(cfg.bridge_name, sizeof(cfg.bridge_name), vap_bridge[vap_index]);
        char str[600] = {0};
        snprintf(str,sizeof(str),"%s"," { \"ANQP\":{ \"IPAddressTypeAvailabilityANQPElement\":{ \"IPv6AddressType\":0, \"IPv4AddressType\":0}, \"DomainANQPElement\":{\"DomainName\":[]}, \"NAIRealmANQPElement\":{\"Realm\":[]}, \"3GPPCellularANQPElement\":{ \"GUD\":0, \"PLMN\":[]}, \"RoamingConsortiumANQPElement\": { \"OI\": []}, \"VenueNameANQPElement\": { \"VenueInfo\": []}}}");
        snprintf((char *)cfg.u.bss_info.interworking.anqp.anqpParameters,sizeof(cfg.u.bss_info.interworking.anqp.anqpParameters),"%s",str);
        memset(str,0,sizeof(str));
        snprintf(str,sizeof(str),"%s","{ \"Passpoint\":{ \"PasspointEnable\":false, \"NAIHomeRealmANQPElement\":{\"Realms\":[]}, \"OperatorFriendlyNameANQPElement\":{\"Name\":[]}, \"ConnectionCapabilityListANQPElement\":{\"ProtoPort\":[]}, \"GroupAddressedForwardingDisable\":true, \"P2pCrossConnectionDisable\":false}}");
        snprintf((char *)cfg.u.bss_info.interworking.passpoint.hs2Parameters,sizeof(cfg.u.bss_info.interworking.passpoint.hs2Parameters),"%s",str);
    }

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
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
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    memset(&cfg,0,sizeof(cfg));

    cfg.notify_wifi_changes = true;
    cfg.prefer_private =  true;
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
    strncpy(cfg.wifi_region_code, "USI",sizeof(cfg.wifi_region_code)-1);
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
    strncpy(cfg.wps_pin, "1234",sizeof(cfg.wps_pin)-1);
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
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    convert_vap_index_to_name(vapIndex,vap_name);
    interworking.interworkingEnabled = 0;
    interworking.asra = 0;
    interworking.esr = 0;
    interworking.uesa = 0;
    interworking.hessOptionPresent = 1;
    strcpy(interworking.hessid,"11:22:33:44:55:66");
    if ( (vapIndex == 5) || (vapIndex == 6) || (vapIndex == 9) || (vapIndex == 10) )    //Xfinity hotspot vaps
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
    int vap_array_index = 0;
    int num_radio = getNumberRadios();
    wifi_vap_info_map_t *l_vap_param_cfg = NULL;
    wifi_radio_operationParam_t *l_radio_cfg = NULL;
    rdk_wifi_vap_map_t *l_rdk_wifi_cfg = NULL;

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
        memset(l_vap_param_cfg, 0, sizeof(wifi_vap_info_map_t));
        l_vap_param_cfg->num_vaps = MAX_NUM_VAP_PER_RADIO;
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
    for (vap_index = 0; vap_index < ((int) getTotalNumberVAPs()); vap_index++)
    {
        if(vap_index%2==0)
        {
            r_index = 0;
        }
        else
        {
            r_index = 1;
        }
        l_vap_param_cfg = get_wifidb_vap_map(r_index);
        if(l_vap_param_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d invalid get_wifidb_vap_parameters \n",__func__, __LINE__);
            return ;
        }

    l_rdk_wifi_cfg = getRdkWifiVap(r_index);
        if(l_rdk_wifi_cfg == NULL)
        {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: invalid get Rdk Wifi Vap vap_index:%d\n",__func__, __LINE__,vap_index);
            return ;
        }
        vap_array_index = vap_index/2;
        wifidb_init_vap_config_default(vap_index,&l_vap_param_cfg->vap_array[vap_array_index]);
        wifidb_init_rdk_vap_config_default(vap_index, l_rdk_wifi_cfg);
        wifidb_init_interworking_config_default(vap_index, &l_vap_param_cfg->vap_array[vap_array_index].u.bss_info.interworking.interworking);
    }

    wifidb_init_global_config_default(&g_wifidb->global_config.global_parameters);
    wifidb_reset_macfilter_hashmap();
    wifidb_init_gas_config_default(&g_wifidb->global_config.gas_config);
    wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi db update completed\n",__func__, __LINE__);

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
    int r_index = 0;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    int num_radio = getNumberRadios();
	wifi_vap_info_map_t *l_vap_param_cfg = NULL;
    wifi_radio_operationParam_t *l_radio_cfg = NULL;

    wifi_util_dbg_print(WIFI_DB,"%s:%d No of radios %d\n",__func__, __LINE__,getNumberRadios());

    //Check for the number of radios
    if (num_radio > MAX_NUM_RADIOS)
    {
        wifi_util_dbg_print(WIFI_DB,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return ;
    }
    wifidb_init_default_value();
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    for (r_index = 0; r_index < num_radio; r_index++)
    {
		l_vap_param_cfg = get_wifidb_vap_map(r_index);
		if(l_vap_param_cfg == NULL)
		{
			wifi_util_dbg_print(WIFI_DB,"%s:%d: invalid get_wifidb_vap_map \n",__func__, __LINE__);
			return;
		}
		l_radio_cfg = get_wifidb_radio_map(r_index);
		if(l_radio_cfg == NULL)
		{
			wifi_util_dbg_print(WIFI_DB,"%s:%d: invalid get_wifidb_radio_map \n",__func__, __LINE__);
			return;
		}
        wifidb_get_wifi_radio_config(r_index, l_radio_cfg);
        wifidb_get_wifi_vap_config(r_index, l_vap_param_cfg);
    }
    wifidb_get_wifi_macfilter_config();
    wifidb_get_wifi_global_config(&g_wifidb->global_config.global_parameters);
    wifidb_get_gas_config(g_wifidb->global_config.gas_config.AdvertisementID,&g_wifidb->global_config.gas_config);
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    wifi_util_dbg_print(WIFI_DB,"%s:%d Wifi data init complete\n",__func__, __LINE__);

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

    OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Radio_Config, true);
    OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_VAP_Config, true);
    OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Security_Config, true);
    OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Interworking_Config, true);
    OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_GAS_Config, true);
    OVSDB_TABLE_MONITOR(g_wifidb->wifidb_fd, Wifi_Global_Config, true);
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

    unsigned int attempts = 0;
    g_wifidb->wifidb_ev_loop = ev_loop_new(0);
    if (!g_wifidb->wifidb_ev_loop) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Could not find default target_loop\n", __func__, __LINE__);
        return -1;
    }
    OVSDB_TABLE_INIT(Wifi_Device_Config, device_mac);
    OVSDB_TABLE_INIT(Wifi_Security_Config,vap_name);
    OVSDB_TABLE_INIT(Wifi_Interworking_Config, vap_name);
    OVSDB_TABLE_INIT(Wifi_GAS_Config, advertisement_id);
    OVSDB_TABLE_INIT(Wifi_VAP_Config, vap_name);
    OVSDB_TABLE_INIT(Wifi_Radio_Config, radio_name);
    OVSDB_TABLE_INIT(Wifi_MacFilter_Config, macfilter_key);
    OVSDB_TABLE_INIT_NO_KEY(Wifi_Global_Config);
    //connect to wifidb with sock path
    snprintf(g_wifidb->wifidb_sock_path, sizeof(g_wifidb->wifidb_sock_path), "%s/wifidb.sock", WIFIDB_RUN_DIR);
    while (attempts < 3) {
        if ((g_wifidb->wifidb_fd = ovsdb_conn(g_wifidb->wifidb_sock_path)) < 0) {
            wifi_util_dbg_print(WIFI_DB,"%s:%d:Failed to connect to wifidb at %s\n",
                __func__, __LINE__, g_wifidb->wifidb_sock_path);
            attempts++;
            sleep(1);
            if (attempts == 3) {
                return -1;
            }
        } else {
            break;
        }
    }
    wifi_util_dbg_print(WIFI_DB,"%s:%d:Connection to wifidb at %s successful\n",
            __func__, __LINE__, g_wifidb->wifidb_sock_path);
    //init evloop for wifidb
    if (ovsdb_init_loop(g_wifidb->wifidb_fd, &g_wifidb->wifidb_ev_io, g_wifidb->wifidb_ev_loop) == false) 
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Could not find default target_loop\n", __func__, __LINE__);
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
    bool debug_option = true;
    DIR     *wifiDbDir = NULL;
    
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
        wifi_util_dbg_print(WIFI_DB,"%s:%d: rdkb database already present\n", __func__, __LINE__);
        sprintf(cmd,"ovsdb-tool convert %s %s/rdkb-wifi.ovsschema",db_file,WIFIDB_SCHEMA_DIR);
        wifi_util_dbg_print(WIFI_DB,"%s:%d: rdkb database check for version upgrade/downgrade %s \n", __func__, __LINE__,cmd);
        system(cmd);
    }
    
    sprintf(cmd, "%s/wifidb-server %s --remote=punix:%s/wifidb.sock %s --unixctl=%s/wifi.ctl --log-file=%s/wifidb.log --detach", WIFIDB_RUN_DIR, db_file, WIFIDB_RUN_DIR, (debug_option == true)?"--verbose=dbg":"", WIFIDB_RUN_DIR, WIFIDB_RUN_DIR);
    
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

