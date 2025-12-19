/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2025 RDK Management
  
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

#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_db.h"
#include "wifi_util.h"
#include "wifi_mgr.h"

#ifdef ONEWIFI_DB_SUPPORT
extern void init_wifidb(void);
extern void init_wifidb_data(void);
extern int update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config);
extern int start_wifidb();
extern void wifidb_print(char *format, ...);
extern int wifidb_get_wifi_vap_info(char *vap_name, wifi_vap_info_t *config, rdk_wifi_vap_info_t *rdk_config);
extern int wifidb_update_wifi_macfilter_config(char *macfilter_key, acl_entry_t *config, bool add);
extern void wifidb_cleanup();
extern int init_wifidb_tables();
extern void wifidb_init_default_value();
extern int start_wifidb_monitor();
extern int wifidb_update_rfc_config(UINT rfc_id, wifi_rfc_dml_parameters_t *rfc_param);
extern int wifidb_init_global_config_default(wifi_global_param_t *config);
extern int wifidb_init_radio_config_default(int radio_index,wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config);
extern int wifidb_init_vap_config_default(int vap_index, wifi_vap_info_t *config, rdk_wifi_vap_info_t *rdk_config);
extern int wifidb_update_wifi_security_config(char *vap_name, wifi_vap_security_t *sec);
extern int wifidb_get_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info);
extern int wifidb_update_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info);
extern int update_wifi_vap_info(char *vap_name,wifi_vap_info_t *config,rdk_wifi_vap_info_t *rdk_config);
extern int update_wifi_interworking_config(char *vap_name, wifi_interworking_t *config);
extern int update_wifi_global_config(wifi_global_param_t *config);
extern int wifidb_update_wifi_passpoint_config(char *vap_name, wifi_interworking_t *config);
extern int wifidb_update_wifi_anqp_config(char *vap_name, wifi_interworking_t *config);
extern int update_wifi_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info);
extern int wifidb_update_wifi_cac_config(wifi_vap_info_map_t *config);
extern int wifidb_update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config);
extern int get_wifi_global_param(wifi_global_param_t *config);
#else
void init_wifidb(void)
{
    init_wifidb_data();

    /* Set Wifi Global Parameters */
    init_wifi_global_config();
}

#define OFFCHAN_DEFAULT_TSCAN_IN_MSEC 63
#define OFFCHAN_DEFAULT_NSCAN_IN_SEC 10800
#define OFFCHAN_DEFAULT_TIDLE_IN_SEC 5
#define DEFAULT_MANAGED_WIFI_SPEED_TIER 2
#define DFS_DEFAULT_TIMER_IN_MIN 30

static int init_radio_config_default(int radio_index, wifi_radio_operationParam_t *config,
    wifi_radio_feature_param_t *feat_config)
{
    int band;
    char country_code[4] = {0};
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
            cfg.variant = WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N;
            break;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
            cfg.operatingClass = 128;
            cfg.channel = 44;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX;

#ifdef CONFIG_IEEE80211BE
            cfg.variant |= WIFI_80211_VARIANT_BE;
#endif /* CONFIG_IEEE80211BE */
            break;
        case WIFI_FREQUENCY_5H_BAND:
            cfg.operatingClass = 128;
            cfg.channel = 157;
            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
            cfg.variant = WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX;

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
//            cfg.channelWidth = WIFI_CHANNELBANDWIDTH_320MHZ;
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
    cfg.basicDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_24MBPS;
    cfg.operationalDataTransmitRates = WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS | WIFI_BITRATE_12MBPS | WIFI_BITRATE_18MBPS | WIFI_BITRATE_24MBPS | WIFI_BITRATE_36MBPS | WIFI_BITRATE_48MBPS | WIFI_BITRATE_54MBPS;
    Fcfg.radio_index = radio_index;
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
        for (int j = 0; j < 5; j++) {
            cfg.amsduTid[j] = TRUE;
        }
    } else {
        for (int j = 0; j < 4; j++) {
            cfg.amsduTid[j] = TRUE;
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

static void init_gas_config_default(wifi_GASConfiguration_t *config)
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

static int init_interworking_config_default(int vapIndex,
    void /*wifi_InterworkingElement_t*/ *config)
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

static int init_vap_config_default(int vap_index, wifi_vap_info_t *config,
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
                cfg.u.sta_info.security.mfp = wifi_mfp_cfg_disabled;
                cfg.u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
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
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.bssTransitionActivated = true;
            cfg.u.bss_info.nbrReportActivated = true;
        } else {
            cfg.u.bss_info.bssTransitionActivated = false;
            cfg.u.bss_info.nbrReportActivated = false;
        }

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
            cfg.u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;
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
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            }
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
            cfg.u.bss_info.bssHotspot = false;
        } else  {
            if (band == WIFI_FREQUENCY_6_BAND) {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                cfg.u.bss_info.security.wpa3_transition_disable = false;
                cfg.u.bss_info.security.mfp = wifi_mfp_cfg_required;
                cfg.u.bss_info.security.u.key.type = wifi_security_key_type_sae;
            } else {
                cfg.u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            }
            cfg.u.bss_info.security.encr = wifi_encryption_aes;
            cfg.u.bss_info.bssHotspot = false;
            cfg.u.bss_info.mbo_enabled = false;
        }
        cfg.u.bss_info.beaconRate = WIFI_BITRATE_6MBPS;
        strncpy(cfg.u.bss_info.beaconRateCtl,"6Mbps",sizeof(cfg.u.bss_info.beaconRateCtl)-1);
        cfg.vap_mode = wifi_vap_mode_ap;
        /*TODO: Are values correct?  */
        cfg.u.bss_info.mld_info.common_info.mld_enable = 0;
        cfg.u.bss_info.mld_info.common_info.mld_id = 255;
        cfg.u.bss_info.mld_info.common_info.mld_link_id = 255;
        cfg.u.bss_info.mld_info.common_info.mld_apply = 1;
//        strcpy(cfg.u.bss_info.mld_info.common_info.mld_addr, "11:11:11:11:11:11");
        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.showSsid = true;
            cfg.u.bss_info.wps.methods = WIFI_ONBOARDINGMETHODS_PUSHBUTTON;
            memset(wps_pin, 0, sizeof(wps_pin));
            if ((wifi_hal_get_default_wps_pin(wps_pin) == RETURN_OK) && ((strlen(wps_pin) != 0))) {
                strcpy(cfg.u.bss_info.wps.pin, wps_pin);
            } else {
                wifi_util_error_print(WIFI_DB, "%s:%d: Incorrect wps pin for vap '%s'\n", __func__, __LINE__, vap_name);
                strcpy(cfg.u.bss_info.wps.pin, "12345678");
            }
        }
        else if (isVapHotspot(vap_index)) {
            cfg.u.bss_info.showSsid = true;
        } else {
            cfg.u.bss_info.showSsid = false;
        }
/*For XER5/XB10/XER10 2.4G XHS is disable by default*/
#if defined(_XER5_PRODUCT_REQ_) || defined(_XB10_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_)
        if (isVapLnfSecure(vap_index) || isVapPrivate(vap_index)) {
            cfg.u.bss_info.enabled = true;
        }
#else
        if ((vap_index == 2) || isVapLnfSecure(vap_index) || isVapPrivate(vap_index)) {
            cfg.u.bss_info.enabled = true;
        }
#endif 
        if (isVapLnfPsk(vap_index)) {
            cfg.u.bss_info.enabled = false;
        }

        if (isVapPrivate(vap_index)) {
            cfg.u.bss_info.bssMaxSta = wifi_hal_cap_obj->wifi_prop.BssMaxStaAllow;
        } else {
            cfg.u.bss_info.bssMaxSta = BSS_MAX_NUM_STA_COMMON;
        }

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
            //set_lnf_radius_server_ip(&cfg.u.bss_info.security);
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
    }

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(config,&cfg,sizeof(cfg));
    if(exists == false) {
        wifi_util_error_print(WIFI_DB,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap_index);
        exists = true;
    }

    rdk_config->exists = exists;
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    return RETURN_OK;
}


void init_wifidb_data(void)
{
    int index, vap_index;
    int num_radio = getNumberRadios();
    wifi_radio_operationParam_t *radio_oper_conf;
    wifi_radio_feature_param_t *radio_feat_conf;
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();

    for (index = 0; index < num_radio; index++) {
        radio_oper_conf = get_wifidb_radio_map(index);
        if (radio_oper_conf == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: failed to get radio oper configuration for index %d\n",
                __func__, __LINE__, index);
            return;
        }

        radio_feat_conf = get_wifidb_radio_feat_map(index);
        if (radio_feat_conf == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: failed to get radio feature configuration for index %d\n",
                __func__, __LINE__, index);
            return;
        }

        init_radio_config_default(index, radio_oper_conf, radio_feat_conf);
    }

    for (index = 0; index < getTotalNumberVAPs(); index++)
    {
        vap_index = VAP_INDEX(g_wifidb->hal_cap, index);
        wifi_vap_info_t *vapInfo = getVapInfo(vap_index);
        if (vapInfo == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: failed to get vap info for index %d\n",
                __func__, __LINE__, vap_index);
            continue;
        }
        rdk_wifi_vap_info_t *rdkVapInfo = getRdkVapInfo(vap_index);
        if (rdkVapInfo == NULL) {
            wifi_util_dbg_print(WIFI_DB, "%s:%d: failed to get rdk vap info for index %d\n",
                __func__, __LINE__, vap_index);
            continue;
        }

        init_vap_config_default(vap_index, vapInfo, rdkVapInfo);
        init_interworking_config_default(vap_index, &vapInfo->u.bss_info.interworking.interworking);
        init_gas_config_default(&g_wifidb->global_config.gas_config);

    }

}

int update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config,
    wifi_radio_feature_param_t *feat_config)
{
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    wifi_radio_operationParam_t *radio_oper_conf;
    wifi_radio_feature_param_t *radio_feat_conf;

    if ((config == NULL) || (feat_config == NULL) || (g_wifidb == NULL)) {
        wifidb_print(
            "%s:%d Failed to update Radio Config and Radio Feat Config for radio_index %d \n",
            __func__, __LINE__, radio_index);
        return -1;
    }

    radio_oper_conf = get_wifidb_radio_map(radio_index);
    if (radio_oper_conf == NULL) {
        wifi_util_dbg_print(WIFI_DB, "%s:%d: failed to get radio oper configuration for index %d\n",
            __func__, __LINE__, radio_index);
        return -1;
    }

    radio_feat_conf = get_wifidb_radio_feat_map(radio_index);
    if (radio_feat_conf == NULL) {
        wifi_util_dbg_print(WIFI_DB,
            "%s:%d: failed to get radio feature configuration for index %d\n", __func__, __LINE__,
            radio_index);
        return -1;
    }

    wifi_util_dbg_print(WIFI_DB, "%s:%d:Update Radio Config for radio_index=%d \n", __func__,
        __LINE__, radio_index);

    /* Call the function to update the operating classes based on Country code and Radio */
    update_radio_operating_classes(config);
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    memcpy(radio_oper_conf, config, sizeof(wifi_radio_operationParam_t));
    memcpy(radio_feat_conf, feat_config, sizeof(wifi_radio_feature_param_t));
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    wifi_util_dbg_print(WIFI_DB,
        "%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  "
        "channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d dcs_enabled=%d "
        "numSecondaryChannels=%d dtim_period %d beacon_interval %d "
        "operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  "
        "fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d "
        "factory_reset_ssid = %d  radio_stats_measuring_rate = %d   radio_stats_measuring_interval "
        "= %d cts_protection = %d obss_coex = %d  stbc_enable = %d  greenfield_enable = %d "
        "user_control = %d  admin_control = %d  chan_util_threshold = %d  "
        "chan_util_selfheal_enable = %d  eco_power_down = %d DFSTimer:%d radarDetected:%s \n",
        __func__, __LINE__, config->enable, config->band, config->autoChannelEnabled,
        config->channel, config->channelWidth, config->variant, config->csa_beacon_count,
        config->countryCode, config->DCSEnabled, config->numSecondaryChannels, config->dtimPeriod,
        config->beaconInterval, config->operatingClass, config->basicDataTransmitRates,
        config->operationalDataTransmitRates, config->fragmentationThreshold, config->guardInterval,
        config->transmitPower, config->rtsThreshold, config->factoryResetSsid,
        config->radioStatsMeasuringRate, config->radioStatsMeasuringInterval, config->ctsProtection,
        config->obssCoex, config->stbcEnable, config->greenFieldEnable, config->userControl,
        config->adminControl, config->chanUtilThreshold, config->chanUtilSelfHealEnable,
        config->EcoPowerDown, config->DFSTimer, config->radarDetected);
    wifi_util_dbg_print(WIFI_DB, " %s:%d Wifi_Radio_Config data Tscan=%lu Nscan=%lu Tidle=%lu \n",
        __FUNCTION__, __LINE__, feat_config->OffChanTscanInMsec, feat_config->OffChanNscanInSec,
        feat_config->OffChanTidleInSec);
    return 0;
}

int start_wifidb()
{
    return 0;
}

void wifidb_print(char *format, ...)
{

}

int wifidb_get_wifi_vap_info(char *vap_name, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    return 0;
}

int wifidb_update_wifi_macfilter_config(char *macfilter_key, acl_entry_t *config, bool add)
{
    return 0;
}

void wifidb_cleanup()
{

}

int init_wifidb_tables()
{
    return 0;
}

void wifidb_init_default_value()
{

}

int start_wifidb_monitor()
{
    return 0;
}
int wifidb_update_rfc_config(UINT rfc_id, wifi_rfc_dml_parameters_t *rfc_param)
{
    return 0;
}

int wifidb_init_global_config_default(wifi_global_param_t *config)
{
    return 0;
}

int wifidb_init_radio_config_default(int radio_index,wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    return 0;
}

int wifidb_init_vap_config_default(int vap_index, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    return 0;
}

int wifidb_update_wifi_security_config(char *vap_name, wifi_vap_security_t *sec)
{
    return 0;
}

int wifidb_get_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    return 0;
}

int wifidb_update_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    return 0;
}

int update_wifi_vap_info(char *vap_name,wifi_vap_info_t *config,rdk_wifi_vap_info_t *rdk_config)
{
    return 0;
}

int update_wifi_interworking_config(char *vap_name, wifi_interworking_t *config)
{
    return 0;
}

int update_wifi_global_config(wifi_global_param_t *config)
{
    return 0;
}

int wifidb_update_wifi_passpoint_config(char *vap_name, wifi_interworking_t *config)
{
    return 0;
}

int wifidb_update_wifi_anqp_config(char *vap_name, wifi_interworking_t *config)
{
    return 0;
}
int update_wifi_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    return 0;
}

int wifidb_update_wifi_cac_config(wifi_vap_info_map_t *config)
{
    return 0;
}

int wifidb_update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    return update_wifi_radio_config(radio_index, config, feat_config);
}

int get_wifi_global_param(wifi_global_param_t *config)
{
   return 0;
}
#endif
void wifidb_init(wifi_db_t *db)
{
    db->desc.init_fn = init_wifidb;
    db->desc.init_data_fn = init_wifidb_data;
    db->desc.update_radio_cfg_fn = update_wifi_radio_config;
    db->desc.update_wifi_vap_info_fn = update_wifi_vap_info;
    db->desc.start_wifidb_fn = start_wifidb;
    db->desc.print_fn = wifidb_print;
    db->desc.get_wifi_vpa_info_fn = wifidb_get_wifi_vap_info;
    db->desc.update_wifi_macfilter_config_fn = wifidb_update_wifi_macfilter_config;
    db->desc.cleanup_fn = wifidb_cleanup;
    db->desc.init_tables_fn = init_wifidb_tables;
    db->desc.init_default_value_fn = wifidb_init_default_value;
    db->desc.start_monitor_fn = start_wifidb_monitor;
    db->desc.update_rfc_config_fn = wifidb_update_rfc_config;
    db->desc.init_global_config_default_fn = wifidb_init_global_config_default;
    db->desc.init_radio_config_default_fn = wifidb_init_radio_config_default;
    db->desc.init_vap_config_default_fn = wifidb_init_vap_config_default;
    db->desc.update_wifi_security_config_fn = wifidb_update_wifi_security_config;
    db->desc.get_gas_config_fn = wifidb_get_gas_config;
    db->desc.update_gas_config_fn = wifidb_update_gas_config;
    db->desc.update_wifi_interworking_cfg_fn = update_wifi_interworking_config;
    db->desc.update_wifi_global_cfg_fn = update_wifi_global_config;
    db->desc.update_wifi_passpoint_cfg_fn = wifidb_update_wifi_passpoint_config;
    db->desc.update_wifi_anqp_cfg_fn = wifidb_update_wifi_anqp_config;
    db->desc.update_wifi_gas_cfg_fn = update_wifi_gas_config;
    db->desc.update_wifi_cac_cfg_fn = wifidb_update_wifi_cac_config;
    db->desc.update_wifi_radio_cfg_fn = wifidb_update_wifi_radio_config;
    db->desc.get_wifi_global_param_fn = get_wifi_global_param;

}
