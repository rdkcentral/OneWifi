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

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "cJSON.h"
#include "wifi_hal.h"
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
#include <assert.h>
#include "collection.h"
#include "wifi_db.h"
#if DML_SUPPORT
#include "ccsp_base_api.h"
#endif // DML_SUPPORT

#include "wifi_util.h"
#include "wifi_mgr.h"

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

void init_wifidb(void)
{
    if (!is_db_consolidated()) {
        start_wifidb();
    }
    init_wifidb_tables();
    //init_wifidb_data();//TBD
    start_wifidb_monitor();
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
        params->op_class = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_G;
    } else if (radio_index == 1) {
        params->band = WIFI_FREQUENCY_5_BAND;
        params->op_class = 1;
        params->channel = 36;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_A;
    } else if (radio_index == 2) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->op_class = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_N;
    } else if (radio_index == 3) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->op_class = 12;
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
