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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "cJSON.h"
#include "wifi_webconfig.h"
#include "ctype.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"

webconfig_error_t encode_radio_setup_object(const rdk_wifi_vap_map_t *vap_map, cJSON *radio_object)
{
    cJSON *obj_array, *obj;
    unsigned int i;

    // RadioIndex
    cJSON_AddNumberToObject(radio_object, "RadioIndex", vap_map->radio_index);

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(radio_object, "VapMap", obj_array);

    for (i = 0; i < vap_map->num_vaps; i++) {
        obj = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj);

        cJSON_AddStringToObject(obj, "VapName", (char *)vap_map->rdk_vap_array[i].vap_name);
        cJSON_AddNumberToObject(obj, "VapIndex", vap_map->rdk_vap_array[i].vap_index);

    }

    return webconfig_error_none;
}

webconfig_error_t encode_radio_object(const rdk_wifi_radio_t *radio, cJSON *radio_object)
{
    const wifi_radio_operationParam_t *radio_info;
    const wifi_radio_feature_param_t *radio_feat;
    char channel_list[BUFFER_LENGTH_WIFIDB] = {0}, str[BUFFER_LENGTH_WIFIDB] = {0};
    char chan_buf[512] = {0};
    unsigned int num_channels, i, k = 0, len = sizeof(channel_list) - 1;
    int itr = 0, arr_size = 0;
    cJSON *obj;
    CHAR buf[512] = {'\0'};
    UINT index = 0;

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(radio_object, "WifiRadioSetup", obj);
    if (encode_radio_setup_object(&radio->vaps, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Radio setup encode failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }


    // RadioName
    cJSON_AddStringToObject(radio_object, "RadioName", radio->name);

    radio_info = &radio->oper;
    radio_feat = &radio->feature;

    if (validate_radio_parameters(radio_info) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Radio parameters validatation failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    // Enabled
    cJSON_AddBoolToObject(radio_object, "Enabled", radio_info->enable);

    // FreqBand
    cJSON_AddNumberToObject(radio_object, "FreqBand", radio_info->band);

    // AutoChannelEnabled
    cJSON_AddBoolToObject(radio_object, "AutoChannelEnabled", radio_info->autoChannelEnabled);

    // Channel
    cJSON_AddNumberToObject(radio_object, "Channel", radio_info->channel);

    // NumSecondaryChannels
    cJSON_AddNumberToObject(radio_object, "NumSecondaryChannels", radio_info->numSecondaryChannels);
    num_channels = (int) radio_info->numSecondaryChannels;
    for (i = 0; i < num_channels; i++) {
        if (k >= (len - 1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Wifi_Radio_Config table Maximum size reached for secondary_channels_list\n",__func__, __LINE__);
            break;
        }

        snprintf(channel_list + k, sizeof(channel_list) - k,"%d,", radio_info->channelSecondary[i]);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Wifi_Radio_Config table Channel list %s %d\t",__func__, __LINE__,channel_list,strlen(channel_list));
        k = strlen(channel_list);
    }

    memset(str, 0, sizeof(str));
    if ((strlen(channel_list) > 1) && (strlen(channel_list) < sizeof(str))) {
        strncpy(str,channel_list,strlen(channel_list)-1);
    } else {
        strcpy(str, " ");
    }

    //SecondaryChannelsList
    cJSON_AddStringToObject(radio_object, "SecondaryChannelsList",str);

    // ChannelWidth
    cJSON_AddNumberToObject(radio_object, "ChannelWidth", radio_info->channelWidth);

    // HwMode
    cJSON_AddNumberToObject(radio_object, "HwMode", radio_info->variant);

    // CsaBeaconCountcountryCode
    cJSON_AddNumberToObject(radio_object, "CsaBeaconCount", radio_info->csa_beacon_count);

    k = radio_info->countryCode;
    memset(str,0,sizeof(str));
    if (k < MAX_WIFI_COUNTRYCODE) {
        snprintf(str,sizeof(str),"%s",wifiCountryMapMembers[k].countryStr);
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s Set failed invalid Country code %d.\n",__FUNCTION__,k);
        return webconfig_error_encode;
    }

    // Country
    cJSON_AddStringToObject(radio_object, "Country", str);

    // RegDomain
    cJSON_AddNumberToObject(radio_object, "RegDomain", radio_info->regDomain);
    
    k = radio_info->operatingEnvironment;
    memset(str,0,sizeof(str));
    arr_size = ((int)(sizeof(wifiEnviromentMap)/sizeof(wifiEnviromentMap[0])));
    for (itr = 0; itr < arr_size; itr++)
    {
        if (k == wifiEnviromentMap[itr].operatingEnvironment)
        {
            strncpy(str, wifiEnviromentMap[itr].environment, sizeof(wifiEnviromentMap[itr].environment)-1);
            break;
        }
    }

    // OperatingEnvironment
    cJSON_AddStringToObject(radio_object, "OperatingEnvironment", str);
    
    // DFS Enable
    cJSON_AddBoolToObject(radio_object, "DFSEnable", radio_info->DfsEnabled);

    //DFSAtBootup
    cJSON_AddBoolToObject(radio_object, "DfsEnabledBootup", radio_info->DfsEnabledBootup);

    // ChannelAvailability
    memset(chan_buf,0,sizeof(chan_buf));
    i=0;
    while (radio_info->channel_map[i].ch_number != 0)
    {
      index+=sprintf(&buf[index],"%d:%d,", radio_info->channel_map[i].ch_number, radio_info->channel_map[i].ch_state);
      i++;
    }
    if (strlen(buf) > 0) {
      strncpy(chan_buf,buf,strlen(buf)-1);
    }
    else { 
      strcpy(chan_buf, " ");
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s Channel Availability State Buffer %s\n",__FUNCTION__,chan_buf);
    cJSON_AddStringToObject(radio_object, "ChannelAvailability", chan_buf);

    //radarInfo
    memset(buf,0,sizeof(buf));
    snprintf(buf,sizeof(buf),"last_channel:%d,num_detected:%d,time:%lld",
             radio->radarInfo.last_channel,radio->radarInfo.num_detected,radio->radarInfo.timestamp);
    cJSON_AddStringToObject(radio_object, "radarInfo", buf);

    // DcsEnabled
    cJSON_AddBoolToObject(radio_object, "DcsEnabled", radio_info->DCSEnabled);

    // DtimPeriod
    cJSON_AddNumberToObject(radio_object, "DtimPeriod", radio_info->dtimPeriod);

    // OperatingClass
    cJSON_AddNumberToObject(radio_object, "OperatingClass", radio_info->operatingClass);

    // BasicDataTransmitRates
    cJSON_AddNumberToObject(radio_object, "BasicDataTransmitRates", radio_info->basicDataTransmitRates);

    // OperationalDataTransmitRates
    cJSON_AddNumberToObject(radio_object, "OperationalDataTransmitRates", radio_info->operationalDataTransmitRates);

    // FragmentationThreshold
    cJSON_AddNumberToObject(radio_object, "FragmentationThreshold", radio_info->fragmentationThreshold);

    // GuardInterval
    cJSON_AddNumberToObject(radio_object, "GuardInterval", radio_info->guardInterval);

    // TransmitPower
    cJSON_AddNumberToObject(radio_object, "TransmitPower", radio_info->transmitPower);

    // BeaconInterval
    cJSON_AddNumberToObject(radio_object, "BeaconInterval", radio_info->beaconInterval);

    // RtsThreshold
    cJSON_AddNumberToObject(radio_object, "RtsThreshold", radio_info->rtsThreshold);

    // FactoryResetSsid
    cJSON_AddBoolToObject(radio_object, "FactoryResetSsid", radio_info->factoryResetSsid);

    // RadioStatsMeasuringRate
    cJSON_AddNumberToObject(radio_object, "RadioStatsMeasuringRate", radio_info->radioStatsMeasuringRate);

    // RadioStatsMeasuringInterval
    cJSON_AddNumberToObject(radio_object, "RadioStatsMeasuringInterval", radio_info->radioStatsMeasuringInterval);

    // CtsProtection
    cJSON_AddBoolToObject(radio_object, "CtsProtection", radio_info->ctsProtection);

    // ObssCoex
    cJSON_AddBoolToObject(radio_object, "ObssCoex", radio_info->obssCoex);

    //StbcEnable
    cJSON_AddBoolToObject(radio_object, "StbcEnable", radio_info->stbcEnable);

    // GreenFieldEnable
    cJSON_AddBoolToObject(radio_object, "GreenFieldEnable", radio_info->greenFieldEnable);

    // UserControl
    cJSON_AddNumberToObject(radio_object, "UserControl", radio_info->userControl);

    // AdminControl
    cJSON_AddNumberToObject(radio_object, "AdminControl", radio_info->adminControl);

    // ChanUtilThreshold
    cJSON_AddNumberToObject(radio_object, "ChanUtilThreshold", radio_info->chanUtilThreshold);

    // ChanUtilSelfHealEnable
    cJSON_AddBoolToObject(radio_object, "ChanUtilSelfHealEnable", radio_info->chanUtilSelfHealEnable);

    // EcoPowerDown
    cJSON_AddBoolToObject(radio_object, "EcoPowerDown", radio_info->EcoPowerDown);

    //Tscan
    cJSON_AddNumberToObject(radio_object, "Tscan", radio_feat->OffChanTscanInMsec);

    //Nscan
    cJSON_AddNumberToObject(radio_object, "Nscan", (radio_feat->OffChanNscanInSec != 0) ? ((24*3600)/(radio_feat->OffChanNscanInSec)) : 0); //We store Nscan as number of scans in the subdoc

    //Tidle
    cJSON_AddNumberToObject(radio_object, "Tidle", radio_feat->OffChanTidleInSec);

    return webconfig_error_none;
}

webconfig_error_t encode_vap_common_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_object)
{
    char mac_str[32];

    //VAP Name
    cJSON_AddStringToObject(vap_object, "VapName", vap_info->vap_name);

    //Bridge Name
    cJSON_AddStringToObject(vap_object, "BridgeName", vap_info->bridge_name);

    //VAP Name
    cJSON_AddStringToObject(vap_object, "RepurposedVapName", vap_info->repurposed_vap_name);

    // Radio Index
    cJSON_AddNumberToObject(vap_object, "RadioIndex", vap_info->radio_index);

    //VAP Mode
    cJSON_AddNumberToObject(vap_object, "VapMode", vap_info->vap_mode);

    // Exists
    cJSON_AddBoolToObject(vap_object, "Exists", rdk_vap_info->exists);

    // SSID
    cJSON_AddStringToObject(vap_object, "SSID", vap_info->u.bss_info.ssid);

    // BSSID
    uint8_mac_to_string_mac((uint8_t *)vap_info->u.bss_info.bssid, mac_str);
    cJSON_AddStringToObject(vap_object, "BSSID", mac_str);

    // Enabled
    cJSON_AddBoolToObject(vap_object, "Enabled", vap_info->u.bss_info.enabled);

    // Broadcast SSID
    cJSON_AddBoolToObject(vap_object, "SSIDAdvertisementEnabled", vap_info->u.bss_info.showSsid);

    // Isolation
    cJSON_AddBoolToObject(vap_object, "IsolationEnable", vap_info->u.bss_info.isolation);

    // ManagementFramePowerControl
    cJSON_AddNumberToObject(vap_object, "ManagementFramePowerControl", vap_info->u.bss_info.mgmtPowerControl);

    // BssMaxNumSta
    cJSON_AddNumberToObject(vap_object, "BssMaxNumSta", vap_info->u.bss_info.bssMaxSta);

    // BSSTransitionActivated
    cJSON_AddBoolToObject(vap_object, "BSSTransitionActivated", vap_info->u.bss_info.bssTransitionActivated);

    // NeighborReportActivated
    cJSON_AddBoolToObject(vap_object, "NeighborReportActivated", vap_info->u.bss_info.nbrReportActivated);

    // ForceApply
    if (rdk_vap_info->force_apply == true) {
        //Add only if ForceApply is true
        cJSON_AddBoolToObject(vap_object, "ForceApply", rdk_vap_info->force_apply);
    }

    //network_initiated_greylist
    cJSON_AddBoolToObject(vap_object, "NetworkGreyList", vap_info->u.bss_info.network_initiated_greylist);

    // RapidReconnCountEnable
    cJSON_AddBoolToObject(vap_object, "RapidReconnCountEnable", vap_info->u.bss_info.rapidReconnectEnable);

    // RapidReconnThreshold
    cJSON_AddNumberToObject(vap_object, "RapidReconnThreshold", vap_info->u.bss_info.rapidReconnThreshold);

    // VapStatsEnable
    cJSON_AddBoolToObject(vap_object, "VapStatsEnable", vap_info->u.bss_info.vapStatsEnable);

    // MacFilterEnable
    cJSON_AddBoolToObject(vap_object, "MacFilterEnable", vap_info->u.bss_info.mac_filter_enable);

    // MacFilterMode
    cJSON_AddNumberToObject(vap_object, "MacFilterMode", vap_info->u.bss_info.mac_filter_mode);

    cJSON_AddBoolToObject(vap_object, "WmmEnabled", vap_info->u.bss_info.wmm_enabled);

    cJSON_AddBoolToObject(vap_object, "UapsdEnabled", vap_info->u.bss_info.UAPSDEnabled);

    cJSON_AddNumberToObject(vap_object, "BeaconRate", vap_info->u.bss_info.beaconRate);

    // WmmNoAck
    cJSON_AddNumberToObject(vap_object, "WmmNoAck", vap_info->u.bss_info.wmmNoAck);

    // WepKeyLength
    cJSON_AddNumberToObject(vap_object, "WepKeyLength", vap_info->u.bss_info.wepKeyLength);

    // BssHotspot
    cJSON_AddBoolToObject(vap_object, "BssHotspot", vap_info->u.bss_info.bssHotspot);

    // wpsPushButton
    cJSON_AddNumberToObject(vap_object, "WpsPushButton", vap_info->u.bss_info.wpsPushButton);

    // wpsEnable
    cJSON_AddBoolToObject(vap_object, "WpsEnable", vap_info->u.bss_info.wps.enable);

    //wpsConfigMethodsEnabled
    if(strstr(vap_info->vap_name, "private") != NULL) {
        cJSON_AddNumberToObject(vap_object, "WpsConfigMethodsEnabled", vap_info->u.bss_info.wps.methods);
        //WpsConfigPin
        cJSON_AddStringToObject(vap_object, "WpsConfigPin", vap_info->u.bss_info.wps.pin);
    }

    // BeaconRateCtl
    cJSON_AddStringToObject(vap_object, "BeaconRateCtl", vap_info->u.bss_info.beaconRateCtl);


    //conncted_building_enabled
    cJSON_AddBoolToObject(vap_object, "Connected_building_enabled", vap_info->u.bss_info.connected_building_enabled);
    return webconfig_error_none;
}

webconfig_error_t encode_postassoc_object(const wifi_postassoc_control_t *postassoc_info, cJSON *postassoc)
{
    // RssiUpThreshold
    if(strlen((char *)postassoc_info->rssi_up_threshold) == 0) {
        cJSON_AddStringToObject(postassoc, "RssiUpThreshold", "disabled");
    } else {
        cJSON_AddStringToObject(postassoc, "RssiUpThreshold", postassoc_info->rssi_up_threshold);
    }
    // SamplingInterval
    if(strlen((char *)postassoc_info->sampling_interval) == 0) {
        cJSON_AddStringToObject(postassoc, "SamplingInterval", "7");
    } else {
        cJSON_AddStringToObject(postassoc, "SamplingInterval", postassoc_info->sampling_interval);
    }
    // SnrThreshold
    if(strlen((char *)postassoc_info->snr_threshold) == 0) {
        cJSON_AddStringToObject(postassoc, "SnrThreshold", "disabled");
    } else {
        cJSON_AddStringToObject(postassoc, "SnrThreshold", postassoc_info->snr_threshold);
    }
    // SamplingCount
    if(strlen((char *)postassoc_info->sampling_count) == 0) {
        cJSON_AddStringToObject(postassoc, "SamplingCount", "3");
    } else {
        cJSON_AddStringToObject(postassoc, "SamplingCount", postassoc_info->sampling_count);
    }
    //CuThreshold
    if(strlen((char *)postassoc_info->cu_threshold) == 0) {
        cJSON_AddStringToObject(postassoc, "CuThreshold", "disabled");
    } else {
        cJSON_AddStringToObject(postassoc, "CuThreshold", postassoc_info->cu_threshold);
    }

    wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Encoding postassoc settings passed\n", __func__, __LINE__);

    return webconfig_error_none;
}

webconfig_error_t encode_preassoc_object(const wifi_preassoc_control_t *preassoc_info, cJSON *preassoc)
{
    // RssiUpThreshold
    if(strlen((char *)preassoc_info->rssi_up_threshold) == 0) {
        cJSON_AddStringToObject(preassoc, "RssiUpThreshold", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "RssiUpThreshold", preassoc_info->rssi_up_threshold);
    }
    // SnrThreshold
    if(strlen((char *)preassoc_info->snr_threshold) == 0) {
        cJSON_AddStringToObject(preassoc, "SnrThreshold", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "SnrThreshold", preassoc_info->snr_threshold);
    }
    // CuThreshold
    if(strlen((char *)preassoc_info->cu_threshold) == 0) {
        cJSON_AddStringToObject(preassoc, "CuThreshold", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "CuThreshold", preassoc_info->cu_threshold);
    }
    // basic_data_transmit_rate
    if(strlen((char *)preassoc_info->basic_data_transmit_rates) == 0) {
        cJSON_AddStringToObject(preassoc, "BasicDataTransmitRates", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "BasicDataTransmitRates", preassoc_info->basic_data_transmit_rates);
    }
    // operational_data_transmit_rate
    if(strlen((char *)preassoc_info->operational_data_transmit_rates) == 0) {
        cJSON_AddStringToObject(preassoc, "OperationalDataTransmitRates", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "OperationalDataTransmitRates", preassoc_info->operational_data_transmit_rates);
    }
    // supported_data_transmit_rate
    if(strlen((char *)preassoc_info->supported_data_transmit_rates) == 0) {
        cJSON_AddStringToObject(preassoc, "SupportedDataTransmitRates", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "SupportedDataTransmitRates", preassoc_info->supported_data_transmit_rates);
    }
    // minimum_advertised_mcs
    if(strlen((char *)preassoc_info->minimum_advertised_mcs) == 0) {
        cJSON_AddStringToObject(preassoc, "MinimumAdvertisedMCS", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "MinimumAdvertisedMCS", preassoc_info->minimum_advertised_mcs);
    }
    // 6GOpInfoMinRates
    if(strlen((char *)preassoc_info->sixGOpInfoMinRate) == 0) {
        cJSON_AddStringToObject(preassoc, "6GOpInfoMinRate", "disabled");
    } else {
        cJSON_AddStringToObject(preassoc, "6GOpInfoMinRate", preassoc_info->sixGOpInfoMinRate);
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Encoding preassoc settings passed\n", __func__, __LINE__);

    return webconfig_error_none;
}

webconfig_error_t encode_connection_ctrl_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // VapName
    cJSON_AddStringToObject(vap_obj, "VapName", vap_info->vap_name);

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "PreAssociationDeny", obj);
    if (encode_preassoc_object(&vap_info->u.bss_info.preassoc, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Preassoc object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "PostAssociationDeny", obj);
    if (encode_postassoc_object(&vap_info->u.bss_info.postassoc, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Postassoc object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_gas_config(const wifi_GASConfiguration_t *gas_info, cJSON *gas_obj)
{
    //AdvertisementId
    cJSON_AddNumberToObject(gas_obj, "AdvertisementId", gas_info->AdvertisementID);

    // PauseForServerResp
    cJSON_AddBoolToObject(gas_obj, "PauseForServerResp", (const cJSON_bool) gas_info->PauseForServerResponse);

    //ResponseTimeout
    cJSON_AddNumberToObject(gas_obj, "RespTimeout", gas_info->ResponseTimeout);

    //ComebackDelay
    cJSON_AddNumberToObject(gas_obj, "ComebackDelay", gas_info->ComeBackDelay);

    //ResponseBufferingTime
    cJSON_AddNumberToObject(gas_obj, "RespBufferTime", gas_info->ResponseBufferingTime);

    //QueryResponseLengthLimit
    cJSON_AddNumberToObject(gas_obj, "QueryRespLengthLimit", gas_info->QueryResponseLengthLimit);

    return webconfig_error_none;
}

webconfig_error_t encode_wifi_global_config(const wifi_global_param_t *global_info, cJSON *global_obj)
{
    char str[BUFFER_LENGTH_WIFIDB] = {0};

    // NotifyWifiChanges
    cJSON_AddBoolToObject(global_obj, "NotifyWifiChanges",(const cJSON_bool) global_info->notify_wifi_changes);

    // PreferPrivate
    cJSON_AddBoolToObject(global_obj, "PreferPrivate", (const cJSON_bool) global_info->prefer_private);

    // PreferPrivateConfigure
    cJSON_AddBoolToObject(global_obj, "PreferPrivateConfigure", (const cJSON_bool) global_info->prefer_private_configure);

    // FactoryReset
    cJSON_AddBoolToObject(global_obj, "FactoryReset", (const cJSON_bool) global_info->factory_reset);

    // TxOverflowSelfheal
    cJSON_AddBoolToObject(global_obj, "TxOverflowSelfheal",(const cJSON_bool) global_info->tx_overflow_selfheal);

    // InstWifiClientEnabled
    cJSON_AddBoolToObject(global_obj, "InstWifiClientEnabled", (const cJSON_bool) global_info->inst_wifi_client_enabled);

    //InstWifiClientReportingPeriod
    cJSON_AddNumberToObject(global_obj, "InstWifiClientReportingPeriod", global_info->inst_wifi_client_reporting_period);

    //InstWifiClientMac
    uint8_mac_to_string_mac((uint8_t *)global_info->inst_wifi_client_mac, str);
    cJSON_AddStringToObject(global_obj, "InstWifiClientMac", str);

    //InstWifiClientDefReportingPeriod
    cJSON_AddNumberToObject(global_obj, "InstWifiClientDefReportingPeriod", global_info->inst_wifi_client_def_reporting_period);

    // WifiActiveMsmtEnabled
    cJSON_AddBoolToObject(global_obj, "WifiActiveMsmtEnabled", (const cJSON_bool) global_info->wifi_active_msmt_enabled);

    //WifiActiveMsmtPktsize
    cJSON_AddNumberToObject(global_obj, "WifiActiveMsmtPktsize", global_info->wifi_active_msmt_pktsize);

    //WifiActiveMsmtNumSamples
    cJSON_AddNumberToObject(global_obj, "WifiActiveMsmtNumSamples", global_info->wifi_active_msmt_num_samples);

    //WifiActiveMsmtSampleDuration
    cJSON_AddNumberToObject(global_obj, "WifiActiveMsmtSampleDuration", global_info->wifi_active_msmt_sample_duration);

    //VlanCfgVersion
    cJSON_AddNumberToObject(global_obj, "VlanCfgVersion", global_info->vlan_cfg_version);

    //WpsPin
    cJSON_AddStringToObject(global_obj, "WpsPin", global_info->wps_pin);

    // BandsteeringEnable
    cJSON_AddBoolToObject(global_obj, "BandsteeringEnable", (const cJSON_bool)global_info->bandsteering_enable);

    //GoodRssiThreshold
    cJSON_AddNumberToObject(global_obj, "GoodRssiThreshold", global_info->good_rssi_threshold);

    //AssocCountThreshold
    cJSON_AddNumberToObject(global_obj, "AssocCountThreshold", global_info->assoc_count_threshold);

    //AssocGateTime
    cJSON_AddNumberToObject(global_obj, "AssocGateTime", global_info->assoc_gate_time);

    //WhixLogInterval
    cJSON_AddNumberToObject(global_obj, "WhixLoginterval", global_info->whix_log_interval);

    //Whix_ChUtility_Loginterval
    cJSON_AddNumberToObject(global_obj, "whix_chutility_loginterval", global_info->whix_chutility_loginterval);

    //AssocMonitorDuration
    cJSON_AddNumberToObject(global_obj, "AssocMonitorDuration", global_info->assoc_monitor_duration);

    // RapidReconnectEnable
    cJSON_AddBoolToObject(global_obj, "RapidReconnectEnable",(const cJSON_bool) global_info->rapid_reconnect_enable);

    // VapStatsFeature
    cJSON_AddBoolToObject(global_obj, "VapStatsFeature",(const cJSON_bool) global_info->vap_stats_feature);

    // MfpConfigFeature
    cJSON_AddBoolToObject(global_obj, "MfpConfigFeature", (const cJSON_bool) global_info->mfp_config_feature);

    // ForceDisableRadioFeature
    cJSON_AddBoolToObject(global_obj, "ForceDisableRadioFeature",(const cJSON_bool) global_info->force_disable_radio_feature);

    // ForceDisableRadioStatus
    cJSON_AddBoolToObject(global_obj, "ForceDisableRadioStatus", (const cJSON_bool) global_info->force_disable_radio_status);

    //FixedWmmParams
    cJSON_AddNumberToObject(global_obj, "FixedWmmParams", global_info->fixed_wmm_params);

    //WifiRegionCode
    cJSON_AddStringToObject(global_obj, "WifiRegionCode", global_info->wifi_region_code);

    // DiagnosticEnable
    cJSON_AddBoolToObject(global_obj, "DiagnosticEnable", (const cJSON_bool) global_info->diagnostic_enable);

    // ValidateSsid
    cJSON_AddBoolToObject(global_obj, "ValidateSsid", (const cJSON_bool) global_info->validate_ssid);

    // DeviceNetworkMode
    cJSON_AddNumberToObject(global_obj, "DeviceNetworkMode", global_info->device_network_mode);

    //Normalized_Rssi_List
    cJSON_AddStringToObject(global_obj, "NormalizedRssiList", global_info->normalized_rssi_list);

    //SNRList
    cJSON_AddStringToObject(global_obj, "SNRList", global_info->snr_list);

    //CliStatList
    cJSON_AddStringToObject(global_obj, "CliStatList", global_info->cli_stat_list);

    //TxRxRateList
    cJSON_AddStringToObject(global_obj, "TxRxRateList", global_info->txrx_rate_list);

    return webconfig_error_none;
}

webconfig_error_t encode_config_object(const wifi_global_config_t *config_info, cJSON *config_obj)
{
    cJSON *obj;


    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(config_obj, "GASConfig", obj);

    if (encode_gas_config(&config_info->gas_config, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode gas config\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (encode_wifi_global_config(&config_info->global_parameters, config_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi global config\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    return webconfig_error_none;
}


extern const char* get_anqp_json_by_vap_name(const char* vap_name);
extern const char* get_passpoint_json_by_vap_name(const char* vap_name);

webconfig_error_t encode_anqp_object(const char *vap_name, cJSON *inter,const unsigned char* anqp)
{
    cJSON *anqpElement = NULL;
    if(inter == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Null interworking obj\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON *p_root = cJSON_Parse((char *)anqp);
    if(p_root == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Unable  to encode anqp json\n", __func__, __LINE__);
        return webconfig_error_none;
        //return webconfig_error_encode;
    }

    if(cJSON_HasObjectItem(p_root, "ANQP") == true) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d  anqp element already exsistingin json\n", __func__, __LINE__);
        anqpElement = cJSON_GetObjectItem(p_root, (const char * const)"ANQP");
        cJSON_AddItemToObject(inter, "ANQP", anqpElement);
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d  Add anqp element to json\n", __func__, __LINE__);
        cJSON_AddItemToObject(inter, "ANQP", p_root);
    }
    return webconfig_error_none;
}

webconfig_error_t encode_passpoint_object(const char *vap_name, cJSON *inter,const unsigned char* passpoint)
{
    cJSON *pass = NULL;
    if(inter == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Null interworking obj\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON *p_root = cJSON_Parse((char *)passpoint);
    if(p_root == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Unable  to encode passpoint json\n", __func__, __LINE__);
        return webconfig_error_none;
    }

      if(cJSON_HasObjectItem(p_root, "Passpoint") == true) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d  Passpoint element already exsisting in json\n", __func__, __LINE__);
        pass = cJSON_GetObjectItem(p_root,  (const char * const) "Passpoint");
        cJSON_AddItemToObject(inter, "Passpoint", pass);
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d  Add Passpoint element to json\n", __func__, __LINE__);
        cJSON_AddItemToObject(inter, "Passpoint", p_root);
    }

    return webconfig_error_none;
}

webconfig_error_t encode_interworking_common_object(const wifi_interworking_t *interworking_info, cJSON *interworking)
{
    cJSON *obj;
    bool invalid_venue_group_type = false;

    cJSON_AddBoolToObject(interworking, "InterworkingEnable", interworking_info->interworking.interworkingEnabled);

    if (interworking_info->interworking.accessNetworkType > 5) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Encode failed for AccessNetworkType\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Access Network type",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_encode;
    }
    cJSON_AddNumberToObject(interworking, "AccessNetworkType", interworking_info->interworking.accessNetworkType);
    cJSON_AddBoolToObject(interworking, "Internet", interworking_info->interworking.internetAvailable);
    cJSON_AddBoolToObject(interworking, "ASRA", interworking_info->interworking.asra);
    cJSON_AddBoolToObject(interworking, "ESR", interworking_info->interworking.esr);
    cJSON_AddBoolToObject(interworking, "UESA", interworking_info->interworking.uesa);
    cJSON_AddBoolToObject(interworking, "HESSOptionPresent", interworking_info->interworking.hessOptionPresent);
    cJSON_AddStringToObject(interworking, "HESSID", interworking_info->interworking.hessid);

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(interworking, "Venue", obj);
    if (interworking_info->interworking.venueType > 15) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Encode failed for VenueGroup\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Venue Group",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_encode;
    }
    cJSON_AddNumberToObject(obj, "VenueType", interworking_info->interworking.venueType);

    switch (interworking_info->interworking.venueGroup) {
        case 0:
            if (interworking_info->interworking.venueType > 0) {
                invalid_venue_group_type = true;
            }
            break;

        case 1:
            if (interworking_info->interworking.venueType > 15) {
                invalid_venue_group_type = true;
            }
            break;

        case 2:
            if (interworking_info->interworking.venueType > 9) {
                invalid_venue_group_type = true;
            }
            break;

        case 3:
            if (interworking_info->interworking.venueType > 3) {
                invalid_venue_group_type = true;
            }
            break;

        case 4:
            if (interworking_info->interworking.venueType > 1) {
                invalid_venue_group_type = true;
            }
            break;

        case 5:
            if (interworking_info->interworking.venueType > 5) {
                invalid_venue_group_type = true;
            }
            break;

        case 6:
            if (interworking_info->interworking.venueType > 5) {
                invalid_venue_group_type = true;
            }
            break;

        case 7:
            if (interworking_info->interworking.venueType > 4) {
                invalid_venue_group_type = true;
            }
            break;

        case 8:
            if (interworking_info->interworking.venueType > 0) {
                invalid_venue_group_type = true;
            }
            break;

        case 9:
            if (interworking_info->interworking.venueType > 0) {
                invalid_venue_group_type = true;
            }
            break;

        case 10:
            if (interworking_info->interworking.venueType > 7) {
                invalid_venue_group_type = true;
            }
            break;

        case 11:
            if (interworking_info->interworking.venueType > 6) {
                invalid_venue_group_type = true;
            }
            break;
    }

    if (invalid_venue_group_type == true) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid venue group and type, encode failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON_AddNumberToObject(obj, "VenueGroup", interworking_info->interworking.venueGroup);

    return webconfig_error_none;
}

webconfig_error_t encode_radius_object(const wifi_radius_settings_t *radius_info, cJSON *radius)
{
    char str[64];

    if (strlen((char *)radius_info->ip) == 0) {
        cJSON_AddStringToObject(radius, "RadiusServerIPAddr", "0.0.0.0");
    } else {
        cJSON_AddStringToObject(radius, "RadiusServerIPAddr", (char *)radius_info->ip);
    }

    cJSON_AddNumberToObject(radius, "RadiusServerPort", radius_info->port);

    if (strlen((char *)radius_info->key) == 0) {
        cJSON_AddStringToObject(radius, "RadiusSecret", INVALID_KEY);
    } else {
        cJSON_AddStringToObject(radius, "RadiusSecret", radius_info->key);
    }

    if (strlen((char *)radius_info->s_ip) == 0) {
        cJSON_AddStringToObject(radius, "SecondaryRadiusServerIPAddr", "0.0.0.0");
    } else {
        cJSON_AddStringToObject(radius, "SecondaryRadiusServerIPAddr", (char *)radius_info->s_ip);
    }

    cJSON_AddNumberToObject(radius, "SecondaryRadiusServerPort", radius_info->s_port);

    if (strlen((char *)radius_info->s_key) == 0) {
        cJSON_AddStringToObject(radius, "SecondaryRadiusSecret", INVALID_KEY);
    } else {
        cJSON_AddStringToObject(radius, "SecondaryRadiusSecret", radius_info->s_key);
    }

    memset(str, 0, sizeof(str));
    getIpStringFromAdrress(str, &radius_info->dasip);
    cJSON_AddStringToObject(radius, "DasServerIPAddr", str);

    cJSON_AddNumberToObject(radius, "DasServerPort", radius_info->dasport);

    if (strlen((char *)radius_info->daskey) == 0) {
        cJSON_AddStringToObject(radius, "DasSecret", INVALID_KEY);
    } else {
        cJSON_AddStringToObject(radius, "DasSecret", radius_info->daskey);
    }

    //max_auth_attempts
    cJSON_AddNumberToObject(radius, "MaxAuthAttempts", radius_info->max_auth_attempts);

    //blacklist_table_timeout
    cJSON_AddNumberToObject(radius, "BlacklistTableTimeout", radius_info->blacklist_table_timeout);

    //identity_req_retry_interval
    cJSON_AddNumberToObject(radius, "IdentityReqRetryInterval", radius_info->identity_req_retry_interval);

    //server_retries
    cJSON_AddNumberToObject(radius, "ServerRetries", radius_info->server_retries);

    return webconfig_error_none;
}

webconfig_error_t encode_security_object(const wifi_vap_security_t *security_info, cJSON *security,
    bool is_6g)
{
    cJSON *obj;

    if (is_6g &&
        security_info->mode != wifi_security_mode_wpa3_personal &&
        security_info->mode != wifi_security_mode_wpa3_enterprise &&
        security_info->mode != wifi_security_mode_enhanced_open) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid security mode %d for 6G interface\n",
            __func__, __LINE__, security_info->mode);
        return webconfig_error_encode;
    }

    switch (security_info->mode) {
        case wifi_security_mode_none:
            cJSON_AddStringToObject(security, "Mode", "None");
            break;

        case wifi_security_mode_enhanced_open:
            cJSON_AddStringToObject(security, "Mode", "Enhanced-Open");
            break;

        case wifi_security_mode_wpa_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA-Personal");
            break;

        case wifi_security_mode_wpa_wpa2_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA-WPA2-Personal");
            break;

        case wifi_security_mode_wpa2_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA2-Personal");
            break;

        case wifi_security_mode_wpa3_transition:
            cJSON_AddStringToObject(security, "Mode", "WPA3-Personal-Transition");
            break;

        case wifi_security_mode_wpa3_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA3-Personal");
            break;

        case wifi_security_mode_wpa_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA-Enterprise");
            break;

        case wifi_security_mode_wpa_wpa2_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA-WPA2-Enterprise");
            break;

        case wifi_security_mode_wpa2_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA2-Enterprise");
            break;

        case wifi_security_mode_wpa3_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA3-Enterprise");
            break;

        default:
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to encode security mode: %d\n",
                __func__, __LINE__, security_info->mode);
            return webconfig_error_encode;
    }

    if (security_info->mode == wifi_security_mode_none ||
        security_info->mode == wifi_security_mode_enhanced_open) {
        obj = cJSON_CreateObject();
        cJSON_AddItemToObject(security, "RadiusSettings", obj);

        if (encode_radius_object(&security_info->u.radius, obj) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to encode radius settings\n",
                __func__, __LINE__);
            return webconfig_error_encode;
        }
    }

    if (security_info->mode == wifi_security_mode_none) {
        return webconfig_error_none;
    }

    if (security_info->mfp != wifi_mfp_cfg_optional &&
        security_info->mode == wifi_security_mode_wpa3_transition) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid MFP value %d for %d mode\n", __func__,
            __LINE__, security_info->mfp, security_info->mode);
        return webconfig_error_encode;
    }

#ifndef CONFIG_IEEE80211BE
    if (security_info->mfp != wifi_mfp_cfg_required &&
        (security_info->mode == wifi_security_mode_enhanced_open ||
        security_info->mode == wifi_security_mode_wpa3_personal ||
        security_info->mode == wifi_security_mode_wpa3_enterprise)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid MFP %d value for %d mode\n", __func__,
            __LINE__, security_info->mfp, security_info->mode);
        return webconfig_error_encode;
    }
#endif // CONFIG_IEEE80211BE

    if (security_info->mfp == wifi_mfp_cfg_disabled) {
        cJSON_AddStringToObject(security, "MFPConfig", "Disabled");
    } else if (security_info->mfp == wifi_mfp_cfg_required) {
        cJSON_AddStringToObject(security, "MFPConfig", "Required");
    } else if (security_info->mfp == wifi_mfp_cfg_optional) {
        cJSON_AddStringToObject(security, "MFPConfig", "Optional");
    } else {
         wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to encode MFP config: %d\n",
            __func__, __LINE__, security_info->mfp);
        return webconfig_error_encode;
    }

    if (security_info->encr != wifi_encryption_aes &&
        (security_info->mode == wifi_security_mode_enhanced_open ||
        security_info->mode == wifi_security_mode_wpa3_enterprise ||
        security_info->mode == wifi_security_mode_wpa3_personal)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid encryption method for %d mode: %d\n",
            __func__, __LINE__, security_info->encr, security_info->mode);
        return webconfig_error_decode;
    }

    if (security_info->encr == wifi_encryption_tkip &&
        security_info->mode == wifi_security_mode_wpa_wpa2_personal) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid encryption method TKIP with "
            "WPA/WPA2 mode\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    switch (security_info->encr) {
        case wifi_encryption_tkip:
            cJSON_AddStringToObject(security, "EncryptionMethod", "TKIP");
            break;

        case wifi_encryption_aes:
            cJSON_AddStringToObject(security, "EncryptionMethod", "AES");
            break;

        case wifi_encryption_aes_tkip:
            cJSON_AddStringToObject(security, "EncryptionMethod", "AES+TKIP");
            break;

        default:
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to encode encryption method: %d\n",
                __func__, __LINE__, security_info->encr);
            return webconfig_error_encode;
    }

    if (security_info->mode == wifi_security_mode_enhanced_open) {
        return webconfig_error_none;
    }

    if (security_info->mode == wifi_security_mode_wpa_enterprise ||
        security_info->mode == wifi_security_mode_wpa_wpa2_enterprise ||
        security_info->mode == wifi_security_mode_wpa2_enterprise ||
        security_info->mode == wifi_security_mode_wpa3_enterprise) {

        cJSON_AddNumberToObject(security, "RekeyInterval", security_info->rekey_interval);
        cJSON_AddBoolToObject(security, "StrictRekey", security_info->strict_rekey);
        cJSON_AddNumberToObject(security, "EapolKeyTimeout", security_info->eapol_key_timeout);
        cJSON_AddNumberToObject(security, "EapolKeyRetries", security_info->eapol_key_retries);
        cJSON_AddNumberToObject(security, "EapIdentityReqTimeout",
            security_info->eap_identity_req_timeout);
        cJSON_AddNumberToObject(security, "EapIdentityReqRetries",
            security_info->eap_identity_req_retries);
        cJSON_AddNumberToObject(security, "EapReqTimeout", security_info->eap_req_timeout);
        cJSON_AddNumberToObject(security, "EapReqRetries", security_info->eap_req_retries);
        cJSON_AddBoolToObject(security, "DisablePmksaCaching",
            security_info->disable_pmksa_caching);

        obj = cJSON_CreateObject();
        cJSON_AddItemToObject(security, "RadiusSettings", obj);

        if (encode_radius_object(&security_info->u.radius, obj) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to encode radius config\n",
                __func__, __LINE__);
            return webconfig_error_encode;
        }

        return webconfig_error_none;
    }

    if (security_info->mode != wifi_security_mode_none &&
        (strlen(security_info->u.key.key) < MIN_PWD_LEN ||
        strlen(security_info->u.key.key) > MAX_PWD_LEN)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid password length: %d\n", __func__,
            __LINE__, strlen(security_info->u.key.key));
        return webconfig_error_encode;
    }

    cJSON_AddBoolToObject(security, "Wpa3_transition_disable",
        security_info->wpa3_transition_disable);
    cJSON_AddStringToObject(security, "Passphrase", security_info->u.key.key);

    cJSON_AddStringToObject(security, "KeyId", security_info->key_id);

    cJSON_AddNumberToObject(security, "RekeyInterval", security_info->rekey_interval);

    return webconfig_error_none;
}

webconfig_error_t encode_hotspot_open_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;
    bool is_6g;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, rdk_vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }


    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "VapConnectionControl", obj);
    if (encode_connection_ctrl_object(vap_info, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d CAC object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    is_6g = strstr(vap_info->vap_name, "6g") ? true : false;
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }
    webconfig_error_t ret = encode_anqp_object(vap_info->vap_name, obj, vap_info->u.bss_info.interworking.anqp.anqpParameters);
    if(ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d anqp encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    ret = encode_passpoint_object(vap_info->vap_name, obj, vap_info->u.bss_info.interworking.passpoint.hs2Parameters);
    if(ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d passpoint encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_hotspot_secure_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;
    bool is_6g;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, rdk_vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "VapConnectionControl", obj);
    if (encode_connection_ctrl_object(vap_info, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d CAC object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    is_6g = strstr(vap_info->vap_name, "6g") ? true : false;
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    webconfig_error_t ret = encode_anqp_object(vap_info->vap_name, obj, vap_info->u.bss_info.interworking.anqp.anqpParameters);
    if(ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d anqp encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    ret = encode_passpoint_object(vap_info->vap_name, obj, vap_info->u.bss_info.interworking.passpoint.hs2Parameters);
    if(ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d passpoint encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_lnf_psk_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, rdk_vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    bool is_6g = strstr(vap_info->vap_name, "6g")?true:false;

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_lnf_radius_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;
    bool is_6g;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, rdk_vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    is_6g = strstr(vap_info->vap_name, "6g") ? true : false;
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_mesh_backhaul_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, rdk_vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    bool is_6g = strstr(vap_info->vap_name, "6g")?true:false;
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_iot_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, rdk_vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    bool is_6g = strstr(vap_info->vap_name, "6g")?true:false;
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_private_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, rdk_vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    bool is_6g = strstr(vap_info->vap_name, "6g")?true:false;
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_mesh_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    return encode_private_vap_object(vap_info, rdk_vap_info, vap_obj);
}

webconfig_error_t encode_scan_params_object(const wifi_scan_params_t *scan_info, cJSON *scan_obj)
{

    // Period
    cJSON_AddNumberToObject(scan_obj, "Period", scan_info->period);

    // Channel
    cJSON_AddNumberToObject(scan_obj, "Channel", scan_info->channel.channel);

    return webconfig_error_none;
}

webconfig_error_t encode_mesh_sta_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj)
{
    cJSON *obj;
    char mac_str[32];

    //VAP Name
    cJSON_AddStringToObject(vap_obj, "VapName", vap_info->vap_name);

    //Bridge Name
    cJSON_AddStringToObject(vap_obj, "BridgeName", vap_info->bridge_name);

    //VAP Mode
    cJSON_AddNumberToObject(vap_obj, "VapMode", vap_info->vap_mode);

    // Radio Index
    cJSON_AddNumberToObject(vap_obj, "RadioIndex", vap_info->radio_index);

    // Exists
    cJSON_AddBoolToObject(vap_obj, "Exists", rdk_vap_info->exists);

    // SSID
    cJSON_AddStringToObject(vap_obj, "SSID", vap_info->u.sta_info.ssid);

    // BSSID
    uint8_mac_to_string_mac((uint8_t *)vap_info->u.sta_info.bssid, mac_str);
    cJSON_AddStringToObject(vap_obj, "BSSID", mac_str);

    // MAC
    uint8_mac_to_string_mac((uint8_t *)vap_info->u.sta_info.mac, mac_str);
    cJSON_AddStringToObject(vap_obj, "MAC", mac_str);

    // Enabled
    cJSON_AddBoolToObject(vap_obj, "Enabled", vap_info->u.sta_info.enabled);

    //ConnectStatus
    if (vap_info->u.sta_info.conn_status == wifi_connection_status_connected) {
        cJSON_AddBoolToObject(vap_obj, "ConnectStatus", true);
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d conn_status:%d true\n",__FUNCTION__, __LINE__, vap_info->u.sta_info.conn_status);
    } else {
        cJSON_AddBoolToObject(vap_obj, "ConnectStatus", false);
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d conn_status:%d false\n",__FUNCTION__, __LINE__, vap_info->u.sta_info.conn_status);
    }

    bool is_6g = strstr(vap_info->vap_name, "6g")?true:false;
    // Security
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_security_object(&vap_info->u.sta_info.security, obj, is_6g) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    // Scan Parameters
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "ScanParameters", obj);
    if (encode_scan_params_object(&vap_info->u.sta_info.scan_params, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Scan Params object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_associated_client_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *assoc_array, assoclist_type_t assoclist_type)
{
    bool print_assoc_client = false;
    if ((rdk_vap_info == NULL) || (assoc_array == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Associated Client encode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON *obj_array, *obj_vaps;
    assoc_dev_data_t *assoc_dev_data = NULL;
    hash_map_t *devices_map = NULL;

    obj_vaps = cJSON_CreateObject();
    obj_array = cJSON_CreateArray();

    cJSON_AddItemToArray(assoc_array, obj_vaps);
    cJSON_AddStringToObject(obj_vaps, "VapName", rdk_vap_info->vap_name);
    cJSON_AddItemToObject(obj_vaps, "associatedClients", obj_array);

    switch (assoclist_type)  {
        case assoclist_type_full:
            devices_map = rdk_vap_info->associated_devices_map;
        break;
        case assoclist_type_remove:
        case assoclist_type_add:
            devices_map = rdk_vap_info->associated_devices_diff_map;
        break;
        default:
            return webconfig_error_encode;
    }


    if (devices_map != NULL) {
        assoc_dev_data = hash_map_get_first(devices_map);
        while (assoc_dev_data != NULL) {
            print_assoc_client = false;
            if (assoclist_type == assoclist_type_full) {
                print_assoc_client = true;
            } else if ((assoclist_type == assoclist_type_add) && (assoc_dev_data->client_state == client_state_connected)) {
                print_assoc_client = true;
            } else if ((assoclist_type == assoclist_type_remove) && (assoc_dev_data->client_state == client_state_disconnected)) {
                print_assoc_client = true;
            }

            if (print_assoc_client == true) {
                cJSON *obj_assoc_client;
                obj_assoc_client = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj_assoc_client);

                char mac_string[18] = {0};

                to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_string);
                str_tolower(mac_string);
                cJSON_AddStringToObject(obj_assoc_client, "MACAddress", mac_string);
                cJSON_AddStringToObject(obj_assoc_client, "WpaKeyMgmt", assoc_dev_data->conn_security.wpa_key_mgmt);
                cJSON_AddStringToObject(obj_assoc_client, "PairwiseCipher", assoc_dev_data->conn_security.pairwise_cipher);
                cJSON_AddBoolToObject(obj_assoc_client, "AuthenticationState", assoc_dev_data->dev_stats.cli_AuthenticationState);
                cJSON_AddNumberToObject(obj_assoc_client, "LastDataDownlinkRate", assoc_dev_data->dev_stats.cli_LastDataDownlinkRate);
                cJSON_AddNumberToObject(obj_assoc_client, "LastDataUplinkRate", assoc_dev_data->dev_stats.cli_LastDataUplinkRate);
                cJSON_AddNumberToObject(obj_assoc_client, "SignalStrength", assoc_dev_data->dev_stats.cli_SignalStrength);
                cJSON_AddNumberToObject(obj_assoc_client, "Retransmissions", assoc_dev_data->dev_stats.cli_Retransmissions);
                cJSON_AddBoolToObject(obj_assoc_client, "Active", assoc_dev_data->dev_stats.cli_Active);
                cJSON_AddStringToObject(obj_assoc_client, "OperatingStandard", assoc_dev_data->dev_stats.cli_OperatingStandard);
                cJSON_AddStringToObject(obj_assoc_client, "OperatingChannelBandwidth", assoc_dev_data->dev_stats.cli_OperatingChannelBandwidth);
                cJSON_AddNumberToObject(obj_assoc_client, "SNR", assoc_dev_data->dev_stats.cli_SNR);
                cJSON_AddStringToObject(obj_assoc_client, "InterferenceSources", assoc_dev_data->dev_stats.cli_InterferenceSources);
                cJSON_AddNumberToObject(obj_assoc_client, "DataFramesSentAck", assoc_dev_data->dev_stats.cli_DataFramesSentAck);
                cJSON_AddNumberToObject(obj_assoc_client, "DataFramesSentNoAck", assoc_dev_data->dev_stats.cli_DataFramesSentNoAck);
                cJSON_AddNumberToObject(obj_assoc_client, "BytesSent", assoc_dev_data->dev_stats.cli_BytesSent);
                cJSON_AddNumberToObject(obj_assoc_client, "BytesReceived", assoc_dev_data->dev_stats.cli_BytesReceived);
                cJSON_AddNumberToObject(obj_assoc_client, "RSSI", assoc_dev_data->dev_stats.cli_RSSI);
                cJSON_AddNumberToObject(obj_assoc_client, "MinRSSI", assoc_dev_data->dev_stats.cli_MinRSSI);
                cJSON_AddNumberToObject(obj_assoc_client, "MaxRSSI", assoc_dev_data->dev_stats.cli_MaxRSSI);
                cJSON_AddNumberToObject(obj_assoc_client, "Disassociations", assoc_dev_data->dev_stats.cli_Disassociations);
                cJSON_AddNumberToObject(obj_assoc_client, "AuthenticationFailures", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
                cJSON_AddNumberToObject(obj_assoc_client, "PacketsSent", assoc_dev_data->dev_stats.cli_PacketsSent);
                cJSON_AddNumberToObject(obj_assoc_client, "PacketsReceived", assoc_dev_data->dev_stats.cli_PacketsReceived);
                cJSON_AddNumberToObject(obj_assoc_client, "ErrorsSent", assoc_dev_data->dev_stats.cli_ErrorsSent);
                cJSON_AddNumberToObject(obj_assoc_client, "RetransCount", assoc_dev_data->dev_stats.cli_RetransCount);
                cJSON_AddNumberToObject(obj_assoc_client, "FailedRetransCount", assoc_dev_data->dev_stats.cli_FailedRetransCount);
                cJSON_AddNumberToObject(obj_assoc_client, "RetryCount", assoc_dev_data->dev_stats.cli_RetryCount);
                cJSON_AddNumberToObject(obj_assoc_client, "MultipleRetryCount", assoc_dev_data->dev_stats.cli_MultipleRetryCount);
            }
            assoc_dev_data = hash_map_get_next(devices_map, assoc_dev_data);
        }
    }
    return webconfig_error_none;
}

webconfig_error_t encode_mac_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *obj_array)
{
    if ((rdk_vap_info == NULL) || (obj_array == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Mac Object encode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON *obj_mac, *obj_acl;
    acl_entry_t *acl_entry;

    obj_mac = cJSON_CreateObject();
    obj_acl = cJSON_CreateArray();

    cJSON_AddItemToArray(obj_array, obj_mac);
    cJSON_AddStringToObject(obj_mac, "VapName", (char *)rdk_vap_info->vap_name);
    cJSON_AddItemToObject(obj_mac, "MACFilterList", obj_acl);

    if(rdk_vap_info->acl_map != NULL) {
        acl_entry = hash_map_get_first(rdk_vap_info->acl_map);
        while(acl_entry != NULL) {

            cJSON *obj_acl_list;
            obj_acl_list= cJSON_CreateObject();
            cJSON_AddItemToArray(obj_acl, obj_acl_list);
            char mac_string[18];
            memset(mac_string,0,18);
            snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                    acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);
            cJSON_AddStringToObject(obj_acl_list, "MAC", mac_string);

            cJSON_AddStringToObject(obj_acl_list, "DeviceName", acl_entry->device_name);
            cJSON_AddNumberToObject(obj_acl_list, "reason", acl_entry->reason);
            cJSON_AddNumberToObject(obj_acl_list, "expiry_time", acl_entry->expiry_time);
            acl_entry = hash_map_get_next(rdk_vap_info->acl_map, acl_entry);
        }
    }
    return webconfig_error_none;
}

webconfig_error_t encode_levl_object(const levl_config_t *levl, cJSON *levl_obj)
{
    if ((levl == NULL) || (levl_obj == NULL)) {
        return webconfig_error_encode;
    }

    char mac_string[18] = {0};
    to_mac_str((unsigned char *)levl->clientMac, mac_string);

    cJSON_AddStringToObject(levl_obj, "clientMac", mac_string);
    cJSON_AddNumberToObject(levl_obj, "maxNumberCSIClients", levl->max_num_csi_clients);
    cJSON_AddNumberToObject(levl_obj, "Duration", levl->levl_sounding_duration);
    cJSON_AddNumberToObject(levl_obj, "Interval", levl->levl_publish_interval);

    return webconfig_error_none;
}

webconfig_error_t encode_blaster_object(const active_msmt_t *blaster_info, cJSON *blaster_obj)
{
   cJSON *stepobj;
   cJSON *obj_array;

    unsigned int i =0;
    if (blaster_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Blaster info is NULL\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON_AddNumberToObject(blaster_obj, "ActiveMsmtPktSize", blaster_info->ActiveMsmtPktSize);
    cJSON_AddNumberToObject(blaster_obj, "ActiveMsmtSampleDuration", blaster_info->ActiveMsmtSampleDuration);
    cJSON_AddNumberToObject(blaster_obj, "ActiveMsmtNumberOfSamples", blaster_info->ActiveMsmtNumberOfSamples);
    cJSON_AddBoolToObject(blaster_obj, "ActiveMsmtEnable", blaster_info->ActiveMsmtEnable);
    cJSON_AddStringToObject(blaster_obj, "PlanId", (char *)blaster_info->PlanId);
    obj_array = cJSON_CreateArray();

    cJSON_AddItemToObject(blaster_obj, "Step", obj_array);
    for (i = 0; i < MAX_STEP_COUNT ; i++) {
        stepobj = cJSON_CreateObject();

        cJSON_AddNumberToObject(stepobj, "StepId", blaster_info->Step[i].StepId);
        cJSON_AddStringToObject(stepobj, "SrcMac", (char *)blaster_info->Step[i].SrcMac);
        cJSON_AddStringToObject(stepobj, "DestMac",(char *)blaster_info->Step[i].DestMac);
        cJSON_AddItemToArray(obj_array, stepobj);
    }
    cJSON_AddNumberToObject(blaster_obj, "Status", blaster_info->Status);
    cJSON_AddStringToObject(blaster_obj, "MQTT Topic", (char *)blaster_info->blaster_mqtt_topic);
    cJSON_AddStringToObject(blaster_obj, "traceParent", (char *)blaster_info->t_header.traceParent);
    cJSON_AddStringToObject(blaster_obj, "traceState", (char *)blaster_info->t_header.traceState);
    return webconfig_error_none;
}

webconfig_error_t encode_wifivapcap(wifi_interface_name_idex_map_t *interface_map, cJSON *hal_obj)
{
    cJSON *object;
    if (interface_map->vap_name[0] != '\0') {
        object =  cJSON_CreateObject();
        cJSON_AddItemToArray(hal_obj, object);
        cJSON_AddStringToObject(object, "VapName", interface_map->vap_name);
        cJSON_AddNumberToObject(object, "PhyIndex", interface_map->phy_index);
        cJSON_AddNumberToObject(object, "RadioIndex", interface_map->rdk_radio_index);
        cJSON_AddStringToObject(object, "InterfaceName", interface_map->interface_name);
        cJSON_AddStringToObject(object, "BridgeName", interface_map->bridge_name);
        cJSON_AddNumberToObject(object, "VLANID", interface_map->vlan_id);
        cJSON_AddNumberToObject(object, "Index", interface_map->index);
    }
    return webconfig_error_none;
}

webconfig_error_t encode_wifiradiointerfacecap(radio_interface_mapping_t *radio_interface_map, cJSON *hal_obj)
{
    cJSON *object;
    if (radio_interface_map->radio_name[0] != '\0') {
        object =  cJSON_CreateObject();
        cJSON_AddItemToArray(hal_obj, object);
        cJSON_AddNumberToObject(object, "PhyIndex", radio_interface_map->phy_index);
        cJSON_AddNumberToObject(object, "RadioIndex", radio_interface_map->radio_index);
        cJSON_AddStringToObject(object, "InterfaceName", radio_interface_map->interface_name);
    }
    return webconfig_error_none;
}

webconfig_error_t encode_csi_object(queue_t *csi_queue, cJSON *csi_obj)
{
    cJSON *object, *obj, *obj_array;
    unsigned int itr, itrj;
    mac_addr_str_t mac_str;
    if ((csi_queue == NULL) && (csi_obj == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    unsigned long count = queue_count(csi_queue);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d count is %lu \n", __func__, __LINE__, count);
    for (itr=0; itr<count; itr++) {
        csi_data_t* csi_data = queue_peek(csi_queue, itr);
        if (csi_data == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }

        object =  cJSON_CreateObject();
        cJSON_AddItemToArray(csi_obj, object);
        cJSON_AddNumberToObject(object, "SessionID", csi_data->csi_session_num);
        cJSON_AddBoolToObject(object, "Enabled", csi_data->enabled);

        obj_array = cJSON_CreateArray();
        if (obj_array == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }

        cJSON_AddItemToObject(object, "MACArray", obj_array);
        for (itrj=0; itrj<csi_data->csi_client_count; itrj++) {
            obj = cJSON_CreateObject();
            if (obj == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                return webconfig_error_encode;
            }

            cJSON_AddItemToArray(obj_array, obj);
            to_mac_str(csi_data->csi_client_list[itrj], mac_str);
            cJSON_AddStringToObject(obj, "macaddress", mac_str);
        }
    }
    return webconfig_error_none;
}

webconfig_error_t encode_wifiradiocap(wifi_platform_property_t *wifi_prop, cJSON *radio_obj, int numRadios)
{
    unsigned int freq_band_count = 0;
    int i;
    cJSON *object;
    wifi_radio_capabilities_t *radiocap;
    int count = 0, temp_count = 0;
    static const wifi_channelBandwidth_t chan_width_arr_enum[] =
    {
        WIFI_CHANNELBANDWIDTH_20MHZ,
        WIFI_CHANNELBANDWIDTH_40MHZ,
        WIFI_CHANNELBANDWIDTH_80MHZ,
        WIFI_CHANNELBANDWIDTH_160MHZ,
#ifdef CONFIG_IEEE80211BE
        WIFI_CHANNELBANDWIDTH_320MHZ,
#endif /* CONFIG_IEEE80211BE */
    };
    int sup_chan_width[8];
    INT channels_list[MAX_CHANNELS];

    if ((wifi_prop == NULL) || (radio_obj == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer radiocap : %p radio_obj : %p\n", __func__, __LINE__, wifi_prop, radio_obj);
        return webconfig_error_encode;
    }
    for (i = 0; i < numRadios; i++) {
         radiocap = &wifi_prop->radiocap[i];
         object =  cJSON_CreateObject();
         cJSON_AddItemToArray(radio_obj, object);
         cJSON_AddNumberToObject(object, "RadioIndex", radiocap->index);

         for (freq_band_count = 0; freq_band_count < radiocap->numSupportedFreqBand; freq_band_count++) {
             (void)memcpy(channels_list, radiocap->channel_list[freq_band_count].channels_list, sizeof(*channels_list) * radiocap->channel_list[freq_band_count].num_channels);
             cJSON_AddItemToObject(object, "PossibleChannels",  cJSON_CreateIntArray(channels_list, radiocap->channel_list[freq_band_count].num_channels));
         }
         freq_band_count = 0;
         temp_count = 0;
         memset(sup_chan_width, 0, sizeof(sup_chan_width));
         for (count = 0; count < (int)(sizeof(chan_width_arr_enum)/sizeof(chan_width_arr_enum[0])); count++) {
             if (radiocap->channelWidth[freq_band_count] & chan_width_arr_enum[count]) {
                 sup_chan_width[temp_count] = chan_width_arr_enum[count];
                 temp_count++;
             }
         }
         if (temp_count != 0) {
             cJSON_AddItemToObject(object, "PossibleChannelWidths",  cJSON_CreateIntArray(sup_chan_width, temp_count));
         }

         cJSON_AddNumberToObject(object, "RadioPresence", wifi_prop->radio_presence[i]);
    }
    return webconfig_error_none;
}

webconfig_error_t encode_stats_config_object(hash_map_t *stats_map, cJSON *st_arr_obj)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);
    cJSON *st_obj;
    INT channels_list[MAX_CHANNELS];

    stats_config_t *st_cfg;
    if ((st_arr_obj == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (stats_map != NULL) {
        st_cfg = hash_map_get_first(stats_map);
        while (st_cfg != NULL) {
            st_obj = cJSON_CreateObject();
            if (st_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToArray(st_arr_obj, st_obj);
            cJSON_AddNumberToObject(st_obj, "StatsType", st_cfg->stats_type);
            cJSON_AddNumberToObject(st_obj, "ReportType", st_cfg->report_type);
            cJSON_AddNumberToObject(st_obj, "RadioType", st_cfg->radio_type);
            cJSON_AddNumberToObject(st_obj, "SurveyType", st_cfg->survey_type);
            cJSON_AddNumberToObject(st_obj, "ReportingInterval", st_cfg->reporting_interval);
            cJSON_AddNumberToObject(st_obj, "ReportingCount", st_cfg->reporting_count);
            cJSON_AddNumberToObject(st_obj, "SamplingInterval", st_cfg->sampling_interval);
            cJSON_AddNumberToObject(st_obj, "SurveyInterval", st_cfg->survey_interval);
            cJSON_AddNumberToObject(st_obj, "ThresholdUtil", st_cfg->threshold_util);
            cJSON_AddNumberToObject(st_obj, "ThresholdMaxDelay", st_cfg->threshold_max_delay);
            (void)memcpy(channels_list, st_cfg->channels_list.channels_list, sizeof(*channels_list) * st_cfg->channels_list.num_channels);
            cJSON_AddItemToObject(st_obj, "ChannelList",  cJSON_CreateIntArray(channels_list, st_cfg->channels_list.num_channels));
            st_cfg = hash_map_get_next(stats_map, st_cfg);
        }
    }

    return webconfig_error_none;
}

webconfig_error_t encode_steering_config_object(hash_map_t *steer_map, cJSON *st_arr_obj)
{
    steering_config_t *st_cfg;
    cJSON *st_obj, *vap_name_array, *vap_name_obj;
    int i = 0;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);

    if ((st_arr_obj == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (steer_map != NULL) {
        st_cfg = hash_map_get_first(steer_map);
        while (st_cfg != NULL) {
            st_obj = cJSON_CreateObject();
            if (st_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToArray(st_arr_obj, st_obj);
            vap_name_array = cJSON_CreateArray();
            if (vap_name_array == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToObject(st_obj, "VapNames", vap_name_array);
            if (st_cfg->vap_name_list_len < 2) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Invalid vap_name_list len : %d\n", __func__, __LINE__, st_cfg->vap_name_list_len);
                return webconfig_error_encode;
            }
            for (i = 0; i < st_cfg->vap_name_list_len; i++) {
                vap_name_obj = cJSON_CreateObject();
                cJSON_AddItemToArray(vap_name_array, vap_name_obj);
                cJSON_AddStringToObject(vap_name_obj, "VapName", (char *)st_cfg->vap_name_list[i]);
            }
            cJSON_AddNumberToObject(st_obj, "ChanUtilAvgCount", st_cfg->chan_util_avg_count);
            cJSON_AddNumberToObject(st_obj, "ChanUtilCheckSec", st_cfg->chan_util_check_sec);
            cJSON_AddNumberToObject(st_obj, "ChanUtilHWM", st_cfg->chan_util_hwm);
            cJSON_AddNumberToObject(st_obj, "ChanUtilLWM", st_cfg->chan_util_lwm);
            cJSON_AddBoolToObject(st_obj, "Dbg2gRawChUtil", st_cfg->dbg_2g_raw_chan_util);
            cJSON_AddBoolToObject(st_obj, "Dbg2gRawRSSI", st_cfg->dbg_2g_raw_rssi);
            cJSON_AddBoolToObject(st_obj, "Dbg5gRawChUtil", st_cfg->dbg_5g_raw_chan_util);
            cJSON_AddBoolToObject(st_obj, "Dbg5gRawChRSSI", st_cfg->dbg_5g_raw_rssi);
            cJSON_AddNumberToObject(st_obj, "DbgLevel", st_cfg->debug_level);
            cJSON_AddNumberToObject(st_obj, "DefRssiInactXing", st_cfg->def_rssi_inact_xing);
            cJSON_AddNumberToObject(st_obj, "DefRssiLowXing", st_cfg->def_rssi_low_xing);
            cJSON_AddNumberToObject(st_obj, "DefRssiXing", st_cfg->def_rssi_xing);
            cJSON_AddBoolToObject(st_obj, "GwOnly", st_cfg->gw_only);
            cJSON_AddNumberToObject(st_obj, "InactChkSec", st_cfg->inact_check_sec);
            cJSON_AddNumberToObject(st_obj, "InactToutSecNormal", st_cfg->inact_tmout_sec_normal);
            cJSON_AddNumberToObject(st_obj, "InactToutSecOverload", st_cfg->inact_tmout_sec_overload);
            cJSON_AddNumberToObject(st_obj, "KickDebouncePeriod", st_cfg->kick_debounce_period);
            cJSON_AddNumberToObject(st_obj, "KickDebounceThresh", st_cfg->kick_debounce_thresh);
            cJSON_AddNumberToObject(st_obj, "StatsReportInterval", st_cfg->stats_report_interval);
            cJSON_AddNumberToObject(st_obj, "SuccesssThreshSecs", st_cfg->success_threshold_secs);
            st_cfg = hash_map_get_next(steer_map, st_cfg);
        }
    }

    return webconfig_error_none;
}


webconfig_error_t encode_steering_clients_object(hash_map_t *steer_clients_map, cJSON *st_arr_obj)
{
    band_steering_clients_t *st_cfg;
    cJSON *st_obj, *param_arr, *param_obj;
    int i = 0;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);

    if ((st_arr_obj == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (steer_clients_map != NULL) {
        st_cfg = hash_map_get_first(steer_clients_map);
        while (st_cfg != NULL) {
            st_obj = cJSON_CreateObject();
            if (st_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToArray(st_arr_obj, st_obj);

            //CsParams
            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToObject(st_obj, "CsParams", param_arr);
            for (i = 0; i < st_cfg->cs_params_len; i++) {
                param_obj = cJSON_CreateObject();
                if ((param_obj == NULL)) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                    return webconfig_error_encode;
                }
                cJSON_AddItemToArray(param_arr, param_obj);
                cJSON_AddStringToObject(param_obj, "Key", (char *)st_cfg->cs_params[i].key);
                cJSON_AddStringToObject(param_obj, "Value", (char *)st_cfg->cs_params[i].value);
            }

            //SteeringBtmParams
            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToObject(st_obj, "SteeringBtmParams", param_arr);
            for (i = 0; i < st_cfg->steering_btm_params_len; i++) {
                param_obj = cJSON_CreateObject();
                if ((param_obj == NULL)) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                    return webconfig_error_encode;
                }
                cJSON_AddItemToArray(param_arr, param_obj);
                cJSON_AddStringToObject(param_obj, "Key", (char *)st_cfg->steering_btm_params[i].key);
                cJSON_AddStringToObject(param_obj, "Value", (char *)st_cfg->steering_btm_params[i].value);
            }

            //RrmBcnRptParams
            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToObject(st_obj, "RrmBcnRptParams", param_arr);
            for (i = 0; i < st_cfg->rrm_bcn_rpt_params_len; i++) {
                param_obj = cJSON_CreateObject();
                if ((param_obj == NULL)) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                    return webconfig_error_encode;
                }
                cJSON_AddItemToArray(param_arr, param_obj);
                cJSON_AddStringToObject(param_obj, "Key", (char *)st_cfg->rrm_bcn_rpt_params[i].key);
                cJSON_AddStringToObject(param_obj, "Value", (char *)st_cfg->rrm_bcn_rpt_params[i].value);
            }

            //sc_btm_params
            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToObject(st_obj, "ScBtmParams", param_arr);
            for (i = 0; i < st_cfg->sc_btm_params_len; i++) {
                param_obj = cJSON_CreateObject();
                if ((param_obj == NULL)) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
                    return webconfig_error_encode;
                }
                cJSON_AddItemToArray(param_arr, param_obj);
                cJSON_AddStringToObject(param_obj, "Key", (char *)st_cfg->sc_btm_params[i].key);
                cJSON_AddStringToObject(param_obj, "Value", (char *)st_cfg->sc_btm_params[i].value);
            }


            cJSON_AddStringToObject(st_obj, "Mac", st_cfg->mac);
            cJSON_AddNumberToObject(st_obj, "BackoffExpBase", st_cfg->backoff_exp_base);
            cJSON_AddNumberToObject(st_obj, "BackoffSecs", st_cfg->backoff_secs);
            cJSON_AddNumberToObject(st_obj, "Hwm", st_cfg->hwm);
            cJSON_AddNumberToObject(st_obj, "Lwm", st_cfg->lwm);
            cJSON_AddNumberToObject(st_obj, "KickDebouncePeriod", st_cfg->kick_debounce_period);
            cJSON_AddNumberToObject(st_obj, "KickReason", st_cfg->kick_reason);
            cJSON_AddBoolToObject(st_obj,   "KickUponIdle", st_cfg->kick_upon_idle);
            cJSON_AddNumberToObject(st_obj, "MaxRejects", st_cfg->max_rejects);
            cJSON_AddBoolToObject(st_obj,   "PreAssocAuthBlock", st_cfg->pre_assoc_auth_block);
            cJSON_AddNumberToObject(st_obj, "RejectsTmoutSecs", st_cfg->rejects_tmout_secs);
            cJSON_AddNumberToObject(st_obj, "ScKickDebouncePeriod", st_cfg->sc_kick_debounce_period);
            cJSON_AddNumberToObject(st_obj, "ScKickReason", st_cfg->sc_kick_reason);
            cJSON_AddBoolToObject(st_obj,   "SteerDuringBackoff", st_cfg->steer_during_backoff);
            cJSON_AddNumberToObject(st_obj, "SteeringFailCnt", st_cfg->steering_fail_cnt);
            cJSON_AddNumberToObject(st_obj, "SteeringKickCnt", st_cfg->steering_kick_cnt);
            cJSON_AddNumberToObject(st_obj, "SteeringSuccessCnt", st_cfg->steering_success_cnt);
            cJSON_AddNumberToObject(st_obj, "StickyKickCnt", st_cfg->sticky_kick_cnt);
            cJSON_AddNumberToObject(st_obj, "StickyKickDebouncePeriod", st_cfg->sticky_kick_debounce_period);
            cJSON_AddNumberToObject(st_obj, "StickyKickReason", st_cfg->sticky_kick_reason);
            cJSON_AddNumberToObject(st_obj, "CsMode", st_cfg->cs_mode);
            cJSON_AddNumberToObject(st_obj, "ForceKick", st_cfg->force_kick);
            cJSON_AddNumberToObject(st_obj, "KickType", st_cfg->kick_type);
            cJSON_AddNumberToObject(st_obj, "Pref5g", st_cfg->pref_5g);
            cJSON_AddNumberToObject(st_obj, "RejectDetection", st_cfg->reject_detection);
            cJSON_AddNumberToObject(st_obj, "ScKickType", st_cfg->sc_kick_type);
            cJSON_AddNumberToObject(st_obj, "StickyKickType", st_cfg->sticky_kick_type);


            st_cfg = hash_map_get_next(steer_clients_map, st_cfg);
        }
    }

    return webconfig_error_none;
}

webconfig_error_t encode_vif_neighbors_object(hash_map_t *neighbors_map, cJSON *neighbor_arr_obj)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);
    cJSON *neighbor_obj;

    vif_neighbors_t *neighbor_cfg;
    if ((neighbor_arr_obj == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (neighbors_map != NULL) {
        neighbor_cfg = hash_map_get_first(neighbors_map);
        while (neighbor_cfg != NULL) {
            neighbor_obj = cJSON_CreateObject();
            if (neighbor_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
                return webconfig_error_encode;
            }
            cJSON_AddItemToArray(neighbor_arr_obj, neighbor_obj);
            cJSON_AddStringToObject(neighbor_obj, "Bssid", neighbor_cfg->bssid);
            cJSON_AddStringToObject(neighbor_obj, "IfName", neighbor_cfg->if_name);
            cJSON_AddNumberToObject(neighbor_obj, "Channel", neighbor_cfg->channel);
            cJSON_AddNumberToObject(neighbor_obj, "HTMode", neighbor_cfg->ht_mode);
            cJSON_AddNumberToObject(neighbor_obj, "Priority", neighbor_cfg->priority);
            neighbor_cfg = hash_map_get_next(neighbors_map, neighbor_cfg);
        }
    }

    return webconfig_error_none;
}

