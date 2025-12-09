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
#include <cjson/cJSON.h>
#include "wifi_webconfig.h"
#include "ctype.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"

#define TCM_WEIGH "0.6"
#define TCMTHRESHOLD "0.18"
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

webconfig_error_t encode_radio_operating_classes(const wifi_radio_operationParam_t *oper,
    cJSON *radio_object)
{
    cJSON *obj_array, *obj;
    unsigned int i, j;
    const wifi_operating_classes_t *oper_classes;
    int nonOperableChannel[MAXNUMNONOPERABLECHANNELS];

    cJSON_AddNumberToObject(radio_object, "NumberOfOpClass", oper->numOperatingClasses);

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(radio_object, "OperatingClasses", obj_array);
    for (i = 0; i < oper->numOperatingClasses; i++) {
        oper_classes = &oper->operatingClasses[i];
        obj = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj);
        cJSON_AddNumberToObject(obj, "NumberOfNonOperChan", oper_classes->numberOfNonOperChan);
        cJSON_AddNumberToObject(obj, "Class", oper_classes->opClass);
        cJSON_AddNumberToObject(obj, "MaxTxPower", oper_classes->maxTxPower);
        for (j = 0; (j < oper_classes->numberOfNonOperChan && j < MAXNUMNONOPERABLECHANNELS); j++) {
            nonOperableChannel[j] = oper_classes->nonOperable[j];
        }
        if (j != 0) {
            cJSON_AddItemToObject(obj, "NonOperable", cJSON_CreateIntArray(nonOperableChannel, j));
        } else {
            cJSON_AddStringToObject(obj, "NonOperable", "[]");
        }
    }
    return webconfig_error_none;
}

webconfig_error_t encode_radio_curr_operating_classes(const wifi_radio_operationParam_t *oper,
    cJSON *radio_object)
{
    cJSON *obj_array, *obj;

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(radio_object, "CurrentOperatingClasses", obj_array);

    // Add operating class and channel as first element in the array
    obj = cJSON_CreateObject();
    cJSON_AddItemToArray(obj_array, obj);
    cJSON_AddNumberToObject(obj, "Class", oper->operatingClass);
    cJSON_AddNumberToObject(obj, "Channel", oper->channel);
    return webconfig_error_none;
}

webconfig_error_t encode_radio_object(const rdk_wifi_radio_t *radio, cJSON *radio_object)
{
    const wifi_radio_operationParam_t *radio_info;
    const wifi_radio_feature_param_t *radio_feat;
    char out_list[BUFFER_LENGTH_WIFIDB] = { 0 }, str[BUFFER_LENGTH_WIFIDB] = { 0 };
    char chan_buf[512] = {0};
    unsigned int num_channels, i, k = 0, len = sizeof(out_list) - 1;
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

        snprintf(out_list + k, sizeof(out_list) - k, "%d,", radio_info->channelSecondary[i]);
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Wifi_Radio_Config table Channel list %s %d\t",
            __func__, __LINE__, out_list, strlen(out_list));
        k = strlen(out_list);
    }

    memset(str, 0, sizeof(str));
    if ((strlen(out_list) > 1) && (strlen(out_list) < sizeof(str))) {
        strncpy(str, out_list, strlen(out_list) - 1);
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

    // TransmitPower, 0 not allowed
    cJSON_AddNumberToObject(radio_object, "TransmitPower",
        radio_info->transmitPower != 0 ? radio_info->transmitPower : 100);

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

    //DfsTimer
    cJSON_AddNumberToObject(radio_object, "DfsTimer", radio_info->DFSTimer);

    //RadarDetected
    cJSON_AddStringToObject(radio_object, "RadarDetected", radio_info->radarDetected);

    // AmsduTid
    memset(out_list, 0, sizeof(str));
    k = 0;
    for (i = 0; i < MAX_AMSDU_TID; i++) {
        if (k >= (len - 1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,
                "%s:%d Wifi_Radio_Config table Maximum size reached for AMSDU TIDs\n", __func__,
                __LINE__);
            break;
        }

        snprintf(out_list + k, sizeof(out_list) - k, "%d,", radio_info->amsduTid[i]);
        k = strlen(out_list);
    }

    if ((strlen(out_list) > 1) && (strlen(out_list) < sizeof(str))) {
        strncpy(str, out_list, strlen(out_list) - 1);
    } else {
        strcpy(str, " ");
    }

    cJSON_AddStringToObject(radio_object, "Amsdu_Tid", str);

    // Operating Class Capability details
    if (encode_radio_operating_classes(radio_info, radio_object) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Radio operation classes failed\n", __func__,
            __LINE__);
        return webconfig_error_encode;
    }

    // Current Operating Class details
    if (encode_radio_curr_operating_classes(radio_info, radio_object) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,
            "%s:%d Radio current operation class encoding failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    return webconfig_error_none;
}

webconfig_error_t encode_vap_common_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_object)
{
    char mac_str[32];
    char mld_mac_str[32];
    char extra_vendor_ies_hex_str[(vap_info->u.bss_info.vendor_elements_len * 2) + 1];

    //VAP Name
    cJSON_AddStringToObject(vap_object, "VapName", vap_info->vap_name);

    //Bridge Name
    cJSON_AddStringToObject(vap_object, "BridgeName", vap_info->bridge_name);

    //Repurposed Bridge Name
    cJSON_AddStringToObject(vap_object, "RepurposedBridgeName", vap_info->repurposed_bridge_name);

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

    // MLD Enable
    cJSON_AddBoolToObject(vap_object, "MLD_Enable", vap_info->u.bss_info.mld_info.common_info.mld_enable);

    // MLD Apply
    cJSON_AddBoolToObject(vap_object, "MLD_Apply", vap_info->u.bss_info.mld_info.common_info.mld_apply);

    // MLD_ID
    cJSON_AddNumberToObject(vap_object, "MLD_ID", vap_info->u.bss_info.mld_info.common_info.mld_id);

    // MLD_Link_ID
    cJSON_AddNumberToObject(vap_object, "MLD_Link_ID", vap_info->u.bss_info.mld_info.common_info.mld_link_id);

    // MLD_Addr
    uint8_mac_to_string_mac((uint8_t *)vap_info->u.bss_info.mld_info.common_info.mld_addr, mld_mac_str);
    cJSON_AddStringToObject(vap_object, "MLD_Addr", mld_mac_str);

    cJSON_AddNumberToObject(vap_object, "SpeedTier", vap_info->u.bss_info.am_config.npc.speed_tier);

    cJSON_AddBoolToObject(vap_object, "MDUEnabled", vap_info->u.bss_info.mdu_enabled);

    // Isolation
    cJSON_AddBoolToObject(vap_object, "IsolationEnable", vap_info->u.bss_info.isolation);

    // ManagementFramePowerControl
    cJSON_AddNumberToObject(vap_object, "ManagementFramePowerControl", vap_info->u.bss_info.mgmtPowerControl);

    cJSON_AddNumberToObject(vap_object, "InteropNumSta", vap_info->u.bss_info.inum_sta);

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

    // HostapMgtFrameCtrl
    cJSON_AddBoolToObject(vap_object, "HostapMgtFrameCtrl",
        vap_info->u.bss_info.hostap_mgt_frame_ctrl);

    // InteropCtrl
    cJSON_AddBoolToObject(vap_object, "InteropCtrl",
        vap_info->u.bss_info.interop_ctrl);

    cJSON_AddBoolToObject(vap_object, "MboEnabled", vap_info->u.bss_info.mbo_enabled);

    memset(extra_vendor_ies_hex_str, 0, sizeof(extra_vendor_ies_hex_str));
    for (unsigned int i = 0; i < vap_info->u.bss_info.vendor_elements_len; i++) {
        sprintf(extra_vendor_ies_hex_str + (i * 2), "%02x", (unsigned int) vap_info->u.bss_info.vendor_elements[i]);
    }
    cJSON_AddStringToObject(vap_object, "ExtraVendorIEs", extra_vendor_ies_hex_str);

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


webconfig_error_t encode_tcm_preassoc_object(const wifi_preassoc_control_t *preassoc_info, cJSON *preassoc)
{
    cJSON_AddNumberToObject(preassoc, "TcmWaitTime", preassoc_info->time_ms);
    cJSON_AddNumberToObject(preassoc, "TcmMinMgmtFrames", preassoc_info->min_num_mgmt_frames);
    if(strlen((char *)preassoc_info->tcm_exp_weightage) == 0) {
        cJSON_AddStringToObject(preassoc, "TcmExpWeightage", TCM_WEIGH);
    } else {
        cJSON_AddStringToObject(preassoc, "TcmExpWeightage", preassoc_info->tcm_exp_weightage);
    }
    if(strlen((char *)preassoc_info->tcm_gradient_threshold) == 0) {
        cJSON_AddStringToObject(preassoc, "TcmGradientThreshold", TCMTHRESHOLD);
    } else {
        cJSON_AddStringToObject(preassoc, "TcmGradientThreshold", preassoc_info->tcm_gradient_threshold);
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Encoding tcm preassoc settings passed\n", __func__, __LINE__);

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
    cJSON_AddItemToObject(vap_obj, "TcmPreAssociationDeny", obj);
    if (encode_tcm_preassoc_object(&vap_info->u.bss_info.preassoc, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d TcmPreassoc object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
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

    // RSS Mem threshold1
    cJSON_AddNumberToObject(global_obj, "rss_memory_restart_threshold_low", global_info->rss_memory_restart_threshold_low);

    // RSS Mem threshold2
    cJSON_AddNumberToObject(global_obj, "rss_memory_restart_threshold_high", global_info->rss_memory_restart_threshold_high);

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

    // MgtFrameRateLimitEnable
    cJSON_AddBoolToObject(global_obj, "MgtFrameRateLimitEnable",
        global_info->mgt_frame_rate_limit_enable);

    // MgtFrameRateLimit
    cJSON_AddNumberToObject(global_obj, "MgtFrameRateLimit", global_info->mgt_frame_rate_limit);

    // MgtFrameRateLimitWindowSize
    cJSON_AddNumberToObject(global_obj, "MgtFrameRateLimitWindowSize",
        global_info->mgt_frame_rate_limit_window_size);

    // MgtFrameRateLimitCooldownTime
    cJSON_AddNumberToObject(global_obj, "MgtFrameRateLimitCooldownTime",
        global_info->mgt_frame_rate_limit_cooldown_time);

    // RSSCheckInterval
    cJSON_AddNumberToObject(global_obj, "rss_check_interval",
        global_info->memwraptool.rss_check_interval);

    // RSSThreshold
    cJSON_AddNumberToObject(global_obj, "rss_threshold", global_info->memwraptool.rss_threshold);

    // RSSMaxLimit
    cJSON_AddNumberToObject(global_obj, "rss_maxlimit", global_info->memwraptool.rss_maxlimit);

    // HeapwalkDuration
    cJSON_AddNumberToObject(global_obj, "heapwalk_duration",
        global_info->memwraptool.heapwalk_duration);

    // HeapwalkInterval
    cJSON_AddNumberToObject(global_obj, "heapwalk_interval",
        global_info->memwraptool.heapwalk_interval);

    // MemwrapToolEnable
    cJSON_AddBoolToObject(global_obj, "MemwrapToolEnable", global_info->memwraptool.enable);

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
        cJSON_DetachItemViaPointer(p_root, anqpElement);
        cJSON_AddItemToObject(inter, "ANQP", anqpElement);
        cJSON_Delete(p_root);
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
        cJSON_DetachItemViaPointer(p_root, pass);
        cJSON_AddItemToObject(inter, "Passpoint", pass);
        cJSON_Delete(p_root);
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
    cJSON_AddBoolToObject(obj, "VenueOptionPresent", interworking_info->interworking.venueOptionPresent);
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

    cJSON_AddNumberToObject(radius, "EAPType", radius_info->eap_type);
    cJSON_AddNumberToObject(radius, "Phase2Auth", radius_info->phase2);
    if (strlen((char *)radius_info->identity) == 0) {
        cJSON_AddStringToObject(radius, "Identity", "username_empty");
    } else {
        cJSON_AddStringToObject(radius, "Identity", radius_info->identity);
    }

    if (strlen((char *)radius_info->key) == 0) {
        cJSON_AddStringToObject(radius, "Key", INVALID_KEY);
    } else {
        cJSON_AddStringToObject(radius, "Key", radius_info->key);
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
    bool is_6g, wifi_vap_mode_t vap_mode)
{
    cJSON *obj;

    if (is_6g &&
        security_info->mode != wifi_security_mode_wpa3_personal &&
        security_info->mode != wifi_security_mode_wpa3_compatibility &&
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

        case wifi_security_mode_wpa3_compatibility:
            cJSON_AddStringToObject(security, "Mode", "WPA3-Personal-Compatibility");
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

    if(security_info->mode == wifi_security_mode_wpa3_compatibility &&
        security_info->mfp != wifi_mfp_cfg_disabled) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Invalid MFP Config %d for %d mode \n",
            __func__, __LINE__, security_info->mfp, security_info->mode);
        return webconfig_error_encode;
    }

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

    if ((security_info->encr != wifi_encryption_aes &&
        security_info->encr != wifi_encryption_aes_gcmp256) &&
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
        case wifi_encryption_aes_gcmp256:
            cJSON_AddStringToObject(security, "EncryptionMethod", "AES+GCMP");
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

    if (vap_mode != wifi_vap_mode_sta) {
        if (security_info->mode != wifi_security_mode_none &&
            (strlen(security_info->u.key.key) < MIN_PWD_LEN ||
            strlen(security_info->u.key.key) > MAX_PWD_LEN)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid password length: %d\n", __func__,
                __LINE__, strlen(security_info->u.key.key));
            return webconfig_error_encode;
        }
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
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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
    if (encode_security_object(&vap_info->u.bss_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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
    
    // Ignite Status
    cJSON_AddBoolToObject(vap_obj, "Ignite_Enabled", vap_info->u.sta_info.ignite_enabled);

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
    if (encode_security_object(&vap_info->u.sta_info.security, obj, is_6g, vap_info->vap_mode) != webconfig_error_none) {
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

char *hextostring(unsigned int in_len, unsigned char *in, unsigned int out_len, char *out)
{
    unsigned int i;
    unsigned char tmp;

    if (out_len < 2 * in_len + 1) {
        return NULL;
    }

    memset(out, 0, out_len);

    for (i = 0; i < in_len; i++) {
        tmp = in[i] >> 4;
        if (tmp < 0xa) {
            out[2 * i] = tmp + 0x30;
        } else {
            out[2 * i] = tmp - 0xa + 0x61;
        }

        tmp = in[i] & 0xf;
        if (tmp < 0xa) {
            out[2 * i + 1] = tmp + 0x30;
        } else {
            out[2 * i + 1] = tmp - 0xa + 0x61;
        }
    }

    return out;
}

webconfig_error_t encode_frame_data(cJSON *obj_assoc_client, frame_data_t *frame)
{
    char assoc_frame_string[MAX_FRAME_SZ * 2 + 1];

    memset(assoc_frame_string, 0, sizeof(assoc_frame_string));

    if (frame->frame.len != 0) {
        hextostring(frame->frame.len, frame->data, MAX_FRAME_SZ * 2 + 1, assoc_frame_string);
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Frame Data is empty.\n", __func__, __LINE__);
        return webconfig_error_none;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Frame Data:\"%s\" Length:%u\n", __func__, __LINE__,
        assoc_frame_string, strlen(assoc_frame_string));
    cJSON_AddStringToObject(obj_assoc_client, "FrameData", assoc_frame_string);

    return webconfig_error_none;
}

webconfig_error_t encode_associated_client_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *assoc_array, assoclist_type_t assoclist_type)
{
    bool print_assoc_client = false, include_frame_data = false;
    pthread_mutex_t *associated_devices_lock;

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

    associated_devices_lock = rdk_vap_info->associated_devices_lock;
    if (associated_devices_lock != NULL) {
        pthread_mutex_lock(associated_devices_lock);
    }
    switch (assoclist_type)  {
        case assoclist_type_full:
            devices_map = rdk_vap_info->associated_devices_map;
        break;
        case assoclist_type_remove:
        case assoclist_type_add:
            devices_map = rdk_vap_info->associated_devices_diff_map;
        break;
        default:
            if (associated_devices_lock != NULL) {
                pthread_mutex_unlock(associated_devices_lock);
            }
            return webconfig_error_encode;
    }


    if (devices_map != NULL) {
        assoc_dev_data = hash_map_get_first(devices_map);
        while (assoc_dev_data != NULL) {
            print_assoc_client = false;
            include_frame_data = false;
            if (assoclist_type == assoclist_type_full) {
                print_assoc_client = true;
            } else if ((assoclist_type == assoclist_type_add) && (assoc_dev_data->client_state == client_state_connected)) {
                print_assoc_client = true;
                include_frame_data = true;
            } else if ((assoclist_type == assoclist_type_remove) && (assoc_dev_data->client_state == client_state_disconnected)) {
                print_assoc_client = true;
            }

            if (print_assoc_client == true) {
                cJSON *obj_assoc_client;
                obj_assoc_client = cJSON_CreateObject();
                mac_addr_str_t mld_mac_str = { 0 };
                char mac_string[18] = {0};
                cJSON_AddItemToArray(obj_array, obj_assoc_client);


                to_mac_str(assoc_dev_data->dev_stats.cli_MLDAddr, mld_mac_str);
                str_tolower(mld_mac_str);
                to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_string);
                str_tolower(mac_string);
                cJSON_AddStringToObject(obj_assoc_client, "MACAddress", mac_string);
                cJSON_AddStringToObject(obj_assoc_client, "MLDAddr", mld_mac_str);
                cJSON_AddBoolToObject(obj_assoc_client, "MLDEnable", assoc_dev_data->dev_stats.cli_MLDEnable);
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
                cJSON_AddNumberToObject(obj_assoc_client, "ActiveNumSpatialStreams", assoc_dev_data->dev_stats.cli_activeNumSpatialStreams);
                cJSON_AddNumberToObject(obj_assoc_client, "PacketsSent", assoc_dev_data->dev_stats.cli_PacketsSent);
                cJSON_AddNumberToObject(obj_assoc_client, "PacketsReceived", assoc_dev_data->dev_stats.cli_PacketsReceived);
                cJSON_AddNumberToObject(obj_assoc_client, "ErrorsSent", assoc_dev_data->dev_stats.cli_ErrorsSent);
                cJSON_AddNumberToObject(obj_assoc_client, "RetransCount", assoc_dev_data->dev_stats.cli_RetransCount);
                cJSON_AddNumberToObject(obj_assoc_client, "FailedRetransCount", assoc_dev_data->dev_stats.cli_FailedRetransCount);
                cJSON_AddNumberToObject(obj_assoc_client, "RetryCount", assoc_dev_data->dev_stats.cli_RetryCount);
                cJSON_AddNumberToObject(obj_assoc_client, "MultipleRetryCount", assoc_dev_data->dev_stats.cli_MultipleRetryCount);
                if (include_frame_data == true &&
                    encode_frame_data(obj_assoc_client, &assoc_dev_data->sta_data.msg_data) !=
                        webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,
                        "%s:%d Encode frame data failed for client %s\n", __func__, __LINE__,
                        mac_string);
                }
            }
            assoc_dev_data = hash_map_get_next(devices_map, assoc_dev_data);
        }
    }
    if (associated_devices_lock != NULL) {
        pthread_mutex_unlock(associated_devices_lock);
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

webconfig_error_t encode_memwraptool_object(memwraptool_config_t *memwrap_info, cJSON *memwrap_obj)
{
    if (memwrap_info == NULL || memwrap_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Memwrap info is NULL\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    cJSON_AddNumberToObject(memwrap_obj, "rss_check_interval", memwrap_info->rss_check_interval);
    cJSON_AddNumberToObject(memwrap_obj, "rss_threshold", memwrap_info->rss_threshold);
    cJSON_AddNumberToObject(memwrap_obj, "rss_maxlimit", memwrap_info->rss_maxlimit);
    cJSON_AddNumberToObject(memwrap_obj, "heapwalk_duration", memwrap_info->heapwalk_duration);
    cJSON_AddNumberToObject(memwrap_obj, "heapwalk_interval", memwrap_info->heapwalk_interval);
    cJSON_AddBoolToObject(memwrap_obj, "enable", memwrap_info->enable);
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

webconfig_error_t encode_device_info(wifi_platform_property_t *wifi_prop, cJSON *device_obj)
{
    mac_addr_str_t mac_str;
    mac_addr_str_t lan_mac_str;
       //Manufacturer
    cJSON_AddStringToObject(device_obj, "Manufacturer", wifi_prop->manufacturer);

    // Model
    cJSON_AddStringToObject(device_obj, "Model",  wifi_prop->manufacturerModel);

    //serialNo
    cJSON_AddStringToObject(device_obj, "SerialNo", wifi_prop->serialNo);

    //software_version
    cJSON_AddStringToObject(device_obj, "Software_version", wifi_prop->software_version);

    //CMMAC
    to_mac_str(wifi_prop->cm_mac, mac_str);
    cJSON_AddStringToObject(device_obj, "CMMAC", mac_str);

    //al_1905_mac
    to_mac_str(wifi_prop->al_1905_mac, lan_mac_str);
    cJSON_AddStringToObject(device_obj, "AL1905-MAC", lan_mac_str);

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

webconfig_error_t encode_radio_channel_radio_params(wifi_provider_response_t *chan_stats, cJSON *radio_stats)
{
    cJSON *radio_stats_obj;

    radio_chan_data_t *chan_data = chan_stats->stat_pointer;

    radio_stats_obj = cJSON_CreateObject();
    if (radio_stats_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    for (unsigned int count = 0; count < chan_stats->stat_array_size; count++) {
        radio_stats_obj = cJSON_CreateObject();
        if (radio_stats_obj == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
            cJSON_Delete(radio_stats_obj);
            return webconfig_error_encode;
        }
        cJSON_AddItemToArray(radio_stats, radio_stats_obj);
        cJSON_AddNumberToObject(radio_stats_obj, "ChannelNumber", chan_data[count].ch_number);
        cJSON_AddNumberToObject(radio_stats_obj, "ChannelNoise", chan_data[count].ch_noise);
        cJSON_AddBoolToObject(radio_stats_obj, "RadarNoise", chan_data[count].ch_radar_noise);
        cJSON_AddNumberToObject(radio_stats_obj, "RSSI", chan_data[count].ch_max_80211_rssi);
        cJSON_AddNumberToObject(radio_stats_obj, "Non80211Noise", chan_data[count].ch_non_80211_noise);
        cJSON_AddNumberToObject(radio_stats_obj, "ChannelUtilization", chan_data[count].ch_utilization);
        cJSON_AddNumberToObject(radio_stats_obj, "TotalUtilization", chan_data[count].ch_utilization_total);
        cJSON_AddNumberToObject(radio_stats_obj, "UtilizationBusy", chan_data[count].ch_utilization_busy);
        cJSON_AddNumberToObject(radio_stats_obj, "UtilizationBusyTx", chan_data[count].ch_utilization_busy_tx);
        cJSON_AddNumberToObject(radio_stats_obj, "UtilizationBusyRx", chan_data[count].ch_utilization_busy_rx);
        cJSON_AddNumberToObject(radio_stats_obj, "UtilizationBusySelf", chan_data[count].ch_utilization_busy_self);
        cJSON_AddNumberToObject(radio_stats_obj, "UtilizationBusyExt", chan_data[count].ch_utilization_busy_ext);
    }
    return webconfig_error_none;
}

webconfig_error_t encode_neighbor_radio_params(wifi_provider_response_t *neigh_stats, cJSON *neigh_stats_obj)
{
    cJSON *neighbor_stats_obj;
    wifi_neighbor_ap2_t *neighbor_data = neigh_stats->stat_pointer;

    neighbor_stats_obj = cJSON_CreateObject();
    if (neighbor_stats_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    for (unsigned int count = 0; count < neigh_stats->stat_array_size; count++) {
        neighbor_stats_obj = cJSON_CreateObject();
        if (neighbor_stats_obj == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
            cJSON_Delete(neighbor_stats_obj);
            return webconfig_error_encode;
        }
        cJSON_AddItemToArray(neigh_stats_obj, neighbor_stats_obj);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_SSID", neighbor_data[count].ap_SSID);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_BSSID", neighbor_data[count].ap_BSSID);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_Mode", neighbor_data[count].ap_Mode);
        cJSON_AddNumberToObject(neighbor_stats_obj, "ap_Channel", neighbor_data[count].ap_Channel);
        cJSON_AddNumberToObject(neighbor_stats_obj, "ap_SignalStrength", neighbor_data[count].ap_SignalStrength);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_SecurityModeEnabled", neighbor_data[count].ap_SecurityModeEnabled);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_EncryptionMode", neighbor_data[count].ap_EncryptionMode);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_OperatingFrequencyBand", neighbor_data[count].ap_OperatingFrequencyBand);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_SupportedStandards", neighbor_data[count].ap_SupportedStandards);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_OperatingStandards", neighbor_data[count].ap_OperatingStandards);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_OperatingChannelBandwidth", neighbor_data[count].ap_OperatingChannelBandwidth);
        cJSON_AddNumberToObject(neighbor_stats_obj, "ap_BeaconPeriod", neighbor_data[count].ap_BeaconPeriod);
        cJSON_AddNumberToObject(neighbor_stats_obj, "ap_Noise", neighbor_data[count].ap_Noise);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_BasicDataTransferRates", neighbor_data[count].ap_BasicDataTransferRates);
        cJSON_AddStringToObject(neighbor_stats_obj, "ap_SupportedDataTransferRates", neighbor_data[count].ap_SupportedDataTransferRates);
        cJSON_AddNumberToObject(neighbor_stats_obj, "ap_DTIMPeriod", neighbor_data[count].ap_DTIMPeriod);
        cJSON_AddNumberToObject(neighbor_stats_obj, "ap_ChannelUtilization", neighbor_data[count].ap_ChannelUtilization);
    }
    return webconfig_error_none;
}

#ifdef EM_APP
webconfig_error_t encode_em_channel_stats_params(channel_scan_response_t *neigh_stats,
    cJSON *neigh_stats_obj)
{
    unsigned int i;
    unsigned short j;
    char mac_str[32];
    cJSON *channel_obj, *neighbors_arr, *neighbor_obj;

    if (neigh_stats == NULL || neigh_stats_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid input parameters\n", __func__,
            __LINE__);
        return webconfig_error_encode;
    }

    for (i = 0; i < neigh_stats->num_results; i++) {
        channel_obj = cJSON_CreateObject();
        if (channel_obj == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: JSON object creation failed\n", __func__,
                __LINE__);
            return webconfig_error_encode;
        }

        cJSON_AddItemToArray(neigh_stats_obj, channel_obj);
        cJSON_AddNumberToObject(channel_obj, "OperatingClass",
            neigh_stats->results[i].operating_class);
        cJSON_AddNumberToObject(channel_obj, "Channel", neigh_stats->results[i].channel);
        cJSON_AddNumberToObject(channel_obj, "ScanStatus", neigh_stats->results[i].scan_status);
        cJSON_AddStringToObject(channel_obj, "Timestamp", neigh_stats->results[i].time_stamp);
        cJSON_AddNumberToObject(channel_obj, "Utilization", neigh_stats->results[i].utilization);
        cJSON_AddNumberToObject(channel_obj, "Noise", neigh_stats->results[i].noise);
        cJSON_AddNumberToObject(channel_obj, "AggregateScanDuration",
            neigh_stats->results[i].aggregate_scan_duration);
        cJSON_AddNumberToObject(channel_obj, "ScanType", neigh_stats->results[i].scan_type);

        neighbors_arr = cJSON_CreateArray();
        cJSON_AddItemToObject(channel_obj, "Neighbors", neighbors_arr);

        for (j = 0; j < neigh_stats->results[i].num_neighbors; j++) {
            neighbor_obj = cJSON_CreateObject();
            if (neighbor_obj == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: JSON object creation failed\n",
                    __func__, __LINE__);
                return webconfig_error_encode;
            }

            cJSON_AddItemToArray(neighbors_arr, neighbor_obj);
            uint8_mac_to_string_mac((uint8_t *)neigh_stats->results[i].neighbors[j].bssid, mac_str);
            cJSON_AddStringToObject(neighbor_obj, "BSSID", mac_str);
            cJSON_AddStringToObject(neighbor_obj, "SSID",
                neigh_stats->results[i].neighbors[j].ssid);
            cJSON_AddNumberToObject(neighbor_obj, "SignalStrength",
                neigh_stats->results[i].neighbors[j].signal_strength);
            cJSON_AddStringToObject(neighbor_obj, "ChannelBandwidth",
                neigh_stats->results[i].neighbors[j].channel_bandwidth);
            cJSON_AddNumberToObject(neighbor_obj, "BSSLoadElementPresent",
                neigh_stats->results[i].neighbors[j].bss_load_element_present);
            cJSON_AddNumberToObject(neighbor_obj, "BSSColor",
                neigh_stats->results[i].neighbors[j].bss_color);
            cJSON_AddNumberToObject(neighbor_obj, "ChannelUtilization",
                neigh_stats->results[i].neighbors[j].channel_utilization);
            cJSON_AddNumberToObject(neighbor_obj, "StationCount",
                neigh_stats->results[i].neighbors[j].station_count);
        }
    }

    return webconfig_error_none;
}
#endif

webconfig_error_t encode_assocdevice_params(wifi_provider_response_t *assoc_dev_stats, cJSON *assoc_stats_obj)
{
    char str[32] = {0};
    cJSON *client_stats_obj;
    sta_data_t *client_stats = assoc_dev_stats->stat_pointer;

    client_stats_obj = cJSON_CreateObject();
    if (client_stats_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    for (unsigned int count = 0; count < assoc_dev_stats->stat_array_size; count++) {
        client_stats_obj = cJSON_CreateObject();
        if (client_stats_obj == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
            cJSON_Delete(client_stats_obj);
            return webconfig_error_encode;
        }

        cJSON_AddItemToArray(assoc_stats_obj, client_stats_obj);
        uint8_mac_to_string_mac((uint8_t *)client_stats[count].dev_stats.cli_MACAddress, str);
        cJSON_AddStringToObject(client_stats_obj, "cli_MACAddress", str);
        cJSON_AddBoolToObject(client_stats_obj, "cli_AuthenticationState", client_stats[count].dev_stats.cli_AuthenticationState);
        cJSON_AddNumberToObject(client_stats_obj, "cli_LastDataDownlinkRate", client_stats[count].dev_stats.cli_LastDataDownlinkRate);
        cJSON_AddNumberToObject(client_stats_obj, "cli_LastDataUplinkRate", client_stats[count].dev_stats.cli_LastDataUplinkRate);
        cJSON_AddNumberToObject(client_stats_obj, "cli_SignalStrength", client_stats[count].dev_stats.cli_SignalStrength);
        cJSON_AddNumberToObject(client_stats_obj, "cli_Retransmissions", client_stats[count].dev_stats.cli_Retransmissions);
        cJSON_AddBoolToObject(client_stats_obj, "cli_Active", client_stats[count].dev_stats.cli_Active);
        cJSON_AddStringToObject(client_stats_obj, "cli_OperatingStandard", client_stats[count].dev_stats.cli_OperatingStandard);
        cJSON_AddStringToObject(client_stats_obj, "cli_OperatingChannelBandwidth", client_stats[count].dev_stats.cli_OperatingChannelBandwidth);
        cJSON_AddNumberToObject(client_stats_obj, "cli_SNR", client_stats[count].dev_stats.cli_SNR);
        cJSON_AddStringToObject(client_stats_obj, "cli_InterferenceSources", client_stats[count].dev_stats.cli_InterferenceSources);
        cJSON_AddNumberToObject(client_stats_obj, "cli_DataFramesSentAck", client_stats[count].dev_stats.cli_DataFramesSentAck);
        cJSON_AddNumberToObject(client_stats_obj, "cli_DataFramesSentNoAck", client_stats[count].dev_stats.cli_DataFramesSentNoAck);
        cJSON_AddNumberToObject(client_stats_obj, "cli_BytesSent", client_stats[count].dev_stats.cli_BytesSent);
        cJSON_AddNumberToObject(client_stats_obj, "cli_BytesReceived", client_stats[count].dev_stats.cli_BytesReceived);
        cJSON_AddNumberToObject(client_stats_obj, "cli_RSSI", client_stats[count].dev_stats.cli_RSSI);
        cJSON_AddNumberToObject(client_stats_obj, "cli_MinRSSI", client_stats[count].dev_stats.cli_MinRSSI);
        cJSON_AddNumberToObject(client_stats_obj, "cli_MaxRSSI", client_stats[count].dev_stats.cli_MaxRSSI);
        cJSON_AddNumberToObject(client_stats_obj, "cli_Disassociations", client_stats[count].dev_stats.cli_Disassociations);
        cJSON_AddNumberToObject(client_stats_obj, "cli_AuthenticationFailures", client_stats[count].dev_stats.cli_AuthenticationFailures);
        cJSON_AddNumberToObject(client_stats_obj, "cli_Associations", client_stats[count].dev_stats.cli_Associations);
        cJSON_AddNumberToObject(client_stats_obj, "cli_PacketsSent", client_stats[count].dev_stats.cli_PacketsSent);
        cJSON_AddNumberToObject(client_stats_obj, "cli_PacketsReceived", client_stats[count].dev_stats.cli_PacketsReceived);
        cJSON_AddNumberToObject(client_stats_obj, "cli_ErrorsSent", client_stats[count].dev_stats.cli_ErrorsSent);
        cJSON_AddNumberToObject(client_stats_obj, "cli_RetransCount", client_stats[count].dev_stats.cli_RetransCount);
        cJSON_AddNumberToObject(client_stats_obj, "cli_FailedRetransCount", client_stats[count].dev_stats.cli_FailedRetransCount);
        cJSON_AddNumberToObject(client_stats_obj, "cli_RetryCount", client_stats[count].dev_stats.cli_RetryCount);
        cJSON_AddNumberToObject(client_stats_obj, "cli_MultipleRetryCount", client_stats[count].dev_stats.cli_MultipleRetryCount);
        cJSON_AddNumberToObject(client_stats_obj, "cli_MaxDownlinkRate", client_stats[count].dev_stats.cli_MaxDownlinkRate);
        cJSON_AddNumberToObject(client_stats_obj, "cli_MaxUplinkRate", client_stats[count].dev_stats.cli_MaxUplinkRate);
        cJSON_AddNumberToObject(client_stats_obj, "cli_activeNumSpatialStreams", client_stats[count].dev_stats.cli_activeNumSpatialStreams);
        cJSON_AddNumberToObject(client_stats_obj, "cli_TxFrames", client_stats[count].dev_stats.cli_TxFrames);
        cJSON_AddNumberToObject(client_stats_obj, "cli_RxRetries", client_stats[count].dev_stats.cli_RxRetries);
        cJSON_AddNumberToObject(client_stats_obj, "cli_RxErrors", client_stats[count].dev_stats.cli_RxErrors);
    }
    return webconfig_error_none;
}

webconfig_error_t encode_radiodiag_params(wifi_provider_response_t *radiodiag_stats, cJSON *radiodiag_obj)
{
    cJSON *diag_obj;
    radio_data_t *diag_stats = radiodiag_stats->stat_pointer;

    diag_obj = cJSON_CreateObject();
    if (diag_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    for (unsigned int count = 0; count < radiodiag_stats->stat_array_size; count++) {
        diag_obj = cJSON_CreateObject();
        if (diag_obj == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
            return webconfig_error_encode;
        }

        cJSON_AddItemToArray(radiodiag_obj, diag_obj);
        cJSON_AddNumberToObject(diag_obj, "primary_radio_channel", diag_stats[count].primary_radio_channel);
        cJSON_AddNumberToObject(diag_obj, "RadioActivityFactor", diag_stats[count].RadioActivityFactor);
        cJSON_AddNumberToObject(diag_obj, "CarrierSenseThreshold_Exceeded", diag_stats[count].CarrierSenseThreshold_Exceeded);
        cJSON_AddNumberToObject(diag_obj, "NoiseFloor", diag_stats[count].NoiseFloor);
        cJSON_AddNumberToObject(diag_obj, "channelUtil", diag_stats[count].channelUtil);
        cJSON_AddNumberToObject(diag_obj, "radio_BytesSent", diag_stats[count].radio_BytesSent);
        cJSON_AddNumberToObject(diag_obj, "radio_BytesReceived", diag_stats[count].radio_BytesReceived);
        cJSON_AddNumberToObject(diag_obj, "radio_PacketsSent", diag_stats[count].radio_PacketsSent);
        cJSON_AddNumberToObject(diag_obj, "radio_PacketsReceived", diag_stats[count].radio_PacketsReceived);
        cJSON_AddNumberToObject(diag_obj, "radio_ErrorsSent", diag_stats[count].radio_ErrorsSent);
        cJSON_AddNumberToObject(diag_obj, "radio_ErrorsReceived", diag_stats[count].radio_ErrorsReceived);
        cJSON_AddNumberToObject(diag_obj, "radio_DiscardPacketsSent", diag_stats[count].radio_DiscardPacketsSent);
        cJSON_AddNumberToObject(diag_obj, "radio_DiscardPacketsReceived", diag_stats[count].radio_DiscardPacketsReceived);
        cJSON_AddNumberToObject(diag_obj, "radio_InvalidMACCount", diag_stats[count].radio_InvalidMACCount);
        cJSON_AddNumberToObject(diag_obj, "radio_PacketsOtherReceived", diag_stats[count].radio_PacketsOtherReceived);
        cJSON_AddNumberToObject(diag_obj, "radio_RetransmissionMetirc", diag_stats[count].radio_RetransmissionMetirc);
        cJSON_AddNumberToObject(diag_obj, "radio_PLCPErrorCount", diag_stats[count].radio_PLCPErrorCount);
        cJSON_AddNumberToObject(diag_obj, "radio_FCSErrorCount", diag_stats[count].radio_FCSErrorCount);
        cJSON_AddNumberToObject(diag_obj, "radio_MaximumNoiseFloorOnChannel", diag_stats[count].radio_MaximumNoiseFloorOnChannel);
        cJSON_AddNumberToObject(diag_obj, "radio_MinimumNoiseFloorOnChannel", diag_stats[count].radio_MinimumNoiseFloorOnChannel);
        cJSON_AddNumberToObject(diag_obj, "radio_MedianNoiseFloorOnChannel", diag_stats[count].radio_MedianNoiseFloorOnChannel);
        cJSON_AddNumberToObject(diag_obj, "radio_StatisticsStartTime", diag_stats[count].radio_StatisticsStartTime);
    }
    return webconfig_error_none;
}

void print_hex_dump(unsigned int length, unsigned char *buffer)
{
    unsigned int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if (length > 500) return;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

#ifdef EM_APP
webconfig_error_t encode_beacon_report_object(sta_beacon_report_reponse_t *sta_data,
    cJSON **beacon_report_obj)
{
    char assoc_frame_string[MAX_FRAME_SZ * 2 + 1];
    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL sta_data Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (*beacon_report_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL beacon_report_obj Pointer\n", __func__,
            __LINE__);
        return webconfig_error_encode;
    }

    memset(assoc_frame_string, 0, sizeof(assoc_frame_string));
    if (sta_data->data_len != 0) {
        // print_hex_dump(sta_data->data_len, sta_data->data);
        hextostring(sta_data->data_len, sta_data->data, MAX_FRAME_SZ * 2 + 1, assoc_frame_string);
        // printf("assoc_frame_string:%s\n", assoc_frame_string);
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d No Report Data\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    cJSON_AddStringToObject(*beacon_report_obj, "ReportData", assoc_frame_string);
    return webconfig_error_none;
}
#endif

webconfig_error_t encode_radio_temperature_params(wifi_provider_response_t *radiotemperature_stats, cJSON *radiotemp_obj)
{
    cJSON *temp_obj;
    radio_data_t *temp_stats = radiotemperature_stats->stat_pointer;

    temp_obj = cJSON_CreateObject();
    if (temp_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    for (unsigned int count = 0; count < radiotemperature_stats->stat_array_size; count++) {
        temp_obj = cJSON_CreateObject();
        if (temp_obj == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d json object creation failed\n", __func__, __LINE__);
            return webconfig_error_encode;
        }

        cJSON_AddItemToArray(radiotemp_obj, temp_obj);
        cJSON_AddNumberToObject(temp_obj, "Radio_Temperature", temp_stats[count].radio_Temperature);
    }

    return webconfig_error_none;
}

#ifdef EM_APP
webconfig_error_t encode_em_config_object(const em_config_t *em_config, cJSON *emconfig_obj)
{
    if ((em_config == NULL) || (em_config == NULL)) {
        return webconfig_error_encode;
    }

    cJSON *policy_obj, *param_arr, *param_obj;
    char mac_str[32];

    policy_obj = cJSON_CreateObject();
    if (policy_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
        return webconfig_error_encode;
    }

    cJSON_AddItemToObject(emconfig_obj, "Policy", policy_obj);

    // AP Metrics Reporting Policy
    param_obj = cJSON_CreateObject();
    if (param_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
        return webconfig_error_encode;
    }
    cJSON_AddItemToObject(policy_obj, "AP Metrics Reporting Policy", param_obj);

    cJSON_AddNumberToObject(param_obj, "Interval", em_config->ap_metric_policy.interval);
    cJSON_AddStringToObject(param_obj, "Managed Client Marker",
        em_config->ap_metric_policy.managed_client_marker);

    // Local Steering Disallowed Policy
    param_obj = cJSON_CreateObject();
    if (param_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
    }
    cJSON_AddItemToObject(policy_obj, "Local Steering Disallowed Policy", param_obj);

    param_arr = cJSON_CreateArray();
    if (param_arr == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
    }
    cJSON_AddItemToObject(param_obj, "Disallowed STA", param_arr);
    for (int i = 0; i < em_config->local_steering_dslw_policy.sta_count; i++) {
        param_obj = cJSON_CreateObject();
        if (param_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                __LINE__);
        }
        cJSON_AddItemToArray(param_arr, param_obj);
        cJSON_AddStringToObject(param_obj, "MAC",
            (const char *)em_config->local_steering_dslw_policy.disallowed_sta[i]);
    }

    // BTM Steering Disallowed Policy
    param_obj = cJSON_CreateObject();
    if (param_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
    }
    cJSON_AddItemToObject(policy_obj, "BTM Steering Disallowed Policy", param_obj);

    param_arr = cJSON_CreateArray();
    if (param_arr == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
    }
    cJSON_AddItemToObject(param_obj, "Disallowed STA", param_arr);
    for (int i = 0; i < em_config->btm_steering_dslw_policy.sta_count; i++) {
        param_obj = cJSON_CreateObject();
        if (param_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                __LINE__);
        }
        cJSON_AddItemToArray(param_arr, param_obj);
        cJSON_AddStringToObject(param_obj, "MAC",
            (const char *)em_config->btm_steering_dslw_policy.disallowed_sta[i]);
    }
    
    // Backhaul BSS Configuration Policy
    param_obj = cJSON_CreateObject();
    if (param_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
    }
    cJSON_AddItemToObject(policy_obj, "Backhaul BSS Configuration Policy", param_obj);
    cJSON_AddStringToObject(param_obj, "BSSID",
        (const char *)em_config->backhaul_bss_config_policy.bssid);
    cJSON_AddBoolToObject(param_obj, "Profile-1 bSTA Disallowed",
        0); // em_config->backhaul_bss_config_policy.profile_1_bsta_disallowed);
    cJSON_AddBoolToObject(param_obj, "Profile-2 bSTA Disallowed",
        1); // em_config->backhaul_bss_config_policy.profile_2_bsta_disallowed);

    // Channel Scan Reporting Policy
    param_obj = cJSON_CreateObject();
    if (param_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
    }
    cJSON_AddItemToObject(policy_obj, "Channel Scan Reporting Policy", param_obj);
    cJSON_AddNumberToObject(param_obj, "Report Independent Channel Scans",
        em_config->channel_scan_reporting_policy.report_independent_channel_scan);

    // Radio Specific Metrics Policy
    param_arr = cJSON_CreateArray();
    if (param_arr == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
    }
    cJSON_AddItemToObject(policy_obj, "Radio Specific Metrics Policy", param_arr);
    for (int i = 0; i < em_config->radio_metrics_policies.radio_count; i++) {
        param_obj = cJSON_CreateObject();
        if (param_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                __LINE__);
        }
        cJSON_AddItemToArray(param_arr, param_obj);

        uint8_mac_to_string_mac((uint8_t *)em_config->radio_metrics_policies.radio_metrics_policy[i].ruid,
            mac_str);
        cJSON_AddStringToObject(param_obj, "ID", mac_str);
        cJSON_AddNumberToObject(param_obj, "STA RCPI Threshold",
            em_config->radio_metrics_policies.radio_metrics_policy[i].sta_rcpi_threshold);
        cJSON_AddNumberToObject(param_obj, "STA RCPI Hysteresis",
            em_config->radio_metrics_policies.radio_metrics_policy[i].sta_rcpi_hysteresis);
        cJSON_AddNumberToObject(param_obj, "AP Utilization Threshold",
            em_config->radio_metrics_policies.radio_metrics_policy[i].ap_util_threshold);
        cJSON_AddBoolToObject(param_obj, "STA Traffic Stats",
            em_config->radio_metrics_policies.radio_metrics_policy[i].traffic_stats);
        cJSON_AddBoolToObject(param_obj, "STA Link Metrics",
            em_config->radio_metrics_policies.radio_metrics_policy[i].link_metrics);
        cJSON_AddBoolToObject(param_obj, "STA Status",
            em_config->radio_metrics_policies.radio_metrics_policy[i].sta_status);
    }

    return webconfig_error_none;
}

webconfig_error_t encode_em_sta_link_metrics_object(const em_assoc_sta_link_metrics_rsp_t *sta_link_metrics, cJSON *sta_link_metrics_obj)
{
    if ((sta_link_metrics  == NULL) || (sta_link_metrics_obj  == NULL)) {
        return webconfig_error_encode;
    }

    char mac_str[32];
    cJSON *assoc_sta_link_metrics_obj, *error_code_obj, *assoc_sta_ext_link_metrics_obj, *param_obj, *temp_obj, *param_arr;

    for (int i = 0; i < sta_link_metrics->sta_count; i++)
    {
        param_obj = cJSON_CreateObject();
        if (param_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
        }

        cJSON_AddItemToArray(sta_link_metrics_obj, param_obj);

        uint8_mac_to_string_mac(sta_link_metrics->per_sta_metrics[i].sta_mac, mac_str);
        cJSON_AddStringToObject(param_obj, "STA MAC", mac_str);
        cJSON_AddStringToObject(param_obj, "Client Type", sta_link_metrics->per_sta_metrics[i].client_type);

        // Associated STA Link Metrics
        if (sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.num_bssid != 0)
        {
            assoc_sta_link_metrics_obj = cJSON_CreateObject();
            if (assoc_sta_link_metrics_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
            }

            cJSON_AddItemToObject(param_obj, "Associated STA Link Metrics", assoc_sta_link_metrics_obj);
            cJSON_AddNumberToObject(assoc_sta_link_metrics_obj, "Number of BSSIDs", 
                sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.num_bssid);
            
            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
            }

            cJSON_AddItemToObject(assoc_sta_link_metrics_obj, "Per BSSID Metrics", param_arr);

            for (int j = 0; j < sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.num_bssid; j++)
            {
                temp_obj = cJSON_CreateObject();
                if (temp_obj == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
                }

                cJSON_AddItemToArray(param_arr, temp_obj);

                uint8_mac_to_string_mac(sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.assoc_sta_link_metrics_data[j].bssid, mac_str);
                cJSON_AddStringToObject(temp_obj, "BSSID", mac_str);
                cJSON_AddNumberToObject(temp_obj, "Time Delta", 
                    sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.assoc_sta_link_metrics_data[j].time_delta);
                cJSON_AddNumberToObject(temp_obj, 
                    "Estimated Mac Rate Down", sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.assoc_sta_link_metrics_data[j].est_mac_rate_down);
                cJSON_AddNumberToObject(temp_obj, 
                    "Estimated Mac Rate Up", sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.assoc_sta_link_metrics_data[j].est_mac_rate_up);
                cJSON_AddNumberToObject(temp_obj, 
                    "RCPI", sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.assoc_sta_link_metrics_data[j].rcpi);
            }
        }

        // Error Code
        if (sta_link_metrics->per_sta_metrics[i].assoc_sta_link_metrics.num_bssid == 0)
        {
            error_code_obj = cJSON_CreateObject();
            if (error_code_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
            }
            cJSON_AddItemToObject(param_obj, "Error Code", error_code_obj);
    
            cJSON_AddNumberToObject(error_code_obj, "Reason Code", 
                sta_link_metrics->per_sta_metrics[i].error_code.reason_code);
            uint8_mac_to_string_mac(sta_link_metrics->per_sta_metrics[i].error_code.sta_mac, mac_str);
            cJSON_AddStringToObject(error_code_obj, "STA MAC", mac_str);
        }

        // Associated STA Extended Link Metrics 
        if (sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.num_bssid != 0)
        {
            assoc_sta_ext_link_metrics_obj = cJSON_CreateObject();
            if (assoc_sta_ext_link_metrics_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
            }
            cJSON_AddItemToObject(param_obj, "Associated STA Extended Link Metrics", assoc_sta_ext_link_metrics_obj);
            cJSON_AddNumberToObject(assoc_sta_ext_link_metrics_obj, 
                "Number of BSSIDs", sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.num_bssid);
    
            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
            }
            cJSON_AddItemToObject(assoc_sta_ext_link_metrics_obj, "Per BSSID Metrics", param_arr);
    
            for (int j = 0; j < sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.num_bssid; j++)
            {
                temp_obj = cJSON_CreateObject();
                if (temp_obj == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
                }

                cJSON_AddItemToArray(param_arr, temp_obj);

                uint8_mac_to_string_mac(sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j].bssid, mac_str);
                cJSON_AddStringToObject(temp_obj, "BSSID", mac_str);
                cJSON_AddNumberToObject(temp_obj, 
                    "Last Data Downlink Rate", sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j].last_data_downlink_rate);
                cJSON_AddNumberToObject(temp_obj, 
                    "Last Data Uplink Rate", sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j].last_data_uplink_rate);
                cJSON_AddNumberToObject(temp_obj, 
                    "Utilization Receive", sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j].utilization_receive);
                cJSON_AddNumberToObject(temp_obj, 
                    "Utilization Transmit", sta_link_metrics->per_sta_metrics[i].assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j].utilization_transmit);
            }
        }
    }
    return webconfig_error_none;
}

webconfig_error_t encode_em_sta_traffic_stats_object(int sta_cnt,
    assoc_sta_traffic_stats_t *sta_traffic_stats, cJSON *ap_report_obj)
{
    cJSON *param_arr, *param_obj;
    mac_addr_str_t mac_string;
    int i = 0;

    if (ap_report_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Null json object\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    // Create AP Metrics array
    param_arr = cJSON_CreateArray();
    if (param_arr == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Array obj creation failed\n", __func__, __LINE__);
        return webconfig_error_none;
    }

    cJSON_AddItemToObject(ap_report_obj, "Associated STA Traffic Stats", param_arr);

    if (sta_traffic_stats == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Null sta_traffic_stats\n", __func__, __LINE__);
        return webconfig_error_none;
    }

    for (i = 0; i < sta_cnt; i++) {
        param_obj = cJSON_CreateObject();
        if (param_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Null objects\n", __func__, __LINE__);
            return webconfig_error_encode;
        }
        cJSON_AddItemToArray(param_arr, param_obj);

        to_mac_str(sta_traffic_stats[i].sta_mac, mac_string);
        cJSON_AddStringToObject(param_obj, "STA MacAddress", mac_string);
        cJSON_AddNumberToObject(param_obj, "BytesSent", sta_traffic_stats[i].bytes_sent);
        cJSON_AddNumberToObject(param_obj, "BytesReceived", sta_traffic_stats[i].bytes_rcvd);
        cJSON_AddNumberToObject(param_obj, "PacketsSent", sta_traffic_stats[i].packets_sent);
        cJSON_AddNumberToObject(param_obj, "PacketsReceived", sta_traffic_stats[i].packets_rcvd);
        cJSON_AddNumberToObject(param_obj, "TxPacketsErrors", sta_traffic_stats[i].tx_packtes_errs);
        cJSON_AddNumberToObject(param_obj, "RxPacketsErrors", sta_traffic_stats[i].rx_packtes_errs);
        cJSON_AddNumberToObject(param_obj, "RetransmissionCount", sta_traffic_stats[i].retrans_cnt);
    }
}

// merge with existing one, later
webconfig_error_t encode_sta_link_metrics_object(per_sta_metrics_t *sta_metrics, int sta_cnt,
    cJSON *sta_obj)
{
    char mac_str[32];
    cJSON *assoc_sta_link_metrics_obj, *error_code_obj, *assoc_sta_ext_link_metrics_obj, *param_obj,
        *temp_obj, *param_arr;

    cJSON *link_metrics_arr = cJSON_CreateArray();
    cJSON_AddItemToObject(sta_obj, "Associated STA Link Metrics Report", link_metrics_arr);

    for (int i = 0; i < sta_cnt; i++) {
        param_obj = cJSON_CreateObject();
        if (param_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
        }

        cJSON_AddItemToArray(link_metrics_arr, param_obj);

        uint8_mac_to_string_mac(sta_metrics[i].sta_mac, mac_str);
        cJSON_AddStringToObject(param_obj, "STA MAC", mac_str);
        cJSON_AddStringToObject(param_obj, "Client Type", sta_metrics[i].client_type);

        // Associated STA Link Metrics
        if (sta_metrics[i].assoc_sta_link_metrics.num_bssid != 0) {
            assoc_sta_link_metrics_obj = cJSON_CreateObject();
            if (assoc_sta_link_metrics_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                    __LINE__);
            }

            cJSON_AddItemToObject(param_obj, "Associated STA Link Metrics",
                assoc_sta_link_metrics_obj);
            cJSON_AddNumberToObject(assoc_sta_link_metrics_obj, "Number of BSSIDs",
                sta_metrics[i].assoc_sta_link_metrics.num_bssid);

            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                    __LINE__);
            }

            cJSON_AddItemToObject(assoc_sta_link_metrics_obj, "Per BSSID Metrics", param_arr);

            for (int j = 0; j < sta_metrics[i].assoc_sta_link_metrics.num_bssid; j++) {
                temp_obj = cJSON_CreateObject();
                if (temp_obj == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                        __LINE__);
                }

                cJSON_AddItemToArray(param_arr, temp_obj);

                uint8_mac_to_string_mac(
                    sta_metrics[i].assoc_sta_link_metrics.assoc_sta_link_metrics_data[j].bssid,
                    mac_str);
                cJSON_AddStringToObject(temp_obj, "BSSID", mac_str);
                cJSON_AddNumberToObject(temp_obj, "Time Delta",
                    sta_metrics[i]
                        .assoc_sta_link_metrics.assoc_sta_link_metrics_data[j]
                        .time_delta);
                cJSON_AddNumberToObject(temp_obj, "Estimated Mac Rate Down",
                    sta_metrics[i]
                        .assoc_sta_link_metrics.assoc_sta_link_metrics_data[j]
                        .est_mac_rate_down);
                cJSON_AddNumberToObject(temp_obj, "Estimated Mac Rate Up",
                    sta_metrics[i]
                        .assoc_sta_link_metrics.assoc_sta_link_metrics_data[j]
                        .est_mac_rate_up);
                cJSON_AddNumberToObject(temp_obj, "RCPI",
                    sta_metrics[i].assoc_sta_link_metrics.assoc_sta_link_metrics_data[j].rcpi);
            }
        }

        // Error Code
        if (sta_metrics[i].assoc_sta_link_metrics.num_bssid == 0) {
            error_code_obj = cJSON_CreateObject();
            if (error_code_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                    __LINE__);
            }
            cJSON_AddItemToObject(param_obj, "Error Code", error_code_obj);

            cJSON_AddNumberToObject(error_code_obj, "Reason Code",
                sta_metrics[i].error_code.reason_code);
            uint8_mac_to_string_mac(sta_metrics[i].error_code.sta_mac, mac_str);
            cJSON_AddStringToObject(error_code_obj, "STA MAC", mac_str);
        }

        // Associated STA Extended Link Metrics
        if (sta_metrics[i].assoc_sta_ext_link_metrics.num_bssid != 0) {
            assoc_sta_ext_link_metrics_obj = cJSON_CreateObject();
            if (assoc_sta_ext_link_metrics_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                    __LINE__);
            }
            cJSON_AddItemToObject(param_obj, "Associated STA Extended Link Metrics",
                assoc_sta_ext_link_metrics_obj);
            cJSON_AddNumberToObject(assoc_sta_ext_link_metrics_obj, "Number of BSSIDs",
                sta_metrics[i].assoc_sta_ext_link_metrics.num_bssid);

            param_arr = cJSON_CreateArray();
            if (param_arr == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                    __LINE__);
            }
            cJSON_AddItemToObject(assoc_sta_ext_link_metrics_obj, "Per BSSID Metrics", param_arr);

            for (int j = 0; j < sta_metrics[i].assoc_sta_ext_link_metrics.num_bssid; j++) {
                temp_obj = cJSON_CreateObject();
                if (temp_obj == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
                        __LINE__);
                }

                cJSON_AddItemToArray(param_arr, temp_obj);

                uint8_mac_to_string_mac(
                    sta_metrics[i]
                        .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j]
                        .bssid,
                    mac_str);
                cJSON_AddStringToObject(temp_obj, "BSSID", mac_str);
                cJSON_AddNumberToObject(temp_obj, "Last Data Downlink Rate",
                    sta_metrics[i]
                        .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j]
                        .last_data_downlink_rate);
                cJSON_AddNumberToObject(temp_obj, "Last Data Uplink Rate",
                    sta_metrics[i]
                        .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j]
                        .last_data_uplink_rate);
                cJSON_AddNumberToObject(temp_obj, "Utilization Receive",
                    sta_metrics[i]
                        .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j]
                        .utilization_receive);
                cJSON_AddNumberToObject(temp_obj, "Utilization Transmit",
                    sta_metrics[i]
                        .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[j]
                        .utilization_transmit);
            }
        }
    }
    return webconfig_error_none;
}

webconfig_error_t encode_em_ap_metrics_report_object(rdk_wifi_radio_t *radio,
    em_ap_metrics_report_t *ap_report, cJSON *emap_metrics_report_obj)
{
    cJSON *error_code_obj, *param_obj, *temp_obj, *param_arr;
    int radio_index = ap_report->radio_index;
    wifi_vap_info_map_t *vap_map = NULL;
    wifi_vap_info_t *vap = NULL;
    em_vap_metrics_t *ap_metrics = NULL;
    mac_addr_str_t mac_string;
    int vap_arr_index = -1;

    if ((ap_report == NULL) || (emap_metrics_report_obj == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NUll obj\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (radio == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to find the interface map entry\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    vap_map = &radio->vaps.vap_map;

    // Add Radio Index
    cJSON_AddNumberToObject(emap_metrics_report_obj, "Radio Index", ap_report->radio_index);

    // Create Vap Info array within the radio object
    param_arr = cJSON_CreateArray();
    if (param_arr == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    cJSON_AddItemToObject(emap_metrics_report_obj, "Vap Info", param_arr);

    for (int j = 0; j < radio->vaps.num_vaps; j++) {
        vap = &vap_map->vap_array[j];
        if (vap == NULL) {
            continue;
        }

        for (int k = 0; k < MAX_NUM_VAP_PER_RADIO; k++) {
            ap_metrics = &ap_report->vap_reports[k];
            if (strncmp(vap->u.bss_info.bssid, ap_metrics->vap_metrics.bssid,
                sizeof(bssid_t)) == 0) {
                    vap_arr_index = k;
                    break;
            }
        }
        if(vap_arr_index == -1) {
            continue;
        }

        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d vap_arr_index: %d\n", __func__, __LINE__, vap_arr_index);

        ap_metrics = &ap_report->vap_reports[vap_arr_index];

        param_obj = cJSON_CreateObject();
        if ((param_obj == NULL)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }
        cJSON_AddItemToArray(param_arr, param_obj);
        cJSON_AddNumberToObject(param_obj, "VapIndex", vap->vap_index);

        temp_obj = cJSON_CreateObject();
        if ((temp_obj == NULL)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }
        cJSON_AddItemToObject(param_obj, "AP Metrics", temp_obj);
        to_mac_str(vap->u.bss_info.bssid, mac_string);
        cJSON_AddStringToObject(temp_obj, "BSSID", mac_string);
        cJSON_AddNumberToObject(temp_obj, "Channel Util", ap_metrics->vap_metrics.channel_util);
        cJSON_AddNumberToObject(temp_obj, "Number of Associated STAs",
            ap_metrics->vap_metrics.num_of_assoc_stas);

        // Create AP Extended Metrics array
        temp_obj = cJSON_CreateObject();
        if ((temp_obj == NULL)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }
        cJSON_AddItemToObject(param_obj, "AP Extended Metrics", temp_obj);
        cJSON_AddStringToObject(temp_obj, "BSSID", mac_string);
        cJSON_AddNumberToObject(temp_obj, "BSS.UnicastBytesSent",
            ap_metrics->vap_metrics.unicast_bytes_sent);
        cJSON_AddNumberToObject(temp_obj, "BSS.UnicastBytesReceived",
            ap_metrics->vap_metrics.unicast_bytes_rcvd);


        // Create Radio Metrics
        temp_obj = cJSON_CreateObject();
        if ((temp_obj == NULL)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }
        cJSON_AddItemToObject(param_obj, "Radio Metrics", temp_obj);
        to_mac_str(ap_report->radio_metrics.ruid, mac_string);
        cJSON_AddStringToObject(temp_obj, "Radio ID", mac_string);
        cJSON_AddNumberToObject(temp_obj, "Radio.Noise",
            ap_report->radio_metrics.noise);
        cJSON_AddNumberToObject(temp_obj, "Radio.Transmit",
            ap_report->radio_metrics.transmit);
        cJSON_AddNumberToObject(temp_obj, "Radio.ReceiveSelf",
            ap_report->radio_metrics.receive_self);
        cJSON_AddNumberToObject(temp_obj, "Radio.ReceiveOther",
            ap_report->radio_metrics.receive_other);

        // check sta link metrics and traffic stats
        if (ap_metrics->is_sta_traffic_stats_enabled == true) {
            encode_em_sta_traffic_stats_object(ap_metrics->sta_cnt,
                ap_metrics->sta_traffic_stats, param_obj);
        }

        if (ap_metrics->is_sta_link_metrics_enabled == true) {
            encode_sta_link_metrics_object(ap_metrics->sta_link_metrics, ap_metrics->sta_cnt,
                param_obj);
        }
    }
}

#endif
