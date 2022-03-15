/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
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
    char channel_list[BUFFER_LENGTH_WIFIDB] = {0}, str[BUFFER_LENGTH_WIFIDB] = {0};
    unsigned int num_channels, i, k = 0, len = sizeof(channel_list) - 1;
    cJSON *obj;

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(radio_object, "WifiRadioSetup", obj);
    if (encode_radio_setup_object(&radio->vaps, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Radio setup encode failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }


    // RadioName
    cJSON_AddStringToObject(radio_object, "RadioName", radio->name);

    radio_info = &radio->oper;

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
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Wifi_Radio_Config table Maximum size reached for secondary_channels_list\n",__func__, __LINE__);
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
    if ((k >= 0) && (k <= MAX_WIFI_COUNTRYCODE)) {
        snprintf(str,sizeof(str),"%s",wifiCountryMap[k].countryStr);
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s Set failed invalid Country code %d.\n",__FUNCTION__,k);
        return webconfig_error_encode;
    }

    // Country
    cJSON_AddStringToObject(radio_object, "Country", str);

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

    return webconfig_error_none;
}

webconfig_error_t encode_vap_common_object(const wifi_vap_info_t *vap_info, cJSON *vap_object)
{
    //VAP Name
    cJSON_AddStringToObject(vap_object, "VapName", vap_info->vap_name);

    //Bridge Name
    cJSON_AddStringToObject(vap_object, "BridgeName", vap_info->bridge_name);

    // Radio Index
    cJSON_AddNumberToObject(vap_object, "RadioIndex", vap_info->radio_index);

    //VAP Mode
    cJSON_AddNumberToObject(vap_object, "VapMode", vap_info->vap_mode);

    // SSID
    cJSON_AddStringToObject(vap_object, "SSID", vap_info->u.bss_info.ssid);

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

    // BeaconRateCtl
    cJSON_AddStringToObject(vap_object, "BeaconRateCtl", vap_info->u.bss_info.beaconRateCtl);


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
    return webconfig_error_none;
}

webconfig_error_t encode_config_object(const wifi_global_config_t *config_info, cJSON *config_obj)
{
    cJSON *obj;


    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(config_obj, "GASConfig", obj);

    if (encode_gas_config(&config_info->gas_config, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode gas config\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (encode_wifi_global_config(&config_info->global_parameters, config_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi global config\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_anqp_object(const wifi_anqp_settings_t *anqp_info, cJSON *anqp)
{
    //cJSON *obj;

    // IPAddressTypeAvailabilityANQPElement

    // DomainANQPElement

    // 3GPPCellularANQPElement

    // RoamingConsolrtium ANQPElemet

    // VenueNameANQPElement

    return webconfig_error_none;
}

webconfig_error_t encode_interworking_common_object(const wifi_interworking_t *interworking_info, cJSON *interworking)
{
    cJSON *obj;
    bool invalid_venue_group_type = false;

    cJSON_AddBoolToObject(interworking, "InterworkingEnable", interworking_info->interworking.interworkingEnabled);

    if (interworking_info->interworking.accessNetworkType > 5) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Encode failed for AccessNetworkType\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Encode failed for VenueGroup\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid venue group and type, encode failed\n", __func__, __LINE__);
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
        cJSON_AddStringToObject(radius, "RadiusSecret", "123456789");
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
        cJSON_AddStringToObject(radius, "SecondaryRadiusSecret", "123456789");
    } else {
        cJSON_AddStringToObject(radius, "SecondaryRadiusSecret", radius_info->s_key);
    }

    memset(str, 0, sizeof(str));
    getIpStringFromAdrress(str, &radius_info->dasip);
    cJSON_AddStringToObject(radius, "DasServerIPAddr", str);

    cJSON_AddNumberToObject(radius, "DasServerPort", radius_info->dasport);

    if (strlen((char *)radius_info->daskey) == 0) {
        cJSON_AddStringToObject(radius, "DasSecret", "123456789");
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

webconfig_error_t encode_no_security_object(const wifi_vap_security_t *security_info, cJSON *security)
{

    switch (security_info->mode) {
        case wifi_security_mode_none:
            cJSON_AddStringToObject(security, "Mode", "None");
            break;

        default:
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Security Mode not valid, value:%d\n",
                            __func__, __LINE__, security_info->mode);
            return webconfig_error_encode;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_enterprise_security_object(const wifi_vap_security_t *security_info, cJSON *security)
{
    cJSON *obj;

    if (security_info->mfp == wifi_mfp_cfg_disabled) {
        cJSON_AddStringToObject(security, "MFPConfig", "Disabled");
    } else if (security_info->mfp == wifi_mfp_cfg_required) {
        cJSON_AddStringToObject(security, "MFPConfig", "Required");
    } else if (security_info->mfp == wifi_mfp_cfg_optional) {
        cJSON_AddStringToObject(security, "MFPConfig", "Optional");
    } else {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%d\n",
                            __func__, __LINE__, security_info->mfp);
        return webconfig_error_encode;
    }

    switch (security_info->mode) {
        case wifi_security_mode_wpa_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA-Enterprise");
            break;

        case wifi_security_mode_wpa3_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA3-Enterprise");
            break;

        case wifi_security_mode_wpa2_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA2-Enterprise");
            break;

        case  wifi_security_mode_wpa_wpa2_enterprise:
            cJSON_AddStringToObject(security, "Mode", "WPA-WPA2-Enterprise");
            break;

        default:
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Security Mode not valid, value:%d\n",
                            __func__, __LINE__, security_info->mode);
            return webconfig_error_encode;
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
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Encryption Method not valid, value:%d\n",
                            __func__, __LINE__, security_info->encr);
            return webconfig_error_encode;
    }

    cJSON_AddBoolToObject(security, "Wpa3_transition_disable", security_info->wpa3_transition_disable);
    cJSON_AddNumberToObject(security, "RekeyInterval", security_info->rekey_interval);
    cJSON_AddBoolToObject(security, "StrictRekey", security_info->strict_rekey);
    cJSON_AddNumberToObject(security, "EapolKeyTimeout", security_info->eapol_key_timeout);
    cJSON_AddNumberToObject(security, "EapolKeyRetries", security_info->eapol_key_retries);
    cJSON_AddNumberToObject(security, "EapIdentityReqTimeout", security_info->eap_identity_req_timeout);
    cJSON_AddNumberToObject(security, "EapIdentityReqRetries", security_info->eap_identity_req_retries);
    cJSON_AddNumberToObject(security, "EapReqTimeout", security_info->eap_req_timeout);
    cJSON_AddNumberToObject(security, "EapReqRetries", security_info->eap_req_retries);
    cJSON_AddBoolToObject(security, "DisablePmksaCaching", security_info->disable_pmksa_caching);

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(security, "RadiusSettings", obj);

    if (encode_radius_object(&security_info->u.radius, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Encoding radius settings failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_personal_security_object(const wifi_vap_security_t *security_info, cJSON *security)
{
    if (security_info->mfp == wifi_mfp_cfg_disabled) {
        cJSON_AddStringToObject(security, "MFPConfig", "Disabled");
    } else if (security_info->mfp == wifi_mfp_cfg_required) {
        cJSON_AddStringToObject(security, "MFPConfig", "Required");
    } else if (security_info->mfp == wifi_mfp_cfg_optional) {
        cJSON_AddStringToObject(security, "MFPConfig", "Optional");
    } else {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%d\n",
                            __func__, __LINE__, security_info->mfp);
        return webconfig_error_encode;
    }

    switch (security_info->mode) {
        case wifi_security_mode_none:
            cJSON_AddStringToObject(security, "Mode", "None");
            break;

        case wifi_security_mode_wpa_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA-Personal");
            break;

        case wifi_security_mode_wpa2_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA2-Personal");
            break;

        case wifi_security_mode_wpa_wpa2_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA-WPA2-Personal");
            break;

        case wifi_security_mode_wpa3_personal:
            cJSON_AddStringToObject(security, "Mode", "WPA3-Personal");
            break;

        case wifi_security_mode_wpa3_transition:
            cJSON_AddStringToObject(security, "Mode", "WPA3-Personal-Transition");
            break;

        default:
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Security Mode not valid, value:%d\n",
                            __func__, __LINE__, security_info->mode);
            return webconfig_error_encode;
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
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Encryption Method not valid, value:%d\n",
                            __func__, __LINE__, security_info->encr);
            return webconfig_error_encode;
    }

    if ((strlen(security_info->u.key.key) < MIN_PWD_LEN)
                || (strlen(security_info->u.key.key) > MAX_PWD_LEN)) {
        //strncpy(execRetVal->ErrorMsg, "Invalid Key passphrase length",sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Incorrect password length\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON_AddStringToObject(security, "Passphrase", security_info->u.key.key);


    return webconfig_error_none;
}

webconfig_error_t encode_hotspot_open_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_no_security_object(&vap_info->u.bss_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_hotspot_secure_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_enterprise_security_object(&vap_info->u.bss_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_lnf_psk_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_personal_security_object(&vap_info->u.bss_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_lnf_radius_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_enterprise_security_object(&vap_info->u.bss_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_mesh_backhaul_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_personal_security_object(&vap_info->u.bss_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_iot_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_personal_security_object(&vap_info->u.bss_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_private_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    cJSON *obj;

    // the input vap_object is an array
    if (encode_vap_common_object(vap_info, vap_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d :common vap objects encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_personal_security_object(&vap_info->u.bss_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Interworking", obj);
    if (encode_interworking_common_object(&vap_info->u.bss_info.interworking, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Interworking object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;

    }

    return webconfig_error_none;
}

webconfig_error_t encode_mesh_vap_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
{
    return encode_private_vap_object(vap_info, vap_obj);
}

webconfig_error_t encode_scan_params_object(const wifi_scan_params_t *scan_info, cJSON *scan_obj)
{

    // Period
    cJSON_AddNumberToObject(scan_obj, "Period", scan_info->period);

    // Channel
    cJSON_AddNumberToObject(scan_obj, "Channel", scan_info->channel.channel);

    return webconfig_error_none;
}

webconfig_error_t encode_mesh_sta_object(const wifi_vap_info_t *vap_info, cJSON *vap_obj)
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

    // SSID
    cJSON_AddStringToObject(vap_obj, "SSID", vap_info->u.sta_info.ssid);

    // BSSID
    uint8_mac_to_string_mac((uint8_t *)vap_info->u.sta_info.bssid, mac_str);
    cJSON_AddStringToObject(vap_obj, "BSSID", mac_str);

    // Security
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "Security", obj);
    if (encode_personal_security_object(&vap_info->u.sta_info.security, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Security object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    // Scan Parameters
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(vap_obj, "ScanParameters", obj);
    if (encode_scan_params_object(&vap_info->u.sta_info.scan_params, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Scan Params object encode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_encode;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_radio_state_object(const schema_wifi_radio_state_t *r_state, cJSON *r_state_obj)
{
    if ((r_state == NULL) || (r_state_obj == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Radio state object encode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_encode;
    }

    /*if_name*/
    cJSON_AddStringToObject(r_state_obj, "if_name", r_state->if_name);

    //freq_band
    cJSON_AddStringToObject(r_state_obj, "freq_band", r_state->freq_band);

    //Enabled
    cJSON_AddBoolToObject(r_state_obj, "enabled", r_state->enabled);

    //dfs_demo
    cJSON_AddBoolToObject(r_state_obj, "dfs_demo", r_state->dfs_demo);

    /*hw_type*/
    cJSON_AddStringToObject(r_state_obj, "hw_type", r_state->hw_type);

    /*country*/
    cJSON_AddStringToObject(r_state_obj, "country", r_state->country);

    /*channel*/
    cJSON_AddNumberToObject(r_state_obj, "channel", r_state->channel);

    /*channel_mode*/
    cJSON_AddStringToObject(r_state_obj, "channel_mode", r_state->channel_mode);

    /*mac*/
    cJSON_AddStringToObject(r_state_obj, "mac", r_state->mac);

    /*hw_mode*/
    cJSON_AddStringToObject(r_state_obj, "hw_mode", r_state->hw_mode);

    /*ht_mode*/
    cJSON_AddStringToObject(r_state_obj, "ht_mode", r_state->ht_mode);

    /*thermal_shutdown*/
    cJSON_AddNumberToObject(r_state_obj, "thermal_shutdown", r_state->thermal_shutdown);

    /*thermal_downgrade_temp*/
    cJSON_AddNumberToObject(r_state_obj, "thermal_downgrade_temp", r_state->thermal_downgrade_temp);

    /*thermal_upgrade_temp*/
    cJSON_AddNumberToObject(r_state_obj, "thermal_upgrade_temp", r_state->thermal_upgrade_temp);

    /*thermal_integration*/
    cJSON_AddNumberToObject(r_state_obj, "thermal_integration", r_state->thermal_integration);

    //thermal_downgraded
    cJSON_AddBoolToObject(r_state_obj, "thermal_downgraded", r_state->thermal_downgraded);

    /*tx_power*/
    cJSON_AddNumberToObject(r_state_obj, "tx_power", r_state->tx_power);

    /*bcn_int*/
    cJSON_AddNumberToObject(r_state_obj, "bcn_int", r_state->bcn_int);

    /*tx_chainmask*/
    cJSON_AddNumberToObject(r_state_obj, "tx_chainmask", r_state->tx_chainmask);

    /*thermal_tx_chainmask*/
    cJSON_AddNumberToObject(r_state_obj, "thermal_tx_chainmask",r_state->thermal_tx_chainmask);

    //To Do:
    //allowed_channels

    return webconfig_error_none;
}


webconfig_error_t encode_vap_state_object(const schema_wifi_vap_state_t *vap_state, cJSON *vap_state_obj)
{
    if ((vap_state == NULL) || (vap_state_obj == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d VAP state object encode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_encode;
    }

    //Enabled
    cJSON_AddBoolToObject(vap_state_obj, "enabled", vap_state->enabled);

    //if_name
    cJSON_AddStringToObject(vap_state_obj, "if_name", vap_state->if_name);

    //mode
    cJSON_AddStringToObject(vap_state_obj, "mode", vap_state->mode);

    //state
    cJSON_AddStringToObject(vap_state_obj, "state", vap_state->state);

    /*channel*/
    cJSON_AddNumberToObject(vap_state_obj, "channel", vap_state->channel);

    //mac
    cJSON_AddStringToObject(vap_state_obj, "mac", vap_state->mac);

    /*vif_radio_idx*/
    cJSON_AddNumberToObject(vap_state_obj, "vif_radio_idx", vap_state->vif_radio_idx);

    //parent
    cJSON_AddStringToObject(vap_state_obj, "parent", vap_state->parent);

    //ssid
    cJSON_AddStringToObject(vap_state_obj, "ssid", vap_state->ssid);

    //ssid_broadcast
    cJSON_AddStringToObject(vap_state_obj, "ssid_broadcast", vap_state->ssid_broadcast);

    //bridge
    cJSON_AddStringToObject(vap_state_obj, "bridge", vap_state->bridge);

    //mac_list_type
    cJSON_AddStringToObject(vap_state_obj, "mac_list_type", vap_state->mac_list_type);

    /*vlan_id*/
    cJSON_AddNumberToObject(vap_state_obj, "vlan_id", vap_state->vlan_id);

    //min_hw_mode
    cJSON_AddStringToObject(vap_state_obj, "min_hw_mode", vap_state->min_hw_mode);

    //uapsd_enable
    cJSON_AddBoolToObject(vap_state_obj, "uapsd_enable", vap_state->uapsd_enable);

    /*group_rekey*/
    cJSON_AddNumberToObject(vap_state_obj, "group_rekey", vap_state->group_rekey);

    //ap_bridge
    cJSON_AddBoolToObject(vap_state_obj, "ap_bridge", vap_state->ap_bridge);

    /*ft_mobility_domain*/
    cJSON_AddNumberToObject(vap_state_obj, "ft_mobility_domain", vap_state->ft_mobility_domain);

    //dynamic_beacon
    cJSON_AddBoolToObject(vap_state_obj, "dynamic_beacon", vap_state->dynamic_beacon);

    /*rrm*/
    cJSON_AddNumberToObject(vap_state_obj, "rrm", vap_state->rrm);

    /*btm*/
    cJSON_AddNumberToObject(vap_state_obj, "btm", vap_state->btm);

    /*mcast2ucast*/
    cJSON_AddBoolToObject(vap_state_obj, "mcast2ucast", vap_state->mcast2ucast);

    //multi_ap
    cJSON_AddStringToObject(vap_state_obj, "multi_ap", vap_state->multi_ap);

    /*wps*/
    cJSON_AddBoolToObject(vap_state_obj, "wps", vap_state->wps);

    /*wps_pbc*/
    cJSON_AddBoolToObject(vap_state_obj, "wps_pbc", vap_state->wps_pbc);

    //wps_pbc_key_id
    cJSON_AddStringToObject(vap_state_obj, "wps_pbc_key_id", vap_state->wps_pbc_key_id);

    return webconfig_error_none;
}

webconfig_error_t encode_associated_client_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *assoc_array)
{
    if ((rdk_vap_info == NULL) || (assoc_array == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Associated Client encode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_encode;
    }

    int count = 0, i = 0;
    cJSON *obj_array, *obj_vaps;
    assoc_dev_data_t *assoc_dev_data = NULL;

    obj_vaps = cJSON_CreateObject();
    obj_array = cJSON_CreateArray();

    cJSON_AddItemToArray(assoc_array, obj_vaps);
    cJSON_AddStringToObject(obj_vaps, "VapName", rdk_vap_info->vap_name);
    cJSON_AddItemToObject(obj_vaps, "associatedClients", obj_array);

    if (rdk_vap_info->associated_devices_queue != NULL) {
        count = queue_count(rdk_vap_info->associated_devices_queue);
    }

    for (i=0; i<count; i++) {
        cJSON *obj_assoc_client;
        obj_assoc_client = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj_assoc_client);

        char mac_string[18];
        assoc_dev_data = (assoc_dev_data_t *)queue_peek(rdk_vap_info->associated_devices_queue, i);
        if (assoc_dev_data == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }

        snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", assoc_dev_data->dev_stats.cli_MACAddress[0], assoc_dev_data->dev_stats.cli_MACAddress[1],
                   assoc_dev_data->dev_stats.cli_MACAddress[2], assoc_dev_data->dev_stats.cli_MACAddress[3], assoc_dev_data->dev_stats.cli_MACAddress[4], assoc_dev_data->dev_stats.cli_MACAddress[5]);
        cJSON_AddStringToObject(obj_assoc_client, "MACAddress", mac_string);
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
        cJSON_AddNumberToObject(obj_assoc_client, "PacketsSent", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
        cJSON_AddNumberToObject(obj_assoc_client, "PacketsReceived", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
        cJSON_AddNumberToObject(obj_assoc_client, "ErrorsSent", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
        cJSON_AddNumberToObject(obj_assoc_client, "RetransCount", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
        cJSON_AddNumberToObject(obj_assoc_client, "FailedRetransCount", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
        cJSON_AddNumberToObject(obj_assoc_client, "RetryCount", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
        cJSON_AddNumberToObject(obj_assoc_client, "MultipleRetryCount", assoc_dev_data->dev_stats.cli_AuthenticationFailures);
    }
    return webconfig_error_none;
}

webconfig_error_t encode_mac_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *obj_array)
{
    if ((rdk_vap_info == NULL) || (obj_array == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Mac Object encode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON *obj_mac, *obj_acl, *obj_acl_add, *obj_acl_del;
    acl_entry_t *acl_entry;

    obj_mac = cJSON_CreateObject();
    obj_acl = cJSON_CreateArray();
    obj_acl_add = cJSON_CreateArray();
    obj_acl_del = cJSON_CreateArray();

    cJSON_AddItemToArray(obj_array, obj_mac);
    cJSON_AddStringToObject(obj_mac, "VapName", (char *)rdk_vap_info->vap_name);
    cJSON_AddItemToObject(obj_mac, "MACListToAdd", obj_acl_add);
    cJSON_AddItemToObject(obj_mac, "MACListToDelete", obj_acl_del);
    cJSON_AddItemToObject(obj_mac, "MACFilterList", obj_acl);

    if(rdk_vap_info->acl_map != NULL) {
        acl_entry = hash_map_get_first(rdk_vap_info->acl_map);
        while(acl_entry != NULL) {
            if(acl_entry->acl_action_type == acl_action_add) {
                cJSON *obj_acl_add_list;
                obj_acl_add_list= cJSON_CreateObject();
                cJSON_AddItemToArray(obj_acl_add, obj_acl_add_list);
                char mac_string[18];
                snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                        acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);

                cJSON_AddStringToObject(obj_acl_add_list, "MAC", mac_string);
                memset(mac_string,0,18);
            } else if (acl_entry->acl_action_type == acl_action_del) {
                cJSON *obj_acl_delete_list;
                obj_acl_delete_list= cJSON_CreateObject();
                cJSON_AddItemToArray(obj_acl_del, obj_acl_delete_list);
                char mac_string[18];
                snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                        acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);

                cJSON_AddStringToObject(obj_acl_delete_list, "MAC", mac_string);
                memset(mac_string,0,18);
            } else {
                cJSON *obj_acl_list;
                obj_acl_list= cJSON_CreateObject();
                cJSON_AddItemToArray(obj_acl, obj_acl_list);
                char mac_string[18];
                snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                        acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);
                cJSON_AddStringToObject(obj_acl_list, "MAC", mac_string);
                memset(&mac_string,0,18);
            }
            acl_entry = hash_map_get_next(rdk_vap_info->acl_map, acl_entry);
        }
    }
    return webconfig_error_none;
}
webconfig_error_t encode_blaster_object(const active_msmt_t *blaster_info, cJSON *blaster_obj)
{
   cJSON *stepobj;
   cJSON *obj_array;

    unsigned int i =0;
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
    return webconfig_error_none;
}
