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
#include <sys/stat.h>
#include <unistd.h>
#if DML_SUPPORT
#include "ansc_platform.h"
#endif // DML_SUPPORT
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"

char help[] = "Usage: wifi_api2 <WiFi API name> <args>";

struct hal_api_info {
    char* name;
    unsigned int num_args;
    char* help;
} wifi_api_list[] =
{
    {"wifi_setRadioOperatingParameters",    2, "<radio index> <json file path>"},
    {"wifi_getRadioOperatingParameters",    1, "<radio index>"},
    {"wifi_createVAP",                      2, "<radio index> <json file path>"},
    {"wifi_getRadioVapInfoMap",             1, "<radio index>"},
    {"wifi_connect",                        1, "<ap index> [bssid] [ssid] [frequency]"},
    {"wifi_disconnect",                     1, "<ap index>"},
    {"wifi_getStationCapability",           1, "<ap index>"},
    {"wifi_getScanResults",                 1, "<ap index> [channel]"},
    {"wifi_getStationStats",                1, "<ap index>"},
    {"wifi_startScan",                      1, "<radio index>"},
    {"wifi_startNeighborScan",              3, "<vap index> <scan mode> <dwell time> [channels]"},
    {"wifi_getNeighboringWiFiStatus",       1, "<radio index"},
    {"wifi_setBTMRequest",                  3, "<vap index> <client mac> <candidate mac>"},
    {"wifi_setRMBeaconRequest",             3, "<vap index> <peer mac> <bssid>"},
    {"wifi_setNeighborReports",             2, "<vap index> <bssid>" },
    {"wifi_configNeighborReports",          3, "<vap index> <neighbor report enable> <neighbor report auto reply>" },
    {"wifi_hal_getRadioTemperature",        1, "<radio index>" },
    {"wifi_getRadioChannelStats",           1, "<radio index>"},
};



void wifiapi_printradioconfig(char *buff, unsigned int buff_size, wifi_radio_operationParam_t *radio_config)
{
    unsigned int i, idx = 0;
    idx += snprintf(&buff[idx], buff_size-idx, "radio Enable: %d\n", radio_config->enable);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "FreqBand:");
    if (idx >= buff_size) return;
    if (radio_config->band == WIFI_FREQUENCY_2_4_BAND) {
        idx += snprintf(&buff[idx], buff_size-idx, " 2.4 GHz\n");
    } else if (radio_config->band == WIFI_FREQUENCY_5_BAND) {
        idx += snprintf(&buff[idx], buff_size-idx, " 5 GHz\n");
    } else if (radio_config->band == WIFI_FREQUENCY_5H_BAND) {
        idx += snprintf(&buff[idx], buff_size-idx, " 5 GHz High\n");
    } else if (radio_config->band == WIFI_FREQUENCY_5L_BAND) {
        idx += snprintf(&buff[idx], buff_size-idx, " 5 GHz Low\n");
    } else if (radio_config->band == WIFI_FREQUENCY_6_BAND) {
        idx += snprintf(&buff[idx], buff_size-idx, " 6 GHz\n");
    } else {
        idx += snprintf(&buff[idx], buff_size-idx, "\n");
    }
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "autoChannelEnabled: %d\n", radio_config->autoChannelEnabled);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "channel: %d\n", radio_config->channel);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "numSecondaryChannels: %d\n", radio_config->numSecondaryChannels);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "channelSecondary: ");
    if (idx >= buff_size) return;
    for (i = 0; i < radio_config->numSecondaryChannels; i++) {
        idx += snprintf(&buff[idx], buff_size-idx, "%d ", radio_config->channelSecondary[i]);
    }
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "\nChannelWidth: ");
    if (idx >= buff_size) return;
    if (radio_config->channelWidth == WIFI_CHANNELBANDWIDTH_20MHZ) {
        idx += snprintf(&buff[idx], buff_size-idx, " 20 MHz");
    } else if (radio_config->channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ) {
        idx += snprintf(&buff[idx], buff_size-idx, " 40 MHz");
    } else if (radio_config->channelWidth == WIFI_CHANNELBANDWIDTH_80MHZ) {
        idx += snprintf(&buff[idx], buff_size-idx, " 80 MHz");
    } else if (radio_config->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        idx += snprintf(&buff[idx], buff_size-idx, " 160 MHz");
    } else if (radio_config->channelWidth == WIFI_CHANNELBANDWIDTH_80_80MHZ) {
        idx += snprintf(&buff[idx], buff_size-idx, " 80+80 MHz");
    }
#ifdef CONFIG_IEEE80211BE
    else if (radio_config->channelWidth == WIFI_CHANNELBANDWIDTH_320MHZ) {
        idx += snprintf(&buff[idx], buff_size-idx, " 320 MHz");
    }
#endif /* CONFIG_IEEE80211BE */

    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "\nvariant:");
    if (idx >= buff_size) return;
    if (radio_config->variant & WIFI_80211_VARIANT_A) {
        idx += snprintf(&buff[idx], buff_size-idx, " a");
    } else if (radio_config->variant & WIFI_80211_VARIANT_B) {
        idx += snprintf(&buff[idx], buff_size-idx, " b");
    } else if (radio_config->variant & WIFI_80211_VARIANT_G) {
        idx += snprintf(&buff[idx], buff_size-idx, " g");
    } else if (radio_config->variant & WIFI_80211_VARIANT_N) {
        idx += snprintf(&buff[idx], buff_size-idx, " n");
    } else if (radio_config->variant & WIFI_80211_VARIANT_H) {
        idx += snprintf(&buff[idx], buff_size-idx, " h");
    } else if (radio_config->variant & WIFI_80211_VARIANT_AC) {
        idx += snprintf(&buff[idx], buff_size-idx, " ac");
    } else if (radio_config->variant & WIFI_80211_VARIANT_AD) {
        idx += snprintf(&buff[idx], buff_size-idx, " ad");
    } else if (radio_config->variant & WIFI_80211_VARIANT_AX) {
        idx += snprintf(&buff[idx], buff_size-idx, " ax");
    }
#ifdef CONFIG_IEEE80211BE
    else if (radio_config->variant & WIFI_80211_VARIANT_BE) {
        idx += snprintf(&buff[idx], buff_size-idx, " be");
    }
#endif /* CONFIG_IEEE80211BE */

    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "\ncsa_beacon_count: %d\n", radio_config->csa_beacon_count);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "countryCode: %d\n", radio_config->countryCode);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "DCSEnabled: %d\n", radio_config->DCSEnabled);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "dtimPeriod: %d\n", radio_config->dtimPeriod);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "beaconInterval: %d\n", radio_config->beaconInterval);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "operatingClass: %d\n", radio_config->operatingClass);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "basicDataTransmitRates: 0x%x\n", radio_config->basicDataTransmitRates);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "operationalDataTransmitRates: 0x%x\n", radio_config->operationalDataTransmitRates);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "fragmentationThreshold: %d\n", radio_config->fragmentationThreshold);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "guardInterval: 0x%x\n", radio_config->guardInterval);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "transmitPower: %d\n", radio_config->transmitPower);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "rtsThreshold: %d\n", radio_config->rtsThreshold);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "factoryResetSsid: %d\n", radio_config->factoryResetSsid);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "radioStatsMeasuringRate: %d\n", radio_config->radioStatsMeasuringRate);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "radioStatsMeasuringInterval: %d\n", radio_config->radioStatsMeasuringInterval);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "ctsProtection: %d\n", radio_config->ctsProtection);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "obssCoex: %d\n", radio_config->obssCoex);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "stbcEnable: %d\n", radio_config->stbcEnable);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "greenFieldEnable: %d\n", radio_config->greenFieldEnable);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "userControl: %d\n", radio_config->userControl);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "adminControl: %d\n", radio_config->adminControl);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "chanUtilThreshold: %d\n", radio_config->chanUtilThreshold);
    if (idx >= buff_size) return;
    idx += snprintf(&buff[idx], buff_size-idx, "chanUtilSelfHealEnable: %d\n", radio_config->chanUtilSelfHealEnable);

}

void wifiapi_printvapconfig(char *buff, unsigned int buff_size, wifi_vap_info_map_t *map)
{
    unsigned int i, idx = 0;
    wifi_back_haul_sta_t *sta;
    wifi_front_haul_bss_t *bss;
    wifi_vap_security_t *security;
    //wifi_interworking_t interworking;
    wifi_wps_t *wps;

    idx += snprintf(&buff[idx], buff_size-idx, "num_vaps: %d\n", map->num_vaps);
    if (idx >= buff_size) return;
    for (i = 0; i < map->num_vaps; i++) {
        security = &(map->vap_array[i].u.bss_info.security);
        //interworking = &(map->vap_array[i].u.bss_info.interworking);

        idx += snprintf(&buff[idx], buff_size-idx, "\n\nvap_index: %d\nvap_name: %s\nradio_index: %d\nbridge_name: %s\nvap_mode: %d\n",
                            map->vap_array[i].vap_index, map->vap_array[i].vap_name, map->vap_array[i].radio_index,
                            map->vap_array[i].bridge_name, map->vap_array[i].vap_mode);
        if (idx >= buff_size) return;

        if (map->vap_array[i].vap_mode == wifi_vap_mode_sta) {
            sta = &(map->vap_array[i].u.sta_info);
            idx += snprintf(&buff[idx], buff_size-idx, "ssid: %s\nbssid: %02X:%02X:%02X:%02X:%02X:%02X\nenabled: %d\n", sta->ssid, sta->bssid[0],
                                            sta->bssid[1], sta->bssid[2], sta->bssid[3],
                                            sta->bssid[4], sta->bssid[5], sta->enabled);
            if (idx >= buff_size) return;
            if (sta->conn_status == wifi_connection_status_disabled) {
                idx += snprintf(&buff[idx], buff_size-idx, "conn_status: disabled\n");
            } else if (sta->conn_status == wifi_connection_status_disconnected) {
                idx += snprintf(&buff[idx], buff_size-idx, "conn_status: disconnected\n");
            } else if (sta->conn_status == wifi_connection_status_connected) {
                idx += snprintf(&buff[idx], buff_size-idx, "conn_status: connected\n");
            } else {
                idx += snprintf(&buff[idx], buff_size-idx, "conn_status: invalid unkown value %d\n", sta->conn_status);
            }
            if (idx >= buff_size) return;
            idx += snprintf(&buff[idx], buff_size-idx, "scan period: %d\nscan channel: %d\nscan channel freq band: %d\n",
                            sta->scan_params.period, sta->scan_params.channel.channel, 
                            sta->scan_params.channel.band);
            if (idx >= buff_size) return;
            security = &(sta->security);
        } else {
            bss = &(map->vap_array[i].u.bss_info);
            idx += snprintf(&buff[idx], buff_size-idx, "ssid: %s\nenabled: %d\nshowSsid: %d\nisolation: %d\nmgmtPowerControl: %d\nbssMaxSta: %d\n",
                                    bss->ssid, bss->enabled, bss->showSsid, bss->isolation, bss->mgmtPowerControl, bss->bssMaxSta);
            if (idx >= buff_size) return;
            idx += snprintf(&buff[idx], buff_size-idx, "bssTransitionActivated: %d\nbrReportActivated: %d\nmac_filter_enable: %d\nmac_filter_mode: %d\n",
                                    bss->bssTransitionActivated, bss->nbrReportActivated, bss->mac_filter_enable, bss->mac_filter_mode);
            if (idx >= buff_size) return;
            idx += snprintf(&buff[idx], buff_size-idx, "brReportActivated: %d\nwmm_enabled: %d\nUAPSDEnabled: %d\nbeaconRate: %d\n",
                                    bss->nbrReportActivated, bss->wmm_enabled, bss->UAPSDEnabled, bss->beaconRate);
            if (idx >= buff_size) return;
            idx += snprintf(&buff[idx], buff_size-idx, "bssid: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                    (unsigned int)bss->bssid[0], (unsigned int)bss->bssid[1], (unsigned int)bss->bssid[2],
                                    (unsigned int)bss->bssid[3], (unsigned int)bss->bssid[4], (unsigned int)bss->bssid[5]);
            if (idx >= buff_size) return;
            idx += snprintf(&buff[idx], buff_size-idx, "wmmNoAck: %d\nwepKeyLength: %d\nbssHotspot: %d\nwpsPushButton: %d\nbeaconRateCtl: %s\n",
                                    bss->wmmNoAck, bss->wepKeyLength, bss->bssHotspot, bss->wpsPushButton, bss->beaconRateCtl);
            if (idx >= buff_size) return;

            wps = &(bss->wps);
            
            idx += snprintf(&buff[idx], buff_size-idx, "WPS enable: %d\n", wps->enable);
            idx += snprintf(&buff[idx], buff_size-idx, "WPS methods: 0x%x\n", wps->methods);
            idx += snprintf(&buff[idx], buff_size-idx, "WPS PIN: %s\n", wps->pin);

            //TODO: add interworking

            security = &(bss->security);
        }

        idx += snprintf(&buff[idx], buff_size-idx, "security mode: %d\nencryption: %d\nmfp: %d\nwpa3_transition_disable: %d\n", 
                                        security->mode, security->encr, security->mfp, security->wpa3_transition_disable);
        if (idx >= buff_size) return;
        idx += snprintf(&buff[idx], buff_size-idx, "rekey_interval: %d\nstrict_rekey: %d\neapol_key_timeout: %d\neapol_key_retries: %d\n", 
                                        security->rekey_interval, security->strict_rekey, security->eapol_key_timeout,
                                        security->eapol_key_retries);
        if (idx >= buff_size) return;
        idx += snprintf(&buff[idx], buff_size-idx, "eap_identity_req_timeout: %d\neap_identity_req_retries: %d\neap_req_timeout: %d\n", 
                                        security->eap_identity_req_timeout, security->eap_identity_req_retries, security->eap_req_timeout);
        if (idx >= buff_size) return;
        idx += snprintf(&buff[idx], buff_size-idx, "eap_req_retries: %d\ndisable_pmksa_caching: %d\n", 
                                        security->eap_req_retries, security->disable_pmksa_caching);
        if (idx >= buff_size) return;

        switch (security->mode) {
            case wifi_security_mode_none:
                break;
            case wifi_security_mode_wep_64:
            case wifi_security_mode_wep_128:
                break;

            case wifi_security_mode_wpa_personal:
            case wifi_security_mode_wpa2_personal:
            case wifi_security_mode_wpa3_personal:
            case wifi_security_mode_wpa_wpa2_personal:
            case wifi_security_mode_wpa3_transition:
                idx += snprintf(&buff[idx], buff_size-idx, "key: %s\nkey type: %d\n", security->u.key.key, security->u.key.type);
                if (idx >= buff_size) return;
                break;

            case wifi_security_mode_wpa_enterprise:
            case wifi_security_mode_wpa2_enterprise:
            case wifi_security_mode_wpa3_enterprise:
            case wifi_security_mode_wpa_wpa2_enterprise:
                idx += snprintf(&buff[idx], buff_size-idx, "radius ip: %s\nradius port: %d\n radius key: %s\nradius identity: %s\n",
                    security->u.radius.ip, security->u.radius.port, security->u.radius.key, security->u.radius.identity);
                if (idx >= buff_size) return;
                idx += snprintf(&buff[idx], buff_size-idx, "radius s_ip: %s\nradius s_port: %d\n radius s_key: %s\nradius identity: %s\n",
                    security->u.radius.ip, security->u.radius.port, security->u.radius.key, security->u.radius.identity);
                if (idx >= buff_size) return;
                //TODO: add all radius settings
                break;

            default:
                break;
        }

    }
}

void wifiapi_printbssinfo(char *buff, unsigned int buff_size, wifi_bss_info_t *bss, UINT num_bss)
{
    unsigned int i, idx = 0;
    if (bss == NULL || num_bss == 0) {
        idx += snprintf(&buff[idx], buff_size-idx, "No network found\n");
        return;
    }
    idx += snprintf(&buff[idx], buff_size-idx, "Found %d networks\n\n", num_bss);
    if (idx >= buff_size) return;
    for (i=0; i<num_bss; i++) {
        idx += snprintf(&buff[idx], buff_size-idx, "ssid: '%s'\nbssid: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                bss[i].ssid, bss[i].bssid[0], bss[i].bssid[1], bss[i].bssid[2],
                                bss[i].bssid[3], bss[i].bssid[4], bss[i].bssid[5]);
        if (idx >= buff_size) return;
        
        idx += snprintf(&buff[idx], buff_size-idx, "rssi: %d\ncaps: %x\nbeacon_int: %d\nfreq: %d\n\n",
                                        bss[i].rssi, bss[i].caps, bss[i].beacon_int, bss[i].freq);
        if (idx >= buff_size) return;
    }
}

static void wifiapi_handle_start_neighbor_scan(char **args, unsigned int num_args, char *result_buf,
    unsigned int result_buf_size)
{
    INT vap_index, scan_mode, dwell_time;
    UINT i, channels[32], chan_num = 0;

    vap_index = atoi(args[1]);
    scan_mode = atoi(args[2]);
    dwell_time = atoi(args[3]);

    for (i = 4; i < num_args; i++) {
        channels[chan_num] = atoi(args[i]);
        chan_num++;
    }

    if (wifi_hal_startNeighborScan(vap_index, scan_mode, dwell_time, chan_num,
        channels) != RETURN_OK) {
        snprintf(result_buf, result_buf_size, "Failed to start neighbor scan\n");
        return;
    }

    snprintf(result_buf, result_buf_size, "%s: OK", args[0]);
}

static void wifiapi_handle_neighbor_scan_status(char **args, unsigned int num_args,
    char *result_buf, int result_buf_size)
{
    wifi_neighbor_ap2_t *neighbor_ap_array;
    UINT i, output_array_size = 0;
    INT radio_index, len = 0;

    radio_index = atoi(args[1]);

    if (wifi_hal_getNeighboringWiFiStatus(radio_index, &neighbor_ap_array,
        &output_array_size) != RETURN_OK) {
        snprintf(result_buf, result_buf_size, "Failed to get neighbor scan results\n");
        return;
    }

    len += snprintf(result_buf, result_buf_size, "\n%s: number of results: %d\n\n", args[0],
        output_array_size);

    for (i = 0; i < output_array_size; i++) {
        if (len >= result_buf_size) {
            return;
        }

        len += snprintf(result_buf + len, result_buf_size - len, "ssid: %s\nbssid: %s\n"
            "mode: %s\nchannel: %u\nsignal strength: %d\nsecurity mode: %s\nencryption mode: %s\n"
            "frequency band: %s\nsupported standards: %s\noperating standards: %s\n"
            "operating bandwidth: %s\nbeacon period: %u\nnoise: %d\nbasic rates: %s\n"
            "supported data rates: %s\ndtim period: %u\nchannel utilization: %u\n\n",
            neighbor_ap_array[i].ap_SSID, neighbor_ap_array[i].ap_BSSID,
            neighbor_ap_array[i].ap_Mode, neighbor_ap_array[i].ap_Channel,
            neighbor_ap_array[i].ap_SignalStrength,
            neighbor_ap_array[i].ap_SecurityModeEnabled, neighbor_ap_array[i].ap_EncryptionMode,
            neighbor_ap_array[i].ap_OperatingFrequencyBand,
            neighbor_ap_array[i].ap_SupportedStandards, neighbor_ap_array[i].ap_OperatingStandards,
            neighbor_ap_array[i].ap_OperatingChannelBandwidth,
            neighbor_ap_array[i].ap_BeaconPeriod, neighbor_ap_array[i].ap_Noise,
            neighbor_ap_array[i].ap_BasicDataTransferRates,
            neighbor_ap_array[i].ap_SupportedDataTransferRates, neighbor_ap_array[i].ap_DTIMPeriod,
            neighbor_ap_array[i].ap_ChannelUtilization);
    }
}

static void wifiapi_handle_set_btm_request(char **args, unsigned int num_args,
    char *result_buf, int result_buf_size)
{
    INT vap_index;
    mac_address_t client_mac, candidate_mac;
    wifi_BTMRequest_t *btm_request = calloc(1, sizeof(wifi_BTMRequest_t));

    if (!btm_request) {
        snprintf(result_buf, result_buf_size, "Failed to allocate memory\n");
        return;
    }

    vap_index = atoi(args[1]);
    str_to_mac_bytes(args[2], client_mac);
    str_to_mac_bytes(args[3], candidate_mac);

    btm_request->requestMode = 0x1; // candidate list included
    btm_request->numCandidates = 1;
    memcpy(&btm_request->candidates[0].bssid, &candidate_mac, sizeof(mac_address_t));

    if (wifi_hal_setBTMRequest(vap_index, client_mac, btm_request) != WIFI_HAL_SUCCESS) {
        snprintf(result_buf, result_buf_size, "Failed to send BTM request\n");
        free(btm_request);
        return;
    }

    snprintf(result_buf, result_buf_size, "%s: OK", args[0]);
    free(btm_request);
}

static void wifiapi_handle_set_rm_beacon_request(char **args, unsigned int num_args,
    char *result_buf, int result_buf_size)
{
    INT vap_index;
    mac_address_t peer_mac, bssid;
    UCHAR diag_token = 0;
    wifi_BeaconRequest_t beacon_req = {};

    vap_index = atoi(args[1]);
    str_to_mac_bytes(args[2], peer_mac);
    str_to_mac_bytes(args[3], bssid);

    memcpy(&beacon_req.bssid, &bssid, sizeof(mac_address_t));

    if (wifi_hal_setRMBeaconRequest(vap_index, peer_mac, &beacon_req,
        &diag_token) != WIFI_HAL_SUCCESS) {
        snprintf(result_buf, result_buf_size, "Failed to send RM beacon request\n");
        return;
    }

    snprintf(result_buf, result_buf_size, "%s: OK", args[0]);
}

static void wifiapi_handle_set_neighbor_reports(char **args, unsigned int num_args,
    char *result_buf, int result_buf_size)
{
    INT vap_index;
    UINT num_neigbor_reports;
    mac_address_t bssid;
    wifi_NeighborReport_t neighbor_report = {};

    vap_index = atoi(args[1]);
    str_to_mac_bytes(args[2], bssid);

    num_neigbor_reports = 1;

    memcpy(&neighbor_report.bssid, &bssid, sizeof(mac_address_t));

    if (wifi_hal_setNeighborReports(vap_index, num_neigbor_reports,
        &neighbor_report) != WIFI_HAL_SUCCESS) {
        snprintf(result_buf, result_buf_size, "Failed to set neighbor report\n");
        return;
    }

    snprintf(result_buf, result_buf_size, "%s: OK", args[0]);
}

static void wifiapi_handle_config_neighbor_reports(char **args, unsigned int num_args,
    char *result_buf, int result_buf_size)
{
    INT vap_index, neighbor_rep_enable, auto_reply;

    vap_index = atoi(args[1]);
    neighbor_rep_enable = atoi(args[2]);
    auto_reply = atoi(args[3]);

    if (wifi_hal_configNeighborReports(vap_index, neighbor_rep_enable,
        auto_reply) != WIFI_HAL_SUCCESS) {
        snprintf(result_buf, result_buf_size, "Failed to config neighbor report\n");
        return;
    }

    snprintf(result_buf, result_buf_size, "%s: OK", args[0]);
}

static void wifiapi_handle_hal_get_radio_temperature(char **args, unsigned int num_args,
    char *result_buf, int result_buf_size)
{
    INT radio_index = atoi(args[1]);
    INT len = 0;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    wifi_radioTemperature_t *radioTemperatureStats = NULL;
    wifi_radio_operationParam_t* radioOperation = NULL;

    if (mon_data->radio_presence[radio_index] == false) {
        snprintf(result_buf, result_buf_size, "%s:%d radio_presence is false for radio : %d\n", __func__,__LINE__, radio_index);
        return;
    }
    radioOperation = getRadioOperationParam(radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d radioOperationParam is NULL for radio_index : %d\n",__func__,__LINE__, radio_index);
        snprintf(result_buf, result_buf_size, "%s:%d radioOperationParam is NULL for radio_index : %d\n", __func__,__LINE__, radio_index);
        return;
    }

    radioTemperatureStats = (wifi_radioTemperature_t *)calloc(1, sizeof(wifi_radioTemperature_t));
    if (radioTemperatureStats == NULL) {
        snprintf(result_buf, result_buf_size, "%s:%d Failed to alloc memory for the radio : %d\n", __func__,__LINE__, radio_index);
        return;
    }

    memset(radioTemperatureStats, 0, sizeof(wifi_radioTemperature_t));

    if (radioOperation->enable == true) {
        if(wifi_hal_getRadioTemperature(radio_index, radioTemperatureStats) != RETURN_OK){
            snprintf(result_buf, result_buf_size, "Failed to get radio temperature\n");
            if (radioTemperatureStats != NULL){
                free(radioTemperatureStats);
                radioTemperatureStats = NULL;
            }
            return;
        }

        len += snprintf(result_buf + len, result_buf_size - len, "radio_data temperature %u", radioTemperatureStats->radio_Temperature);
    }
    if (radioTemperatureStats != NULL){
        free(radioTemperatureStats);
        radioTemperatureStats = NULL;
    }

}

static void wifiapi_handle_get_radio_channel_stats(char **args, unsigned int num_args,
    char *result_buf, int result_buf_size)
{

    wifi_channelStats_t *chan_stats = NULL;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    unsigned int chan_count = 0;
    wifi_radio_capabilities_t *wifi_cap = NULL;
    int   num_channels = 0;
    int channels[64] = {0};
    wifi_radio_operationParam_t* radioOperation = NULL;
    INT radio_index, len = 0;

    radio_index = atoi(args[1]);

    if (mon_data->radio_presence[radio_index] == false) {
        snprintf(result_buf, result_buf_size, "%s:%d radio_presence is false for radio : %d\n", __func__,__LINE__, radio_index);
        return;
    }

    radioOperation = getRadioOperationParam(radio_index);
    if (radioOperation == NULL) {
        snprintf(result_buf, result_buf_size, "%s:%d NULL radioOperation pointer for radio : %d\n", __func__,__LINE__, radio_index);
        return;
    }

    wifi_cap = getRadioCapability(radio_index);

    if (get_allowed_channels(radioOperation->band, wifi_cap, channels, &num_channels, radioOperation->DfsEnabled) != RETURN_OK) {
        snprintf(result_buf, result_buf_size, "%s:%d get allowed channels failed for the radio : %d\n", __func__,__LINE__, radio_index);
        return;
    }

    chan_stats = (wifi_channelStats_t *) calloc(num_channels, sizeof(wifi_channelStats_t));
    if (chan_stats == NULL) {
        snprintf(result_buf, result_buf_size, "%s:%d Failed to alloc memory for the radio : %d\n", __func__,__LINE__, radio_index);
        return;
    }

    for (chan_count = 0; chan_count < (unsigned int)num_channels; chan_count++) {
        chan_stats[chan_count].ch_number = channels[chan_count];
        chan_stats[chan_count].ch_in_pool= TRUE;
    }

    if (wifi_getRadioChannelStats(radio_index, chan_stats, chan_count) != RETURN_OK) {
        snprintf(result_buf, result_buf_size, "Failed to get radio channel stats\n");
        goto err;
    }
    for (unsigned int i = 0; i < chan_count; i++) {
        if (len >= result_buf_size) {
            goto err;
        }
        len += snprintf(result_buf + len, result_buf_size - len, "channel: %d noise: %d ch_radar_noise: %d "
            "ch_max_80211_rssi: %d ch_non_80211_noise:%d ch_utilization: %d "
            "ch_utilization_total: %llu ch_utilization_busy: %llu ch_utilization_busy_tx: %llu "
            "ch_utilization_busy_rx: %llu ch_utilization_busy_self: %llu "
            "ch_utilization_busy_ext: %llu\n",
            chan_stats[i].ch_number, chan_stats[i].ch_noise,
            chan_stats[i].ch_radar_noise, chan_stats[i].ch_max_80211_rssi,
            chan_stats[i].ch_non_80211_noise, chan_stats[i].ch_utilization,
            chan_stats[i].ch_utilization_total, chan_stats[i].ch_utilization_busy,
            chan_stats[i].ch_utilization_busy_tx, chan_stats[i].ch_utilization_busy_rx,
            chan_stats[i].ch_utilization_busy_self, chan_stats[i].ch_utilization_busy_ext);
    }
err:
    if (NULL != chan_stats) {
        free(chan_stats);
        chan_stats = NULL;
    }
}

void process_wifiapi_command(char *command, unsigned int len)
{
    char input[1024];
    unsigned int num_args = 0, i, found = 0, ret;
    unsigned int radio_index = 0, vap_index, vap_array_index = 0;
    char *args[10];
    char *str;
    char *saveptr = NULL;
    static char buff[10024];

    webconfig_t *config;
    webconfig_subdoc_data_t data = {0};
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    FILE *json_file;
    long fsize;
    char *raw = NULL;
    wifi_vap_info_map_t *vap_map;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t *vap_info;
#ifndef LINUX_VM_PORT
    rdk_wifi_vap_info_t *rdk_vap_info;
#endif
    
    memset(input, 0, 1024);
    memcpy(input, command, len);
    str = strtok_r(input, " ", &saveptr);
    while (str != NULL && num_args < 10) {
        args[num_args] = str;
        num_args++;
        str = strtok_r(NULL, " ", &saveptr);
    }

    for (i=0; i < (sizeof(wifi_api_list)/sizeof(struct hal_api_info)); i++) {
        if (strcmp(args[0], wifi_api_list[i].name) == 0) {
            if(num_args-1 < wifi_api_list[i].num_args ) {
                sprintf(buff, "wifi_api2: Error - Invalid number of arguments\nhelp: %s %s\n", 
                                wifi_api_list[i].name, wifi_api_list[i].help);
                goto publish;
            } else {
                found = 1;
                break;
            }
        }
    }
    if (found == 0) {
        sprintf(buff, "wifi_api2: Invalid API '%s'", args[0]);
        goto publish;
    }

    if (strcmp(args[0], "wifi_setRadioOperatingParameters")==0) {
        //check radio_index
        radio_index = strtol(args[1], NULL, 10);
        if (radio_index > getNumberRadios()-1) {
            sprintf(buff, "%s: Invalid radio index (%d)", args[0], radio_index);
            goto publish;
        }
        //read file - json
        json_file = fopen(args[2], "rb");
        if( json_file == NULL) {
            sprintf(buff, "%s: failed to open file '%s'", args[0], args[2]);
            goto publish;
        }
        fseek(json_file, 0, SEEK_END);
        fsize = ftell(json_file);
        fseek(json_file, 0, SEEK_SET);
        if (fsize == 0) {
            sprintf(buff, "%s: Invalid content size (0). file '%s'", args[0], args[2]);
            fclose(json_file);
            goto publish;
        }
        raw = malloc(fsize + 1);
        if(raw == NULL) {
            sprintf(buff, "%s: failed to allocate memory", args[0]);
            fclose(json_file);
            goto publish;
        }
        fread(raw, fsize, 1, json_file);
        fclose(json_file);
        raw[fsize] = '\0';

        //webconfig decode
        config = &ctrl->webconfig;

        if (webconfig_decode(config, &data, raw) == webconfig_error_none) {
            if (data.type != webconfig_subdoc_type_wifiapiradio) {
                sprintf(buff, "%s: invalid configuration format. type %d", args[0], data.type);
                goto publish;
            }
        } else {
            sprintf(buff, "%s: invalid configuration format", args[0]);
            goto publish;
        }
        if (data.u.decoded.radios[radio_index].name[0] == '\0') {
            sprintf(buff, "%s: radio name in the configuration does not match radio index", args[0]);
            goto publish;
        }
        //validation and check for changes?
        //call hal_api
        ret = wifi_hal_setRadioOperatingParameters(radio_index, &(data.u.decoded.radios[radio_index].oper));
        if (ret != RETURN_OK) {
            sprintf(buff, "%s: wifi_hal_setRadioOperatingParameters failed", args[0]);
            goto publish;
        }
        //update db/global memory
#ifndef LINUX_VM_PORT
        wifidb_update_wifi_radio_config(radio_index, &(data.u.decoded.radios[radio_index].oper), &(data.u.decoded.radios[radio_index].feature));
#endif
        //update result
        wifiapi_printradioconfig(buff, sizeof(buff), &(data.u.decoded.radios[radio_index].oper));


    } else if (strcmp(args[0], "wifi_getRadioOperatingParameters")==0) {
        //check radio_index
        radio_index = strtol(args[1], NULL, 10);
        if (radio_index > getNumberRadios()-1) {
            sprintf(buff, "%s: Invalid radio index (%d)", args[0], radio_index);
            goto publish;
        }
        //call hal_api
        //ret = wifi_hal_getRadioOperatingParameters(radio_index, &data.u.decoded.radios[radio_index]);
        //if (ret != RETURN_OK) {
        //    sprintf(buff, "%s: wifi_hal_getRadioOperatingParameters failed", args[0]);
        //}
        //update result
        //wifiapi_printradioconfig(buff, sizeof(buff), &(data.u.decoded.radios[radio_index].oper));
        wifiapi_printradioconfig(buff, sizeof(buff), &(mgr->radio_config[radio_index].oper));

    } else if (strcmp(args[0], "wifi_createVAP")==0) {
        //check radio_index
        radio_index = strtol(args[1], NULL, 10);
        if (radio_index > getNumberRadios()-1) {
            sprintf(buff, "%s: Invalid radio index (%d)", args[0], radio_index);
            goto publish;
        }
        //read file - json
        json_file = fopen(args[2], "rb");
        if( json_file == NULL) {
            sprintf(buff, "%s: failed to open file '%s'", args[0], args[2]);
            goto publish;
        }
        fseek(json_file, 0, SEEK_END);
        fsize = ftell(json_file);
        fseek(json_file, 0, SEEK_SET);
        if (fsize == 0) {
            sprintf(buff, "%s: Invalid content size (0). file '%s'", args[0], args[2]);
            fclose(json_file);
            goto publish;
        }
        raw = malloc(fsize + 1);
        if(raw == NULL) {
            sprintf(buff, "%s: failed to allocate memory", args[0]);
            fclose(json_file);
            goto publish;
        }
        fread(raw, fsize, 1, json_file);
        fclose(json_file);
        raw[fsize] = '\0';

        //webconfig decode
        config = &ctrl->webconfig;

        if (webconfig_decode(config, &data, raw) == webconfig_error_none) {
            if (data.type != webconfig_subdoc_type_wifiapivap) {
                sprintf(buff, "%s: invalid configuration format. type %d", args[0], data.type);
                goto publish;
            }
        } else {
            sprintf(buff, "%s: invalid configuration format", args[0]);
            goto publish;
        }
        radio = &data.u.decoded.radios[radio_index];
        vap_map = &radio->vaps.vap_map;
        vap_info = &vap_map->vap_array[0];
        if (vap_info->vap_name[0] == '\0') {
            sprintf(buff, "%s: vap names in the configuration does not match radio index", args[0]);
            goto publish;
        }
        //call hal_api
        if (wifi_hal_createVAP(radio_index, vap_map) != RETURN_OK) {
            sprintf(buff, "%s: wifi_hal_createVAP failed", args[0]);
            goto publish;
        }

        // write the value to database
#ifndef LINUX_VM_PORT
        for (i=0; i < vap_map->num_vaps; i++) {
            vap_info = &vap_map->vap_array[i];
            rdk_vap_info = &radio->vaps.rdk_vap_array[i];
            wifidb_update_wifi_vap_info(vap_info->vap_name, vap_info, rdk_vap_info);
            if (isVapSTAMesh(vap_info->vap_index)) {
                wifidb_update_wifi_security_config(vap_info->vap_name,&vap_info->u.sta_info.security);
            } else {
                wifidb_update_wifi_interworking_config(vap_info->vap_name, &vap_info->u.bss_info.interworking);
                wifidb_update_wifi_security_config(vap_info->vap_name, &vap_info->u.bss_info.security);
            }
        }
#endif
        //update result
        wifiapi_printvapconfig(buff, sizeof(buff), vap_map);


    } else if (strcmp(args[0], "wifi_getRadioVapInfoMap")==0) {
        //check radio_index
        radio_index = strtol(args[1], NULL, 10);
        if (radio_index > getNumberRadios()-1) {
            sprintf(buff, "%s: Invalid radio index (%d)", args[0], radio_index);
            goto publish;
        }
        //call hal_api
        
        //update result
        wifiapi_printvapconfig(buff, sizeof(buff), &(mgr->radio_config[radio_index].vaps.vap_map));
    } else if (strcmp(args[0], "wifi_connect")==0) {
        wifi_bss_info_t bss;
        //check vap_index
        vap_index = strtol(args[1], NULL, 10);
        if (vap_index >= mgr->hal_cap.wifi_prop.numRadios*MAX_NUM_VAP_PER_RADIO) {
            sprintf(buff, "%s: Invalid ap index (%d)", args[0], vap_index);
            goto publish;
        }
        get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, (uint8_t)vap_index, (uint8_t *)&radio_index, (uint8_t *)&vap_array_index);
        if(mgr->radio_config[radio_index].vaps.vap_map.vap_array[vap_array_index].vap_mode != wifi_vap_mode_sta) {
            sprintf(buff, "%s: ap index is not station(%d)", args[0], vap_index);
            goto publish;
        }
        if (num_args == 5) {
            sscanf(args[2], "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned int *)&bss.bssid[0], (unsigned int *)&bss.bssid[1], (unsigned int *)&bss.bssid[2],
                    (unsigned int *)&bss.bssid[3], (unsigned int *)&bss.bssid[4], (unsigned int *)&bss.bssid[5]);
            sprintf(bss.ssid, "%s", args[3]);
            bss.freq = strtol(args[4], NULL, 10);
            //call hal api
            if (wifi_hal_connect(vap_index, &bss) != RETURN_OK) {
                sprintf(buff, "%s: wifi_hal_connect failed", args[0]);
                goto publish;
            }
        } else {
            //call hal api
            if (wifi_hal_connect(vap_index, NULL) != RETURN_OK) {
                sprintf(buff, "%s: wifi_hal_connect failed", args[0]);
                goto publish;
            }
        }
        sprintf(buff, "%s: OK", args[0]);
    } else if (strcmp(args[0], "wifi_disconnect")==0) {
        //check vap_index
        vap_index = strtol(args[1], NULL, 10);
        if (vap_index >= mgr->hal_cap.wifi_prop.numRadios*MAX_NUM_VAP_PER_RADIO) {
            sprintf(buff, "%s: Invalid ap index (%d)", args[0], vap_index);
            goto publish;
        }
        get_vap_and_radio_index_from_vap_instance(&mgr->hal_cap.wifi_prop, (uint8_t)vap_index, (uint8_t *)&radio_index, (uint8_t *)&vap_array_index);
        if(mgr->radio_config[radio_index].vaps.vap_map.vap_array[vap_array_index].vap_mode != wifi_vap_mode_sta) {
            sprintf(buff, "%s: ap index is not station(%d). r %d va %d mode %d", args[0], vap_index, radio_index, vap_array_index, mgr->radio_config[radio_index].vaps.vap_map.vap_array[vap_array_index].vap_mode);
            goto publish;
        }
        //call hal api
        if (wifi_hal_disconnect(vap_index) != RETURN_OK) {
            sprintf(buff, "%s: wifi_hal_disconnect failed", args[0]);
            goto publish;
        }
        sprintf(buff, "%s: OK", args[0]);
    } else if (strcmp(args[0], "wifi_getStationCapability")==0) {
        sprintf(buff, "%s: Not implemented", args[0]);
    } else if (strcmp(args[0], "wifi_getScanResults")==0) {
        wifi_bss_info_t *bss;
        UINT num_bss;
        //check radio_index
        radio_index = strtol(args[1], NULL, 10);
        if (radio_index > getNumberRadios()-1) {
            sprintf(buff, "%s: Invalid radio index (%d)", args[0], radio_index);
            goto publish;
        }
        if (wifi_hal_getScanResults(radio_index, NULL, &bss, &num_bss) != RETURN_OK) {
            sprintf(buff, "%s: wifi_hal_getScanResults failed", args[0]);
            goto publish;
        }
        wifiapi_printbssinfo(buff, sizeof(buff), bss, num_bss);
        
    } else if (strcmp(args[0], "wifi_getStationStats")==0) {
    } else if (strcmp(args[0], "wifi_startScan")==0) {
        //check radio_index
        radio_index = strtol(args[1], NULL, 10);
        if (radio_index > getNumberRadios()-1) {
            sprintf(buff, "%s: Invalid radio index (%d)", args[0], radio_index);
            goto publish;
        }
        if (wifi_hal_startScan(radio_index, WIFI_RADIO_SCAN_MODE_ONCHAN, 0, 0, NULL) != RETURN_OK) {
            sprintf(buff, "%s: wifi_hal_startScan failed", args[0]);
            goto publish;
        }
        sprintf(buff, "%s: OK", args[0]);
    } else if (strcmp(args[0], "wifi_startNeighborScan") == 0) {
        wifiapi_handle_start_neighbor_scan(args, num_args, buff, sizeof(buff));
    } else if (strcmp(args[0], "wifi_getNeighboringWiFiStatus") == 0) {
        wifiapi_handle_neighbor_scan_status(args, num_args, buff, sizeof(buff));
    } else if (strcmp(args[0], "wifi_setBTMRequest") == 0) {
        wifiapi_handle_set_btm_request(args, num_args, buff, sizeof(buff));
    } else if (strcmp(args[0], "wifi_setRMBeaconRequest") == 0) {
        wifiapi_handle_set_rm_beacon_request(args, num_args, buff, sizeof(buff));
    } else if (strcmp(args[0], "wifi_setNeighborReports") == 0) {
        wifiapi_handle_set_neighbor_reports(args, num_args, buff, sizeof(buff));
    } else if (strcmp(args[0], "wifi_configNeighborReports") == 0) {
        wifiapi_handle_config_neighbor_reports(args, num_args, buff, sizeof(buff));
    } else if (strcmp(args[0], "wifi_hal_getRadioTemperature") == 0) {
        wifiapi_handle_hal_get_radio_temperature(args, num_args, buff, sizeof(buff));
    } else if (strcmp(args[0], "wifi_getRadioChannelStats") == 0) {
        wifiapi_handle_get_radio_channel_stats(args, num_args, buff, sizeof(buff));
    } else {
        unsigned int idx = 0;
        idx += snprintf(&buff[idx], sizeof(buff)-idx, "wifi_api2: Invalid API '%s'\nSupported APIs:\n", args[0]);
        if (idx >= sizeof(buff)) goto publish;
        for (i=0; i < (sizeof(wifi_api_list)/sizeof(struct hal_api_info)); i++) {
            idx += snprintf(&buff[idx], sizeof(buff)-idx, "%s\n", wifi_api_list[i].name);
            if (idx >= sizeof(buff)) goto publish;
        }
    }

publish:
    ctrl->wifiapi.result = buff;
    wifiapi_result_publish();
    if (raw != NULL) {
        free(raw);
    }
    webconfig_data_free(&data);
    return;
}
