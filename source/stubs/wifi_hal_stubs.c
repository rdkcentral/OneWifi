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

#include <pthread.h>
#include <sys/time.h>
#include <wifi_hal_rdk_framework.h>
#include <wifi_hal_ap.h>
#include <wifi_hal_generic.h>

#define RETURN_OK 0

INT wifi_anqpSendResponse(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *head)
{
    // TODO: Free previously allocated memory
    return RETURN_OK;
}

INT wifi_hal_purgeScanResult(INT apIndex, bssid_t bssid)
{
    return RETURN_OK;
}

INT wifi_hal_disconnect(INT apIndex)
{
    return RETURN_OK;
}

INT wifi_chan_event_register(wifi_chan_event_CB_t event_cb)
{
    return RETURN_OK;
}

INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct)
{
    return RETURN_OK;
}

INT wifi_hal_connect(INT ap_index, wifi_bss_info_t *bss)
{
    return RETURN_OK;
}

INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    return RETURN_OK;
}

INT wifi_hal_findNetworks(INT ap_index, wifi_channel_t *channel, wifi_bss_info_t **bss_array, UINT *num_bss)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_keypassphrase(char *password, int vap_index)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_ssid(char *ssid, int vap_index)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_wps_pin(char *pin)
{
    return RETURN_OK;
}

INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal)
{
    return RETURN_OK;
}

INT wifi_hal_getScanResults(wifi_radio_index_t index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss)
{
    return RETURN_OK;
}

INT wifi_hal_init()
{
    return RETURN_OK;
}

INT wifi_hal_kickAssociatedDevice(INT ap_index, mac_address_t mac)
{
    return RETURN_OK;
}

INT wifi_hal_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback func)
{
    return RETURN_OK;
}

INT wifi_hal_post_init()
{
    return RETURN_OK;
}

INT wifi_hal_pre_init()
{
    return RETURN_OK;
}

void wifi_hal_scanResults_callback_register(wifi_scanResults_callback func)
{
}

INT wifi_hal_setApWpsButtonPush(INT ap_index)
{
    return RETURN_OK;
}

INT wifi_hal_setApWpsCancel(INT ap_index)
{
    return RETURN_OK;
}

INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return RETURN_OK;
}

void wifi_hal_staConnectionStatus_callback_register(wifi_staConnectionStatus_callback func)
{
}

INT wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_country_code(char *code)
{
    return RETURN_OK;
}

INT wifi_hal_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_radius_key(char *radius_key)
{
    return RETURN_OK;
} 

INT wifi_hal_setApWpsPin(INT ap_index, char *wps_pin)
{
    return RETURN_OK;
}

INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    return RETURN_OK;
}
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    return RETURN_OK;
}
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    return RETURN_OK;
}
INT wifi_delApAclDevices(INT apINdex)
{
    return RETURN_OK;
}
INT wifi_hal_set_neighbor_report(UINT apIndex,UINT numNeighborReports, mac_address_t mac)
{
    return 0;
}

INT wifi_hal_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time,
    UINT chan_num, UINT *chan_list)
{
    return 0;
}

INT wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array,
    UINT *output_array_size)
{
    return 0;
}

INT wifi_hal_setBTMRequest(UINT apIndex, mac_address_t peerMac, wifi_BTMRequest_t *request)
{
    return 0;
}

INT wifi_hal_setRMBeaconRequest(UINT apIndex, mac_address_t peer_mac, wifi_BeaconRequest_t *in_req,
    UCHAR *out_DialogToken)
{
    return 0;
}

INT wifi_hal_setNeighborReports(UINT apIndex, UINT numNeighborReports,
    wifi_NeighborReport_t *neighborReports)
{
    return 0;
}

INT wifi_hal_configNeighborReports(UINT apIndex, bool enable, bool auto_resp)
{
    return 0;
}

INT wifi_hal_getRadioTemperature(wifi_radio_index_t radioIndex, wifi_radioTemperature_t *radioPhyTemperature)
{
  return 0;
}
BOOL is_db_upgrade_required( CHAR* inactive_firmware)
{
   return FALSE;
}
