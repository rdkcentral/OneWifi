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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "bus.h"
#include "wifi_data_model.h"
#include "wifi_dml_api.h"
#include "wfa_data_model.h"
#include "wifi_ctrl.h"
#include "dml_onewifi_api.h"
#include "wifi_mgr.h"

bus_error_t set_output_value(char *param_name, raw_data_t *p_data, void *p_value) {
    switch(p_data->data_type) {
        case bus_data_type_boolean:
            p_data->raw_data.b = *((bool *)p_value);
        break;
        case bus_data_type_int32:
            p_data->raw_data.i32 = *((int32_t *)p_value);
        break;
        case bus_data_type_uint32:
            p_data->raw_data.u32 = *((uint32_t *)p_value);
        break;
        case bus_data_type_string:
            scratch_data_buff_t temp_buff = { 0 };
            set_output_string(&temp_buff, (char *)p_value);
            p_data->raw_data.bytes = temp_buff.buff;
            p_data->raw_data_len   = temp_buff.buff_len;
        break;
        case bus_data_type_none:
        default:
            wifi_util_error_print(WIFI_DMCLI,"%s:%d unsupported param:%x failed for [%s]\n", __func__, __LINE__, p_data->data_type, param_name);
            return bus_error_invalid_input;
        break;
    }
    return bus_error_success;
}

bool wfa_network_get_param_value(void *obj_ins_context, char *param_name, raw_data_t *p_data)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    if (STR_CMP(param_name, "DeviceNumberOfEntries")) {
        uint32_t device_num = 1;
        set_output_value(param_name, p_data, &device_num);
    } else if (STR_CMP(param_name, "ID")) {
        set_output_value(param_name, p_data, " ");
    } else if (STR_CMP(param_name, "TimeStamp")) {
        set_output_value(param_name, p_data, " ");
    } else if (STR_CMP(param_name, "ControllerID")) {
        set_output_value(param_name, p_data, " ");
    } else if (STR_CMP(param_name, "MSCSDisallowedStaList")) {
        set_output_value(param_name, p_data, " ");
    } else if (STR_CMP(param_name, "SCSDisallowedStaList")) {
        set_output_value(param_name, p_data, " ");
    } else if (STR_CMP(param_name, "ColocatedAgentID")) {
        set_output_value(param_name, p_data, " ");
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bus_error_t wfa_network_ssid_get_param_value(void *obj_ins_context, char *param_name, raw_data_t *p_data)
{
    wifi_vap_info_t *vap = obj_ins_context;
    wifi_radio_operationParam_t *radio_param = getRadioOperationParam(vap->radio_index);
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    if (STR_CMP(param_name, "SSID")) {
        return set_output_value(param_name, p_data, vap->u.bss_info.ssid);
    } else if (STR_CMP(param_name, "Band")) {
        switch (radio_param->band)
        {
            case WIFI_FREQUENCY_2_4_BAND: return set_output_value(param_name, p_data, "2.4");
            case WIFI_FREQUENCY_5_BAND: return set_output_value(param_name, p_data, "5");
            case WIFI_FREQUENCY_6_BAND: return set_output_value(param_name, p_data, "6");
            default: return set_output_value(param_name, p_data, "NotImplemented");
        }
    }
    else if (STR_CMP(param_name, "AKMsAllowed")) {
        return set_output_value(param_name, p_data, "NotImplemented");
    }
    else if (STR_CMP(param_name, "SuiteSelector")) {
        return set_output_value(param_name, p_data, "NotImplemented");
    }
    else if (STR_CMP(param_name, "MFPConfig")) {
#if defined(WIFI_HAL_VERSION_3)
        switch (vap->u.bss_info.security.mfp) {
            case wifi_mfp_cfg_disabled: return set_output_value(param_name, p_data, "Disabled");
            case wifi_mfp_cfg_optional: return set_output_value(param_name, p_data, "Optional");
            case wifi_mfp_cfg_required: return set_output_value(param_name, p_data, "Required");
            default: return set_output_value(param_name, p_data, "NotImplemented");
        }
#else
        return set_output_value(param_name, p_data, vap->u.bss_info.security.mfpConfig);
#endif
    }
    else if (STR_CMP(param_name, "MobilityDomain")) {
        return set_output_value(param_name, p_data, "NotImplemented");
    }
    else if (STR_CMP(param_name, "HaulType")) {
        if (!strncmp(vap->vap_name, "mesh_backhaul", strlen("mesh_backhaul")) ||
            !strncmp(vap->vap_name, "mesh_sta", strlen("mesh_sta"))) {
            return set_output_value(param_name, p_data, "Backhaul");
        }
        else {
            return set_output_value(param_name, p_data, "Fronthaul");
        }
    }
    else if (STR_CMP(param_name, "AdvertisementEnabled")) {
        return set_output_value(param_name, p_data, &vap->u.bss_info.showSsid);
    }
    else if (STR_CMP(param_name, "Enable")) {
        return set_output_value(param_name, p_data, &vap->u.bss_info.enabled);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return bus_error_invalid_input;
    }
}

bus_error_t wfa_apmld_get_param_value(void *obj_ins_context, char *param_name, raw_data_t *p_data)
{
    mld_group_t *mld_grp = obj_ins_context;

    wifi_multi_link_modes_t capab_val = get_wifimgr_obj()->hal_cap.wifi_prop.radiocap[0].mldOperationalCap;
    wifi_vap_info_t *vap = NULL;
    uint32_t affap_index = 0;

    if (strstr(param_name, "AffiliatedAP."))
        sscanf(param_name, "AffiliatedAP.%d.%s", &affap_index, param_name);

    if (affap_index > 0) {
        vap = mld_grp->mld_vaps[affap_index - 1];
        if (!vap) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cannot find VAP\n", __FUNCTION__, __LINE__);
            return bus_error_invalid_input;
        }
        uint32_t statval = 0;
        if (STR_CMP(param_name, "BSSID")) {
            mac_addr_str_t affsta_bssid_str = { 0 };
            to_mac_str(vap->u.bss_info.bssid, affsta_bssid_str);
            return set_output_value(param_name, p_data, affsta_bssid_str);
        } else if (STR_CMP(param_name, "LinkID")) {
            INT mld_link_id = vap->u.bss_info.mld_info.common_info.mld_link_id;
            return set_output_value(param_name, p_data, &mld_link_id);
        } else if (STR_CMP(param_name, "RUID")) {
            return set_output_value(param_name, p_data, "Not Implemented");
        } else if (STR_CMP(param_name, "PacketsSent")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "PacketsReceived")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "ErrorsSent")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "UnicastBytesSent")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "UnicastBytesReceived")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "MulticastBytesSent")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "MulticastBytesReceived")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "BroadcastBytesSent")) {
            return set_output_value(param_name, p_data, &statval);
        } else if (STR_CMP(param_name, "BroadcastBytesReceived")) {
            return set_output_value(param_name, p_data, &statval);
        }
    } else if (STR_CMP(param_name, "MLDMACAddress")) {
        mac_addr_str_t mld_mac_str = { 0 };
        vap = mld_grp->mld_vaps[0]; /* All affiliated APs share the same MLD MAC address */
        if (!vap) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cannot find VAP\n", __FUNCTION__, __LINE__);
            return bus_error_invalid_input;
        }
        to_mac_str(vap->u.bss_info.mld_info.common_info.mld_addr, mld_mac_str);
        return set_output_value(param_name, p_data, mld_mac_str);
    } else if (STR_CMP(param_name, "TIDLinkMapNumberOfEntries")) {
        uint32_t num_tid_link_map = 0;
        return set_output_value(param_name, p_data, &num_tid_link_map);
    } else if (STR_CMP(param_name, "AffiliatedAPNumberOfEntries")) {
        uint32_t num_af_ap = get_total_num_affiliated_ap_dml(mld_grp);
        return set_output_value(param_name, p_data, &num_af_ap);
    } else if (STR_CMP(param_name, "STAMLDNumberOfEntries")) {
        uint32_t num_sta = 0;
        uint8_t apmld_index = get_apmld_index_from_mld_group(mld_grp);
        update_dml_stamld_list(apmld_index);
        num_sta = get_total_num_stamld_dml(apmld_index);
        return set_output_value(param_name, p_data, &num_sta);
    } else if (STR_CMP(param_name, "LinkToOpClassMapNumberOfEntries")) {
        uint32_t num_link_opclass = 0;
        return set_output_value(param_name, p_data, &num_link_opclass);
    } else if (STR_CMP(param_name, "APMLDConfig.EMLMREnabled")) {
        bool bool_val = capab_val & eMLMR;
        return set_output_value(param_name, p_data, &bool_val);
    } else if (STR_CMP(param_name, "APMLDConfig.EMLSREnabled")) {
        bool bool_val = capab_val & eMLSR;
        return set_output_value(param_name, p_data, &bool_val);
    } else if (STR_CMP(param_name, "APMLDConfig.STREnabled")) {
        bool bool_val = capab_val & STR;
        return set_output_value(param_name, p_data, &bool_val);
    } else if (STR_CMP(param_name, "APMLDConfig.NSTREnabled")) {
        bool bool_val = capab_val & NSTR;
        return set_output_value(param_name, p_data, &bool_val);
    } else if (STR_CMP(param_name, "APMLDConfig.TIDLinkMapNegotiation")) {
        bool bool_val = false; /* TODO Implement */
        return set_output_value(param_name, p_data, &bool_val);
    }

    wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
    return bus_error_invalid_input;
}

/* Generic macro to sum a numeric field across all affiliated STAs in a STAMLD */
#define WFA_STAMLD_SUM(stamld, field) \
({ \
    typeof(((assoc_dev_data_t *)0)->field) __total = 0; \
    if (stamld) { \
        for (UINT __i = 0; __i < (stamld)->affiliated_sta_count; __i++) { \
            if ((stamld)->affiliated_sta[__i]) { \
                __total += (stamld)->affiliated_sta[__i]->field; \
            } \
        } \
    } \
    __total; \
})

bus_error_t wfa_stamld_get_param_value(void *obj_ins_context, char *param_name, raw_data_t *p_data)
{
    stamld_data_t *stamld = (stamld_data_t *)obj_ins_context;
    
    if (!stamld) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Invalid STAMLD\n", __func__, __LINE__);
        return bus_error_invalid_input;
    }
    
    if (STR_CMP(param_name, "MLDMACAddress")) {
        mac_addr_str_t mld_mac_str = { 0 };
        to_mac_str(stamld->affiliated_sta[0]->dev_stats.cli_MACAddress, mld_mac_str);
        return set_output_value(param_name, p_data, mld_mac_str);
    }
    else if (STR_CMP(param_name, "Hostname")) {
        return set_output_value(param_name, p_data, " ");
    }
    else if (STR_CMP(param_name, "IPv4Address")) {
        return set_output_value(param_name, p_data, " ");
    }
    else if (STR_CMP(param_name, "IPv6Address")) {
        return set_output_value(param_name, p_data, " ");
    } 
    else if (STR_CMP(param_name, "IsbSTA")) {
        bool is_bsta = false;
        return set_output_value(param_name, p_data, &is_bsta);
    }
    else if (STR_CMP(param_name, "LastConnectTime")) {
        uint32_t last_connect_time = 0;
        return set_output_value(param_name, p_data, &last_connect_time);
    } else if (STR_CMP(param_name, "BytesReceived")) {
        uint32_t total = WFA_STAMLD_SUM(stamld, dev_stats.cli_BytesReceived);
        return set_output_value(param_name, p_data, &total);
    }
    else if (STR_CMP(param_name, "BytesSent")) {
        uint32_t total = WFA_STAMLD_SUM(stamld, dev_stats.cli_BytesSent);
        return set_output_value(param_name, p_data, &total);
    }
    else if (STR_CMP(param_name, "PacketsReceived")) {
        uint32_t total = WFA_STAMLD_SUM(stamld, dev_stats.cli_PacketsReceived);
        return set_output_value(param_name, p_data, &total);
    }
    else if (STR_CMP(param_name, "PacketsSent")) {
        uint32_t total = WFA_STAMLD_SUM(stamld, dev_stats.cli_PacketsSent);
        return set_output_value(param_name, p_data, &total);
    }
    else if (STR_CMP(param_name, "ErrorsReceived")) {
        uint32_t total = WFA_STAMLD_SUM(stamld, dev_stats.cli_RxErrors);
        return set_output_value(param_name, p_data, &total);
    }
    else if (STR_CMP(param_name, "ErrorsSent")) {
        uint32_t total = WFA_STAMLD_SUM(stamld, dev_stats.cli_ErrorsSent);
        return set_output_value(param_name, p_data, &total);
    }
    else if (STR_CMP(param_name, "RetransCount")) {
        uint32_t total = WFA_STAMLD_SUM(stamld, dev_stats.cli_RetransCount);
        return set_output_value(param_name, p_data, &total);
    }
    else if (STR_CMP(param_name, "PairwiseAKM")) {
        char selector_hex[9] = { 0 };

        if (!rsn_akm_selector_hex(stamld->affiliated_sta[0]->conn_security.wpa_key_mgmt, selector_hex, sizeof(selector_hex))) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d:PairwiseAKM:%d conversion failure\n",
                __func__, __LINE__, stamld->affiliated_sta[0]->conn_security.wpa_key_mgmt);
            return set_output_value(param_name, p_data, " ");
        }

        return set_output_value(param_name, p_data, selector_hex);
    }
    else if (STR_CMP(param_name, "PairwiseCipher")) {
        char selector_hex[9] = { 0 };

        if (!rsn_cipher_selector_hex(stamld->affiliated_sta[0]->conn_security.pairwise_cipher, selector_hex, sizeof(selector_hex))) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d:PairwiseCipher:%d conversion failure\n",
                __func__, __LINE__, stamld->affiliated_sta[0]->conn_security.pairwise_cipher);
            return set_output_value(param_name, p_data, " ");
        }
        return set_output_value(param_name, p_data, selector_hex);
    }
    else if (STR_CMP(param_name, "RSNCapabilities")) {
        uint32_t rsn_capabilities = stamld->affiliated_sta[0]->conn_security.rsn_capabilities;
        return set_output_value(param_name, p_data, &rsn_capabilities);
    }
    else if (STR_CMP(param_name, "AffiliatedSTANumberOfEntries")) {
        return set_output_value(param_name, p_data, &stamld->affiliated_sta_count);
    }
    else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return bus_error_invalid_input;
    }
}

bus_error_t wfa_affiliatedsta_get_param_value(void *obj_ins_context, char *param_name, raw_data_t *p_data)
{
    assoc_dev_data_t *assoc_dev = (assoc_dev_data_t *)obj_ins_context;
    mac_addr_str_t mac_str = { 0 };
    
    if (!assoc_dev) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Invalid AffiliatedSTA device\n", __func__, __LINE__);
        return bus_error_invalid_input;
    }
    
    if (STR_CMP(param_name, "MACAddress")) {
        to_mac_str(assoc_dev->dev_stats.cli_MACAddress, mac_str);
        return set_output_value(param_name, p_data, mac_str);
    }
    else if (STR_CMP(param_name, "BSSID")) {
        wifi_vap_info_t *vap = getVapInfo(assoc_dev->ap_index);
        if (!vap) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cannot find VAP for ap_index:%d\n", __FUNCTION__, __LINE__, assoc_dev->ap_index);
            return bus_error_invalid_input;
        }
        to_mac_str(vap->u.bss_info.bssid, mac_str);
        return set_output_value(param_name, p_data, mac_str);
    }
    else if (STR_CMP(param_name, "BytesSent")) {
        return set_output_value(param_name, p_data, &assoc_dev->dev_stats.cli_BytesSent);
    }
    else if (STR_CMP(param_name, "BytesReceived")) {
        return set_output_value(param_name, p_data, &assoc_dev->dev_stats.cli_BytesReceived);
    }
    else if (STR_CMP(param_name, "PacketsSent")) {
        return set_output_value(param_name, p_data, &assoc_dev->dev_stats.cli_PacketsSent);
    }
    else if (STR_CMP(param_name, "PacketsReceived")) {
        return set_output_value(param_name, p_data, &assoc_dev->dev_stats.cli_PacketsReceived);
    }
    else if (STR_CMP(param_name, "ErrorsSent")) {
        return set_output_value(param_name, p_data, &assoc_dev->dev_stats.cli_ErrorsSent);
    }
    else if (STR_CMP(param_name, "SignalStrength")) {
        uint32_t rcpi = rssi_to_rcpi(assoc_dev->dev_stats.cli_SignalStrength);
        return set_output_value(param_name, p_data, &rcpi);
    }
    else if (STR_CMP(param_name, "EstMACDataRateDownlink")) {
        /* Estimated MAC layer throughput downlink in Mbps */
        return set_output_value(param_name, p_data, &assoc_dev->dev_stats.cli_MaxDownlinkRate);
    }
    else if (STR_CMP(param_name, "EstMACDataRateUplink")) {
        /* Estimated MAC layer throughput uplink in Mbps */
        return set_output_value(param_name, p_data, &assoc_dev->dev_stats.cli_MaxUplinkRate);
    }
    else if (STR_CMP(param_name, "LastDataDownlinkRate")) {
        /* Last data transmit rate downlink in kbps */
        uint32_t last_downlink_rate_kbps = assoc_dev->dev_stats.cli_LastDataDownlinkRate * 1000;
        return set_output_value(param_name, p_data, &last_downlink_rate_kbps);
    }
    else if (STR_CMP(param_name, "LastDataUplinkRate")) {
        /* Last data transmit rate uplink in kbps */
        uint32_t last_uplink_rate_kbps = assoc_dev->dev_stats.cli_LastDataUplinkRate * 1000;
        return set_output_value(param_name, p_data, &last_uplink_rate_kbps);
    }
    else if (STR_CMP(param_name, "UtilizationReceive")) {
        /* Channel utilization receiving in milliseconds */
        uint64_t util_rx = 0; // TODO implement
        return set_output_value(param_name, p_data, &util_rx);
    }
    else if (STR_CMP(param_name, "UtilizationTransmit")) {
        /* Channel utilization transmitting in milliseconds */
        uint64_t util_tx = 0; // TODO implement
        return set_output_value(param_name, p_data, &util_tx);
    }
    else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return bus_error_invalid_input;
    }
}