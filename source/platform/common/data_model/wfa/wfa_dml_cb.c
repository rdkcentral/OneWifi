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
#include <stdbool.h>
#include <stdint.h>
#include "bus.h"
#include "wifi_data_model.h"
#include "wifi_dml_api.h"
#include "wfa_data_model.h"
#include "wifi_ctrl.h"
#include "dml_onewifi_api.h"
#include "wifi_mgr.h"

static bus_error_t set_output_value(char *param_name, raw_data_t *p_data, void *p_value) {
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

bool wfa_network_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    if (STR_CMP(param_name, "DeviceNumberOfEntries")) {
        *output_value = 1;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }
    return true;
}

bool wfa_network_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    if (STR_CMP(param_name, "ID")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "TimeStamp")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "ControllerID")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "MSCSDisallowedStaList")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "SCSDisallowedStaList")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "ColocatedAgentID")) {
        set_output_string(output_value, " ");
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
    //get the first radio config
    wifi_multi_link_modes_t capab_val = get_wifimgr_obj()->hal_cap.wifi_prop.radiocap[0].mldOperationalCap;
    if (STR_CMP(param_name, "MLDMACAddress")) {
        mac_addr_str_t mld_mac_str = { 0 };
        wifi_vap_info_t *vap = mld_grp->mld_vaps[0]; /* All affiliated APs share the same MLD MAC address */
        if (!vap) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cannot find VAP\n", __FUNCTION__, __LINE__);
            return bus_error_invalid_input;
        }
        to_mac_str(vap->u.bss_info.mld_info.common_info.mld_addr, mld_mac_str);
        return set_output_value(param_name, p_data, mld_mac_str);
    } else if (STR_CMP(param_name, "AffiliatedAPNumberOfEntries")) {
        UINT num_af_ap = get_total_num_affiliated_ap_dml(mld_grp);
        return set_output_value(param_name, p_data, &num_af_ap);
    } else if (STR_CMP(param_name, "STAMLDNumberOfEntries")) {
        UINT num_sta = get_mld_associated_devices_count(mld_grp);
        return set_output_value(param_name, p_data, &num_sta);
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
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return bus_error_invalid_input;
    }
}