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