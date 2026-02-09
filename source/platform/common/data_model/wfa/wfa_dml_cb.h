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

#ifndef WFA_DML_CB_H
#define WFA_DML_CB_H

#include <stdbool.h>
#include <stdint.h>
#include "bus.h"

/**
 * @brief Get unsigned integer parameter value for WFA Network
 * 
 * @param obj_ins_context Object instance context
 * @param param_name Parameter name to retrieve
 * @param output_value Pointer to store the retrieved value
 * @return true on success, false on failure
 */
bool wfa_network_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);

/**
 * @brief Get string parameter value for WFA Network
 * 
 * @param obj_ins_context Object instance context
 * @param param_name Parameter name to retrieve
 * @param output_value Pointer to scratch buffer for storing the retrieved string
 * @return true on success, false on failure
 */
bool wfa_network_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value);

/**
 * @brief Get string parameter value for WFA Network SSID
 * 
 * @param obj_ins_context Object instance context
 * @param param_name Parameter name to retrieve
 * @param raw_data_t Pointer to raw data object
 * @return true on success, false on failure
 */
bus_error_t wfa_network_ssid_get_param_value(void *obj_ins_context, char *param_name, raw_data_t *p_data);

bus_error_t wfa_apmld_get_param_value(void *obj_ins_context, char *param_name, raw_data_t *p_data);

#endif // WFA_DML_CB_H
