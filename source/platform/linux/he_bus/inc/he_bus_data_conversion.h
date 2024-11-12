/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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
#ifndef HE_BUS_DATA_CONVERSION_H
#define HE_BUS_DATA_CONVERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "he_bus_common.h"
#include "he_bus_core.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

he_bus_error_t convert_bus_raw_msg_data_to_buffer(he_bus_raw_data_msg_t *raw_data,
    he_bus_stretch_buff_t *output_data);
he_bus_error_t convert_buffer_to_bus_raw_msg_data(he_bus_raw_data_msg_t *raw_data,
    he_bus_stretch_buff_t *input_data);
he_bus_error_t decode_and_handle_data(he_bus_handle_t handle, int fd,
    he_bus_stretch_buff_t *raw_buff, he_bus_raw_data_msg_t *p_res_data);
int send_bus_initial_msg_info(int fd, char *comp_name);
he_bus_error_t handle_bus_msg_data(he_bus_handle_t handle, int fd,
    he_bus_raw_data_msg_t *p_msg_data, he_bus_raw_data_msg_t *p_res_data);

uint32_t set_bus_object_data(char *event_name, he_bus_data_object_t *p_obj_data,
    he_bus_msg_sub_type_t msg_sub_type, he_bus_raw_data_t *cfg_data, he_bus_error_t ret_status);

he_bus_error_t validate_sub_response(he_bus_event_sub_t *sub_data_map,
    he_bus_raw_data_msg_t *recv_data);
he_bus_error_t prepare_initial_bus_header(he_bus_raw_data_msg_t *p_data, char *comp_name,
    he_bus_msg_type_t msg_type);
he_bus_error_t prepare_rem_payload_bus_msg_data(char *event_name,
    he_bus_raw_data_msg_t *p_base_hdr_data, he_bus_msg_sub_type_t msg_sub_type,
    he_bus_raw_data_t *payload_data, he_bus_error_t ret_status);

#ifdef __cplusplus
}
#endif
#endif // HE_BUS_DATA_CONVERSION_H
