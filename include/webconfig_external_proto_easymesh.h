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

#ifndef EXTERNAL_PROTO_EASYMESH_H
#define EXTERNAL_PROTO_EASYMESH_H
#include "em_base.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned int (*ext_proto_get_num_radio_t)(void *data_model);
typedef void (*ext_proto_set_num_radio_t)(void *data_model, unsigned int num_radio);
typedef unsigned int (*ext_proto_get_num_op_class_t)(void *data_model);
typedef void (*ext_proto_set_num_op_class_t)(void *data_model, unsigned int num_op_class);
typedef unsigned int (*ext_proto_get_num_bss_t)(void *data_model);
typedef void (*ext_proto_set_num_bss_t)(void *data_model, unsigned int num_bss);
typedef em_device_info_t *	(*ext_proto_em_get_device_info_t)(void *data_model);
typedef em_network_info_t *	(*ext_proto_em_get_network_info_t)(void *data_model);
typedef em_radio_info_t *	(*ext_proto_em_get_radio_info_t)(void *data_model, unsigned int radio_index);
typedef em_ieee_1905_security_info_t *	(*ext_proto_em_get_ieee_1905_security_info_t)(void *data_model);
typedef em_bss_info_t *     (*ext_proto_em_get_bss_info_t)(void *data_model, unsigned bss_index);
typedef em_op_class_info_t *     (*ext_proto_em_get_op_class_info_t)(void *data_model, unsigned int radio_index);
typedef em_sta_info_t * (*ext_proto_get_first_sta_info_t)(void *data_model, em_target_sta_map_t target);
typedef em_sta_info_t * (*ext_proto_get_next_sta_info_t)(void *data_model, em_sta_info_t *sta_info, em_target_sta_map_t target);
typedef em_sta_info_t * (*ext_proto_get_sta_info_t)(void *data_model, mac_address_t sta, bssid_t bssid, mac_address_t ruid, em_target_sta_map_t target);
typedef void (*ext_proto_put_sta_info_t)(void *data_model, em_sta_info_t *sta_info, em_target_sta_map_t target);
typedef em_bss_info_t * (*ext_proto_em_get_bss_info_with_mac_t)(void *data_model, mac_address_t mac);
typedef unsigned int (*ext_proto_get_num_scan_results_t)(void *data_model);
typedef void (*ext_proto_set_num_scan_results_t)(void *data_model, unsigned int num);
typedef em_scan_result_t * (*ext_proto_get_scan_result_info_t)(void *data_model, unsigned int index);

typedef struct {
    void *data_model; /* agent data model dm_easy_mesh_t */

    void *m2ctrl_radioconfig;
    void *policy_config;
    // descriptors to access data model
    ext_proto_get_num_radio_t   get_num_radio;
    ext_proto_set_num_radio_t   set_num_radio;
    ext_proto_get_num_op_class_t   get_num_op_class;
    ext_proto_set_num_op_class_t   set_num_op_class;
    ext_proto_get_num_bss_t   get_num_bss;
    ext_proto_set_num_bss_t   set_num_bss;
    ext_proto_em_get_device_info_t	get_device_info;
    ext_proto_em_get_network_info_t get_network_info;
    ext_proto_em_get_radio_info_t   get_radio_info;
    ext_proto_em_get_ieee_1905_security_info_t  get_ieee_1905_security_info;
    ext_proto_em_get_bss_info_t get_bss_info;
    ext_proto_em_get_op_class_info_t get_op_class_info;
    ext_proto_get_first_sta_info_t   get_first_sta_info;
    ext_proto_get_next_sta_info_t   get_next_sta_info;
    ext_proto_get_sta_info_t   get_sta_info;
    ext_proto_put_sta_info_t   put_sta_info;
    ext_proto_em_get_bss_info_with_mac_t   get_bss_info_with_mac;
    ext_proto_get_num_scan_results_t get_num_scan_results;
    ext_proto_set_num_scan_results_t set_num_scan_results;
    ext_proto_get_scan_result_info_t get_scan_result_info;
} webconfig_external_easymesh_t;

void webconfig_proto_easymesh_init(webconfig_external_easymesh_t *proto, void *data_model, void *m2ctrl_vapconfig, void *policy_config,
        ext_proto_get_num_radio_t   get_num_radio, ext_proto_set_num_radio_t set_num_radio,
        ext_proto_get_num_op_class_t   get_num_op_class, ext_proto_set_num_op_class_t set_num_op_class,
        ext_proto_get_num_bss_t   get_num_bss, ext_proto_set_num_bss_t set_num_bss,
        ext_proto_em_get_device_info_t get_dev, ext_proto_em_get_network_info_t get_net,
        ext_proto_em_get_radio_info_t get_radio, ext_proto_em_get_ieee_1905_security_info_t get_sec,
        ext_proto_em_get_bss_info_t get_bss, ext_proto_em_get_op_class_info_t get_op_class,
        ext_proto_get_first_sta_info_t get_first_sta, ext_proto_get_next_sta_info_t get_next_sta,
        ext_proto_get_sta_info_t get_sta, ext_proto_put_sta_info_t put_sta, ext_proto_em_get_bss_info_with_mac_t get_bss_info_with_mac,
        ext_proto_get_num_scan_results_t get_num_scan_res, ext_proto_set_num_scan_results_t set_num_scan_res, ext_proto_get_scan_result_info_t get_scan_result);

#ifdef __cplusplus
}
#endif

#endif //EXTERNAL_PROTO_EASYMESH_H
