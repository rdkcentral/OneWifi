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

#ifndef MULTIAP_H
#define MULTIAP_H

#ifdef __cplusplus
extern "C" {
#endif
#define CTRL_CAP_SZ 8

typedef struct {
    void *data;
} multiap_data_t;

typedef enum {
    vsz_event_id_wan_up = 2,
    vsz_event_id_autoconfig_req = 6,
    vsz_event_id_autoconfig_resp = 7,
    vsz_event_id_extender_mode = 11,
} vsz_event_id_t;

typedef struct {
    vsz_event_id_t id;
    unsigned char data[1024 - sizeof(vsz_event_id_t)];
} web_event_t;

typedef enum {
    multiap_msg_type_autoconf_search = 0x0007,
    multiap_msg_type_autoconf_resp = 0x0008,
} multiap_msg_type_t;

typedef enum {
    multiap_state_none,
    multiap_state_search_rsp_pending,
    multiap_state_completed,
    multiap_state_sta_create_and_connect,
    multiap_state_respond_to_search,
} multiap_state_t;

typedef char multiap_short_string_t[64];
typedef unsigned char multiap_enum_type_t;

typedef struct {
    mac_address_t dst;
    mac_address_t src;
    unsigned short type;
} __attribute__((__packed__)) multiap_raw_hdr_t;

typedef enum {
    multiap_freq_band_24, /* IEEE-multiap-1-2013 table 6-23 */
    multiap_freq_band_5,
    multiap_freq_band_60,
    multiap_freq_band_unknown
} multiap_freq_band_t;

typedef struct {
    unsigned char type;
    unsigned short len;
    unsigned char value[0];
} __attribute__((__packed__)) multiap_tlv_t;

typedef enum {
    multiap_service_type_ctrl,
    multiap_service_type_agent,
    multiap_service_type_cli,
    multiap_service_type_gateway = 98,
    multiap_service_type_extender = 99,
    multi_service_type_none
} multiap_service_type_t;

typedef struct {
    unsigned char ver;
    unsigned char reserved;
    unsigned short type;
    unsigned short id;
    unsigned char frag_id;
    unsigned char reserved_field : 6;
    unsigned char relay_ind : 1;
    unsigned char last_frag_ind : 1;
} __attribute__((__packed__)) multiap_cmdu_t;

typedef enum {
    multiap_profile_type_reserved,
    multiap_profile_type_1,
    multiap_profile_type_2,
    multiap_profile_type_3,
} multiap_profile_type_t;

typedef struct {
    unsigned char onboarding_proto;
    unsigned char integrity_algo;
    unsigned char encryption_algo;
} __attribute__((__packed__)) multiap_ieee_1905_security_cap_t;

typedef struct {
    unsigned char value[CTRL_CAP_SZ];
} __attribute__((__packed__)) multiap_ctrl_cap_t;

typedef enum {
    multiap_tlv_type_eom = 0,
    multiap_tlv_type_al_mac_address = 1,
    multiap_tlv_type_mac_address = 2,
    multiap_tlv_type_device_info = 3,
    multiap_tlv_type_searched_role = 0x0d,
    multiap_tlv_type_autoconf_freq_band = 0x0e,
    multiap_tlv_type_supported_role = 0x0f,
    multiap_tlv_type_supported_freq_band = 0x10,
    multiap_tlv_type_1905_layer_security_cap = 0xa9,
    multiap_tlv_type_profile = 0xb3,
    multiap_tlv_type_supported_service = 0x80,
    multiap_tlv_type_searched_service = 0x81,
    multiap_tlv_type_radio_id = 0x82,
    multiap_tlv_type_sta_mac_addr = 0x95,
    multiap_tlv_type_ctrl_cap = 0xdd,
} multiap_tlv_type_t;

typedef struct {
    unsigned char num_service;
    unsigned char supported_service[0];
} __attribute__((__packed__)) multiap_supported_srv_t;

#ifdef __cplusplus
}
#endif
#endif
