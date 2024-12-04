 /****************************************************************************
  If not stated otherwise in this file or this component's LICENSE
  file the following copyright and licenses apply:

  Copyright 2020 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

 ****************************************************************************/

#ifndef WIFI_WEBCONF_H
#define WIFI_WEBCONF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <wifi_base.h>
#include <cjson/cJSON.h>

#define WIFI_WEBCONFIG_DOC_DATA_NORTH   "Device.WiFi.WebConfig.Data.Subdoc.North"
#define WIFI_WEBCONFIG_DOC_DATA_SOUTH   "Device.WiFi.WebConfig.Data.Subdoc.South"
#define WIFI_WEBCONFIG_INIT_DATA        "Device.WiFi.WebConfig.Data.Init"
#define WIFI_WEBCONFIG_INIT_DML_DATA    "Device.WiFi.WebConfig.Data.Init_dml"
#define WIFI_WEBCONFIG_GET_ASSOC        "Device.WiFi.AssociatedClients"
#define WIFI_WEBCONFIG_GET_ACL          "Device.WiFi.MacFilter"
#define WIFI_WEBCONFIG_GET_CSI          "Device.WiFi.CSI"

#define WIFI_WEBCONFIG_PRIVATE_VAP      "Device.WiFi.Private"
#define WIFI_WEBCONFIG_HOME_VAP         "Device.WiFi.Home"
#define WIFI_WEBCONFIG_GET_NULL_SUBDOC  "Device.WiFi.Null"

#define DEVICE_WIFI_SSID                "Device.WiFi.SSID.%d.SSID"
#define DEVICE_WIFI_KEYPASSPHRASE       "Device.WiFi.AccessPoint.%d.Security.X_COMCAST-COM_KeyPassphrase"
#define FACTORY_RESET_NOTIFICATION      "Device.WiFi.NotifyWiFiChanges"
#define CONFIG_WIFI                     "Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi"
#define MAX_SSID_NAME_LEN          33
#define MIN_PWD_LEN                8
#define MAX_PWD_LEN                63

#define     WEBCONFIG_MAGIC_SIGNATUTRE  0xdecddecd
#define     WEBCONFIG_MAX_ASSOCIATED_CLIENTS BSS_MAX_NUM_STATIONS * MAX_NUM_RADIOS

typedef enum {
    webconfig_error_none,
    webconfig_error_init,
    webconfig_error_not_permitted,
    webconfig_error_unpack,
    webconfig_error_not_map,
    webconfig_error_key_absent,
    webconfig_error_invalid_subdoc,
    webconfig_error_decode,
    webconfig_error_encode,
    webconfig_error_apply,
    webconfig_error_save,
    webconfig_error_empty_anqp,
    webconfig_error_venue_entries,
    webconfig_error_venue_name_size,
    webconfig_error_oui_entries,
    webconfig_error_oui_length,
    webconfig_error_oui_char,
    webconfig_error_ipaddress,
    webconfig_error_realm_entries,
    webconfig_error_realm_length,
    webconfig_error_eap_entries,
    webconfig_error_eap_length,
    webconfig_error_eap_value,
    webconfig_error_auth_entries,
    webconfig_error_auth_param,
    webconfig_error_generic,
    webconfig_error_translate_to_ovsdb,
    webconfig_error_translate_from_ovsdb,
    webconfig_error_translate_to_tr181,
    webconfig_error_translate_from_tr181,
    webconfig_error_translate_to_easymesh,
    webconfig_error_translate_from_easymesh,
    webconfig_error_translate_from_ovsdb_cfg_no_change,
    webconfig_error_max
} webconfig_error_t;

typedef char    webconfig_error_str_t[128];

typedef struct {
    webconfig_error_t   err;
    webconfig_error_str_t   str;
} webconfig_error_map_t;

typedef enum {
    webconfig_subdoc_type_unknown,
    webconfig_subdoc_type_private,
    webconfig_subdoc_type_null,
    webconfig_subdoc_type_home,
    webconfig_subdoc_type_xfinity,
    webconfig_subdoc_type_radio,
    webconfig_subdoc_type_mesh,
    webconfig_subdoc_type_mesh_backhaul,
    webconfig_subdoc_type_mesh_sta,
    webconfig_subdoc_type_lnf,
    webconfig_subdoc_type_dml,
    webconfig_subdoc_type_associated_clients,
    webconfig_subdoc_type_wifiapiradio,
    webconfig_subdoc_type_wifiapivap,
    webconfig_subdoc_type_mac_filter,
    webconfig_subdoc_type_blaster,
    webconfig_subdoc_type_harvester,
    webconfig_subdoc_type_wifi_config,
    webconfig_subdoc_type_csi,
    webconfig_subdoc_type_stats_config,
    webconfig_subdoc_type_steering_config,
    webconfig_subdoc_type_steering_clients,
    webconfig_subdoc_type_vif_neighbors,
    webconfig_subdoc_type_mesh_backhaul_sta,
    webconfig_subdoc_type_levl,
    webconfig_subdoc_type_cac,
    webconfig_subdoc_type_radio_stats,
    webconfig_subdoc_type_neighbor_stats,
    webconfig_subdoc_type_assocdev_stats,
    webconfig_subdoc_type_radiodiag_stats,
    webconfig_subdoc_type_radio_temperature,
    webconfig_subdoc_type_vap_24G,
    webconfig_subdoc_type_vap_5G,
    webconfig_subdoc_type_vap_6G,
    webconfig_subdoc_type_max
} webconfig_subdoc_type_t;

typedef enum {
    webconfig_subdoc_object_type_version,
    webconfig_subdoc_object_type_subdoc,
    webconfig_subdoc_object_type_config,
    webconfig_subdoc_object_type_radios,
    webconfig_subdoc_object_type_vaps,
    webconfig_subdoc_object_type_radio_status,
    webconfig_subdoc_object_type_vap_status,
    webconfig_subdoc_object_type_wifi_mac_filter,
    webconfig_subdoc_object_type_harvester,
    webconfig_subdoc_object_type_wificap,
    webconfig_subdoc_object_type_associated_clients,
    webconfig_subdoc_object_type_csi,
    webconfig_subdoc_object_type_stats_config,
    webconfig_subdoc_object_type_steering_config,
    webconfig_subdoc_object_type_steering_clients,
    webconfig_subdoc_object_type_vif_neighbors,
    webconfig_subdoc_object_type_levl,
    webconfig_subdoc_object_type_cac,
    webconfig_subdoc_object_max
} webconfig_subdoc_object_type_t;

typedef enum {
    webconfig_initializer_none,
    webconfig_initializer_onewifi,
    webconfig_initializer_ovsdb,
    webconfig_initializer_dml,
    webconfig_initializer_wifievents,
    webconfig_initializer_cci,
    webconfig_initializer_max
} webconfig_initializer_t;

typedef enum {
    assoclist_notifier_full,
    assoclist_notifier_diff,
} assoclist_notifier_type_t;

typedef enum {
    assoclist_type_full,
    assoclist_type_add,
    assoclist_type_remove
} assoclist_type_t;

typedef enum {
    stats_type_radio_channel
} subscribe_stats_type_t;

typedef struct {
    subscribe_stats_type_t stats_type;
    void *stats;
} collect_subscribed_stats_t;

typedef struct {
    wifi_global_config_t    config;
    wifi_hal_capability_t   hal_cap;
    rdk_wifi_radio_t    radios[MAX_NUM_RADIOS];
    queue_t *csi_data_queue;
    active_msmt_t blaster;
    instant_measurement_config_t  harvester;
    levl_config_t levl;
    hash_map_t  *stats_config_map;
    hash_map_t  *steering_config_map;
    hash_map_t  *steering_client_map;
    hash_map_t  *vif_neighbors_map;
    // external structures that need translation to above structures
    unsigned int num_radios;
    assoclist_notifier_type_t assoclist_notifier_type;
    void *external_protos;
    collect_subscribed_stats_t collect_stats;
} webconfig_subdoc_decoded_data_t;

typedef char  * webconfig_subdoc_encoded_raw_t;
typedef cJSON * webconfig_subdoc_encoded_json_t;

typedef struct {
    webconfig_subdoc_encoded_raw_t  raw;
    webconfig_subdoc_encoded_json_t json;
} webconfig_subdoc_encoded_data_t;

typedef struct {
    unsigned int signature;
    webconfig_subdoc_type_t type;
#define     webconfig_data_descriptor_encoded                 1 << 0
#define     webconfig_data_descriptor_translate_to_tr181      1 << 1
#define     webconfig_data_descriptor_translate_to_ovsdb      1 << 2
#define     webconfig_data_descriptor_translate_to_easymesh   1 << 3

#define     webconfig_data_descriptor_decoded                 1 << 16
#define     webconfig_data_descriptor_translate_from_tr181    1 << 17
#define     webconfig_data_descriptor_translate_from_ovsdb    1 << 18
#define     webconfig_data_descriptor_translate_from_easymesh 1 << 19
    unsigned int   descriptor;//TBD Onewifi
    struct {
        webconfig_subdoc_decoded_data_t decoded;
        webconfig_subdoc_encoded_data_t encoded;
    } u;
} webconfig_subdoc_data_t;

struct webconfig;

typedef char    webconfig_subdoc_name_t[32];
typedef char    webconfig_subdoc_object_name_t[32];

typedef struct webconfig_subdoc webconfig_subdoc_t;

typedef webconfig_error_t   (* webconfig_apply_data_t)(struct webconfig_subdoc *doc, webconfig_subdoc_data_t *data);

typedef webconfig_error_t   (* webconfig_init_subdoc_t)(struct webconfig_subdoc *doc);
typedef webconfig_error_t   (* webconfig_access_check_subdoc_t)(struct webconfig *config, webconfig_subdoc_data_t *data);
typedef webconfig_error_t   (* webconfig_translate_to_subdoc_t)(struct webconfig *config, webconfig_subdoc_data_t *data);
typedef webconfig_error_t   (* webconfig_translate_from_subdoc_t)(struct webconfig *config, webconfig_subdoc_data_t *data);
typedef webconfig_error_t   (* webconfig_decode_subdoc_t)(struct webconfig *config, webconfig_subdoc_data_t *data);
typedef webconfig_error_t   (* webconfig_encode_subdoc_t)(struct webconfig *config, webconfig_subdoc_data_t *data);

typedef struct {
    webconfig_subdoc_object_type_t  type;
    webconfig_subdoc_object_name_t  name;
} webconfig_subdoc_object_t;

typedef webconfig_error_t   (* wifi_webconfig_translate_to_proto_t)   (webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data);
typedef webconfig_error_t   (* wifi_webconfig_translate_from_proto_t) (webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data);

typedef struct {
    wifi_webconfig_translate_to_proto_t     translate_to;
    wifi_webconfig_translate_from_proto_t   translate_from;
} webconfig_proto_desc_t;

typedef struct webconfig_subdoc {
    webconfig_subdoc_type_t type;
    webconfig_subdoc_name_t name;
    unsigned int    num_objects;
    webconfig_subdoc_object_t   objects[webconfig_subdoc_object_max];
    unsigned int    major;
    unsigned int    minor;
    webconfig_init_subdoc_t init_subdoc;
    webconfig_access_check_subdoc_t     access_check_subdoc;
    webconfig_translate_to_subdoc_t translate_to_subdoc;
    webconfig_translate_from_subdoc_t   translate_from_subdoc;
    webconfig_decode_subdoc_t   decode_subdoc;
    webconfig_encode_subdoc_t   encode_subdoc;
} webconfig_subdoc_t;

typedef int (* multi_doc_obj_register_t)();
typedef int (* single_doc_obj_register_t)();

typedef struct {
    void  *multi_doc;
    multi_doc_obj_register_t register_func;
} webconfig_multi_doc_t;


typedef struct {
    void  *doc;
    single_doc_obj_register_t register_func;
} webconfig_single_doc_t;

typedef struct webconfig {
    webconfig_initializer_t initializer;
    webconfig_apply_data_t  apply_data;
    webconfig_subdoc_t      subdocs[webconfig_subdoc_type_max];
    webconfig_proto_desc_t  proto_desc;
    webconfig_multi_doc_t   multi_doc_desc;
    webconfig_single_doc_t  single_doc_desc;
} webconfig_t;

// common api for all processes linking with this library
webconfig_error_t webconfig_init(webconfig_t *config);

webconfig_error_t webconfig_multi_doc_init();
webconfig_error_t webconfig_single_doc_init();


// API related to  multi subdoc of webconfig
size_t webconf_timeout_handler(size_t numOfEntries);
void webconf_free_resources(void *arg);
int wifi_vap_cfg_rollback_handler();


// external api sets for onewifi
webconfig_error_t webconfig_encode(webconfig_t *config, webconfig_subdoc_data_t *data, webconfig_subdoc_type_t type);
webconfig_error_t webconfig_decode(webconfig_t *config, webconfig_subdoc_data_t *data, const char *str);
webconfig_error_t webconfig_data_free(webconfig_subdoc_data_t *data);


// internal to webconfig
webconfig_error_t webconfig_set(webconfig_t *config, webconfig_subdoc_data_t *data);

webconfig_error_t       init_null_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_null_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_null_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_null_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_null_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_null_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// private
webconfig_error_t       init_private_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// mesh backhaul
webconfig_error_t       init_mesh_backhaul_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_mesh_backhaul_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_mesh_backhaul_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_mesh_backhaul_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_mesh_backhaul_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_mesh_backhaul_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// mesh backhaul sta
webconfig_error_t       init_mesh_backhaul_sta_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_mesh_backhaul_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_mesh_backhaul_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_mesh_backhaul_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_mesh_backhaul_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_mesh_backhaul_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// mesh sta
webconfig_error_t       init_mesh_sta_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// home
webconfig_error_t       init_home_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_home_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_home_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_home_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_home_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_home_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// xfinity
webconfig_error_t       init_xfinity_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// radio
webconfig_error_t       init_radio_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// mesh
webconfig_error_t       init_mesh_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_mesh_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_mesh_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_mesh_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_mesh_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_mesh_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// dml
webconfig_error_t       init_dml_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// radio_status
webconfig_error_t       init_radio_status_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// vap_status
webconfig_error_t       init_vap_status_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//associated_clients
webconfig_error_t       access_check_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// wifiapiradio
webconfig_error_t       init_wifiapiradio_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// wifiapivap
webconfig_error_t       init_wifiapivap_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// mac_filter
webconfig_error_t       init_mac_filter_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//csi data
webconfig_error_t       init_csi_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//blaster config

webconfig_error_t       init_blaster_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_blaster_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_blaster_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_blaster_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_blaster_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_blaster_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//harvester

webconfig_error_t       init_harvester_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//global_config_param

webconfig_error_t       init_wifi_config_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_wifi_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_wifi_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_wifi_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_wifi_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_wifi_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//  lnf
webconfig_error_t       init_lnf_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//steering config

webconfig_error_t       init_steering_config_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       decode_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       access_check_steer_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//stats config

webconfig_error_t       init_stats_config_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       decode_stats_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_stats_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_stats_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_stats_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       access_check_stats_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);


//steering clients 

webconfig_error_t       init_steering_clients_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       decode_steering_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_steering_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_steering_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_steering_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       access_check_steering_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//  vif_neighbors
webconfig_error_t       init_vif_neighbors_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//Levl
webconfig_error_t       init_levl_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_levl_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_levl_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_levl_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_levl_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_levl_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

//  cac
webconfig_error_t       init_cac_config_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// radio channel stats
webconfig_error_t       init_radio_channel_stats_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_radio_channel_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_radio_channel_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_radio_channel_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_radio_channel_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_radio_channel_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// Neighbor stats
webconfig_error_t       init_neighbor_stats_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_neighbor_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_radio_neighbor_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_radio_neighbor_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_neighbor_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_neighbor_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// Assoc device Stats
webconfig_error_t       init_assocdev_stats_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_assocdev_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_associated_device_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_associated_device_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_assocdev_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_assocdev_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// Radio Diagnostics Stats
webconfig_error_t       init_radiodiag_stats_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_radiodiag_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_radio_radiodiag_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_radio_radiodiag_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_radiodiag_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_radiodiag_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// Radio Temperature
webconfig_error_t       init_radio_temperature_stats_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_radio_temperature_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_radio_temperature_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_radio_temperature_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_radio_temperature_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_radio_temperature_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);

// Vap_24G, Vap_5G and Vap_6G 
webconfig_error_t       init_multivap_subdoc(webconfig_subdoc_t *doc);
webconfig_error_t       access_check_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       decode_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       encode_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_to_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
webconfig_error_t       translate_from_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data);
#ifdef __cplusplus
}
#endif

#endif
