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

#ifndef WIFI_DB_H
#define WIFI_DB_H

#include <ev.h>
#include "wifi_base.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
    mac_addr_str_t  mac;
    char            vap_name[32];
    struct timeval  tm;
    char            dev_name[32];
} mac_filter_data_t;

typedef void (* wifi_db_init_fn_t)(void);
typedef void (* wifi_db_init_data_fn_t)(void);
typedef int (* wifi_db_update_radio_cfg_fn_t)(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config);
typedef int (* wifi_db_start_fn_t)(void);
typedef void (* wifi_db_print_fn_t)(char *format, ...);
typedef int (* wifi_db_get_wifi_vap_info_fn_t)(char *vap_name, wifi_vap_info_t *config, rdk_wifi_vap_info_t *rdk_config);
typedef int (* wifi_db_update_wifi_macfilter_config_fn_t)(char *macfilter_key, acl_entry_t *config, bool add);
typedef void (* wifi_db_cleanup_fn_t)(void);
typedef int (* wifi_db_init_tables_fn_t)(void);
typedef void (* wifi_db_init_default_value_fn_t)(void);
typedef int (* wifi_db_start_monitor_fn_t)(void);
typedef int (* wifi_db_update_rfc_config_fn_t)(UINT rfc_id, wifi_rfc_dml_parameters_t *rfc_param);
typedef int (* wifi_db_init_global_config_default_fn_t)(wifi_global_param_t *config);
typedef int (* wifi_db_init_radio_config_default_fn_t)(int radio_index,wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config);
typedef int (* wifi_db_init_vap_config_default_fn_t)(int vap_index, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config);
typedef int (* wifi_db_update_wifi_security_config_fn_t)(char *vap_name, wifi_vap_security_t *sec);
typedef int (* wifi_db_get_gas_config_fn_t)(UINT advertisement_id, wifi_GASConfiguration_t *gas_info);
typedef int (* wifi_db_update_gas_config_fn_t)(UINT advertisement_id, wifi_GASConfiguration_t *gas_info);
typedef int (* wifi_db_update_wifi_vap_info_fn_t)(char *vap_name,wifi_vap_info_t *config,rdk_wifi_vap_info_t *rdk_config);
typedef int (* wifi_db_update_wifi_interworking_cfg_fn_t)(char *vap_name, wifi_interworking_t *config);
typedef int (* wifi_db_update_wifi_global_cfg_fn_t)(wifi_global_param_t *config);
typedef int (* wifi_db_update_wifi_passpoint_cfg_fn_t)(char *vap_name, wifi_interworking_t *config);
typedef int (* wifi_db_update_wifi_anqp_cfg_fn_t)(char *vap_name, wifi_interworking_t *config);

typedef struct {
    wifi_db_init_fn_t                          init_fn;
    wifi_db_init_data_fn_t                     init_data_fn;
    wifi_db_update_radio_cfg_fn_t              update_radio_cfg_fn;
    wifi_db_start_fn_t                         start_wifidb_fn;
    wifi_db_print_fn_t                         print_fn;
    wifi_db_get_wifi_vap_info_fn_t             get_wifi_vpa_info_fn;
    wifi_db_update_wifi_macfilter_config_fn_t  update_wifi_macfilter_config_fn;
    wifi_db_cleanup_fn_t                       cleanup_fn;
    wifi_db_init_tables_fn_t                   init_tables_fn;
    wifi_db_init_default_value_fn_t            init_default_value_fn;
    wifi_db_start_monitor_fn_t                 start_monitor_fn;
    wifi_db_update_rfc_config_fn_t             update_rfc_config_fn;
    wifi_db_init_global_config_default_fn_t    init_global_config_default_fn;
    wifi_db_init_radio_config_default_fn_t     init_radio_config_default_fn;
    wifi_db_init_vap_config_default_fn_t       init_vap_config_default_fn;
    wifi_db_update_wifi_security_config_fn_t   update_wifi_security_config_fn;
    wifi_db_get_gas_config_fn_t                get_gas_config_fn;
    wifi_db_update_gas_config_fn_t             update_gas_config_fn;
    wifi_db_update_wifi_vap_info_fn_t          update_wifi_vap_info_fn;
    wifi_db_update_wifi_interworking_cfg_fn_t  update_wifi_interworking_cfg_fn;
    wifi_db_update_wifi_global_cfg_fn_t        update_wifi_global_cfg_fn;
    wifi_db_update_wifi_passpoint_cfg_fn_t     update_wifi_passpoint_cfg_fn;
    wifi_db_update_wifi_anqp_cfg_fn_t          update_wifi_anqp_cfg_fn;
} wifidb_desc_t;

typedef struct {
    wifidb_desc_t  desc;
    struct         ev_loop *wifidb_ev_loop;
    struct         ev_io   wifidb_ev_io;
    int            wifidb_fd;
    int            wifidb_wfd;
    char           wifidb_sock_path[256];
    char           wifidb_run_dir[256];
    char           wifidb_bin_dir[256];
    char           wifidb_schema_dir[256];
    pthread_t      wifidb_thr_id;
    pthread_t      evloop_thr_id;
    bool           debug;
} wifi_db_t;

#define WIFIDB_SCHEMA_DIR "/usr/ccsp/wifi"
#ifndef WIFIDB_DIR
#define WIFIDB_DIR "/opt/secure/wifi"
#endif // WIFIDB_DIR
#define WIFIDB_RUN_DIR "/var/tmp"
#define DEFAULT_WPS_PIN  "1234"
//Schema version also needs to be
//updated in the managers.init if opensync code 
#define ONEWIFI_SCHEMA_DEF_VERSION 100007 
#define WIFIDB_CONSOLIDATED_PATH "/var/run/openvswitch/db.sock"
#define BUFFER_LENGTH_WIFIDB 32

#define LNF_PRIMARY_RADIUS_IP      "127.0.0.1"
#define LNF_SECONDARY_RADIUS_IP    "192.168.106.254"

int start_wifidb();
int init_wifidb_tables();
int wifidb_update_wifi_vap_config(int radio_index, wifi_vap_info_map_t *config,
    rdk_wifi_vap_info_t *rdk_config);

#ifdef __cplusplus
}
#endif

#endif //WIFI_DB_H
