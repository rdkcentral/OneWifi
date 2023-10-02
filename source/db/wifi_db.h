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

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
	mac_addr_str_t	mac;
	char	vap_name[32];
	struct timeval tm;
	char	dev_name[32];
} mac_filter_data_t;

typedef struct {
    struct      ev_loop	*wifidb_ev_loop;
    struct      ev_io wifidb_ev_io;
    int         wifidb_fd;
    int         wifidb_wfd;
    char        wifidb_sock_path[256];
    char        wifidb_run_dir[256];
    char        wifidb_bin_dir[256];
    char        wifidb_schema_dir[256];
    pthread_t	wifidb_thr_id;
    pthread_t   evloop_thr_id;
    bool	debug;
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

#ifdef __cplusplus
}
#endif

#endif //WIFI_DB_H
