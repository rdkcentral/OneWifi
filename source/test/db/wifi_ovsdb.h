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

#ifndef WIFI_OVSDB_H
#define WIFI_OVSDB_H

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
	struct ev_loop	*ovs_ev_loop;
	struct ev_io wovsdb;
	int ovsdb_fd;
	char ovsdb_sock_path[256];
    char    ovsdb_run_dir[256];
    char    ovsdb_bin_dir[256];
    char    ovsdb_schema_dir[256];
	pthread_t	ovsdb_thr_id;
	pthread_t   evloop_thr_id;
	bool	debug;
} wifi_ovsdb_t;

#ifdef __cplusplus
}
#endif

#endif //WIFI_OVSDB_H
