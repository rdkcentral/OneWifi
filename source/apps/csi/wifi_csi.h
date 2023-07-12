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

#ifndef WIFI_CSI_H
#define WIFI_CSI_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NUM_CSI_SOUNDING 6

typedef int (*csi_start_fn_t) (void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app);
typedef int (*csi_stop_fn_t)  (void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app);

typedef struct {
    csi_start_fn_t csi_start_fn;
    csi_stop_fn_t  csi_stop_fn;
} csi_base_app_t;

typedef struct {
    hash_map_t           *csi_sounding_mac_map;
    int                  num_current_sounding;
    csi_base_app_t       csi_fns;
} __attribute__((__packed__))  csi_app_t;

typedef struct {
    mac_address_t mac_addr;
    int  ap_index;
    int  subscribed_apps;
} csi_mac_data_t;

int csi_init(wifi_app_t *app, unsigned int create_flag);

#ifdef __cplusplus
}
#endif

#endif
