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

#ifndef _WIFI_TESTS_H
#define _WIFI_TESTS_H

#define     SIM_NUMBER          5
#define     SIM_LOOP_TIMEOUT    1
#define     SIM_RSSI_HIGH       -35
#define     SIM_RSSI_LOW        -100
#define     SIM_RSSI_CONNECTED_THRESH   -75

typedef enum {
    wifi_hal_cb_connect,
    wifi_hal_cb_disconnect,
    wifi_hal_cb_deauth,
    wifi_hal_cb_max
} wifi_hal_cb_t;

typedef struct {
    wifi_hal_cb_t type;
    void *func;
} wifi_hal_cb_func;

typedef struct {
    mac_addr_t  sta_mac;
    bool        connected;
    rssi_t      rssi;
    bool        update;
} simulator_state_t;

typedef struct {

    simulator_state_t       simulator[SIM_NUMBER];
    pthread_t        sim_id;
    pthread_t           cb_id;
    
    pthread_cond_t      cond;
    pthread_mutex_t     lock;
    bool            started;
    wifi_hal_cb_func    cb[wifi_hal_cb_max];
} wifi_tests_simulator_t;

typedef int (* device_associated)(int ap_index, wifi_associated_dev_t *associated_dev, int reason);
typedef int (* device_deauthenticated)(int ap_index, char *mac, int reason);
typedef int (* device_disassociated)(int ap_index, char *mac, int reason);


#endif // _WIFI_TESTS_H
