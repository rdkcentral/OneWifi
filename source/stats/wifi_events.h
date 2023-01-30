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

#ifndef _WIFI_EVENTS_H_
#define _WIFI_EVENTS_H_

#include "wifi_hal.h"
#include "collection.h"
#include "wifi_monitor.h"

#define CLIENTDIAG_JSON_BUFFER_SIZE 665
#define MAX_CSI_INTERVAL    30000
#define MIN_CSI_INTERVAL    100

#define MIN_DIAG_INTERVAL    5000
int events_init(void);
int events_publish(wifi_monitor_data_t data);
int events_deinit(void);
void events_update_clientdiagdata(unsigned int num_devs, int vap_idx, wifi_associated_dev3_t *dev_array);


#endif
