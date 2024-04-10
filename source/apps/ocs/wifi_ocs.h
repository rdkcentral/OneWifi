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

#ifndef _WIFI_OCS_H_
#define _WIFI_OCS_H_

#include "wifi_base.h"

#define MAX_5G_CHANNELS 25

typedef struct {
    //Off channel params
    ULONG            TscanMsec;
    ULONG            NscanSec;
    ULONG            TidleSec;
    int              curr_off_channel_scan_period; //holds old value of Nscan
    unsigned int     radio_index;
    bool             is_scan_running;
    UINT             curr_prim_channel;
    UINT             chan_list[MAX_5G_CHANNELS];
    int              ocs_scheduler_id;
    bool             off_scan_rfc;
    pthread_mutex_t  lock;
} off_channel_param_t;

off_channel_param_t *get_wifi_ocs(unsigned int R_Index);
int ocs_init(wifi_app_t *app, unsigned int create_flag);
int ocs_deinit(wifi_app_t *app);
int ocs_event(wifi_app_t *app, wifi_event_t *event);

#endif //_WIFI_ocs_H_