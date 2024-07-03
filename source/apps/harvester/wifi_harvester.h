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

#ifndef _WIFI_HARVESTER_H_
#define _WIFI_HARVESTER_H_

#include "wifi_base.h"
#include "wifi_monitor.h"

typedef struct {
    queue_t             *queue;
    pthread_cond_t      cond;
    pthread_mutex_t     queue_lock;
    pthread_mutex_t     data_lock;
    pthread_t           id;
    radio_data_t        *radio_data[MAX_NUM_RADIOS];
    int                 count;
    int                 maxCount;
    unsigned int        poll_period;
    int                 inst_msmt_id;
    int                 instantDefReportPeriod;
    int                 instantDefOverrideTTL;
    int                 instantPollPeriod;
    bool                instntMsmtenable;
    char                instantMac[MIN_MAC_ADDR_LEN];
    instant_msmt_t      inst_msmt;
} wifi_harvester_t;


#endif //_WIFI_HARVESTER_H_
