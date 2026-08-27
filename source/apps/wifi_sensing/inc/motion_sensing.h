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

#ifndef MOTION_SENSING_H
#define MOTION_SENSING_H

#include <stdbool.h>
#include "wifi_base.h"
#include "wifi_events.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wifi_app wifi_app_t;

typedef struct sensing_app_obj {
    bool sensing_enabled;
} sensing_app_obj_t;


int sensing_app_init(wifi_app_t *app, unsigned int create_flag);
int sensing_app_deinit(wifi_app_t *app);
int sensing_app_event(wifi_app_t *app, wifi_event_t *event);

#ifdef __cplusplus
}
#endif

#endif//MOTION_SENSING_H
