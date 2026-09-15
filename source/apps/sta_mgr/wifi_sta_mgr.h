/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
<<<<<<<< HEAD:source/platform/dbus/misc.h

  Copyright 2024 RDK Management

========
  
  Copyright 2025 RDK Management
  
>>>>>>>> origin/develop:source/apps/sta_mgr/wifi_sta_mgr.h
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

<<<<<<<< HEAD:source/platform/dbus/misc.h
#ifndef _MISC_H_
#define _MISC_H_

#include "misc_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

void wifi_misc_init();

typedef struct {
    wifi_misc_desc_t                desc;
} wifi_misc_t;

wifi_misc_desc_t *get_misc_descriptor();
wifi_misc_t *get_misc_obj();

#ifdef __cplusplus
}
#endif

#endif //_MISC_H
========
#ifndef WIFI_STA_MGR_H
#define WIFI_STA_MGR_H

typedef struct {
    void *data;
} sta_mgr_data_t;

#endif
>>>>>>>> origin/develop:source/apps/sta_mgr/wifi_sta_mgr.h
