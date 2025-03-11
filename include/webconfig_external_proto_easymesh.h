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

#ifndef EXTERNAL_PROTO_EASYMESH_H
#define EXTERNAL_PROTO_EASYMESH_H
#include "em_base.h"

typedef struct {
    em_device_info_t  *em_device_cap_data;
    em_network_info_t *em_network_data;
    em_radio_list_t   *em_radio_data;
    em_ieee_1905_security_info_t * ieee_1905_security_data;
} webconfig_external_easymesh_t;

#endif //EXTERNAL_PROTO_EASYMESH_H
