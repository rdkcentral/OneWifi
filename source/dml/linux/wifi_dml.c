/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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

#include "wifi_dml.h"

void start_dml()
{

}

void set_dml_init_status(bool status)
{

}

void ssp_init()
{

}

int push_data_to_ssp_queue(const void *msg, unsigned int len, uint32_t type, uint32_t sub_type)
{
    return 0;
}

void wifi_dml_init(wifi_dml_t *dml)
{
    dml->desc.start_dml_fn = start_dml;
    dml->desc.set_dml_init_status_fn = set_dml_init_status;
    dml->desc.ssp_init_fn = ssp_init;
    dml->desc.push_data_to_ssp_queue_fn = push_data_to_ssp_queue;
}

