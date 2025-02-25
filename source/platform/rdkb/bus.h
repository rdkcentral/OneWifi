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

#ifndef BUS_H
#define BUS_H

#include "bus_common.h"
#include <rbus/rbus.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bus_handle {
    union {
        rbusHandle_t rbus_handle;
    } u;
} bus_handle_t;

typedef struct rbus_sub_callback_table {
    rbusEventHandler_t                sub_handler;
    rbusSubscribeAsyncRespHandler_t   sub_ex_async_handler;
} rbus_sub_callback_table_t;

typedef struct {
    wifi_bus_desc_t        desc;
    bus_cb_multiplexing_t  bus_cb_mux;
} wifi_bus_t;

wifi_bus_desc_t *get_bus_descriptor();
wifi_bus_t *get_bus_obj(void);
bus_error_t bus_init(bus_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif // BUS_H
