/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2025 RDK Management
  
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

#ifndef DPP_CAPACITY_H_INCLUDED
#define DPP_CAPACITY_H_INCLUDED

#include "ds.h"
#include "ds_dlist.h"

#include "dpp_types.h"

typedef struct
{
    uint64_t                        bytes_tx;
    uint32_t                        busy_tx;
    uint32_t                        samples;
    uint32_t                        queue[RADIO_QUEUE_MAX_QTY];
    uint64_t                        timestamp_ms;
} dpp_capacity_record_t;

typedef struct
{
    dpp_capacity_record_t           entry;
    ds_dlist_node_t                 node;
} dpp_capacity_record_list_t;

typedef ds_dlist_t                  dpp_capacity_list_t;

static inline dpp_capacity_record_list_t * dpp_capacity_record_alloc()
{
    dpp_capacity_record_list_t *record = NULL;

    record = malloc(sizeof(dpp_capacity_record_list_t));
    if (record)
    {
        memset(record, 0, sizeof(dpp_capacity_record_list_t));
    }

    return record;
}

static inline void dpp_capacity_record_free(dpp_capacity_record_list_t *record)
{
    if (NULL != record)
    {
        free(record);
    }
}

typedef struct
{
    radio_type_t                    radio_type;
    uint64_t                        timestamp_ms;
    dpp_capacity_list_t             list;
} dpp_capacity_report_data_t;

#endif /* DPP_CAPACITY_H_INCLUDED */
