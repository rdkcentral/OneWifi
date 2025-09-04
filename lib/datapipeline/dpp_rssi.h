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

#ifndef DPP_RSSI_H_INCLUDED
#define DPP_RSSI_H_INCLUDED

#include "ds.h"
#include "ds_dlist.h"

#include "dpp_types.h"

typedef struct
{
    uint32_t                        rssi;
    uint64_t                        timestamp_ms;
    ds_dlist_node_t                 node;
} dpp_rssi_raw_t;

typedef struct
{
    mac_address_t                   mac;
    rssi_source_t                   source;
    union {
        ds_dlist_t                  raw;    /* dpp_rssi_raw_t */
        dpp_avg_t                   avg;
    } rssi;
    uint64_t                        rx_ppdus;
    uint64_t                        tx_ppdus;
    ds_dlist_node_t                 node;
} dpp_rssi_record_t;

static inline dpp_rssi_record_t * dpp_rssi_record_alloc()
{
    dpp_rssi_record_t *record = NULL;

    record = malloc(sizeof(dpp_rssi_record_t));
    if (record) {
        memset(record, 0, sizeof(dpp_rssi_record_t));
    }

    return record;
}

static inline void dpp_rssi_record_free(dpp_rssi_record_t *record)
{
    if (NULL != record) {
        free(record);
    }
}

typedef struct
{
    radio_type_t                    radio_type;
    report_type_t                   report_type;
    uint64_t                        timestamp_ms;
    ds_dlist_t                      list;   /* dpp_rssi_record_t */
} dpp_rssi_report_data_t;

#endif /* DPP_RSSI_H_INCLUDED */
