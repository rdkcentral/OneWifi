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
