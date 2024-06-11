#ifndef DPP_NEIGHBOR_H_INCLUDED
#define DPP_NEIGHBOR_H_INCLUDED

#include "ds.h"
#include "ds_dlist.h"

#include "dpp_types.h"

typedef struct
{
    radio_type_t                    type;
    radio_bssid_t                   bssid;
    uint64_t                        tsf;
    uint32_t                        chan;
    int32_t                         sig;
    int32_t                         lastseen;
    radio_essid_t                   ssid;
    radio_chanwidth_t               chanwidth;
} dpp_neighbor_record_t;

typedef struct
{
    dpp_neighbor_record_t           entry;
    ds_dlist_node_t                 node;
} dpp_neighbor_record_list_t;

typedef ds_dlist_t                  dpp_neighbor_list_t;

static inline dpp_neighbor_record_list_t * dpp_neighbor_record_alloc()
{
    dpp_neighbor_record_list_t *record = NULL;

    record = malloc(sizeof(dpp_neighbor_record_list_t));
    if (record)
    {
        memset(record, 0, sizeof(dpp_neighbor_record_list_t));
    }

    return record;
}

static inline void dpp_neighbor_record_free(dpp_neighbor_record_list_t *record)
{
    if (NULL != record)
    {
        free(record);
    }
}

typedef struct
{
    radio_type_t                    radio_type;
    report_type_t                   report_type;
    radio_scan_type_t               scan_type;
    uint64_t                        timestamp_ms;
    dpp_neighbor_list_t             list;
} dpp_neighbor_report_data_t;

#endif /* DPP_NEIGHBOR_H_INCLUDED */
