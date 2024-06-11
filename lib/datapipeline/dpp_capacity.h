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
