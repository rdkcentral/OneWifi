#ifndef DPP_SURVEY_H_INCLUDED
#define DPP_SURVEY_H_INCLUDED

#include "ds.h"
#include "ds_dlist.h"

#include "dpp_types.h"

typedef struct
{
    uint32_t                        chan;
    uint64_t                        timestamp_ms;
} dpp_survey_info_t;

#define DPP_TARGET_SURVEY_RECORD_COMMON_STRUCT \
    struct { \
        ds_dlist_node_t node; \
        dpp_survey_info_t info; \
    }

typedef struct
{
    dpp_survey_info_t               info;
    dpp_avg_t                       chan_busy;
    dpp_avg_t                       chan_busy_ext;
    dpp_avg_t                       chan_self;
    dpp_avg_t                       chan_rx;
    dpp_avg_t                       chan_tx;
    dpp_avg_signed_t                chan_noise; /* dBm */
    ds_dlist_node_t                 node;
} dpp_survey_record_avg_t;

typedef struct
{
    /* General survey data (All targets must provide same) */
    dpp_survey_info_t               info;

    /* Statistics survey data */
    uint32_t                        chan_active;
    uint32_t                        chan_busy;
    uint32_t                        chan_busy_ext;
    uint32_t                        chan_self;
    uint32_t                        chan_rx;
    uint32_t                        chan_tx;
    int32_t                         chan_noise; /* dBm */
    uint32_t                        duration_ms;

    /* Linked list survey data */
    ds_dlist_node_t                 node;
} dpp_survey_record_t;

static inline dpp_survey_record_t * dpp_survey_record_alloc()
{
    dpp_survey_record_t *record = NULL;

    record = malloc(sizeof(dpp_survey_record_t));
    if (record) {
        memset(record, 0, sizeof(dpp_survey_record_t));
    }

    return record;
}

static inline void dpp_survey_record_free(dpp_survey_record_t *record)
{
    if (NULL != record) {
        free(record);
    }
}

typedef struct
{
    radio_type_t                    radio_type;
    report_type_t                   report_type;
    radio_scan_type_t               scan_type;
    uint64_t                        timestamp_ms;
    ds_dlist_t                      list;       /* dpp_survey_record_t or dpp_survey_record_avg_t depending on report_type */
} dpp_survey_report_data_t;

#endif /* DPP_SURVEY_H_INCLUDED */
