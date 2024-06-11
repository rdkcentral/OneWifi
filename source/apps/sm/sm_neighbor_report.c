/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2023 RDK Management

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
#include "sm_report.h"
#include "sm_utils.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "dpp_neighbor.h"

static int neighbor_report_calculate_raw(sm_neighbor_cache_t *cache, survey_type_t survey_type, ds_dlist_t *result)
{
    CHECK_NULL(result);
    CHECK_NULL(cache);
    CHECK_NULL(cache->neighbors);

    sm_neighbor_t *neighbor = hash_map_get_first(cache->neighbors);
    while (neighbor != NULL) {
        sm_neighbor_scan_t *scan = sm_neighbor_get_scan_data(neighbor, survey_type);
        neighbor = hash_map_get_next(cache->neighbors, neighbor);

        if (!scan) {
            continue;
        }

        ds_dlist_t *samples = &scan->samples;
        if (!samples || ds_dlist_is_empty(samples)) {
            continue;
        }

        /* Get only the first sample */
        dpp_neighbor_record_list_t *cached_sample = ds_dlist_head(samples);
        dpp_neighbor_record_list_t *sample = dpp_neighbor_record_alloc();
        if (!sample) {
            continue;
        }

        memcpy(sample, cached_sample, sizeof(*cached_sample));
        ds_dlist_insert_tail(result, sample);
    }

    return RETURN_OK;
}


static int neighbor_report_calculate_diff(sm_neighbor_cache_t *cache, survey_type_t survey_type, ds_dlist_t *result)
{
    CHECK_NULL(result);
    CHECK_NULL(cache);
    CHECK_NULL(cache->neighbors);
#if 0
    sm_neighbor_t *neighbor = hash_map_get_first(cache->neighbors);
    while (neighbor != NULL) {
        sm_neighbor_scan_t *scan = sm_neighbor_get_scan_data(neighbor, scan_mode);
        ds_dlist_t *samples = &scan->samples;

        dpp_neighbor_record_list_t *cached_sample = NULL;
        ds_dlist_iter_t             cached_sample_iter;
        /*
         *  TODO: implement diff calculation
         *
         */
        neighbor = hash_map_get_next(cache->neighbors, neighbor);
    }
#endif
    return RETURN_OK;
}


static int neighbor_dpp_report_free(dpp_neighbor_report_data_t *report)
{
    CHECK_NULL(report);

    dpp_neighbor_record_list_t *neighbor;
    dpp_neighbor_record_list_t *tmp_neighbor;

    ds_dlist_foreach_safe(&report->list, neighbor, tmp_neighbor) {
        ds_dlist_remove(&report->list, neighbor);
        switch (report->report_type) {
            case REPORT_TYPE_RAW:
                dpp_neighbor_record_free(neighbor);
                break;
            case REPORT_TYPE_AVERAGE:
                free(neighbor);
                break;
            default:
                break;
        }
    }
    return RETURN_OK;
}

/* PUBLIC API */


int sm_neighbor_report_push_to_dpp(sm_neighbor_cache_t *cache, wifi_freq_bands_t freq_band,
                                   survey_type_t survey_type, reporting_type_t report_type)
{
    int rc = RETURN_OK;

    if (!cache) {
        wifi_util_error_print(WIFI_SM, "%s:%d: report is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    dpp_neighbor_report_data_t dpp_report = {
        .timestamp_ms = get_real_ms(),
        .radio_type = freq_band_to_dpp_radio_type(freq_band),
        .report_type = reporting_type_to_dpp_report_type(report_type),
        .scan_type = survey_type_to_dpp_scan_type(survey_type),
    };

    ds_dlist_init(&dpp_report.list, dpp_neighbor_record_list_t, node);

    switch (report_type) {
        case report_type_raw:
            rc = neighbor_report_calculate_raw(cache, survey_type, &dpp_report.list);
            break;
        case report_type_diff:
            rc = neighbor_report_calculate_diff(cache, survey_type, &dpp_report.list);
            break;
        default:
            rc = RETURN_ERR;
            wifi_util_dbg_print(WIFI_SM, "%s:%d: report type %d is not supported\n", __func__, __LINE__, report_type);
            break;
    }

    if (rc == RETURN_OK && !ds_dlist_is_empty(&dpp_report.list)) {
        dpp_put_neighbor(&dpp_report);
        wifi_util_dbg_print(WIFI_SM, "%s:%d: neighbor report %s %s is pushed to dpp for freq_band=%d, report_type=%d\n",
                            __func__, __LINE__, radio_get_name_from_type(dpp_report.radio_type), survey_type_to_str(survey_type),
                            freq_band, report_type);
    }

    sm_neighbor_cache_clean(cache, survey_type);
    neighbor_dpp_report_free(&dpp_report);
    return RETURN_OK;
}
