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
#include "dpp_survey.h"

static int survey_report_calculate_raw(sm_survey_cache_t *cache, survey_type_t survey_type, ds_dlist_t *result)
{
    CHECK_NULL(result);
    CHECK_NULL(cache);
    CHECK_NULL(cache->surveys);

    sm_survey_t *survey = hash_map_get_first(cache->surveys);
    while (survey != NULL) {
        sm_survey_scan_t *scan = sm_survey_get_scan_data(survey, survey_type);
        ds_dlist_t *samples = &scan->samples;

        dpp_survey_record_t *cached_sample = NULL;
        ds_dlist_iter_t      cached_sample_iter;

        for (cached_sample = ds_dlist_ifirst(&cached_sample_iter, samples);
             cached_sample != NULL;
             cached_sample = ds_dlist_inext(&cached_sample_iter))
        {
            dpp_survey_record_t *sample = dpp_survey_record_alloc();

            CHECK_NULL(sample);

            memcpy(sample, cached_sample, sizeof(*cached_sample));
            ds_dlist_insert_tail(result, sample);
        }
        survey = hash_map_get_next(cache->surveys, survey);
    }

    return RETURN_OK;
}


static int survey_report_calculate_average(sm_survey_cache_t *cache, survey_type_t survey_type, ds_dlist_t *result)
{
    CHECK_NULL(result);
    CHECK_NULL(cache);
    CHECK_NULL(cache->surveys);

    sm_survey_t *survey = hash_map_get_first(cache->surveys);
    while (survey != NULL) {
        sm_survey_scan_t *scan = sm_survey_get_scan_data(survey, survey_type);
        ds_dlist_t *samples = &scan->samples;

        dpp_survey_record_avg_t *sample = calloc(1, sizeof(dpp_survey_record_avg_t));
        if (sample && sm_survey_samples_calc_average(samples, sample)) {
            ds_dlist_insert_tail(result, sample);
        } else {
            free(sample);
        }

        survey = hash_map_get_next(cache->surveys, survey);
    }

    return RETURN_OK;
}


static int survey_dpp_report_free(dpp_survey_report_data_t *report)
{
    CHECK_NULL(report);

    dpp_survey_record_t *survey;
    dpp_survey_record_t *tmp_survey;

    ds_dlist_foreach_safe(&report->list, survey, tmp_survey) {
        ds_dlist_remove(&report->list, survey);
        switch (report->report_type) {
            case REPORT_TYPE_RAW:
                dpp_survey_record_free(survey);
                break;
            case REPORT_TYPE_AVERAGE:
                free(survey);
                break;
            default:
                break;
        }
    }
    return RETURN_OK;
}

/* PUBLIC API */


int sm_survey_report_push_to_dpp(sm_survey_cache_t *cache, wifi_freq_bands_t freq_band,
                                 survey_type_t survey_type, reporting_type_t report_type,
                                 unsigned int *report_counter)
{
    int rc = RETURN_OK;

    if (!cache) {
        wifi_util_error_print(WIFI_SM, "%s:%d: report is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    dpp_survey_report_data_t dpp_report = {
        .timestamp_ms = get_real_ms(),
        .radio_type = freq_band_to_dpp_radio_type(freq_band),
        .report_type = reporting_type_to_dpp_report_type(report_type),
        .scan_type = survey_type_to_dpp_scan_type(survey_type),
    };
    ds_dlist_init(&dpp_report.list, dpp_survey_record_t, node);

    switch (report_type) {
        case report_type_raw:
            rc = survey_report_calculate_raw(cache, survey_type, &dpp_report.list);
            break;
        case report_type_average:
            rc = survey_report_calculate_average(cache, survey_type, &dpp_report.list);
            break;
        default:
            rc = RETURN_ERR;
            wifi_util_dbg_print(WIFI_SM, "%s:%d: report type %d is not supported\n", __func__, __LINE__, report_type);
            break;
    }

    if (rc == RETURN_OK && !ds_dlist_is_empty(&dpp_report.list)) {
        dpp_put_survey(&dpp_report);
        (*report_counter)++;
        wifi_util_dbg_print(WIFI_SM, "%s:%d: survey report is pushed to dpp for %s %s freq_band=%d, report_type=%d\n",
                            __func__, __LINE__, radio_get_name_from_type(dpp_report.radio_type), survey_type_to_str(survey_type), freq_band, report_type);
    }
    else {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: nothing to send to dpp for %s %s freq_band=%d, report_type=%d\n",
                            __func__, __LINE__, radio_get_name_from_type(dpp_report.radio_type), survey_type_to_str(survey_type), freq_band, report_type);
    }

    sm_survey_cache_clean(cache, survey_type);
    survey_dpp_report_free(&dpp_report);

    return RETURN_OK;
}


int survey_report_counter_publish_cb(void *args)
{
    wifi_app_t *app = (wifi_app_t *)args;

    for (unsigned int i = 0; i < getNumberRadios(); i++) {
        wifi_util_info_print(WIFI_SM, "%s:%d: INFO_SURVEY_%s_OFF_CHAN_%u\n", __func__, __LINE__, radio_index_to_radio_type_str(i), app->data.u.sm_data.off_chan_report_counter[i]);
        wifi_util_info_print(WIFI_SM, "%s:%d: INFO_SURVEY_%s_ON_CHAN_%u\n", __func__, __LINE__, radio_index_to_radio_type_str(i), app->data.u.sm_data.on_chan_report_counter[i]);
        app->data.u.sm_data.off_chan_report_counter[i] = 0;
        app->data.u.sm_data.on_chan_report_counter[i] = 0;
    }

    return RETURN_OK;
}

