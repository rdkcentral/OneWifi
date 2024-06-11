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
#include "sm_cache.h"
#include "sm_utils.h"
#include "wifi_util.h"
#include "dpp_survey.h"

extern sm_survey_cache_t sm_survey_report_cache[MAX_NUM_RADIOS];


static void survey_samples_free(ds_dlist_t *samples)
{
    dpp_survey_record_t *sample = NULL;
    ds_dlist_iter_t      sample_iter;

    if (!samples) {
        return;
    }

    for (sample = ds_dlist_ifirst(&sample_iter, samples);
         sample != NULL;
         sample = ds_dlist_inext(&sample_iter))
    {
        ds_dlist_iremove(&sample_iter);
        dpp_survey_record_free(sample);
        sample = NULL;
    }
}


static int survey_id_get(const unsigned int radio_index, const unsigned int channel, sm_survey_id_t id)
{
    memset(id, 0, sizeof(sm_survey_id_t));
    snprintf(id, sizeof(sm_survey_id_t), "%01x_%03x", radio_index, channel);
    return RETURN_OK;
}


static void survey_clean_by_survey_type(sm_survey_cache_t *cache, sm_survey_t *survey, survey_type_t survey_type)
{
    if (!cache || !cache->surveys || !survey) {
        return;
    }

    sm_survey_scan_t *scan = NULL;
    scan = sm_survey_get_scan_data(survey, survey_type);
    if (!scan) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get scan\n", __func__, __LINE__);
        return;
    }

    scan->is_updated = false;
    survey_samples_free(&scan->samples);
}


static void survey_free(sm_survey_cache_t *cache, sm_survey_t *survey)
{
    if (!cache || !cache->surveys || !survey) {
        return;
    }

    sm_survey_id_t id = {0};
    memcpy(&id[0], survey->id, sizeof(sm_survey_id_t));

    survey_samples_free(&survey->onchan.samples);
    survey_samples_free(&survey->offchan.samples);

    free(survey->onchan.old_stats);
    survey->onchan.old_stats = NULL;

    free(survey->offchan.old_stats);
    survey->offchan.old_stats = NULL;

    survey = hash_map_remove(cache->surveys, id);
    free(survey);
}


static bool survey_ready_to_free(sm_survey_t *survey)
{
    if (!survey) {
        return false;
    }

    return (survey->onchan.old_stats == NULL && survey->offchan.old_stats == NULL);
}


static void survey_free_by_survey_type(sm_survey_cache_t *cache, sm_survey_t *survey, survey_type_t survey_type)
{
    if (!cache || !cache->surveys || !survey) {
        return;
    }

    sm_survey_scan_t *scan = NULL;
    scan = sm_survey_get_scan_data(survey, survey_type);
    if (!scan) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get scan\n", __func__, __LINE__);
        return;
    }


    wifi_util_dbg_print(WIFI_SM, "%s:%d: free survey scan %s survey_type %s\n",
                        __func__, __LINE__, survey->id, survey_type_to_str(survey_type));
    survey_samples_free(&scan->samples);
    free(scan->old_stats);
    scan->old_stats = NULL;

    if (survey_ready_to_free(survey)) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: survey '%s' is ready to be removed \n", __func__, __LINE__, survey->id);
        survey_free(cache, survey);
    }
}


static sm_survey_t* survey_alloc(sm_survey_cache_t *cache, sm_survey_id_t survey_id)
{
    if (!cache || !cache->surveys) {
        return NULL;
    }

    sm_survey_t *survey = calloc(1, sizeof(sm_survey_t));
    if (survey) {
        memcpy(survey->id, survey_id, sizeof(sm_survey_id_t));
        ds_dlist_init(&survey->onchan.samples,  dpp_survey_record_t, node);
        ds_dlist_init(&survey->offchan.samples, dpp_survey_record_t, node);
        survey->onchan.old_stats = NULL;
        survey->offchan.old_stats = NULL;
        survey->onchan.is_updated = false;
        survey->offchan.is_updated = false;
        hash_map_put(cache->surveys, strdup(survey_id), survey);
    }
    return survey;
}


static sm_survey_t* survey_get_or_alloc(sm_survey_cache_t *cache, sm_survey_id_t survey_id)
{
    if (!cache || !cache->surveys) {
        return NULL;
    }

    sm_survey_t *survey = hash_map_get(cache->surveys, survey_id);
    if (!survey) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: creating new survey %.*s\n", __func__, __LINE__,
                            sizeof(sm_survey_id_t), survey_id);
        survey = survey_alloc(cache, survey_id);
    }
    return survey;
}


static void survery_result_extra_calc(survey_type_t survey_type, dpp_survey_record_t *result)
{
    uint32_t chan_sum = result->chan_rx + result->chan_tx;

    if (chan_sum > result->chan_busy) {
        if (result->chan_tx > result->chan_busy) {
            result->chan_tx = result->chan_busy;
        }

        result->chan_rx = result->chan_busy - result->chan_tx;
    }

    if (survey_type == survey_type_on_channel && result->chan_self > result->chan_rx) {
        result->chan_self = result->chan_rx;
    }
}


#define DELTA(X) (new->X - old->X)
#define PERCENT(A, B) ((B) > 0 ? ((A) * 100 / (B)) : 0)

static int survey_convert_hal_to_sample(unsigned int radio_index, survey_type_t survey_type, radio_chan_data_t *old,
                                        radio_chan_data_t *new, dpp_survey_record_t *result)
{
    CHECK_NULL(old);
    CHECK_NULL(new);
    CHECK_NULL(result);

    wifi_util_dbg_print(WIFI_SM, "%s:%d: Fetched %s sample %s ch:%d survey: busy=%llu tx=%llu self=%llu rx=%llu ext=%llu noise=%d total=%llu\n",
                    __func__, __LINE__, radio_index_to_radio_type_str(radio_index), survey_type_to_str(survey_type),
                    new->ch_number, new->ch_utilization_busy, new->ch_utilization_busy_tx, new->ch_utilization_busy_self, new->ch_utilization_busy_rx,
                    new->ch_utilization_busy_ext, new->ch_noise, new->ch_utilization_total);

    result->info.chan = new->ch_number;
    result->info.timestamp_ms = new->LastUpdatedTime * MSEC_IN_SEC + new->LastUpdatedTimeUsec / USEC_IN_MSEC;

    if (!(result->duration_ms = DELTA(ch_utilization_total) / USEC_IN_MSEC)) {
        return RETURN_ERR;
    }

    result->chan_noise     = new->ch_noise;
    result->chan_busy      = PERCENT(DELTA(ch_utilization_busy),     DELTA(ch_utilization_total));
    result->chan_tx        = PERCENT(DELTA(ch_utilization_busy_tx),  DELTA(ch_utilization_total));
    result->chan_rx        = PERCENT(DELTA(ch_utilization_busy_rx),  DELTA(ch_utilization_total));

    if (survey_type == survey_type_on_channel) {
        result->chan_self     = PERCENT(DELTA(ch_utilization_busy_self), DELTA(ch_utilization_total));
        result->chan_busy_ext = PERCENT(DELTA(ch_utilization_busy_ext),  DELTA(ch_utilization_total));
    }

    survery_result_extra_calc(survey_type, result);

    wifi_util_dbg_print(WIFI_SM, "%s:%d: Calculated %s sample %s survey percent: busy=%u tx=%u self=%u rx=%u ext=%u noise=%d duration=%u\n",
                    __func__, __LINE__, radio_index_to_radio_type_str(radio_index), survey_type_to_str(survey_type),
                    result->chan_busy, result->chan_tx, result->chan_self, result->chan_rx, result->chan_busy_ext, result->chan_noise, result->duration_ms);

    return RETURN_OK;
}

#undef PERCENT
#undef DELTA

static int survey_sample_add(sm_survey_cache_t *cache, survey_type_t survey_type,
                             unsigned int radio_index, radio_chan_data_t *stats)
{
    CHECK_NULL(cache);
    CHECK_NULL(stats);

    int rc = RETURN_OK;
    dpp_survey_record_t *sample = NULL;
    sm_survey_t *survey = NULL;
    sm_survey_id_t survey_id = {0};
    sm_survey_scan_t *scan = NULL;

    unsigned int channel = stats->ch_number;

    if (RETURN_OK != survey_id_get(radio_index, channel, survey_id)) {
        wifi_util_error_print(WIFI_SM, "%s:%d: cannot get survey_id \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    survey = survey_get_or_alloc(cache, survey_id);
    if (!survey) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get survey for %.*s\n", __func__, __LINE__, sizeof(sm_survey_id_t), survey_id);
        return RETURN_ERR;
    }

    scan = sm_survey_get_scan_data(survey, survey_type);
    if (!scan) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get scan\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (scan->old_stats == NULL) {
    /*
     * old_stats will be freed only after the configuration removal.
     * This will prevent removing the stats for some channels
     * when reporting interval is not long enough to scan all the required channels in one go
    */
        scan->old_stats = malloc(sizeof(*stats)); /* allocate once for the report */
    } else {
        sample = dpp_survey_record_alloc();
        if (!sample) {
            wifi_util_error_print(WIFI_SM, "%s:%d: failed to alloc new record for cache\n", __func__, __LINE__);
            rc = RETURN_ERR;
            goto exit;
        }

        rc = survey_convert_hal_to_sample(radio_index, survey_type, scan->old_stats, stats, sample);
        if (rc == RETURN_OK) {
            ds_dlist_insert_tail(&scan->samples, sample);
        } else {
            wifi_util_dbg_print(WIFI_SM, "%s:%d: warning, convert hal to sample returned error\n", __func__, __LINE__);
            dpp_survey_record_free(sample);
        }
    }

exit:
    /* save the old value to cache */
    memcpy(scan->old_stats, stats, sizeof(*stats));
    scan->is_updated = true;
    return rc;
}


/* PUBLIC API */


int sm_survey_sample_store(unsigned int radio_index, survey_type_t survey_type, radio_chan_data_t *stats)
{
    CHECK_NULL(stats);
    int rc;

    rc = survey_sample_add(&sm_survey_report_cache[radio_index], survey_type, radio_index, stats);
    if (rc == RETURN_OK) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d added sample %s for channel=%u\n",
                        __func__, __LINE__, survey_type_to_str(survey_type), stats->ch_number);
    }

    return rc;
}

#define CALC_AVERAGE(X) do {                        \
        result->X.avg += tmp->X / len;              \
        result->X.min = MIN(result->X.min, tmp->X); \
        result->X.max = MAX(result->X.max, tmp->X); \
        result->X.num = len;                        \
    } while (0);

int sm_survey_samples_calc_average(ds_dlist_t *samples, dpp_survey_record_avg_t *result)
{
    CHECK_NULL(samples);
    CHECK_NULL(result);

    size_t len = get_ds_dlist_len(samples);
    dpp_survey_record_t *tmp = NULL;
    dpp_survey_record_t *last = ds_dlist_tail(samples);

    CHECK_NULL(last);
    memcpy(&result->info, &last->info, sizeof(result->info));

    if (len <= 0) {
        wifi_util_error_print(WIFI_SM, "%s:%d empty samples list\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /* Average */
    ds_dlist_foreach(samples, tmp) {
        CALC_AVERAGE(chan_busy);
        CALC_AVERAGE(chan_busy_ext);
        CALC_AVERAGE(chan_self);
        CALC_AVERAGE(chan_rx);
        CALC_AVERAGE(chan_tx);
        CALC_AVERAGE(chan_noise);
    }

    return RETURN_OK;
}

#undef CALC_AVERAGE

void sm_survey_cache_clean(sm_survey_cache_t *cache, survey_type_t survey_type)
{
    sm_survey_t *tmp_survey = NULL;
    sm_survey_t *survey = NULL;

    if (!cache || !cache->surveys) {
        return;
    }

    survey = hash_map_get_first(cache->surveys);
    while (survey) {
        tmp_survey = survey;
        survey = hash_map_get_next(cache->surveys, survey);
        survey_clean_by_survey_type(cache, tmp_survey, survey_type);
    }
}


void sm_survey_cache_free_after_reconf(unsigned int radio_index, survey_type_t survey_type)
{
    sm_survey_t *tmp_survey = NULL;
    sm_survey_t *survey = NULL;
    sm_survey_cache_t *cache = &sm_survey_report_cache[radio_index];

    if (!cache->surveys) {
        return;
    }

    wifi_util_dbg_print(WIFI_SM, "%s:%d: free survey cache after reconf for radio %u, survey_type %s\n",
                        __func__, __LINE__, radio_index, survey_type_to_str(survey_type));
    survey = hash_map_get_first(cache->surveys);
    while (survey) {
        tmp_survey = survey;
        survey = hash_map_get_next(cache->surveys, survey);
        survey_free_by_survey_type(cache, tmp_survey, survey_type);
    }
}


void sm_survey_cache_free(sm_survey_cache_t *cache)
{
    sm_survey_t *tmp_survey = NULL;
    sm_survey_t *survey = NULL;

    if (!cache || !cache->surveys) {
        return;
    }

    survey = hash_map_get_first(cache->surveys);
    while (survey) {
        tmp_survey = survey;
        survey = hash_map_get_next(cache->surveys, survey);
        survey_free(cache, tmp_survey);
    }
}


void sm_survey_cache_init(sm_survey_cache_t *cache)
{
    if (!cache) {
        return;
    }
    cache->surveys = hash_map_create();
}


void sm_survey_cache_deinit(sm_survey_cache_t *cache)
{
    if (!cache) {
        return;
    }
    sm_survey_cache_free(cache);
    hash_map_destroy(cache->surveys);
}


sm_survey_scan_t* sm_survey_get_scan_data(sm_survey_t *survey, survey_type_t survey_type)
{
    if (survey_type == survey_type_on_channel) {
        return &survey->onchan;
    }
    return &survey->offchan;
}
