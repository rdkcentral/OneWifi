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
#include "dpp_neighbor.h"

extern sm_neighbor_cache_t sm_neighbor_report_cache[MAX_NUM_RADIOS];


static void neighbor_samples_free(ds_dlist_t *samples)
{
    dpp_neighbor_record_list_t *sample = NULL;
    ds_dlist_iter_t             sample_iter;

    if (!samples) {
        return;
    }

    for (sample = ds_dlist_ifirst(&sample_iter, samples);
         sample != NULL;
         sample = ds_dlist_inext(&sample_iter))
    {
        ds_dlist_iremove(&sample_iter);
        dpp_neighbor_record_free(sample);
        sample = NULL;
    }
}


static int neighbor_id_get(const unsigned int radio_index, radio_bssid_t bssid, sm_neighbor_id_t id)
{
    memset(id, 0, sizeof(sm_neighbor_id_t));
    snprintf(id, sizeof(sm_neighbor_id_t), "%02x%02x%02x%02x%02x%02x_%01x",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], radio_index);
    return RETURN_OK;
}


static void neighbor_clean(sm_neighbor_cache_t *cache, sm_neighbor_t *neighbor, survey_type_t survey_type)
{
    if (!cache || !cache->neighbors || !neighbor) {
        return;
    }

    sm_neighbor_scan_t *scan = NULL;
    scan = sm_neighbor_get_scan_data(neighbor, survey_type);
    if (!scan) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get scan\n", __func__, __LINE__);
        return;
    }
    neighbor_samples_free(&scan->samples);
    free(scan->old_stats);
    scan->old_stats = NULL; /* to start calculations from the new sample */
}


static void neighbor_free(sm_neighbor_cache_t *cache, sm_neighbor_t *neighbor)
{
    if (!cache || !cache->neighbors || !neighbor) {
        return;
    }

    sm_neighbor_id_t id = {0};
    memcpy(&id[0], neighbor->id, sizeof(sm_neighbor_id_t));

    neighbor_samples_free(&neighbor->onchan.samples);
    neighbor_samples_free(&neighbor->offchan.samples);
    free(neighbor->onchan.old_stats);
    free(neighbor->offchan.old_stats);
    neighbor = hash_map_remove(cache->neighbors, id);
    free(neighbor);
}


static sm_neighbor_t* neighbor_alloc(sm_neighbor_cache_t *cache, sm_neighbor_id_t neighbor_id)
{
    if (!cache || !cache->neighbors) {
        return NULL;
    }

    sm_neighbor_t *neighbor = calloc(1, sizeof(sm_neighbor_t));
    if (neighbor) {
        memcpy(neighbor->id, neighbor_id, sizeof(sm_neighbor_id_t));
        ds_dlist_init(&neighbor->onchan.samples,  dpp_neighbor_record_list_t, node);
        ds_dlist_init(&neighbor->offchan.samples, dpp_neighbor_record_list_t, node);
        hash_map_put(cache->neighbors, strdup(neighbor_id), neighbor);
    }
    return neighbor;
}


static sm_neighbor_t* neighbor_get_or_alloc(sm_neighbor_cache_t *cache, sm_neighbor_id_t neighbor_id)
{
    if (!cache || !cache->neighbors) {
        return NULL;
    }

    sm_neighbor_t *neighbor = hash_map_get(cache->neighbors, neighbor_id);
    if (!neighbor) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: creating new neighbor %.*s\n", __func__, __LINE__,
                            sizeof(sm_neighbor_id_t), neighbor_id);
        neighbor = neighbor_alloc(cache, neighbor_id);
    }
    return neighbor;
}


static int neighbor_convert_hal_to_sample(unsigned int radio_index, wifi_neighbor_ap2_t *hal, dpp_neighbor_record_list_t *result)
{
    CHECK_NULL(hal);
    CHECK_NULL(result);

    dpp_neighbor_record_t *entry = &result->entry;

    entry->type = radio_index_to_dpp_radio_type(radio_index);
    strncpy(entry->bssid, hal->ap_BSSID, sizeof(entry->bssid) - 1); /* string in MAC format */
    strncpy(entry->ssid, hal->ap_SSID, sizeof(entry->ssid));
    entry->chan = hal->ap_Channel;
    entry->sig = rssi_to_above_noise_floor(hal->ap_SignalStrength);
    entry->lastseen = time(NULL); /* TODO: get the time of the scan ? */
    entry->chanwidth = str_to_dpp_chan_width(hal->ap_OperatingChannelBandwidth);

    wifi_util_dbg_print(WIFI_SM, "%s:%d: Fetched neighbor sample on %s channel %u SSID %s\n", __func__, __LINE__, radio_index_to_radio_type_str(radio_index), hal->ap_Channel, hal->ap_SSID);

    return RETURN_OK;
}


static int neighbor_sample_add(sm_neighbor_cache_t *cache, survey_type_t survey_type,
                             unsigned int radio_index, wifi_neighbor_ap2_t *stats)
{
    CHECK_NULL(cache);
    CHECK_NULL(stats);

    int rc = RETURN_ERR;
    dpp_neighbor_record_list_t *sample = NULL;
    sm_neighbor_t *neighbor = NULL;
    sm_neighbor_id_t neighbor_id = {0};
    sm_neighbor_scan_t *scan = NULL;

    if (RETURN_OK != neighbor_id_get(radio_index, stats->ap_BSSID, neighbor_id)) {
        wifi_util_error_print(WIFI_SM, "%s:%d: cannot get neighbor_id \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    sample = dpp_neighbor_record_alloc();
    if (!sample) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to alloc new record for cache\n", __func__, __LINE__);
        goto exit_err;
    }

    neighbor = neighbor_get_or_alloc(cache, neighbor_id);
    if (!neighbor) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get neighbor for %.*s\n", __func__, __LINE__, sizeof(sm_neighbor_id_t), neighbor_id);
        goto exit_err;
    }

    scan = sm_neighbor_get_scan_data(neighbor, survey_type);
    if (!scan) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get scan\n", __func__, __LINE__);
        goto exit_err;
    }

    rc = neighbor_convert_hal_to_sample(radio_index, stats, sample);
    if (rc != RETURN_OK) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to convert hal to sample\n", __func__, __LINE__);
        goto exit_err;
    }

    ds_dlist_insert_tail(&scan->samples, sample);

    return RETURN_OK;
exit_err:
    dpp_neighbor_record_free(sample);
    return RETURN_ERR;
}

/* PUBLIC API */


#if 0
int sm_neighbor_samples_calc_diff(ds_dlist_t *samples, dpp_neighbor_record_t *result)
{
    /* TODO: implement*/
    return RETURN_OK;
}
#endif

int sm_neighbor_sample_store(unsigned int radio_index, survey_type_t survey_type, wifi_neighbor_ap2_t *stats)
{
    CHECK_NULL(stats);
    int rc;

    rc = neighbor_sample_add(&sm_neighbor_report_cache[radio_index], survey_type, radio_index, stats);
    if (rc != RETURN_OK) {
        wifi_util_error_print(WIFI_SM, "%s:%d failed to add sample %s for SSID=%s\n",
                              __func__, __LINE__, survey_type_to_str(survey_type), stats->ap_SSID);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_SM, "%s:%d added sample %s for SSID=%s\n",
                        __func__, __LINE__, survey_type_to_str(survey_type), stats->ap_SSID);

    return RETURN_OK;
}


void sm_neighbor_cache_clean(sm_neighbor_cache_t *cache, survey_type_t survey_type)
{
    sm_neighbor_t *tmp_neighbor = NULL;
    sm_neighbor_t *neighbor = NULL;

    if (!cache || !cache->neighbors) {
        return;
    }

    neighbor = hash_map_get_first(cache->neighbors);
    while (neighbor) {
        tmp_neighbor = neighbor;
        neighbor = hash_map_get_next(cache->neighbors, neighbor);
        neighbor_clean(cache, tmp_neighbor, survey_type);
    }
}


void sm_neighbor_cache_free(sm_neighbor_cache_t *cache)
{
    sm_neighbor_t *tmp_neighbor = NULL;
    sm_neighbor_t *neighbor = NULL;

    if (!cache || !cache->neighbors) {
        return;
    }

    neighbor = hash_map_get_first(cache->neighbors);
    while (neighbor) {
        tmp_neighbor = neighbor;
        neighbor = hash_map_get_next(cache->neighbors, neighbor);
        neighbor_free(cache, tmp_neighbor);
    }
}


void sm_neighbor_cache_init(sm_neighbor_cache_t *cache)
{
    if (!cache) {
        return;
    }
    cache->neighbors = hash_map_create();
}


void sm_neighbor_cache_deinit(sm_neighbor_cache_t *cache)
{
    if (!cache) {
        return;
    }
    sm_neighbor_cache_free(cache);
    hash_map_destroy(cache->neighbors);
}


sm_neighbor_scan_t* sm_neighbor_get_scan_data(sm_neighbor_t *neighbor, survey_type_t survey_type)
{
    if (survey_type == survey_type_on_channel) {
        return &neighbor->onchan;
    }
    return &neighbor->offchan;
}
