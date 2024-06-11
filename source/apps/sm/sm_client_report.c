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
#include "dpp_client.h"

static int client_report_calculate(sm_client_cache_t *cache, ds_dlist_t *result)
{
    CHECK_NULL(result);
    CHECK_NULL(cache);
    CHECK_NULL(cache->clients);

    sm_client_t *client = hash_map_get_first(cache->clients);

    while (client != NULL) {
        if (client->is_updated) {
            /* Do not send the report if client was not updated */
            dpp_client_record_t *sample = dpp_client_record_alloc();
            if (sample && (sm_client_samples_calc_total(&client->samples, sample) == RETURN_OK)) {
                ds_dlist_insert_tail(result, sample);
            } else {
                dpp_client_record_free(sample);
            }
        }
        client = hash_map_get_next(cache->clients, client);
    }

    return RETURN_OK;
}


static int client_dpp_report_free(dpp_client_report_data_t *report)
{
    CHECK_NULL(report);

    dpp_client_record_t *client;
    dpp_client_record_t *tmp_client;

    ds_dlist_foreach_safe(&report->list, client, tmp_client) {
        ds_dlist_remove(&report->list, client);
        dpp_client_record_free(client);
    }
    return RETURN_OK;
}

/* PUBLIC API */


int sm_client_report_push_to_dpp(sm_client_cache_t *cache, wifi_freq_bands_t freq_band, unsigned int channel)
{
    CHECK_NULL(cache);
    int rc = RETURN_OK;

    dpp_client_report_data_t dpp_report = {
        .timestamp_ms = get_real_ms(),
        .radio_type = freq_band_to_dpp_radio_type(freq_band),
        .channel = channel, /* operating channel, getting from hal */
    };

    ds_dlist_init(&dpp_report.list, dpp_client_record_t, node);

    rc = client_report_calculate(cache, &dpp_report.list);
    if (rc == RETURN_OK && !ds_dlist_is_empty(&dpp_report.list)) {
        dpp_put_client(&dpp_report);
        wifi_util_dbg_print(WIFI_SM, "%s:%d: client report is pushed to dpp for freq_band=%d, channel=%u timestamp_ms=%llu\n",
                              __func__, __LINE__, freq_band, channel, dpp_report.timestamp_ms);
    }

    sm_client_cache_free(cache);
    client_dpp_report_free(&dpp_report);

    return RETURN_OK;
}
