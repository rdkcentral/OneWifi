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
#include "wifi_mgr.h"
#include "wifi_util.h"
#include <const.h>
#include <math.h>
#include <stdio.h>

extern sm_client_cache_t sm_client_report_cache[MAX_NUM_RADIOS];

#define DURATION_MS_NO_DISCONNECTS (0)
#define TS_DEFAULT (0)

typedef enum {
    FREE_SAMPLE_ALL,
    FREE_SAMPLE_ALL_EXCEPT_LAST
} free_samples_type;


static bool is_client_alive(sm_client_t *client)
{
    if (!client) {
        return false;
    }

    if (!client->is_updated) {
        return false;
    }

    dpp_client_record_t *last_sample = ds_dlist_tail(&client->samples);
    return (last_sample && last_sample->is_connected);
}


static int client_id_get(const mac_address_t mac, const unsigned int vap_index, sm_client_id_t id)
{
    memset(id, 0, sizeof(sm_client_id_t));
    snprintf(id, sizeof(sm_client_id_t), "%02x%02x%02x%02x%02x%02x_%08x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vap_index);
    return RETURN_OK;
}


static inline sm_client_t* client_alloc(sm_client_cache_t *cache, sm_client_id_t client_id)
{
    if (!cache || !cache->clients) {
        return NULL;
    }

    sm_client_t *client = calloc(1, sizeof(sm_client_t));
    if (client) {
        memcpy(client->id, client_id, sizeof(sm_client_id_t));
        ds_dlist_init(&client->samples, dpp_client_record_t, node);
        hash_map_put(cache->clients, strdup(client_id), client);
    }
    return client;
}


static inline sm_client_t* client_get_or_alloc(sm_client_cache_t *cache, sm_client_id_t client_id)
{
    if (!cache || !cache->clients) {
        return NULL;
    }

    sm_client_t *client = hash_map_get(cache->clients, client_id);
    if (!client) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: creating new client %.*s\n", __func__, __LINE__,
                            sizeof(sm_client_id_t), client_id);
        client = client_alloc(cache, client_id);
    }
    return client;
}


static void client_samples_free(ds_dlist_t *samples, free_samples_type type)
{
    dpp_client_record_t *sample = NULL;
    ds_dlist_iter_t      sample_iter;

    if (!samples || ds_dlist_is_empty(samples)) {
        return;
    }

    for (sample = ds_dlist_ifirst(&sample_iter, samples);
         sample != NULL;
         sample = ds_dlist_inext(&sample_iter))
    {
        if (type == FREE_SAMPLE_ALL_EXCEPT_LAST
            && ds_dlist_tail(samples) == ds_dlist_head(samples)) {
            break;
        }
        ds_dlist_iremove(&sample_iter);
        dpp_client_record_free(sample);
        sample = NULL;
    }
}


static int client_hal_to_sample(unsigned int radio_index, ssid_t ssid, if_name_t ifname,
                                wifi_associated_dev3_t *dev3, sm_client_conn_t *conn_info,
                                dpp_client_record_t *result)
{
    CHECK_NULL(result);
    CHECK_NULL(dev3);
    CHECK_NULL(conn_info);

    result->info.type = radio_index_to_dpp_radio_type(radio_index);

    memcpy(result->info.mac, dev3->cli_MACAddress, sizeof(result->info.mac));
    strncpy(result->info.essid, ssid, sizeof(result->info.essid) - 1);
    strncpy(result->info.ifname, ifname, sizeof(result->info.ifname) - 1);

    result->stats.bytes_tx   = (uint64_t)dev3->cli_BytesSent;
    result->stats.frames_tx  = (uint64_t)dev3->cli_TxFrames;
    result->stats.retries_tx = (uint64_t)dev3->cli_RetransCount;
    result->stats.errors_tx  = (uint64_t)dev3->cli_ErrorsSent;

    result->stats.bytes_rx   = (uint64_t)dev3->cli_BytesReceived;
    result->stats.frames_rx  = (uint64_t)dev3->cli_PacketsReceived;
    result->stats.retries_rx = (uint64_t)dev3->cli_RxRetries;
    result->stats.errors_rx  = (uint64_t)dev3->cli_RxErrors;

    result->stats.rate_tx    = (double)dev3->cli_LastDataDownlinkRate;
    result->stats.rate_rx    = (double)dev3->cli_LastDataUplinkRate;

    result->stats.rssi = dev3->cli_SNR;

    result->is_connected   = dev3->cli_Active;
    result->connected      = dev3->cli_Associations;
    result->disconnected   = dev3->cli_Disassociations;
    result->connect_ts     = conn_info->connect_ts;
    result->disconnect_ts  = conn_info->disconnect_ts;
    result->duration_ms    = conn_info->duration_ms;

    mac_addr_str_t mac_str = {0};
    to_mac_str(dev3->cli_MACAddress, mac_str);
    wifi_util_dbg_print(WIFI_SM, "%s:%d: Fetched client %s sample on %s ifname %s SSID %s\n", __func__, __LINE__, mac_str, radio_index_to_radio_type_str(radio_index), ifname, ssid);

    return RETURN_OK;
}


static int client_sample_add(sm_client_cache_t *cache,
                             unsigned int radio_index, unsigned int vap_index, ssid_t ssid, if_name_t ifname,
                             wifi_associated_dev3_t *dev3, sm_client_conn_t *conn_info)
{
    CHECK_NULL(cache);
    CHECK_NULL(dev3);
    CHECK_NULL(conn_info);

    int rc = RETURN_ERR;
    dpp_client_record_t *sample = NULL;
    sm_client_t *client = NULL;
    sm_client_id_t client_id = {0};

    if (RETURN_OK != client_id_get(dev3->cli_MACAddress, vap_index, client_id)) {
        wifi_util_error_print(WIFI_SM, "%s:%d: cannot get client_id \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    sample = dpp_client_record_alloc();
    if (!sample) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to alloc new record for cache\n", __func__, __LINE__);
        goto exit_err;
    }

    rc = client_hal_to_sample(radio_index, ssid, ifname, dev3, conn_info, sample);
    if (rc != RETURN_OK) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to convert hal to sample\n", __func__, __LINE__);
        goto exit_err;
    }

    client = client_get_or_alloc(cache, client_id);
    if (!client) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to get client\n", __func__, __LINE__);
        goto exit_err;
    }

    ds_dlist_insert_tail(&client->samples, sample);
    client->is_updated = true;

    return RETURN_OK;
exit_err:
    dpp_client_record_free(sample);
    return RETURN_ERR;
}


/* PUBLIC API */

#define DELTA(X) (curr->X - prev->X)
/* After client reconnection, dev3 stats counters are cleared up.
   Take into consideration only samples where client was connected.
   If the client was disconnected in the previous sample, take the absolute current value;
   Calculate delta otherwise
*/
#define DELTA_CONN_STATS(NO_RECONNECT, X) ((curr->X >= prev->X) && NO_RECONNECT ? DELTA(X) : curr->X)
#define DELTA_STATS(X) DELTA_CONN_STATS((prev->connected == curr->connected), stats.X)
#define ROUNDF(X) (roundf((X) * 100) / 100.0)
#define CLIENT_STATS_PRINT(S,M) \
    wifi_util_dbg_print(WIFI_SM, "%s:%d: Client %s %s=%llu\n", __func__, __LINE__, M, #S, result->S);

int sm_client_samples_calc_total(ds_dlist_t *samples, dpp_client_record_t *result)
{
    CHECK_NULL(samples);
    CHECK_NULL(result);

    dpp_client_record_t *prev = NULL;
    dpp_client_record_t *curr = NULL;

    size_t len = get_ds_dlist_len(samples);
    if (len <= 0) {
        wifi_util_error_print(WIFI_SM, "%s:%d empty samples list\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ds_dlist_foreach(samples, curr) {
        /* average */
        result->stats.rate_tx += curr->stats.rate_tx / len;
        result->stats.rate_rx += curr->stats.rate_rx / len;
        result->stats.rssi    += curr->stats.rssi    / len;

        if (!prev) {
            /* cannot calculate the delta from the first element*/
            prev = curr;
            continue;
        }

        /* connected(cli_Associations) should be used to determine
         * if it is necessary to calculate delta or use the absolute values */
        /* If cli_Associations changes, that means the absolute value should be taken,
         * delta otherwise */
        result->stats.bytes_tx   += DELTA_STATS(bytes_tx);
        result->stats.frames_tx  += DELTA_STATS(frames_tx);
        result->stats.retries_tx += DELTA_STATS(retries_tx);
        result->stats.errors_tx  += DELTA_STATS(errors_tx);

        result->stats.bytes_rx   += DELTA_STATS(bytes_rx);
        result->stats.frames_rx  += DELTA_STATS(frames_rx);
        result->stats.retries_rx += DELTA_STATS(retries_rx);
        result->stats.errors_rx  += DELTA_STATS(errors_rx);

        prev = curr;
    }

    result->stats.rate_tx = ROUNDF(result->stats.rate_tx);
    result->stats.rate_rx = ROUNDF(result->stats.rate_rx);
    result->stats.rssi    = ROUNDF(result->stats.rssi);

    prev = ds_dlist_head(samples);
    curr = ds_dlist_tail(samples);

    /* client_info */
    memcpy(&result->info, &curr->info, sizeof(result->info));

    /* connection */
    result->is_connected   = curr->is_connected;

    result->connected      = DELTA(connected);
    result->disconnected   = DELTA(disconnected);

    result->connect_ts     = TS_DEFAULT;
    result->disconnect_ts  = TS_DEFAULT;
    result->duration_ms    = DURATION_MS_NO_DISCONNECTS;

    if (result->connected != 0) {
        result->connect_ts  = curr->connect_ts;
    }

    if (result->disconnected != 0) {
        result->disconnect_ts  = curr->disconnect_ts;
    }

    result->duration_ms = DELTA(duration_ms);

    mac_addr_str_t mac_str = {0};
    to_mac_str(result->info.mac, mac_str);
    wifi_util_dbg_print(WIFI_SM, "%s:%d: Processed calculation %s client %s sample stats total: \n",
                        __func__, __LINE__, radio_get_name_from_type(result->info.type), mac_str);
    CLIENT_STATS_PRINT(stats.bytes_tx, mac_str);
    CLIENT_STATS_PRINT(stats.bytes_rx, mac_str);
    CLIENT_STATS_PRINT(stats.frames_tx, mac_str);
    CLIENT_STATS_PRINT(stats.frames_rx, mac_str);
    CLIENT_STATS_PRINT(stats.retries_tx, mac_str);
    CLIENT_STATS_PRINT(stats.retries_rx, mac_str);
    CLIENT_STATS_PRINT(stats.errors_tx, mac_str);
    CLIENT_STATS_PRINT(stats.errors_rx, mac_str);
    wifi_util_dbg_print(WIFI_SM, "%s:%d: Client %s stats.rssi=%d\n", __func__, __LINE__, mac_str, result->stats.rssi);

    return RETURN_OK;
}

#undef ROUNDF
#undef DELTA_STATS
#undef DELTA_CONN_STATS
#undef DELTA


int sm_client_sample_store(unsigned int radio_index, unsigned int vap_index,
                           wifi_associated_dev3_t *dev3, sm_client_conn_t *conn_info)
{
    CHECK_NULL(dev3);
    CHECK_NULL(conn_info);

    // Store into internal cache
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;
    ssid_t ssid = {0};
    if_name_t ifname = {0};

    if (radio_index >= MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_SM, "%s:%d invalid radio_index=%d\n", __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    if (get_ssid_from_vap_index(vap_index, ssid) != RETURN_OK) {
        wifi_util_error_print(WIFI_SM, "%s:%d failed to get ssid for radio_index=%d\n", __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap_index, ifname, sizeof(ifname)) != RETURN_OK) {
        wifi_util_error_print(WIFI_SM, "%s:%d failed to get ifname for vap_index=%d\n", __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    mac_addr_str_t mac_str = {0};
    to_mac_str(dev3->cli_MACAddress, mac_str);

    if (client_sample_add(&sm_client_report_cache[radio_index], radio_index, vap_index,
                          ssid, ifname, dev3, conn_info) != RETURN_OK) {
        wifi_util_error_print(WIFI_SM, "%s:%d failed to add sample for radio_index=%d, client=%s\n",
                              __func__, __LINE__, radio_index, mac_str);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_SM, "%s:%d added sample for radio_index=%d, vap_index=%d, client=%s\n",
                        __func__, __LINE__, radio_index, vap_index, mac_str);

    return RETURN_OK;
}


void sm_client_cache_free(sm_client_cache_t *cache)
{
    sm_client_t *tmp_client = NULL;
    sm_client_t *client = NULL;

    if (!cache || !cache->clients) {
        return;
    }

    client = hash_map_get_first(cache->clients);
    while (client) {
        client->is_updated = false;
        tmp_client = client;
        client = hash_map_get_next(cache->clients, client);
        if (is_client_alive(tmp_client)) {
            client_samples_free(&tmp_client->samples, FREE_SAMPLE_ALL_EXCEPT_LAST);
        } else {
            /* clean all samples */
            client_samples_free(&tmp_client->samples, FREE_SAMPLE_ALL);
            tmp_client = hash_map_remove(cache->clients, tmp_client->id);
            free(tmp_client);
        }
    }
}


void sm_client_cache_init(sm_client_cache_t *cache)
{
    if (!cache) {
        return;
    }
    cache->clients = hash_map_create();
}


void sm_client_cache_deinit(sm_client_cache_t *cache)
{
    if (!cache) {
        return;
    }
    sm_client_cache_free(cache);
    hash_map_destroy(cache->clients);
}
