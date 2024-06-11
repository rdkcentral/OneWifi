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

#ifndef SM_CACHE_H
#define SM_CACHE_H

#include "wifi_base.h"
#include "wifi_monitor.h"

#include <stdint.h>

#include <collection.h>
#include "ds_dlist.h"
#include "dpp_client.h"
#include "dpp_survey.h"
#include <wifi_hal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CLIENT */

#define SM_CLIENT_ID_LEN   (6 * 2 + 1 + 8)
/* device mac, _ and vap_index */
typedef char sm_client_id_t[SM_CLIENT_ID_LEN + 1];

#define IF_NAME_LEN 16
typedef char if_name_t[IF_NAME_LEN];

typedef struct {
    uint64_t        connect_ts;
    uint64_t        disconnect_ts;
    uint64_t        duration_ms;
} sm_client_conn_t;

typedef struct {
    sm_client_id_t   id;         /* vap_index + client_mac*/
    ds_dlist_t       samples;    /* dpp_client_record_t */
    bool             is_updated; /* there were new samples within the reporting interval */
} sm_client_t;

typedef struct {
    hash_map_t    *clients; /* sm_client_t */
} sm_client_cache_t; /* per radio */


void sm_client_cache_init(sm_client_cache_t *cache);
void sm_client_cache_deinit(sm_client_cache_t *cache);
int  sm_client_samples_calc_total(ds_dlist_t *samples, dpp_client_record_t *result);
int  sm_client_sample_store(unsigned int radio_index, unsigned int vap_index,
                            wifi_associated_dev3_t *dev3, sm_client_conn_t *conn_info);
void sm_client_cache_free(sm_client_cache_t *cache);


/* SURVEY */

#define SM_SURVEY_ID_LEN   (1 + 1 + 3)
/* radio_index + _ + channel */
typedef char sm_survey_id_t[SM_SURVEY_ID_LEN + 1];

typedef struct
{
    ds_dlist_t          samples;    /* dpp_survey_record_t */
    radio_chan_data_t   *old_stats;
    bool                is_updated; /* there were new samples within the reporting interval */
} sm_survey_scan_t;

typedef struct
{
    sm_survey_id_t      id;                /* radio_index + channel */

    sm_survey_scan_t    onchan;
    sm_survey_scan_t    offchan;
} sm_survey_t;

typedef struct {
    hash_map_t     *surveys;  /* sm_survey_t */
} sm_survey_cache_t; /* per radio */

void sm_survey_cache_init(sm_survey_cache_t *cache);
void sm_survey_cache_deinit(sm_survey_cache_t *cache);
int  sm_survey_sample_store(unsigned int radio_index, survey_type_t survey_type, radio_chan_data_t *stats);
int  sm_survey_samples_calc_average(ds_dlist_t *samples, dpp_survey_record_avg_t *result);
sm_survey_scan_t* sm_survey_get_scan_data(sm_survey_t *survey, survey_type_t survey_type);
void sm_survey_cache_clean(sm_survey_cache_t *cache, survey_type_t survey_type);
void sm_survey_cache_free_after_reconf(unsigned int radio_index, survey_type_t survey_type);

/* NEIGHBOR */

#define SM_NEIGHBOR_ID_LEN   (6 * 2 + 1 + 1)
/* bssid + _ +  radio_index */
typedef char sm_neighbor_id_t[SM_NEIGHBOR_ID_LEN + 1];

typedef struct
{
    ds_dlist_t            samples;    /* dpp_neighbor_record_list_t */
    wifi_neighbor_ap2_t   *old_stats;
    bool                  is_updated; /* there were new samples within the reporting interval */
} sm_neighbor_scan_t;

typedef struct
{
    sm_neighbor_id_t      id;    /* radio_index +  */

    sm_neighbor_scan_t    onchan;
    sm_neighbor_scan_t    offchan;
} sm_neighbor_t;

typedef struct {
    hash_map_t     *neighbors;  /* sm_neighbor_t */
} sm_neighbor_cache_t; /* per radio */

void sm_neighbor_cache_init(sm_neighbor_cache_t *cache);
void sm_neighbor_cache_deinit(sm_neighbor_cache_t *cache);
int  sm_neighbor_sample_store(unsigned int radio_index, survey_type_t survey_type, wifi_neighbor_ap2_t *stats);
sm_neighbor_scan_t* sm_neighbor_get_scan_data(sm_neighbor_t *neighbor, survey_type_t survey_type);
void sm_neighbor_cache_clean(sm_neighbor_cache_t *cache, survey_type_t survey_type);

#ifdef __cplusplus
}
#endif

#endif // SM_CACHE_H
