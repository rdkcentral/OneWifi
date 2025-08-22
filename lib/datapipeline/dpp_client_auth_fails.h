/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2025 RDK Management
  
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

#ifndef DPP_CLIENT_AUTH_FAILS_H
#define DPP_CLIENT_AUTH_FAILS_H

typedef struct {
    mac_address_str_t mac;
    uint32_t auth_fails;
    uint32_t invalid_psk;

    ds_dlist_node_t node;
} dpp_client_auth_fails_client_t;

typedef struct {
    ifname_t if_name;
    ds_dlist_t clients;

    ds_dlist_node_t node;
} dpp_client_auth_fails_bss_t;

typedef struct {
    radio_type_t radio_type;
    ds_dlist_t bsses;
} dpp_client_auth_fails_report_data_t;

static inline dpp_client_auth_fails_client_t *
dpp_client_auth_fails_client_alloc(void)
{
    return calloc(1, sizeof(dpp_client_auth_fails_client_t));
}

static inline void
dpp_client_auth_fails_client_free(dpp_client_auth_fails_client_t *client)
{
    free(client);
}

static inline dpp_client_auth_fails_bss_t *
dpp_client_auth_fails_bss_alloc(void)
{
    return calloc(1, sizeof(dpp_client_auth_fails_bss_t));
}

static inline void
dpp_client_auth_fails_bss_free(dpp_client_auth_fails_bss_t *bss)
{
    if (!bss)
        return;

    while (!ds_dlist_is_empty(&bss->clients)) {
        dpp_client_auth_fails_client_t *client = ds_dlist_head(&bss->clients);
        ds_dlist_remove(&bss->clients, client);
        dpp_client_auth_fails_client_free(client);
    }

    free(bss);
}

static inline dpp_client_auth_fails_report_data_t *
dpp_client_auth_fails_report_data_alloc(void)
{
    return calloc(1, sizeof(dpp_client_auth_fails_report_data_t));
}

static inline void
dpp_client_auth_fails_report_data_free(dpp_client_auth_fails_report_data_t *report)
{
    if (!report)
        return;

    while (!ds_dlist_is_empty(&report->bsses)) {
        dpp_client_auth_fails_bss_t *bss = ds_dlist_head(&report->bsses);
        ds_dlist_remove(&report->bsses, bss);
        dpp_client_auth_fails_bss_free(bss);
    }

    free(report);
}

#endif /* DPP_CLIENT_AUTH_FAILS_H */
