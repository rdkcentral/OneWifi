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
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"


#define NULL_CHAR '\0'
#define NEW_LINE '\n'
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define MOCK_LEN_32 32
#define MOCK_LEN_16 16
#define MAX_KEYPASSPHRASE_LEN 129
#define MAX_SSID_LEN 33
#define INVALID_KEY  "12345678"


int wifi_rrm_send_beacon_req(struct wifi_interface_info_t *interface, const u8 *addr,
    u16 num_of_repetitions, u8 measurement_request_mode, u8 oper_class, u8 channel,
    u16 random_interval, u16 measurement_duration, u8 mode, const u8 *bssid,
    struct wpa_ssid_value *ssid, u8 *rep_cond, u8 *rep_cond_threshold, u8 *rep_detail,
    const u8 *ap_ch_rep, unsigned int ap_ch_rep_len, const u8 *req_elem, unsigned int req_elem_len,
    u8 *ch_width, u8 *ch_center_freq0, u8 *ch_center_freq1, u8 last_indication)
{
    return 0;
}

/* called by BTM API */
int wifi_wnm_send_bss_tm_req(struct wifi_interface_info_t *interface, struct sta_info *sta,
    u8 dialog_token, u8 req_mode, int disassoc_timer, u8 valid_int, const u8 *bss_term_dur,
    const char *url, const u8 *nei_rep, size_t nei_rep_len, const u8 *mbo_attrs, size_t mbo_len)
{
    return 0;
}

int handle_wnm_action_frame(struct wifi_interface_info_t *interface, const mac_address_t sta,
    struct ieee80211_mgmt *mgmt, size_t len)
{
    return 0;
}

int handle_rrm_action_frame(struct wifi_interface_info_t *interface, const mac_address_t sta,
    const struct ieee80211_mgmt *mgmt, size_t len, int ssi_signal)
{
    return 0;
}

#ifdef CONFIG_IEEE80211BE
int nl80211_drv_mlo_msg(struct nl_msg *msg, struct nl_msg **msg_mlo, void *priv,
    struct wpa_driver_ap_params *params)
{
    (void)msg;
    (void)msg_mlo;
    (void)priv;
    (void)params;

    return 0;
}

int nl80211_send_mlo_msg(struct nl_msg *msg)
{
    (void)msg;

    return 0;
}

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb)
{
    (void)eht_capab;
    (void)tb;
}

int update_hostap_mlo(wifi_interface_info_t *interface)
{
    (void)interface;

    return 0;
}
#endif /* CONFIG_IEEE80211BE */
