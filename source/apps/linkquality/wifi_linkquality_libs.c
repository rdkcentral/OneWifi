/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

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
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "wifi_hal.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include "wifi_linkquality_libs.h"
#include "wifi_linkquality.h"
#include "run_qmgr.h"
#include "lq_ipc_sender.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#define MAX_EM_BUFF_SZ  1024
#define QMGR_FILE "/tmp/qmgr_ready"

/* EXT(XB8): GW MAC learned from incoming autoconf_search; initially zero until first poll received */

#if 0
static  int create_autoconfig_resp_msg(unsigned char *buff, unsigned char *dst, 
    char *interface_name,stats_arg_t *stats, int len,ext_qualitymgr_type_t event);

static int send_frame(unsigned char *buff, unsigned int len, bool multicast,  char *ifname);
#endif

/* -------------------------------------------------------------------------
 * Helper: returns true when running in Extender mode.
 * Checks ctrl->network_mode first; falls back to /nvram/config.txt role.
 * ------------------------------------------------------------------------- */
static bool is_ext_mode(void)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        return true;
    }
    /* Fallback: read /nvram/config.txt for role (testing between 2 GWs) */
    FILE *fp = fopen("/nvram/config.txt", "r");
    if (fp) {
        char line[100], role[50] = {0};
        if (fgets(line, sizeof(line), fp)) {
            sscanf(line, "%[^,]", role);
        }
        fclose(fp);
        if (strcmp(role, "Extender") == 0) {
            return true;
        }
    }
    return false;
}

/* -------------------------------------------------------------------------
 * Unified IPC functions – GW sends via AF_UNIX (lq_ipc_send),
 * EXT is a placeholder for 1905.1/TCP forwarding to the GW.
 * ------------------------------------------------------------------------- */

/* CAFFINITY_EVENT (msg_type 4) – HAL/DHCP events for caffinity scoring */
static int periodic_caffinity_stats_update_impl(stats_arg_t *stats, int len)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->CAFFINITY_EVENT] MAC=%s event=%d status_code=%u "
        "conn_time=%llds disconn_time=%llds dhcp_event=%d dhcp_msg_type=%d\n",
        __func__, __LINE__, stats->mac_str, stats->event, stats->status_code,
        (long long)stats->total_connected_time.tv_sec,
        (long long)stats->total_disconnected_time.tv_sec,
        stats->dhcp_event, stats->dhcp_msg_type);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward CAFFINITY_EVENT to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send CAFFINITY_EVENT to GW via 1905/TCP\n",
            __func__, __LINE__);
        return 0;
    }

    /* GW mode: send via AF_UNIX IPC to linkquality-stats */
    int rc = lq_ipc_send(LQ_IPC_MSG_CAFFINITY_EVENT, stats,
                         (uint32_t)len, sizeof(stats_arg_t));
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->CAFFINITY_EVENT] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* REGISTER_STA (msg_type 7) – Ignite RF-down station registration */
static void register_station_mac_impl(const char *str)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->REGISTER_STA] MAC=%s\n", __func__, __LINE__, str);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward REGISTER_STA to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send REGISTER_STA to GW via 1905/TCP\n",
            __func__, __LINE__);
        return;
    }

    size_t slen = strlen(str) + 1;
    int rc = lq_ipc_send(LQ_IPC_MSG_REGISTER_STA, str, 1, slen);
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->REGISTER_STA] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
}

/* UNREGISTER_STA (msg_type 8) – Ignite RF-down station unregistration */
static void unregister_station_mac_impl(const char *str)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->UNREGISTER_STA] MAC=%s\n", __func__, __LINE__, str);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward UNREGISTER_STA to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send UNREGISTER_STA to GW via 1905/TCP\n",
            __func__, __LINE__);
        return;
    }

    size_t slen = strlen(str) + 1;
    int rc = lq_ipc_send(LQ_IPC_MSG_UNREGISTER_STA, str, 1, slen);
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->UNREGISTER_STA] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
}

/* START_METRICS (msg_type 5) – ctrl startup */
static int start_link_metrics_impl()
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->START_METRICS]\n", __func__, __LINE__);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward START_METRICS to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send START_METRICS to GW via 1905/TCP\n",
            __func__, __LINE__);
        return 0;
    }

    /* GW mode: start local DHCP sniffer + send IPC to linkquality-stats */
    wifi_util_info_print(WIFI_APPS,
        "%s:%d Starting DHCP sniffer (GW mode)\n", __func__, __LINE__);
    dhcp_sniffer_start();

    int rc = lq_ipc_send(LQ_IPC_MSG_START_METRICS, NULL, 0, 0);
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->START_METRICS] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* STOP_METRICS (msg_type 6) – ctrl shutdown */
static int stop_link_metrics_impl()
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->STOP_METRICS]\n", __func__, __LINE__);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward STOP_METRICS to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send STOP_METRICS to GW via 1905/TCP\n",
            __func__, __LINE__);
        return 0;
    }

    /* GW mode: stop local DHCP sniffer + send IPC to linkquality-stats */
    wifi_util_info_print(WIFI_APPS,
        "%s:%d Stopping DHCP sniffer (GW mode)\n", __func__, __LINE__);
    dhcp_sniffer_stop();

    int rc = lq_ipc_send(LQ_IPC_MSG_STOP_METRICS, NULL, 0, 0);
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->STOP_METRICS] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* RAPID_DISCONNECT (msg_type 3) – rapid connect/disconnect detection */
static int disconnect_link_stats_impl(stats_arg_t *stats)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->RAPID_DISCONNECT] MAC=%s status_code=%u "
        "conn_time=%llds disconn_time=%llds\n",
        __func__, __LINE__, stats->mac_str, stats->status_code,
        (long long)stats->total_connected_time.tv_sec,
        (long long)stats->total_disconnected_time.tv_sec);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward RAPID_DISCONNECT to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send RAPID_DISCONNECT to GW via 1905/TCP\n",
            __func__, __LINE__);
        return 0;
    }

    int rc = lq_ipc_send(LQ_IPC_MSG_RAPID_DISCONNECT, stats, 1,
                         sizeof(stats_arg_t));
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->RAPID_DISCONNECT] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* REINIT_METRICS (msg_type 9) – webconfig/EM param update */
static int reinit_link_metrics_impl(server_arg_t *arg)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->REINIT_METRICS] reporting=%u threshold=%f\n",
        __func__, __LINE__, arg->reporting, arg->threshold);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward REINIT_METRICS to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send REINIT_METRICS to GW via 1905/TCP\n",
            __func__, __LINE__);
        return 0;
    }

    int rc = lq_ipc_send(LQ_IPC_MSG_REINIT_METRICS, arg, 1,
                         sizeof(server_arg_t));
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->REINIT_METRICS] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* DISCONNECT (msg_type 2) – client permanently left sta_map */
static int remove_link_stats_impl(stats_arg_t *stats)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->DISCONNECT] MAC=%s status_code=%u "
        "conn_time=%llds disconn_time=%llds\n",
        __func__, __LINE__, stats->mac_str, stats->status_code,
        (long long)stats->total_connected_time.tv_sec,
        (long long)stats->total_disconnected_time.tv_sec);

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward DISCONNECT to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send DISCONNECT to GW via 1905/TCP\n",
            __func__, __LINE__);
        return 0;
    }

    int rc = lq_ipc_send(LQ_IPC_MSG_DISCONNECT, stats, 1,
                         sizeof(stats_arg_t));
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->DISCONNECT] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* PERIODIC_STATS (msg_type 1) – periodic monitor poll batch */
static int process_lq_stats_impl(stats_arg_t *stats, int len)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->PERIODIC_STATS] count=%d\n", __func__, __LINE__, len);

    for (int i = 0; i < len; i++) {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d  [%d] MAC=%s snr=%d vap=%u status_code=%u "
            "conn_time=%llds disconn_time=%llds\n",
            __func__, __LINE__, i,
            stats[i].mac_str, stats[i].dev.cli_SNR, stats[i].vap_index,
            stats[i].status_code,
            (long long)stats[i].total_connected_time.tv_sec,
            (long long)stats[i].total_disconnected_time.tv_sec);
    }

    if (is_ext_mode()) {
        /* TODO: EXT mode – forward PERIODIC_STATS to GW via 1905.1/TCP frame */
        wifi_util_info_print(WIFI_APPS,
            "%s:%d EXT mode: placeholder – send PERIODIC_STATS to GW via 1905/TCP\n",
            __func__, __LINE__);
        return 0;
    }

    int rc = lq_ipc_send(LQ_IPC_MSG_PERIODIC_STATS, stats,
                         (uint32_t)len, sizeof(stats_arg_t));
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC->PERIODIC_STATS] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* get_link_metrics – local only, no IPC equivalent */
static char* get_link_metrics_impl()
{
    wifi_util_dbg_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    return NULL;
}

/* set_quality_flags – local only, no IPC equivalent */
static int set_quality_flags_impl(quality_flags_t *flag)
{
    wifi_util_dbg_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    (void)flag;
    return 0;
}

/* get_quality_flags – local only, no IPC equivalent */
static int get_quality_flags_impl(quality_flags_t *flag)
{
    wifi_util_dbg_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    (void)flag;
    return 0;
}

/* -------------------------------------------------------------------------
 * get_lq_descriptor – singleton; wires up unified functions (no separate
 * _ext/_gw split; mode is checked inside each function).
 * ------------------------------------------------------------------------- */
wifi_lq_descriptor_t* get_lq_descriptor()
{
    static bool initialized = false;
    static wifi_lq_descriptor_t desc;

    if (!initialized) {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d initializing LQ descriptor (mode=%s)\n",
            __func__, __LINE__, is_ext_mode() ? "EXT" : "GW");

        desc.periodic_caffinity_stats_update_fn = periodic_caffinity_stats_update_impl;
        desc.register_station_mac_fn            = register_station_mac_impl;
        desc.unregister_station_mac_fn          = unregister_station_mac_impl;
        desc.start_link_metrics_fn              = start_link_metrics_impl;
        desc.stop_link_metrics_fn               = stop_link_metrics_impl;
        desc.disconnect_link_stats_fn           = disconnect_link_stats_impl;
        desc.reinit_link_metrics_fn             = reinit_link_metrics_impl;
        desc.remove_link_stats_fn               = remove_link_stats_impl;
        desc.get_link_metrics_fn                = get_link_metrics_impl;
        desc.set_quality_flags_fn               = set_quality_flags_impl;
        desc.get_quality_flags_fn               = get_quality_flags_impl;
        desc.process_lq_stats_fn                = process_lq_stats_impl;

        initialized = true;
    }

    return &desc;
}

static int send_frame(unsigned char *buff, unsigned int len, bool multicast,  char *ifname)
{
    int ret = 0;
    multiap_raw_hdr_t *hdr = (multiap_raw_hdr_t *)(buff);

    struct sockaddr_ll sadr_ll;
    int sock;
    mac_address_t   multi_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    wifi_util_info_print(WIFI_CTRL,"Sending frame on %s\n",ifname);

    sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        return -1;
    }

    sadr_ll.sll_ifindex = (int)(if_nametoindex(ifname));
    sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
    sadr_ll.sll_protocol = htons(ETH_P_ALL);
    memcpy(sadr_ll.sll_addr, (multicast == true) ? multi_addr:hdr->dst, sizeof(mac_address_t));

    ret = (int)(sendto(sock, buff, len, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll)));
    wifi_util_info_print(WIFI_CTRL,"Sent frame on %s ret val =%d\n",ifname,ret);
    close(sock);
    return ret;
 }

#if 0
int create_autoconfig_resp_msg(unsigned char *buff, unsigned char *dst, char *interface_name,stats_arg_t *stats, int num_devs,ext_qualitymgr_type_t event)
{
    unsigned short msg_id = multiap_msg_type_autoconf_resp;
    multiap_cmdu_t *cmdu;
    multiap_tlv_t *tlv;
    int len = 0;
    unsigned char *tmp = buff;
    unsigned char src_addr[64];
    char st[64] = { 0 };
    
    unsigned short type = htons(ETH_P_1905);
    
    mac_address_from_name(interface_name, src_addr);

    uint8_mac_to_string_mac(src_addr, st);
    wifi_util_info_print(WIFI_APPS, "Source MAC from interface %s = %s\n", interface_name, st);

    uint8_mac_to_string_mac(dst, st);
    wifi_util_info_print(WIFI_APPS, "Destination MAC = %s\n", st);

    memcpy(tmp, (unsigned char *)dst, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += (int)(sizeof(mac_address_t));

    memcpy(tmp, (unsigned char *)src_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += (int)(sizeof(mac_address_t));

    memcpy(tmp, (unsigned char *)(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += (int)(sizeof(unsigned short));
    cmdu = (multiap_cmdu_t *)(tmp);

    memset(tmp, 0, sizeof(multiap_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = msg_id;
    msg_id++;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(multiap_cmdu_t);
    len += (int)(sizeof(multiap_cmdu_t));

  // supported service tlv 17.2.1
    tlv = (multiap_tlv_t *) (tmp);
    tlv->type = multiap_tlv_type_searched_role;
    tlv->len = htons(sizeof(unsigned char));
    
    memcpy(&tlv->value[1], &event, sizeof(multiap_enum_type_t));

    tmp += (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);
    len += (int) (sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1);

    /* LinkQualityData TLV */
    tlv = (multiap_tlv_t *)tmp;

    tlv->type =  multiap_tlv_type_lq;  // or correct type
    int payload_len = num_devs * sizeof(stats_arg_t);

     tlv->len = htons(payload_len);

    memcpy(tlv->value, stats, payload_len);

    tmp += sizeof(multiap_tlv_t) + payload_len;
    len += sizeof(multiap_tlv_t) + payload_len;
    
    /* End of message */
    tlv = (multiap_tlv_t *)(tmp);
    tlv->type = multiap_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(multiap_tlv_t));
    len += (int)(sizeof(multiap_tlv_t));
    wifi_util_info_print(WIFI_APPS, "%s:%d Autoconfig response message created successfully, total_length=%d bytes\n",
       __func__, __LINE__, len);

    return len;
}
#endif
/* -------------------------------------------------------------------------
 * EXT side: listener thread that learns the GW MAC from incoming
 * autoconf_search (CMDU type 0x0007) frames received on the backhaul iface.
 * The learned MAC is stored in g_gw_mac and used by all _ext stubs as the
 * destination for autoconf_resp frames.
 * ------------------------------------------------------------------------- */
void* run_extender_1905_thread(void *arg)
{
    uint8_t buf[MAX_EM_BUFF_SZ];
    ssize_t n;
    int sock;
    uint8_t g_gw_mac[6] = {0};
    char gw_mac_str[18] = {0};
    wifi_util_dbg_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_1905));
    if (sock < 0) {
        wifi_util_error_print(WIFI_APPS, " 1905 EXT %s:%d socket() failed: %s\n",
            __func__, __LINE__, strerror(errno));
        return NULL;
    }

    /* EXT(XB8): backhaul interface is brlan0; for RPI extender: change to "eth0" */
    const char *ext_iface = "brlan0";
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ext_iface,
                   (socklen_t)(strlen(ext_iface) + 1)) < 0) {
        wifi_util_error_print(WIFI_APPS, " 1905 EXT %s:%d SO_BINDTODEVICE(%s) failed: %s\n",
            __func__, __LINE__, ext_iface, strerror(errno));
        close(sock);
        return NULL;
    }

    wifi_util_info_print(WIFI_APPS, " 1905 EXT %s:%d listening for autoconf_search on %s\n",
        __func__, __LINE__, ext_iface);

    while (1) {
        n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0) {
            wifi_util_error_print(WIFI_APPS, " 1905 EXT %s:%d recvfrom error: %s\n",
                __func__, __LINE__, strerror(errno));
            continue;
        }

        if (n < (ssize_t)(sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t))) {
            continue;
        }

        multiap_raw_hdr_t *raw = (multiap_raw_hdr_t *)buf;
        if (raw->type != htons(ETH_P_1905)) {
            continue;
        }

        multiap_cmdu_t *cmdu = (multiap_cmdu_t *)(buf + sizeof(multiap_raw_hdr_t));
        if (ntohs(cmdu->type) != multiap_msg_type_autoconf_search) {
            wifi_util_dbg_print(WIFI_APPS, " 1905 EXT %s:%d ignoring CMDU type=0x%04x\n",
                __func__, __LINE__, ntohs(cmdu->type));
            continue;
        }

        memcpy(g_gw_mac, raw->src, sizeof(mac_address_t));
//	store_gw_mac(g_gw_mac);
        uint8_mac_to_string_mac(g_gw_mac, gw_mac_str);
        wifi_util_info_print(WIFI_APPS,
            " 1905 EXT %s:%d received autoconf_search — stored GW MAC: %s\n",
            __func__, __LINE__, gw_mac_str);
        break;
    }

    close(sock);
    return NULL;
}

/* -------------------------------------------------------------------------
 * GW side: sends an IEEE 1905.1 autoconf_search (CMDU 0x0007) broadcast on
 * the backhaul interface so the EXT learns the GW MAC and can direct its
 * autoconf_resp frames here.  Called from link_quality_event_exec_timeout().
 * ------------------------------------------------------------------------- */
int lq_send_autoconf_search(const char *ifname)
{
    uint8_t buf[sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t) + sizeof(multiap_tlv_t)];
    unsigned char src_addr[6] = {0};
    int frame_len = 0;
    int i = 0;

    memset(buf, 0, sizeof(buf));

    multiap_raw_hdr_t *raw = (multiap_raw_hdr_t *)buf;
    memset(raw->dst, 0xFF, sizeof(mac_address_t));   /* broadcast */
    if (mac_address_from_name(ifname, src_addr) < 0) {
        wifi_util_error_print(WIFI_APPS, " 1905 GW %s:%d mac_address_from_name(%s) failed\n",
            __func__, __LINE__, ifname);
        return -1;
    }
    memcpy(raw->src, src_addr, sizeof(mac_address_t));
    raw->type = htons(ETH_P_1905);
    frame_len += (int)sizeof(multiap_raw_hdr_t);

    multiap_cmdu_t *cmdu = (multiap_cmdu_t *)(buf + sizeof(multiap_raw_hdr_t));
    cmdu->ver         = 0;
    cmdu->type        = htons(multiap_msg_type_autoconf_search);
    cmdu->id          = htons((unsigned short)(rand() & 0xFFFF));
    cmdu->frag_id     = 0;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind   = 1;
    frame_len += (int)sizeof(multiap_cmdu_t);

    /* TLV EOM */
    multiap_tlv_t *tlv = (multiap_tlv_t *)(buf + sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t));
    tlv->type = multiap_tlv_type_eom;
    tlv->len  = 0;
    frame_len += (int)sizeof(multiap_tlv_t);

    wifi_util_info_print(WIFI_APPS, " 1905 GW %s:%d sending autoconf_search on %s len=%d\n",
        __func__, __LINE__, ifname, frame_len);
    for ( i = 0 ;i<4;i++) {
        send_frame(buf, (unsigned int)frame_len, false, (char *)ifname);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * GW side: parse an incoming IEEE 1905.1 autoconf_resp (CMDU 0x0008) from
 * the EXT and dispatch the embedded stats_arg_t[] into the qmgr.
 * Called from sniffer_thread_func() whenever eth_type == 0x893a is seen.
 * ------------------------------------------------------------------------- */
void lq_handle_1905_frame(const uint8_t *buf, ssize_t len)
{
#if 0
    if (len < (ssize_t)(sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t))) {
        wifi_util_dbg_print(WIFI_APPS, " 1905 GW %s:%d frame too short len=%zd\n",
            __func__, __LINE__, len);
        return;
    }

    multiap_cmdu_t *cmdu = (multiap_cmdu_t *)(buf + sizeof(multiap_raw_hdr_t));
    if (ntohs(cmdu->type) != multiap_msg_type_autoconf_resp) {
        wifi_util_dbg_print(WIFI_APPS, " 1905 GW %s:%d ignoring CMDU type=0x%04x (not autoconf_resp)\n",
            __func__, __LINE__, ntohs(cmdu->type));
        return;
    }

    const uint8_t *ptr   = buf + sizeof(multiap_raw_hdr_t) + sizeof(multiap_cmdu_t);
    const uint8_t *end   = buf + len;
    ext_qualitymgr_type_t event = (ext_qualitymgr_type_t)-1;
    stats_arg_t *lq_buf  = NULL;
    int count            = 0;

    while (ptr + sizeof(multiap_tlv_t) <= end) {
        const multiap_tlv_t *tlv = (const multiap_tlv_t *)ptr;

        if (tlv->type == multiap_tlv_type_searched_role) {
            /* Writer places the event byte at value[1] and advances 5 bytes total
             * (sizeof(multiap_tlv_t)=3 + sizeof(multiap_enum_type_t)=1 + 1 pad). */
            event = (ext_qualitymgr_type_t)tlv->value[1];
            ptr  += sizeof(multiap_tlv_t) + sizeof(multiap_enum_type_t) + 1;

        } else if (tlv->type == multiap_tlv_type_lq) {
            int payload_len = (int)ntohs(tlv->len);
            count = payload_len / (int)sizeof(stats_arg_t);
            if (count <= 0 || count > 256) {
                wifi_util_error_print(WIFI_APPS,
                    " 1905 GW %s:%d invalid count=%d in lq TLV\n",
                    __func__, __LINE__, count);
                return;
            }
            lq_buf = calloc((size_t)count, sizeof(stats_arg_t));
            if (!lq_buf) {
                wifi_util_error_print(WIFI_APPS,
                    " 1905 GW %s:%d calloc failed count=%d\n",
                    __func__, __LINE__, count);
                return;
            }
            memcpy(lq_buf, tlv->value, (size_t)payload_len);
            ptr += sizeof(multiap_tlv_t) + payload_len;

        } else if (tlv->type == multiap_tlv_type_eom) {
            break;

        } else {
            /* Unknown TLV: skip based on declared length */
            ptr += sizeof(multiap_tlv_t) + (int)ntohs(tlv->len);
        }
    }

    if (!lq_buf) {
        wifi_util_dbg_print(WIFI_APPS, " 1905 GW %s:%d no lq TLV found in frame\n",
            __func__, __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_APPS,"1905 GW %s:%d dispatching event=%d count=%d\n",
        __func__, __LINE__, (int)event, count);

    switch (event) {
        case ext_qualitymgr_add_stats:
            add_stats_metrics(lq_buf, count);
            break;

        case ext_qualitymgr_periodic_caffinity:
            periodic_caffinity_stats_update(lq_buf, count);
            break;

        case ext_qualitymgr_disconnect_link_stats:
            disconnect_link_stats(lq_buf);
            break;

        case ext_qualitymgr_remove_link_stats:
            remove_link_stats(lq_buf);
            break;

        case ext_qualitymgr_lq_affinity:
            add_stats_metrics(lq_buf, count);
            periodic_caffinity_stats_update(lq_buf, count);
            break;

        default:
            wifi_util_error_print(WIFI_APPS,
                " 1905 GW %s:%d unknown event=%d\n",
                __func__, __LINE__, (int)event);
            break;

    }

    free(lq_buf);
#endif
}

