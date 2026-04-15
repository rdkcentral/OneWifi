/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RUN_H
#define RUN_H
#ifdef __cplusplus
extern "C" {
#endif
#define MAX_LINE_SIZE   1024
 #define MAX_FILE_NAME_SZ 1024

#define MAX_LINKQ_PARAMS    6
#define MAX_SCORE_PARAMS    12
#define THRESHOLD 0.4
#define SAMPLING_INTERVAL 5
#define REPORTING_INTERVAL 5
#include "wifi_base.h"

#define LINKQ_DL_SNR        (1 << 0)
#define LINKQ_DL_PER        (1 << 1)
#define LINKQ_DL_PHY        (1 << 2)
#define LINKQ_UL_SNR        (1 << 3)
#define LINKQ_UL_PER        (1 << 4)
#define LINKQ_UL_PHY        (1 << 5)
#define LINKQ_AGGREGATE     (1 << 6)
#define LINKQ_INT_RECONN    (1 << 7)

#define LINKQ_VALID_MASK    0xFF   /* Only first 8 bits valid */
#define LINK_QTY_B0  1.386
#define LINK_QTY_B1  0.02
typedef struct {
    char path[MAX_FILE_NAME_SZ];
    char output_file[MAX_FILE_NAME_SZ];
    double threshold;
    unsigned int sampling;
    unsigned int reporting;
} server_arg_t;

/* ext_qualitymgr_type — set by _ext stubs on Extender, read by run_gateway_thread on GW */
typedef enum {
    ext_qualitymgr_add_stats,
    ext_qualitymgr_periodic_caffinity,
    ext_qualitymgr_disconnect_link_stats,
    ext_qualitymgr_remove_link_stats,
    ext_qualitymgr_lq_affinity,

} ext_qualitymgr_type_t;

typedef struct {
    mac_addr_str_t mac_str;
    mac_addr_str_t ap_mac_str;
    unsigned int vap_index;
    unsigned int radio_index;
    int channel_utilization;
    dev_stats_t dev;
    struct timespec total_connected_time;
    struct timespec total_disconnected_time;
    int event;
    unsigned int status_code;
    int dhcp_event;
    int dhcp_msg_type;
  } stats_arg_t;

typedef struct {
    unsigned int  pkt_sent;
    unsigned  int pkt_recv;
    unsigned int  err_sent;
    unsigned int  err_recv;
  } window_per_param_t;

typedef struct {
    int radio_2g_max_snr;
    int radio_5g_max_snr;
    int radio_6g_max_snr;
} radio_max_snr_t;

typedef struct {
    bool downlink_snr;
    bool downlink_per;
    bool downlink_phy;
    bool uplink_snr;
    bool uplink_per;
    bool uplink_phy;
    bool aggregate;
    bool int_reconn;

  } quality_flags_t;

/* DHCP event flag for affinity updates */
#define DHCP_EVENT_UPDATE    1


typedef void (*qmgr_report_batch_cb_t)(const report_batch_t *report);
typedef void (*qmgr_report_score_cb_t)(const char *str, double score,double threshold);
typedef int (*qmgr_max_snr_cb_t)(int radio_index,int score);

/* Registration function (called from C main) */
void qmgr_register_batch_callback(qmgr_report_batch_cb_t cb);
void qmgr_register_score_callback(qmgr_report_score_cb_t cb);
void qmgr_register_max_snr_callback(qmgr_max_snr_cb_t cb);

bool qmgr_is_batch_registered(void);
bool qmgr_is_score_registered(void);

void reset_qmgr_score_cb(void);
void qmgr_invoke_batch(const report_batch_t *batch);
void qmgr_invoke_score(const char *str, double score,double threshold);
void qmgr_invoke_max_snr_callback(int radio_index,int max_snr);

int run_web_server();
int stop_web_server();


int add_stats_metrics(stats_arg_t *stats,int len);
int remove_link_stats(stats_arg_t *stats);
int start_link_metrics();
int stop_link_metrics();
int disconnect_link_stats(stats_arg_t *stats);
int reinit_link_metrics(server_arg_t *arg);
char* get_link_metrics();
int set_quality_flags(quality_flags_t *flag);
int get_quality_flags(quality_flags_t *flag);

/* Ignite station mac register and unregister function to monitor*/
void register_station_mac(const char* str);
void unregister_station_mac(const char* str);

/* Sets the max_snr per radios after its learnt */
int set_max_snr_radios(radio_max_snr_t *max_snr_val);

/* Connection Affinity related helper functions */
int update_affinity_stats(stats_arg_t *arg,bool flag);

/* Periodic caffinity stats update for connected/disconnected time and SNR */
int periodic_caffinity_stats_update(stats_arg_t *stats ,int len);

/* Store GW mac address in extender so that extender can send data*/
int store_gw_mac(uint8_t *mac);

/* Retrive GW mac address in extender so that extender can send data*/
int get_gw_mac(uint8_t *mac);

/* Check if a client is connected using caffinity tracking */
bool is_client_connected(const char *mac_str);

#ifdef __cplusplus
}
#endif
#endif
