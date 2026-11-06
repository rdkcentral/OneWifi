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

/* WEI RFC config defaults */
#define WEI_RFC_LQ_DURATION_DEFAULT        1
#define WEI_RFC_RADIO_2G_MAX_SNR_DEFAULT   60
#define WEI_RFC_RADIO_5G_MAX_SNR_DEFAULT   70
#define WEI_RFC_RADIO_6G_MAX_SNR_DEFAULT   70
#define WEI_RFC_RADIO_2G_MAX_PHY_DEFAULT   286
#define WEI_RFC_RADIO_5G_MAX_PHY_DEFAULT   1200
#define WEI_RFC_RADIO_6G_MAX_PHY_DEFAULT   2401

#define WEI_RFC_MASK               "Device.X_RDKCENTRAL-COM_WEI.RFC_MASK"
#define WEI_MEASUREMENT_RFC        "Device.X_RDKCENTRAL-COM_WEI.Enable"
#define WEI_LINK_QUALITY_FLAGS     "Device.X_RDKCENTRAL-COM_WEI.LinkQualityFlags"
#define WEI_LINK_QUALITY_DURATION  "Device.X_RDKCENTRAL-COM_WEI.LinkQualityDuration"
/* Published by OneWifi whenever Wifi_Wei_Rfc_Config changes; carries a
 * monotonically increasing generation counter that tells WEI to re-GET. */
#define WEI_RFC_CONFIG_CHANGED     "Device.X_RDKCENTRAL-COM_WEI.ConfigChanged"
#define WEI_RFC_ID_DEFAULT         "0"
//WEI endpoint for ignite
#define WEI_IGNITE_ENABLE_DMPATH   "Device.X_RDKCENTRAL-COM_WEI.Ignite.Enable"

#define WEI_DIAGNOSTIC_ENABLE_DMPATH "Device.X_RDKCENTRAL-COM_WEI.Diagnostic.Enable"

/* ---- Staying-Connected (SC) TR-181 parameter paths (WiFi-DB owned) ---- */
#define WEI_SC_HOME_ENABLE_DMPATH          "Device.X_RDKCENTRAL-COM_WEI.SC.Home.Enable"
#define WEI_SC_HOME_THRESHOLD_DMPATH       "Device.X_RDKCENTRAL-COM_WEI.SC.Home.Threshold"
#define WEI_SC_HOME_DETAIL_ENABLE_DMPATH   "Device.X_RDKCENTRAL-COM_WEI.SC.Home.Detail.Enable"
#define WEI_SC_CLIENT_ENABLE_DMPATH        "Device.X_RDKCENTRAL-COM_WEI.SC.Client.Enable"
#define WEI_SC_CLIENT_THRESHOLD_DMPATH     "Device.X_RDKCENTRAL-COM_WEI.SC.Client.Threshold"
#define WEI_SC_CLIENT_DETAIL_ENABLE_DMPATH "Device.X_RDKCENTRAL-COM_WEI.SC.Client.Detail.Enable"
#define WEI_SC_CLIENT_WHITELIST_DMPATH     "Device.X_RDKCENTRAL-COM_WEI.SC.Client.Detail.WhitelistClientIds"

/* ---- Getting-Connected (GC) TR-181 parameter paths (WiFi-DB owned) ---- */
#define WEI_GC_HOME_ENABLE_DMPATH          "Device.X_RDKCENTRAL-COM_WEI.GC.Home.Enable"
#define WEI_GC_HOME_THRESHOLD_DMPATH       "Device.X_RDKCENTRAL-COM_WEI.GC.Home.Threshold"
#define WEI_GC_HOME_DETAIL_ENABLE_DMPATH   "Device.X_RDKCENTRAL-COM_WEI.GC.Home.Detail.Enable"
#define WEI_GC_CLIENT_ENABLE_DMPATH        "Device.X_RDKCENTRAL-COM_WEI.GC.Client.Enable"
#define WEI_GC_CLIENT_THRESHOLD_DMPATH     "Device.X_RDKCENTRAL-COM_WEI.GC.Client.Threshold"
#define WEI_GC_CLIENT_DETAIL_ENABLE_DMPATH "Device.X_RDKCENTRAL-COM_WEI.GC.Client.Detail.Enable"
#define WEI_GC_CLIENT_WHITELIST_DMPATH     "Device.X_RDKCENTRAL-COM_WEI.GC.Client.Detail.WhitelistClientIds"

/* ---- When-Connected / Link-Quality (LQ) pillar TR-181 paths (WiFi-DB owned) ---- */
#define WEI_LQ_HOME_ENABLE_DMPATH          "Device.X_RDKCENTRAL-COM_WEI.LQ.Home.Enable"
#define WEI_LQ_HOME_THRESHOLD_DMPATH       "Device.X_RDKCENTRAL-COM_WEI.LQ.Home.Threshold"
#define WEI_LQ_HOME_DETAIL_ENABLE_DMPATH   "Device.X_RDKCENTRAL-COM_WEI.LQ.Home.Detail.Enable"
#define WEI_LQ_CLIENT_ENABLE_DMPATH        "Device.X_RDKCENTRAL-COM_WEI.LQ.Client.Enable"
#define WEI_LQ_CLIENT_THRESHOLD_DMPATH     "Device.X_RDKCENTRAL-COM_WEI.LQ.Client.Threshold"
#define WEI_LQ_CLIENT_DETAIL_ENABLE_DMPATH "Device.X_RDKCENTRAL-COM_WEI.LQ.Client.Detail.Enable"
#define WEI_LQ_CLIENT_WHITELIST_DMPATH     "Device.X_RDKCENTRAL-COM_WEI.LQ.Client.Detail.WhitelistClientIds"

/* Score params bitmask — controls quality_flags_t (same as UI checkboxes)
 * Uses LINKQ_DL_SNR..LINKQ_INT_RECONN (bits 0-7) defined above.
 * Valid mask is LINKQ_VALID_MASK (0xFF). */

#define LINK_QTY_B0  -9.495604
#define LINK_QTY_B1  0.081093
typedef struct {
    char path[MAX_FILE_NAME_SZ];
    char output_file[MAX_FILE_NAME_SZ];
    double threshold;
    unsigned int sampling;
    unsigned int reporting;
} server_arg_t;


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

typedef enum {
    DHCP_DISCOVER = 1,
    DHCP_OFFER    = 2,
    DHCP_REQUEST  = 3,
    DHCP_DECLINE  = 4,
    DHCP_ACK      = 5,
    DHCP_NAK      = 6,
    DHCP_UNKNOWN
} dhcp_pkt_type_t;

typedef enum
{
    WEI_RFC_NONE   = 0x00,  /* Main WEI RFC disabled                  */
    WEI_RFC_MAIN   = 0x01,  /* Main WEI RFC enabled                   */
    WEI_RFC_LQ     = 0x02,  /* Link Quality pillar enabled            */
    WEI_RFC_GC     = 0x04,  /* Getting Connected pillar enabled       */
    WEI_RFC_SC     = 0x08,  /* Staying Connected pillar enabled       */
    WEI_RFC_IGNITE = 0x10,  /* WEI was switched on by ignite RF-down  */
    WEI_RFC_ALL   = (WEI_RFC_MAIN | WEI_RFC_LQ | WEI_RFC_GC | WEI_RFC_SC)
} wei_rfc_mask_t;

/* One SC/GC/LQ pillar's home + client scoring config, mirrors WEI's
 * wei_rfc_config_t so the two sides map field-for-field. */
typedef struct {
    bool     home_enable;
    uint32_t home_threshold;
    bool     home_detail_enable;
    bool     client_enable;
    uint32_t client_threshold;
    bool     client_detail_enable;
    char     client_whitelist[256 + 1];
} wei_rfc_pillar_config_t;

/* Full WEI RFC configuration set, backed by Wifi_Wei_Rfc_Config (WiFi DB is
 * the single source of truth; WEI holds only a runtime cache of this). */
typedef struct {
    char                     wei_rfc_id[16 + 1];
    bool                     wei_enable;
    uint32_t                 lq_meas_params_mask;
    uint32_t                 lq_meas_duration;
    uint32_t                 radio_2g_max_snr;
    uint32_t                 radio_5g_max_snr;
    uint32_t                 radio_6g_max_snr;
    uint32_t                 radio_2g_max_phy;
    uint32_t                 radio_5g_max_phy;
    uint32_t                 radio_6g_max_phy;
    wei_rfc_pillar_config_t  sc;
    wei_rfc_pillar_config_t  gc;
    wei_rfc_pillar_config_t  lq;
    bool                     wei_diagnostic_enable;
} wei_rfc_dml_parameters_t;

/* Field type tags for the WEI RFC parameter descriptor table (drives the
 * generic rbus get/set handlers in wifi_ctrl_rbus_handlers.c). */
typedef enum { FIELD_BOOL, FIELD_UINT, FIELD_STRING } wei_field_type_t;

/* One row per WEI RFC rbus parameter: maps a TR-181 path to the field it
 * reads/writes in wei_rfc_dml_parameters_t via offset, so a new parameter
 * only needs a new table row instead of a new get/set handler pair. */
typedef struct {
    const char       *dmpath;
    wei_field_type_t  type;
    size_t            offset;      /* offset within wei_rfc_dml_parameters_t */
    size_t            field_size;  /* only meaningful for FIELD_STRING */
} wei_param_entry_t;


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


int add_stats_metrics(stats_arg_t *stats);
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

/* Sets score params booster flags via bitmask */
int set_score_params(uint32_t mask);

/* Connection Affinity related helper functions */
int update_affinity_stats(stats_arg_t *arg,bool flag);

/* Periodic caffinity stats update for connected/disconnected time and SNR */
int periodic_caffinity_stats_update(stats_arg_t *stats ,int len);


/* Check if a client is connected using caffinity tracking */
bool is_client_connected(const char *mac_str);

#ifdef __cplusplus
}
#endif
#endif
