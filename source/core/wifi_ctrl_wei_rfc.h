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

#ifndef WIFI_CTRL_WEI_RFC_H
#define WIFI_CTRL_WEI_RFC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * WEI (Wi-Fi Experience Index) RFC configuration - rbus/TR-181 parameter
 * names, the derived pillar bitmask, and the config structs backing them.
 *
 * OneWifi owns storage/persistence of every WEI RFC parameter in
 * Wifi_Wei_Rfc_Config; WEI (a separate process) only keeps a runtime cache
 * fed by GET/subscribe over these same rbus paths. Kept in one header so
 * adding/auditing a WEI RFC parameter doesn't require hunting through
 * wifi_ctrl.h.
 * ============================================================ */

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

#ifdef __cplusplus
}
#endif

#endif /* WIFI_CTRL_WEI_RFC_H */
