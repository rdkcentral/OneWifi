/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
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
*/

#ifndef __WIFI_HAL_EXTENDER_H__
#define __WIFI_HAL_EXTENDER_H__

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Wi-Fi channel statistics.
 */
typedef struct _wifi_channelStats
{
    INT ch_number; /**< Channel number (each channel is only 20MHz bandwidth). */
    BOOL ch_in_pool; /**< Whether the channel is in the pool. If false, the driver does not need to scan this channel. */
    INT ch_noise; /**< Average noise floor in dBm. */
    BOOL ch_radar_noise; /**< Whether radar noise is present on the channel (5GHz only). */
    INT ch_max_80211_rssi; /**< Maximum RSSI from a neighboring AP in dBm on this channel. */
    INT ch_non_80211_noise; /**< Average non-802.11 noise. */
    INT ch_utilization; /**< 802.11 utilization in percent. */
    ULLONG ch_utilization_total; /**< Total time the radio spent receiving or transmitting on the channel. */
    ULLONG ch_utilization_busy; /**< Time the radio detected that the channel was busy (Busy = Rx + Tx + Interference). */
    ULLONG ch_utilization_busy_tx; /**< Time the radio spent transmitting on the channel. */
    ULLONG ch_utilization_busy_rx; /**< Time the radio spent receiving on the channel (Rx = Rx_obss + Rx_self + Rx_errr (self and obss errors)). */
    ULLONG ch_utilization_busy_self; /**< Time the radio spent receiving on the channel from its own connected clients. */
    ULLONG ch_utilization_busy_ext; /**< Time the radio detected that the extended channel was busy (40MHz extension channel busy). */
} wifi_channelStats_t;

/* MCS/NSS/BW rate table and indexes that should be used for supported rates
   ----------------------------------------------
   | type | bw         | nss        |  mcs
   ----------------------------------------------
   | OFDM | 0 (20Mhz)  | 0 (legacy) |  0 - 6M
   |      |            |            |  1 - 9M
   |      |            |            |  2 - 12M
   |      |            |            |  3 - 18M
   |      |            |            |  4 - 24M
   |      |            |            |  5 - 36M
   |      |            |            |  6 - 48M
   |      |            |            |  7 - 54M
   ----------------------------------------------
   | CCK  | 0 (20Mhz)  | 0 (legacy) |  8 - L1M
   |      |            |            |  9 - L2M
   |      |            |            | 10 - L5.5M
   |      |            |            | 11 - L11M
   |      |            |            | 12 - S2M
   |      |            |            | 13 - S5.5M
   |      |            |            | 14 - S11M"
   ----------------------------------------------
   | VHT  | 0 (20Mhz)  | 1 (chain1) |  1 - HT/VHT
   |      | 1 (40Mhz)  | ...        |  2 - HT/VHT
   |      | 2 (80MHz)  | 8 (chain8) |  3 - HT/VHT
   |      | 2 (160MHz) |            |  4 - HT/VHT
   |      |            |            |  5 - HT/VHT
   |      |            |            |  6 - HT/VHT
   |      |            |            |  7 - HT/VHT
   |      |            |            |  8 - VHT
   |      |            |            |  9 - VHT
   ----------------------------------------------
   NOTE: The size of this table on 4x4 can be big - we could send only non-zero elements!
*/

/**
 * @brief RX statistics for a specific rate.
 */
typedef struct _wifi_associated_dev_rate_info_rx_stats
{
    UCHAR nss; /**< Number of spatial streams (0 for legacy protocols like OFDM and CCK, 1 or more for HT and VHT). */
    UCHAR mcs; /**< MCS index (0-7 for HT, 0-9 for VHT). */
    USHORT bw; /**< Bandwidth in MHz (20, 40, 80, 160, etc.). */
    ULLONG flags; /**< Flags indicating data validation: HAS_BYTES, HAS_MSDUS, HAS_MPDUS, HAS_PPDUS, HAS_BW_80P80, HAS_RSSI_COMB, HAS_RSSI_ARRAY. */
    ULLONG bytes; /**< Number of bytes received for the given rate. */
    ULLONG msdus; /**< Number of MSDUs received for the given rate. */
    ULLONG mpdus; /**< Number of MPDUs received for the given rate. */
    ULLONG ppdus; /**< Number of PPDUs received for the given rate. */
    ULLONG retries; /**< Number of retries received for the given rate. */
    UCHAR rssi_combined; /**< Last RSSI received for the given rate. */
    /* Per antenna RSSI (above noise floor) for all widths (primary,secondary) 
        -----------------------------------------------
        | chain_num |  20MHz [pri20                   ]
        |           |  40MHZ [pri20,sec20             ] 
        |           |  80MHz [pri20,sec20,sec40,      ]
        |           | 160MHz [pri20,sec20,sec40,sec80 ]
        -----------------------------------------------
        |  1        |  rssi  [pri20,sec20,sec40,sec80 ]
        |  ...      |  ...
        |  8        |  rssi  [pri20,sec20,sec40,sec80 ]
        -----------------------------------------------    */    
    UCHAR rssi_array[8][4]; /**< Per-antenna RSSI (above noise floor) for all widths (primary, secondary). */
} wifi_associated_dev_rate_info_rx_stats_t;

/**
 * @brief TX statistics for a specific rate.
 */
typedef struct _wifi_associated_dev_rate_info_tx_stats
{
    UCHAR nss; /**< Number of spatial streams (0 for legacy protocols like OFDM and CCK, 1 or more for HT and VHT). */
    UCHAR mcs; /**< MCS index (0-7 for HT, 0-9 for VHT). */
    USHORT bw; /**< Bandwidth in MHz (20, 40, 80, 160, etc.). */
    ULLONG flags; /**< Flags indicating data validation: HAS_BYTES, HAS_MSDUS, HAS_MPDUS, HAS_PPDUS, HAS_BW_80P80, HAS_RSSI_COMB, HAS_RSSI_ARRAY. */
    ULLONG bytes; /**< Number of bytes transmitted for the given rate. */
    ULLONG msdus; /**< Number of MSDUs transmitted for the given rate. */
    ULLONG mpdus; /**< Number of MPDUs transmitted for the given rate. */
    ULLONG ppdus; /**< Number of PPDUs transmitted for the given rate. */
    ULLONG retries; /**< Number of transmission retries for the given rate. */
    ULLONG attempts; /**< Number of attempts trying to transmit on the given rate. */
} wifi_associated_dev_rate_info_tx_stats_t;

/**
 * @brief TID entry.
 */
typedef struct wifi_associated_dev_tid_entry
{
    UCHAR ac; /**< Access category (BE, BK, VI, VO). */
    UCHAR tid; /**< TID (0-15). */
    ULLONG ewma_time_ms; /**< Moving average value based on the last couple of transmitted MSDUs. */
    ULLONG sum_time_ms; /**< Delta of cumulative MSDU times over the interval. */
    ULLONG num_msdus; /**< Number of MSDUs in the given interval. */
} wifi_associated_dev_tid_entry_t;

/**
 * @brief TID statistics.
 */
typedef struct wifi_associated_dev_tid_stats
{
    wifi_associated_dev_tid_entry_t tid_array[16]; /**< Array of TID entries. */
} wifi_associated_dev_tid_stats_t;

/**
 * @brief Associated device statistics.
 */
typedef struct _wifi_associated_dev_stats
{
    ULLONG cli_rx_bytes; /**< The total number of bytes received from the client device, including framing characters. */
    ULLONG cli_tx_bytes; /**< The total number of bytes transmitted to the client device, including framing characters. */
    ULLONG cli_rx_frames; /**< The total number of frames received from the client. */
    ULLONG cli_tx_frames; /**< The total number of frames transmitted to the client. */
    ULLONG cli_rx_retries; /**< Number of RX retries. */
    ULLONG cli_tx_retries; /**< Number of TX retries. */
    ULLONG cli_rx_errors; /**< Number of RX errors. */
    ULLONG cli_tx_errors; /**< Number of TX errors. */
    double cli_rx_rate; /**< Average RX data rate used. */
    double cli_tx_rate; /**< Average TX data rate used. */
    wifi_rssi_snapshot_t cli_rssi_bcn; /**< RSSI from the last 4 beacons received (STA). */
    wifi_rssi_snapshot_t cli_rssi_ack; /**< RSSI from the last 4 ACKs received (AP). */
} wifi_associated_dev_stats_t;

/**
 * @brief Steering configuration per AP.
 *
 * This structure defines the configuration for each Access Point (AP) added
 * to a steering group.
 *
 * Channel utilization is sampled every `utilCheckIntervalSec` seconds, and
 * after collecting `utilAvgCount` samples, the
 * `WIFI_STEERING_EVENT_CHAN_UTILIZATION` event is sent with the averaged
 * value.
 *
 * Client activity checking is performed every `inactCheckIntervalSec`
 * seconds. If a client is idle for `inactCheckThresholdSec` seconds, it is
 * marked as inactive. The `WIFI_STEERING_EVENT_CLIENT_ACTIVITY` event is
 * sent whenever a client changes state between active and inactive.
 */
typedef struct
{
    INT apIndex; /**< AP index. */
    UINT utilCheckIntervalSec; /**< Channel utilization check interval. */
    UINT utilAvgCount; /**< Number of samples to average for channel utilization. */
    UINT inactCheckIntervalSec; /**< Client inactivity check interval. */
    UINT inactCheckThresholdSec; /**< Client inactivity threshold. */
} wifi_steering_apConfig_t;

/**
 * @brief Configuration per Client
 *
 * This defines the per-client, per-apIndex configuration settings. The
 * high water mark + low water mark pairs define RSSI ranges, in which
 * given packet types (probe or auth) are responded to as long as the RSSI
 * of the request packet is within the defined range.
 *
 * The RSSI crossings define thresholds which result in steering events
 * being generated when a connected client's RSSI crosses above or below
 * the given threshold.
 *
 * `authRejectReason`, when non-zero, results in auth requests being
 * rejected with the given reason code. When set to zero, auth requests
 * that do not fall in the RSSI hwm+lwm range will be silently ignored.
 *
 * @see https://supportforums.cisco.com/document/141136/80211-association-status-80211-deauth-reason-codes
 */
typedef struct
{
    UINT rssiProbeHWM;     /**< Probe response RSSI high water mark.    */
    UINT rssiProbeLWM;     /**< Probe response RSSI low water mark.     */
    UINT rssiAuthHWM;      /**< Auth response RSSI high water mark.     */
    UINT rssiAuthLWM;      /**< Auth response RSSI low water mark.      */
    UINT rssiInactXing;    /**< Inactive RSSI crossing threshold.       */
    UINT rssiHighXing;     /**< High RSSI crossing threshold.           */
    UINT rssiLowXing;      /**< Low RSSI crossing threshold.            */
    UINT authRejectReason; /**< Inactive RSSI crossing threshold.       */
} wifi_steering_clientConfig_t;

/**
 * @brief Wifi Disconnect Sources
 *
 * These are the possible sources of a wifi disconnect.
 * If the disconnect was initiated by the client, then `DISCONNECT_SOURCE_REMOTE`
 * should be used.
 * If initiated by the local AP, then `DISCONNECT_SOURCE_LOCAL` should be used.
 * If this information is not available, then `DISCONNECT_SOURCE_UNKNOWN` should be used.
 */
typedef enum
{
    DISCONNECT_SOURCE_UNKNOWN = 0, /**< Unknown source. */
    DISCONNECT_SOURCE_LOCAL,       /**< Initiated locally. */
    DISCONNECT_SOURCE_REMOTE       /**< Initiated remotely. */
} wifi_disconnectSource_t;

/**
 * @brief Wifi Disconnect Types
 *
 * These are the types of wifi disconnects.
 */
typedef enum
{
    DISCONNECT_TYPE_UNKNOWN = 0, /**< Unknown type. */
    DISCONNECT_TYPE_DISASSOC,   /**< Disassociation. */
    DISCONNECT_TYPE_DEAUTH,     /**< Deauthentication. */
    DISCONNECT_TYPE_RECONNECT   /**< Reconnection. */
} wifi_disconnectType_t;

/**
 * @brief Wifi Steering Event Types
 *
 * These are the different steering event types that are sent by the wifi_hal
 * steering library.
 */
typedef enum
{
    WIFI_STEERING_EVENT_PROBE_REQ = 1,    /**< Probe Request Event. */
    WIFI_STEERING_EVENT_CLIENT_CONNECT,     /**< Client association completed successfully Event. */
    WIFI_STEERING_EVENT_CLIENT_DISCONNECT,  /**< Client Disconnect Event. */
    WIFI_STEERING_EVENT_CLIENT_ACTIVITY,    /**< Client Active Change Event. */
    WIFI_STEERING_EVENT_CHAN_UTILIZATION,   /**< Channel Utilization Event. */
    WIFI_STEERING_EVENT_RSSI_XING,          /**< Client RSSI Crossing Event. */
    WIFI_STEERING_EVENT_RSSI,               /**< Instant Measurement Event. */
    WIFI_STEERING_EVENT_AUTH_FAIL           /**< Client Auth Failure Event. */
} wifi_steering_eventType_t;

/**
 * @brief RSSI Crossing Values
 *
 * These are the RSSI crossing values provided in RSSI crossing events.
 */
typedef enum
{
    WIFI_STEERING_RSSI_UNCHANGED = 0, /**< RSSI hasn't crossed. */
    WIFI_STEERING_RSSI_HIGHER,       /**< RSSI went higher. */
    WIFI_STEERING_RSSI_LOWER         /**< RSSI went lower. */
} wifi_steering_rssiChange_t;

/**
 * @brief STA datarate information
 *
 * These are STA capabilities values.
 */
typedef struct
{
    UINT maxChwidth;        /**< Max bandwidth supported. */
    UINT maxStreams;        /**< Max spatial streams supported. */
    UINT phyMode;           /**< PHY Mode supported. */
    UINT maxMCS;            /**< Max MCS supported. */
    UINT maxTxpower;        /**< Max TX power supported. */
    UINT isStaticSmps;      /**< Operating in Static SM Power Save Mode. */
    UINT isMUMimoSupported; /**< Supports MU-MIMO. */
} wifi_steering_datarateInfo_t;

/**
 * @brief Radio Resource Management (RRM) capabilities.
 */
typedef struct
{
    BOOL linkMeas;      /**< Supports link measurement. */
    BOOL neighRpt;      /**< Supports neighbor reports. */
    BOOL bcnRptPassive; /**< Supports Passive 11k scans. */
    BOOL bcnRptActive;  /**< Supports Active 11k scans. */
    BOOL bcnRptTable;   /**< Supports beacon report table. */
    BOOL lciMeas;       /**< Supports LCI measurement. */
    BOOL ftmRangeRpt;   /**< Supports FTM Range report. */
} wifi_steering_rrmCaps_t;

/**
 * @brief Probe Request Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_PROBE_REQ`.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC Address. */
    UINT rssi;           /**< RSSI of probe frame. */
    BOOL broadcast;      /**< True if broadcast probe. */
    BOOL blocked;        /**< True if response blocked. */
} wifi_steering_evProbeReq_t;

#ifdef WIFI_HAL_VERSION_3_PHASE2

/**
 * @brief Client Connect Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_CLIENT_CONNECT`.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC Address. */
    UINT isBTMSupported; /**< Client supports BSS TM. */
    UINT isRRMSupported; /**< Client supports RRM. */
    wifi_freq_bands_t bandsCap; /**< Bitmask with the frequencies that the Client is capable. */
    wifi_steering_datarateInfo_t datarateInfo; /**< Client supported datarate information. */
    wifi_steering_rrmCaps_t rrmCaps; /**< Client supported RRM capabilities. */
} wifi_steering_evConnect_t;

#else
/**
 * @brief Client Connect Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_CLIENT_CONNECT`.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC Address. */
    UINT isBTMSupported; /**< Client supports BSS TM. */
    UINT isRRMSupported; /**< Client supports RRM. */
    BOOL bandCap2G; /**< Client is 2.4GHz capable. */
    BOOL bandCap5G; /**< Client is 5GHz capable. */
    BOOL bandCap6G; /**< Client is 6GHz capable. */
    wifi_steering_datarateInfo_t datarateInfo; /**< Client supported datarate information. */
    wifi_steering_rrmCaps_t rrmCaps; /**< Client supported RRM capabilities. */
} wifi_steering_evConnect_t;
#endif

/**
 * @brief Client Disconnect Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_CLIENT_DISCONNECT`.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC Address. */
    UINT reason; /**< Reason code of disconnect. */
    wifi_disconnectSource_t source; /**< Source of disconnect. */
    wifi_disconnectType_t type; /**< Disconnect Type. */
} wifi_steering_evDisconnect_t;

/**
 * @brief Client Activity Change Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_CLIENT_ACTIVITY`.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC Address. */
    BOOL active; /**< True if client is active. */
} wifi_steering_evActivity_t;

/**
 * @brief Channel Utilization Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_CHAN_UTILIZATION`.
 */
typedef struct
{
    UINT utilization; /**< Channel utilization (0-100). */
} wifi_steering_evChanUtil_t;

/**
 * @brief Client RSSI Crossing Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_RSSI_XING`.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC address. */
    UINT rssi; /**< Client's current RSSI. */
    wifi_steering_rssiChange_t inactveXing; /**< Inactive threshold crossing status. */
    wifi_steering_rssiChange_t highXing; /**< High threshold crossing status. */
    wifi_steering_rssiChange_t lowXing; /**< Low threshold crossing status. */
} wifi_steering_evRssiXing_t;

/**
 * @brief Client RSSI Measurement Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_RSSI`, which is sent in
 * response to a request for the client's current RSSI measurement.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC address. */
    UINT rssi; /**< Client's current RSSI. */
} wifi_steering_evRssi_t;

/**
 * @brief Auth Failure Event Data
 *
 * This data is provided with `WIFI_STEERING_EVENT_AUTH_FAIL`.
 */
typedef struct
{
    mac_address_t client_mac; /**< Client MAC Address. */
    UINT rssi; /**< RSSI of auth frame. */
    UINT reason; /**< Reject Reason. */
    BOOL bsBlocked; /**< True if purposely blocked. */
    BOOL bsRejected; /**< True if rejection sent. */
} wifi_steering_evAuthFail_t;

/**
 * @brief Wifi Steering Event
 *
 * This is the data containing a single steering event.
 */
typedef struct
{
    wifi_steering_eventType_t type; /**< Event Type. */
    INT apIndex; /**< apIndex event is from. */
    ULLONG timestamp_ms; /**< Optional: Event Timestamp. */
    union
    {
        wifi_steering_evProbeReq_t probeReq; /**< Probe Request Data. */
        wifi_steering_evConnect_t connect; /**< Client Connect Data. */
        wifi_steering_evDisconnect_t disconnect; /**< Client Disconnect Data. */
        wifi_steering_evActivity_t activity; /**< Client Active Change Data. */
        wifi_steering_evChanUtil_t chanUtil; /**< Channel Utilization Data. */
        wifi_steering_evRssiXing_t rssiXing; /**< Client RSSI Crossing Data. */
        wifi_steering_evRssi_t rssi; /**< Client Measured RSSI Data. */
        wifi_steering_evAuthFail_t authFail; /**< Auth Failure Data. */
    } data;
} wifi_steering_event_t;

// 802.11v BSS Transition Management Definitions
/**
 * @brief Maximum number of BTM devices.
 */
#define MAX_BTM_DEVICES 64

/**
 * @brief Maximum length of a URL.
 */
#define MAX_URL_LEN 512

/**
 * @brief Maximum number of BSS transition candidates.
 */
#define MAX_CANDIDATES 64

/**
 * @brief Maximum size of vendor-specific data.
 */
#define MAX_VENDOR_SPECIFIC 32

/**
 * @brief BSS Termination Duration subelement.
 *
 * This structure represents the BSS Termination Duration subelement (ID = 4),
 * as defined in 802.11 section 9.4.2.2.
 */
typedef struct
{
    ULONG tsf; /**< 8-octet TSF timer value. */
    USHORT duration; /**< Duration. */
} wifi_BTMTerminationDuration_t;

/**
 * @brief Condensed Country String.
 */
typedef struct
{
    CHAR condensedStr[3]; /**< 2-character country code from `do11CountryString`. */
} wifi_CondensedCountryString_t;

/**
 * @brief TSF information.
 */
typedef struct
{
    USHORT offset; /**< Offset. */
    USHORT interval; /**< Interval. */
} wifi_TSFInfo_t;

/**
 * @brief BSS Transition Candidate Preference.
 */
typedef struct
{
    UCHAR preference; /**< Preference value. */
} wifi_BSSTransitionCandidatePreference_t;

/**
 * @brief Bearing information.
 */
typedef struct
{
    USHORT bearing; /**< Bearing. */
    UINT dist; /**< Distance. */
    USHORT height; /**< Height. */
} wifi_Bearing_t;

/**
 * @brief Wide Bandwidth Channel Element.
 *
 * This structure represents the Wide Bandwidth Channel Element (ID = 194),
 * as defined in 802.11-2016 section 9.4.2.161.
 */
typedef struct
{
    UCHAR bandwidth; /**< Bandwidth. */
    UCHAR centerSeg0; /**< Center segment 0. */
    UCHAR centerSeg1; /**< Center segment 1. */
} wifi_WideBWChannel_t;

/**
 * @brief Measurement information.
 * Wide Bandwidth Channel Element, ID = 194.  802.11-2016 section 9.4.2.161.
 */
typedef struct
{
    UCHAR token; /**< Token. */
    UCHAR mode; /**< Mode. */
    UCHAR type; /**< Type. */
    union
    {
        UCHAR lci; /**< Location Configuration Information (LCI). */
        UCHAR lcr; /**< Location Civic Report (LCR). */
    } u;
} wifi_Measurement_t;

/**
 * @brief HT Capabilities Element.
 *
 * This structure represents the HT Capabilities Element (ID = 45), as defined
 * in 802.11-2016 section 9.4.2.56.
 */
typedef struct
{
    USHORT info; /**< Information field (bitfield). */
    UCHAR ampduParams; /**< AMPDU parameters. */
    UCHAR mcs[16]; /**< MCS set (bitfield). */
    USHORT extended; /**< Extended capabilities (bitfield). */
    UINT txBeamCaps; /**< Transmit beamforming capabilities (bitfield). */
    UCHAR aselCaps; /**< Antenna selection capabilities. */
} wifi_HTCapabilities_t;

/**
 * @brief VHT Capabilities Element.
 *
 * This structure represents the VHT Capabilities Element (ID = 191), as
 * defined in 802.11-2016 section 9.4.2.158.
 */
typedef struct
{
    UINT   info;                   /**< Information field. */
    USHORT mcs;                    /**< Supported VHT-MCS and NSS Set (part 1). */
    USHORT rxHighestSupportedRate; /**< Supported VHT-MCS and NSS Set (part 2). */
    USHORT txVHTmcs;               /**< Supported VHT-MCS and NSS Set (part 3). */
    USHORT txHighestSupportedRate; /**< Supported VHT-MCS and NSS Set (part 4). */
} wifi_VHTCapabilities_t;

/**
 * @brief HT Operation Element.
 *
 * This structure represents the HT Operation Element (ID = 61), as defined in
 * 802.11-2016 section 9.4.2.57.
 */
typedef struct
{
    UCHAR primary; /**< Primary channel. */
    UCHAR opInfo[5]; /**< Operating information (bitfield). */
    UCHAR mcs[16]; /**< MCS set. */
} wifi_HTOperation_t;

/**
 * @brief VHT Operation Element.
 *
 * This structure represents the VHT Operation Element (ID = 192), as defined
 * in 802.11-2016 section 9.4.2.159.
 */
typedef struct
{
    wifi_WideBWChannel_t opInfo; /**< Operating information (channel width, center of segment 0, center of segment 1). */
    USHORT mcs_nss; /**< MCS and NSS set (bitfield). */
} wifi_VHTOperation_t;

/**
 * @brief Secondary Channel Offset Element.
 *
 * This structure represents the Secondary Channel Offset Element (ID = 62),
 * as defined in 802.11-2016 section 9.4.2.20.
 */
typedef struct
{
    UCHAR secondaryChOffset; /**< Secondary channel offset. */
} wifi_SecondaryChannelOffset_t;

/**
 * @brief RM Enabled Capabilities Element.
 *
 * This structure represents the RM Enabled Capabilities Element (ID = 70),
 * as defined in 802.11-2016 section 9.4.2.45.
 */
typedef struct
{
    UCHAR capabilities[5]; /**< Capabilities (bitfield). */
} wifi_RMEnabledCapabilities_t;

/**
 * @brief Vendor Specific Element.
 *
 * This structure represents the Vendor Specific Element (ID = 221), as
 * defined in 802.11-2016 section 9.4.2.26.
 */
typedef struct
{
    UCHAR oui[5]; /**< 3 or 5 octet OUI, depending on the format. */
    UCHAR buff[MAX_VENDOR_SPECIFIC]; /**< Vendor-specific content. */
} wifi_VendorSpecific_t;

/**
 * @brief Measurement Pilot Transmission Element.
 *
 * This structure represents the Measurement Pilot Transmission Element
 * (ID = 66), as defined in 802.11-2016 section 9.4.2.42.
 */
typedef struct
{
    UCHAR pilot; /**< Pilot value. */
    wifi_VendorSpecific_t vendorSpecific; /**< Vendor-specific subelement. */
} wifi_MeasurementPilotTransmission_t;

/**
 * @brief Neighbor Report.
 */
typedef struct
{
    bssid_t bssid; /**< BSSID. */
    //  32 bit optional value, bit fileds are
    //  b0, b1 for reachability
    //  b2 security
    //  b3 key scope
    //  b4 to b9 capabilities
    //  b10 mobility domain
    //  b11 high troughput
    //  b12 very high throughput
    //  b13 ftm
    //  b14 to b31 reserved
    UINT info; /**< Information field (32-bit optional value, bitfields are defined as follows). */
    UCHAR opClass; /**< Operating class. */
    UCHAR channel; /**< Channel number. */
    UCHAR phyTable; /**< PHY table. */
    BOOL tsfPresent; /**< Whether the TSF Information field is present. */
    wifi_TSFInfo_t tsfInfo; /**< TSF information. */
    BOOL condensedCountrySringPresent; /**< Whether the Condensed Country String field is present. */
    wifi_CondensedCountryString_t condensedCountryStr; /**< Condensed Country String. */
    BOOL bssTransitionCandidatePreferencePresent; /**< Whether the BSS Transition Candidate Preference field is present. */
    wifi_BSSTransitionCandidatePreference_t bssTransitionCandidatePreference; /**< BSS Transition Candidate Preference. */
    BOOL btmTerminationDurationPresent; /**< Whether the BTM Termination Duration field is present. */
    wifi_BTMTerminationDuration_t btmTerminationDuration; /**< BTM Termination Duration. */
    BOOL bearingPresent; /**< Whether the Bearing field is present. */
    wifi_Bearing_t bearing; /**< Bearing information. */
    BOOL wideBandWidthChannelPresent; /**< Whether the Wide Bandwidth Channel field is present. */
    wifi_WideBWChannel_t wideBandwidthChannel; /**< Wide Bandwidth Channel information. */
    BOOL htCapsPresent; /**< Whether the HT Capabilities field is present. */
    wifi_HTCapabilities_t htCaps; /**< HT Capabilities. */
    BOOL vhtCapsPresent; /**< Whether the VHT Capabilities field is present. */
    wifi_VHTCapabilities_t vbhtCaps; /**< VHT Capabilities. */
    BOOL htOpPresent; /**< Whether the HT Operation field is present. */
    wifi_HTOperation_t htOp; /**< HT Operation. */
    BOOL vhtOpPresent; /**< Whether the VHT Operation field is present. */
    wifi_VHTOperation_t vhtOp; /**< VHT Operation. */
    BOOL secondaryChannelOffsetPresent; /**< Whether the Secondary Channel Offset field is present. */
    wifi_SecondaryChannelOffset_t secondaryChannelOffset; /**< Secondary Channel Offset. */
    BOOL rmEnabledCapsPresent; /**< Whether the RM Enabled Capabilities field is present. */
    wifi_RMEnabledCapabilities_t rmEnabledCaps; /**< RM Enabled Capabilities. */
    BOOL msmtPilotTransmissionPresent; /**< Whether the Measurement Pilot Transmission field is present. */
    wifi_MeasurementPilotTransmission_t msmtPilotTransmission; /**< Measurement Pilot Transmission. */
    BOOL vendorSpecificPresent; /**< Whether the Vendor Specific field is present. */
    wifi_VendorSpecific_t vendorSpecific; /**< Vendor Specific information. */
    ssid_t target_ssid; /**< Target SSID. */
} wifi_NeighborReport_t;

/**
 * @brief BSS Transition Management Request Frame.
 *
 * This structure represents the BSS Transition Management Request Frame, as
 * defined in 802.11-2016 section 9.6.14.9.
 */
typedef struct
{
    UCHAR token; /**< Set by the STA to relate reports. */
    UCHAR requestMode; /**< Requested instructions for the STA. */
    USHORT timer; /**< Timer value. */
    UCHAR validityInterval; /**< Validity interval. */
    // The optional fields may include:
    // 1. BSS Termination Duration Subelement, ID = 4. 802.11-2016 Figure 9-300.
    // 2. Session Information URL.
    // 3. BSS Transition Candidate List Entries
    wifi_BTMTerminationDuration_t termDuration; /**< BSS Termination Duration subelement. */
    UCHAR disassociationImminent; /**< Whether disassociation is imminent. */
    USHORT urlLen; /**< Length of the URL. */
    CHAR url[MAX_URL_LEN]; /**< URL. */
    UCHAR numCandidates; /**< Number of candidates. */
    wifi_NeighborReport_t candidates[MAX_CANDIDATES]; /**< Candidate APs. */
} wifi_BTMRequest_t;

/**
 * @brief BSS Transition Management Query Frame.
 *
 * This structure represents the BSS Transition Management Query Frame, as
 * defined in 802.11-2016 section 9.6.14.8.
 */
typedef struct
{
    UCHAR token; /**< Set by the STA to relate reports. */
    UCHAR queryReason; /**< Reason for the query. */
    UCHAR numCandidates; /**< Number of candidates. */
    wifi_NeighborReport_t candidates[MAX_CANDIDATES]; /**< Candidate APs. */
} wifi_BTMQuery_t;

/**
 * @brief BSS Transition Management Response Frame.
 *
 * This structure represents the BSS Transition Management Response Frame, as
 * defined in 802.11-2016 section 9.6.14.10.
 */
typedef struct
{
    UCHAR token; /**< Set by the STA to relate reports. */
    UCHAR status; /**< Status code. */
    UCHAR terminationDelay; /**< Termination delay. */
    bssid_t target; /**< Target BSSID. */
    UCHAR numCandidates; /**< Number of candidates. */
    wifi_NeighborReport_t candidates[MAX_CANDIDATES]; /**< Candidate APs. */
} wifi_BTMResponse_t;

/**
 * @brief Neighbor Request Frame.
 *
 * This structure represents the Neighbor Request Frame, as defined in
 * 802.11-2016 section 9.6.7.6.
 */
typedef struct
{
    UCHAR token; /**< Set by the STA to relate reports. */
    UCHAR ssidLen; /**< Length of the SSID (0 if not present). */
    ssid_t ssid; /**< SSID. */
    UCHAR measCount; /**< Number of measurements. */
    wifi_Measurement_t measurements[2]; /**< Measurements. */
} wifi_NeighborRequestFrame_t;

// 802.11k Beacon request & report structures and function prototypes
/**
 * @brief Maximum number of requested elements in a beacon report.
 */
#define MAX_REQUESTED_ELEMS 8

/**
 * @brief Maximum number of channels in a channel report.
 */
#define MAX_CHANNELS_REPORT 16

/**
 * @brief Beacon reporting configuration.
 */
typedef struct
{
    UCHAR condition; /**< Reporting condition. */
    UCHAR threshold; /**< Reporting threshold. */
} wifi_BeaconReporting_t;

/**
 * @brief Requested element IDs.
 */
typedef struct
{
    UCHAR ids[MAX_REQUESTED_ELEMS]; /**< Array of element IDs. */
} wifi_RequestedElementIDS_t;

/**
 * @brief Extended requested element IDs.
 */
typedef wifi_RequestedElementIDS_t wifi_ExtdRequestedElementIDS_t;

/**
 * @brief AP Channel Report Element.
 *
 * This structure represents the AP Channel Report Element (ID = 51), as
 * defined in 802.11-2016 section 9.4.2.36.
 */
typedef struct
{
    UCHAR opClass; /**< Operating class. */
    UCHAR channels[MAX_CHANNELS_REPORT]; /**< Channel list. */
} wifi_ChannelReport_t;

/**
 * @brief Beacon Request.
 *
 * This structure represents the Beacon Request frame, as defined in
 * 802.11-2016 section 9.4.2.21.7.
 */
typedef struct
{
    UCHAR opClass; /**< Operating class. */
    UCHAR channel; /**< Channel number. */
    USHORT randomizationInterval; /**< Randomization interval. */
    USHORT duration; /**< Duration. */
    UCHAR mode; /**< Mode. */
    bssid_t bssid; /**< BSSID. */
    BOOL ssidPresent; /**< Whether the SSID field is present. */
    ssid_t ssid; /**< SSID. */
    BOOL beaconReportingPresent; /**< Whether the Beacon Reporting Detail field is present. */
    wifi_BeaconReporting_t beaconReporting; /**< Beacon reporting configuration. */
    BOOL reportingRetailPresent; /**< Whether the Reporting Detail field is present. */
    UCHAR reportingDetail; /**< Reporting detail. */
    BOOL wideBandWidthChannelPresent; /**< Whether the Wide Bandwidth Channel field is present. */
    wifi_WideBWChannel_t wideBandwidthChannel; /**< Wide Bandwidth Channel information. */
    BOOL requestedElementIDSPresent; /**< Whether the Requested Element IDs field is present. */
    wifi_RequestedElementIDS_t requestedElementIDS; /**< Requested element IDs. */
    BOOL extdRequestedElementIDSPresent; /**< Whether the Extended Requested Element IDs field is present. */
    wifi_ExtdRequestedElementIDS_t extdRequestedElementIDS; /**< Extended requested element IDs. */
    BOOL channelReportPresent; /**< Whether the Channel Report field is present. */
    wifi_ChannelReport_t channelReport; /**< Channel report. */
    BOOL vendorSpecificPresent; /**< Whether the Vendor Specific field is present. */
    wifi_VendorSpecific_t vendorSpecific; /**< Vendor Specific information. */
    USHORT numRepetitions; /**< Number of repetitions. */
} wifi_BeaconRequest_t;

/**
 * @brief Beacon Report.
 *
 * This structure represents the Beacon Report frame, as defined in
 * 802.11-2016 section 9.4.2.22.7.
 */
typedef struct
{
    UCHAR opClass; /**< Operating class. */
    UCHAR channel; /**< Channel number. */
    ULLONG startTime; /**< Start time. */
    USHORT duration; /**< Duration. */
    UCHAR frameInfo; /**< Frame information. */
    UCHAR rcpi; /**< Received Channel Power Indicator (RCPI). */
    UCHAR rsni; /**< Received Signal to Noise Indicator (RSNI). */
    bssid_t bssid; /**< BSSID. */
    UCHAR antenna; /**< Antenna ID. */
    UINT tsf; /**< Timing Synchronization Function (TSF) value. */
    BOOL wideBandWidthChannelPresent; /**< Whether the Wide Bandwidth Channel field is present. */
    wifi_WideBWChannel_t wideBandwidthChannel; /**< Wide Bandwidth Channel information. */
    USHORT numRepetitions; /**< Number of repetitions. */
} wifi_BeaconReport_t;
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */

/**
 * @brief Gets radio channel statistics.
 * 
 * This function retrieves the utilization status of the specified radio 
 * channels. The `input_output_channelStats_array` is used to specify the 
 * channels of interest and to store the retrieved statistics.
 * 
 * When `array_size` is 0, the function returns ONCHAN statistics in a single 
 * `wifi_channelStats_t` element. Otherwise, the `input_output_channelStats_array` 
 * should be pre-filled with the channel numbers to query, and the function will 
 * fill the corresponding elements with the channel statistics.
 * 
 * This function should be non-blocking.
 *
 * @param[in] radioIndex              The index of the radio.
 * @param[in,out] input_output_channelStats_array The array of channel statistics.
 * @param[in] array_size              The size of the `input_output_channelStats_array`.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array, INT array_size);

/**
 * @brief Gets the per-rate receive statistics for an associated device.
 *
 * This function retrieves the receive statistics for an associated client
 * on the specified radio, broken down by rate. The statistics are returned
 * in the `stats_array`, which is allocated by the HAL and should be freed
 * by the caller.
 * 
 * This function should be non-blocking.
 *
 * @param[in] radioIndex          The index of the radio array.
 * @param[in] clientMacAddress    The MAC address of the client.
 * @param[out] stats_array         Pointer to a pointer to an array of
 *                                 `wifi_associated_dev_rate_info_rx_stats_t`
 *                                 structures to store the receive statistics.
 * @param[out] output_array_size   Pointer to a variable to store the size of
 *                                 the returned array.
 * @param[out] handle              Pointer to a status validation handle used
 *                                 to determine reconnections. This handle is
 *                                 incremented for every association.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_rx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle);

/**
 * @brief Gets the per-rate transmit statistics for an associated device.
 *
 * This function retrieves the transmit statistics for an associated client
 * on the specified radio, broken down by rate. The statistics are returned
 * in the `stats_array`, which is allocated by the HAL and should be freed
 * by the caller.
 * 
 * This function should be non-blocking.
 *
 * @param[in] radioIndex          The index of the radio array.
 * @param[in] clientMacAddress    The MAC address of the client.
 * @param[out] stats_array         Pointer to a pointer to an array of
 *                                 `wifi_associated_dev_rate_info_tx_stats_t`
 *                                 structures to store the transmit statistics.
 * @param[out] output_array_size   Pointer to a variable to store the size of
 *                                 the returned array.
 * @param[out] handle              Pointer to a status validation handle used
 *                                 to determine reconnections. This handle is
 *                                 incremented for every association.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle);

/**
 * @brief Gets the TID statistics for an associated device.
 *
 * This function retrieves the TID (Traffic Identifier) statistics for an
 * associated client on the specified radio.
 * 
 * This function should be non-blocking.
 *
 * @param[in] radioIndex        The index of the radio array.
 * @param[in] clientMacAddress  The MAC address of the client.
 * @param[out] tid_stats        Pointer to a `wifi_associated_dev_tid_stats_t`
 *                             structure to store the TID statistics.
 * @param[in] handle           Status validation handle used to determine
 *                             reconnections, incremented for every association.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDeviceTidStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_tid_stats_t *tid_stats, ULLONG *handle);

/**
 * @brief Gets the statistics for an associated device.
 *
 * This function retrieves the statistics for an associated client on the
 * specified Access Point.
 * 
 * This function should be non-blocking.
 *
 * @param[in] apIndex              The index of the Access Point array.
 * @param[in] clientMacAddress     The MAC address of the client.
 * @param[out] associated_dev_stats Pointer to a
 *                                   `wifi_associated_dev_stats_t` structure to
 *                                   store the device statistics.
 * @param[in] handle               Status validation handle used to determine
 *                                 reconnections. This handle is incremented for
 *                                 every association.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDeviceStats(INT apIndex, mac_address_t *clientMacAddress, wifi_associated_dev_stats_t *associated_dev_stats, ULLONG *handle);

/**
 * @brief Gets the radio index associated with an SSID.
 *
 * This function retrieves the index of the radio associated with the
 * specified SSID entry.
 * 
 * This function should be non-blocking.
 *
 * @param[in] ssidIndex  SSID index.
 * @param[out] radioIndex Pointer to a variable to store the radio index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex);

/**
 * @brief Applies SSID and AP settings to the hardware.
 *
 * This function applies the SSID and AP (in the case of Access Point
 * devices) settings to the hardware.
 * 
 * This function should be non-blocking.
 *
 * @param[in] ssidIndex SSID index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_applySSIDSettings(INT ssidIndex);

/**
 * @brief Starts a neighbor scan.
 *
 * @param[in] apIndex    The index of the Access Point array.
 * @param[in] scan_mode  Scan mode.
 * @param[in] dwell_time Amount of time spent on each channel in the hopping
 *                       sequence.
 * @param[in] chan_num   The channel number.
 * @param[in] chan_list  List of channels.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list);

/**
 * @brief Sets the CSA deauthentication mode for an AP.
 *
 * This function sets the Channel Switch Announcement (CSA) deauthentication
 * mode for the specified Access Point. This mode determines how the AP will
 * deauthenticate clients before switching to a new channel, in the event that
 * some clients do not support or react to CSA.
 *
 * @param[in] apIndex The index of the Access Point array.
 * @param[in] mode    Enum value indicating the deauthentication mode:
 *                    0 = none,
 *                    1 = unicast,
 *                    2 = broadcast.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApCsaDeauth(INT apIndex, INT mode);

/**
 * @brief Enables or disables the scan filter in the driver.
 *
 * When the scan filter is enabled, two values are configured:
 *   - `enable`: Whether the filter is enabled (true/false).
 *   - `essid`: The ESSID to filter on.
 *
 * When `essid` is blank (`apIndex` is -1), the configured SSID on the
 * interface is used. When `essid` is not empty (`apIndex` is 0 to 15), the
 * filter will apply to the provided ESSID.
 *
 * @param[in] apIndex The index of the Access Point array.
 * @param[in] mode    Whether the filter is disabled or enabled.
 * @param[in] essid   The ESSID to filter on.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApScanFilter(INT apIndex, INT mode, CHAR *essid);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Adds a steering group.
 *
 * This function adds a steering group, which defines a group of Access Points
 * (APs) that can have steering done between them.
 *
 * @param[in] steeringGroupIndex The index of the steering group.
 * @param[in] numElements        The number of elements in the `cfgArray`.
 * @param[in] cfgArray           The array of `wifi_steering_apConfig_t`
 *                               structures, containing the settings for each
 *                               AP in the group.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_steering_setGroup(UINT steeringGroupIndex, UINT numElements, wifi_steering_apConfig_t *cfgArray);
#endif

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
 
/**
 * @brief Wi-Fi steering types.
 */
typedef enum
{
    pre_assoc_probe_block, /**< Pre-association probe block. */
    pre_assoc_assoc_block, /**< Pre-association association block. */
    post_assoc_idle_80211v, /**< Post-association idle 802.11v steering. */
    post_assoc_idle_kick_mac, /**< Post-association idle kick MAC steering. */
    post_assoc_active_80211v, /**< Post-association active 802.11v steering. */
    post_assoc_active_kickmac, /**< Post-association active kick MAC steering. */
} wifi_steer_type_t;

/**
 * @brief Wi-Fi steering matching condition.
 */
typedef unsigned int wifi_steer_matching_condition_t;

/**
 * @brief Wi-Fi steering trigger data.
 */
typedef struct
{
    CHAR *module; /**< Module name. */
    mac_address_t sta_mac; /**< Station MAC address. */
    mac_address_t src_bss; /**< Source BSS MAC address. */
    mac_address_t dst_bss; /**< Destination BSS MAC address. */
    wifi_steer_type_t type; /**< Steering type. */
    wifi_steer_matching_condition_t cond; /**< Matching condition. */
} wifi_steer_trigger_data_t;

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
 
/**
 * @brief Wi-Fi steering triggered callback function.
 *
 * @param[in] apIndex Index of the Access Point.
 * @param[in] data    Pointer to the steering trigger data.
 *
 * @returns The status of the operation.
 */
typedef INT (*wifi_steerTriggered_callback)(INT apIndex, wifi_steer_trigger_data_t *data);
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Registers a callback function for steering triggered events.
 *
 * @param[in] callback_proc Pointer to the callback function to register.
 * @param[in] module        Module name.
 */
void wifi_steerTriggered_callback_register(wifi_steerTriggered_callback callback_proc, CHAR *module);

/**
 * @brief Wi-Fi steering event callback function.
 *
 * @param[in] steeringgroupIndex Steering group index.
 * @param[in] event              Pointer to the steering event.
 */
typedef void (*wifi_steering_eventCB_t)(UINT steeringgroupIndex, wifi_steering_event_t *event);

/**
 * @brief Registers for steering event callbacks.
 *
 * @param[in] event_cb Pointer to the callback function to register.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb);

/**
 * @brief Unregisters for steering event callbacks.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_steering_eventUnregister(void);

/**
 * @brief Adds or modifies client configuration for an AP.
 *
 * @param[in] steeringgroupIndex Steering group index.
 * @param[in] apIndex            Access Point index.
 * @param[in] client_mac         Client MAC address.
 * @param[in] config             Pointer to the client configuration.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config);

/**
 * @brief Removes client configuration from an AP.
 *
 * @param[in] steeringgroupIndex Steering group index.
 * @param[in] apIndex            Access Point index.
 * @param[in] client_mac         Client MAC address.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac);

/**
 * @brief Initiates an instant client RSSI measurement.
 *
 * This function initiates an instant client RSSI measurement. The recommended
 * method of performing this measurement is to send five NULL Wi-Fi frames to
 * the client and average the RSSI of the ACK frames returned. This averaged
 * RSSI value should be sent back using the `WIFI_STEERING_EVENT_RSSI`
 * steering event type.
 *
 * Instant measurement improves user experience by not reacting to
 * false-positive RSSI crossings.
 *
 * @param[in] steeringgroupIndex Steering group index.
 * @param[in] apIndex            Access Point index.
 * @param[in] client_mac         Client MAC address.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK  If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_steering_clientMeasure(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac);

/**
 * @brief Initiates a client disconnect.
 *
 * @param[in] steeringgroupIndex Steering group index.
 * @param[in] apIndex            Access Point index.
 * @param[in] client_mac         Client MAC address.
 * @param[in] type               Disconnect type.
 * @param[in] reason             Reason code to provide in the deauthentication
 *                               or disassociation frame.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK  If successful.
 * @retval RETURN_ERR If any error is detected.
 *
 * @see https://supportforums.cisco.com/document/141136/80211-association-status-80211-deauth-reason-codes
 */
INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
*/

#ifdef WIFI_HAL_VERSION_3_PHASE2

/**
 * @brief Callback function invoked when a STA sends a BTM query.
 *
 * This callback function is invoked when a STA sends a BTM query message to a
 * VAP in the gateway. The driver will use the frame returned from this
 * function to process the response to the query. A BTM transaction is started
 * by a STA sending a query or by the AP sending an autonomous request. This
 * callback is used for the former.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] peerMac The MAC address of the peer STA the query was received
 *                    from.
 * @param[in] query A pointer to a `wifi_BTMQuery_t` structure containing the
 *                  BTM query frame received from the STA.
 * @param[in] inMemSize The size of the memory allocated by the callback for
 *                      the `request` parameter. The caller should set this to
 *                      the maximum size for the request, otherwise the
 *                      callback may drop elements or return an error.
 * @param[out] request A pointer to a `wifi_BTMRequest_t` structure to be
 *                     populated with the BTM request frame to send in
 *                     response to the query. The caller allocates the memory
 *                     for the response. The caller may free the memory when
 *                     the callback returns and the response is sent to the
 *                     STA.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
typedef INT (*wifi_BTMQueryRequest_callback)(UINT apIndex,
                                                    mac_address_t peerMac,
                                                    wifi_BTMQuery_t *query,
                                                    UINT inMemSize,
                                                    wifi_BTMRequest_t *request);

/**
 * @brief Callback function invoked when a STA responds to a BTM request.
 *
 * This callback function is invoked when a STA responds to a BTM request from
 * the gateway.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] peerMac The MAC address of the peer the response was received
 *                    from.
 * @param[in] response A pointer to a `wifi_BTMResponse_t` structure
 *                     containing the BTM response frame received from the STA.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
typedef INT (*wifi_BTMResponse_callback)(UINT apIndex,
                                            mac_address_t peerMac,
                                            wifi_BTMResponse_t *response);

#else

/**
 * @brief Callback function invoked when a STA sends a BTM query.
 *
 * This callback function is invoked when a STA sends a BTM query message to a
 * VAP in the gateway. The driver will use the frame returned from this
 * function to process the response to the query. A BTM transaction is started
 * by a STA sending a query or by the AP sending an autonomous request. This
 * callback is used for the former.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] peerMac The MAC address of the peer STA the query was received
 *                    from.
 * @param[in] query A pointer to a `wifi_BTMQuery_t` structure containing the
 *                  BTM query frame received from the STA.
 * @param[in] inMemSize The size of the memory allocated by the callback for
 *                      the `request` parameter. The caller should set this to
 *                      the maximum size for the request, otherwise the
 *                      callback may drop elements or return an error.
 * @param[out] request A pointer to a `wifi_BTMRequest_t` structure to be
 *                     populated with the BTM request frame to send in
 *                     response to the query. The caller allocates the memory
 *                     for the response. The caller may free the memory when
 *                     the callback returns and the response is sent to the
 *                     STA.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
typedef INT (*wifi_BTMQueryRequest_callback)(UINT apIndex,
                                                    CHAR *peerMac,
                                                    wifi_BTMQuery_t *query,
                                                    UINT inMemSize,
                                                    wifi_BTMRequest_t *request);

/**
 * @brief Callback function invoked when a STA responds to a BTM request.
 *
 * This callback function is invoked when a STA responds to a BTM request from
 * the gateway.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] peerMac The MAC address of the peer the response was received
 * from.
 * @param[in] response A pointer to a `wifi_BTMResponse_t` structure
 *                     containing the BTM response frame received from the STA.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
typedef INT (*wifi_BTMResponse_callback)(UINT apIndex,
                                            CHAR *peerMac,
                                            wifi_BTMResponse_t *response);
#endif

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Registers a callback function for BTM queries.
 *
 * @param[in] apIndex            Access Point index.
 * @param[in] btmQueryCallback  Pointer to the callback function for BTM queries.
 * @param[in] btmResponseCallback Pointer to the callback function for BTM
 *                                responses.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_BTMQueryRequest_callback_register(UINT apIndex, wifi_BTMQueryRequest_callback btmQueryCallback, wifi_BTMResponse_callback btmResponseCallback);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Sends a BTM request to a non-AP STA.
 *
 * @param[in] apIndex  Access Point index.
 * @param[in] peerMac  MAC address of the peer STA.
 * @param[in] request  Pointer to the BTM request frame to send.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBTMRequest(UINT apIndex, mac_address_t peerMac, wifi_BTMRequest_t *request);
#endif

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
 
/**
 * @brief Callback function invoked when a STA responds to a Beacon Request.
 * 
 * This callback function is invoked when a station (STA) responds to a Beacon 
 * Request from the gateway, or as a triggered autonomous report. 
 * 
 * An autonomous report can be configured by a Beacon Request by setting the 
 * enable, request, and report bits in the measurement request, as described in 
 * 802.11-2016 Table 9-81 and section 11.11.8. 
 * 
 * When a triggered autonomous report causes the callback to be invoked, the 
 * dialog token and measurement token are both set to 0.
 *
 * @param[in] apIndex      Access Point index.
 * @param[out] out_struct  Pointer to a `wifi_BeaconReport_t` structure to store
 *                         the beacon report.
 * @param[out] out_array_size Pointer to a variable to store the size of the
 *                         beacon report array.
 * @param[out] out_DialogToken Pointer to a variable to store the dialog token.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
typedef INT (*wifi_RMBeaconReport_callback)(UINT apIndex,
                                            wifi_BeaconReport_t *out_struct,
                                            UINT *out_array_size,
                                            UCHAR *out_DialogToken);
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
 
/**
 * @brief Registers a callback function for Beacon Requests.
 *
 * @param[in] apIndex              Access Point index.
 * @param[in] beaconReportCallback Pointer to the callback function to register.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_RMBeaconRequestCallbackRegister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback);

/**
 * @brief Unregisters a callback function for Beacon Requests.
 *
 * @param[in] apIndex              Access Point index.
 * @param[in] beaconReportCallback Pointer to the callback function to unregister.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_RMBeaconRequestCallbackUnregister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback);

/**
 * @brief Cancels a pending radio measurement beacon request.
 *
 * @param[in] apIndex     Access Point index.
 * @param[in] dialogToken Dialog token of the request to cancel.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_cancelRMBeaconRequest(UINT apIndex, UCHAR dialogToken);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Sends a radio measurement beacon request.
 *
 * This function sends a radio measurement beacon request to a peer STA. The
 * request is sent based on the information in the `in_request` parameter.
 * Returns an error if a callback has not been registered for the AP.
 *
 * @param[in] apIndex        Index of the VAP to send the request from.
 * @param[in] peer           MAC address of the peer device to send the request to.
 * @param[in] in_request     Pointer to a `wifi_BeaconRequest_t` structure containing the beacon request information.
 * @param[out] out_DialogToken Pointer to a variable to store the dialog token chosen by the STA.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK  If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_setRMBeaconRequest(UINT apIndex,
                            mac_address_t peer,
                            wifi_BeaconRequest_t *in_request,
                            UCHAR *out_DialogToken);

/**
 * @brief Gets the Radio Measurement capabilities of a peer device.
 *
 * @param[in] peer            MAC address of the peer device.
 * @param[out] out_Capabilities Pointer to an array to store the capabilities, as defined in 802.11-2016
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRMCapabilities(mac_address_t peer, UCHAR out_Capabilities[5]);
#endif

/** @} */  //END OF GROUP WIFI_HAL_APIS

#ifdef __cplusplus
}
#endif

#endif //__WIFI_HAL_EXTENDER_H__