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
#ifndef __WIFI_HAL_TELEMETRY_H__
#define __WIFI_HAL_TELEMETRY_H__

#ifdef __cplusplus
extern "C"{
#endif

#include "wifi_hal_generic.h"
/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Wi-Fi radio traffic statistics.
 */
typedef struct _wifi_radioTrafficStats2
{
    ULONG radio_BytesSent;             /**< The total number of bytes transmitted out of the interface, including framing characters. */
    ULONG radio_BytesReceived;         /**< The total number of bytes received on the interface, including framing characters. */
    ULONG radio_PacketsSent;           /**< The total number of packets transmitted out of the interface. */
    ULONG radio_PacketsReceived;       /**< The total number of packets received on the interface. */
    ULONG radio_ErrorsSent;            /**< The total number of outbound packets that could not be transmitted because of errors. */
    ULONG radio_ErrorsReceived;        /**< The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol. */
    ULONG radio_DiscardPacketsSent;     /**< The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG radio_DiscardPacketsReceived; /**< The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG radio_PLCPErrorCount;        /**< The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error. */
    ULONG radio_FCSErrorCount;         /**< The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012]. */
    ULONG radio_InvalidMACCount;       /**< The number of packets that were received with a detected invalid MAC header error. */
    ULONG radio_PacketsOtherReceived;  /**< The number of packets that were received, but which were destined for a MAC address that is not associated with this interface. */
    INT   radio_NoiseFloor;            /**< The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0). Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm */
    ULONG radio_ChannelUtilization;     /**< Percentage of time the channel was occupied by the radio's own activity (Activity Factor) or the activity of other radios. Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc. The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval". The calculation of this metric MUST only use the data collected from the just completed interval. If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage */
    INT   radio_ActivityFactor;       /**< Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc. The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval". The calculation of this metric MUST only use the data collected from the just completed interval. If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage */
    INT   radio_CarrierSenseThreshold_Exceeded; /**< Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval". The calculation of this metric MUST only use the data collected from the just completed interval. If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage */
    INT   radio_RetransmissionMetirc;   /**< Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one. The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval". The calculation of this metric MUST only use the data collected from the just completed interval. If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in percentage */
    INT   radio_MaximumNoiseFloorOnChannel; /**< Maximum Noise on the channel during the measuring interval. The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval". The calculation of this metric MUST only use the data collected in the just completed interval. If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm */
    INT   radio_MinimumNoiseFloorOnChannel; /**< Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval". The calculation of this metric MUST only use the data collected in the just completed interval. If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm */
    INT   radio_MedianNoiseFloorOnChannel;  /**< Median Noise on the channel during the measuring interval. The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval". The calculation of this metric MUST only use the data collected in the just completed interval. If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm */
    ULONG radio_StatisticsStartTime;     /**< The date and time at which the collection of the current set of statistics started. This time must be updated whenever the radio statistics are reset. */
} wifi_radioTrafficStats2_t;

/**
 * @brief Wi-Fi SSID traffic statistics.
 */
typedef struct _wifi_ssidTrafficStats2
{
    ULONG ssid_BytesSent;              /**< The total number of bytes transmitted out of the interface, including framing characters. */
    ULONG ssid_BytesReceived;          /**< The total number of bytes received on the interface, including framing characters. */
    ULONG ssid_PacketsSent;            /**< The total number of packets transmitted out of the interface. */
    ULONG ssid_PacketsReceived;        /**< The total number of packets received on the interface. */
    ULONG ssid_RetransCount;           /**< The total number of transmitted packets which were retransmissions. Two retransmissions of the same packet results in this counter incrementing by two. */
    ULONG ssid_FailedRetransCount;      /**< The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit. This parameter is based on dot11FailedCount from [802.11-2012]. */
    ULONG ssid_RetryCount;             /**< The number of packets that were successfully transmitted after one or more retransmissions. This parameter is based on dot11RetryCount from [802.11-2012]. */
    ULONG ssid_MultipleRetryCount;    /**< The number of packets that were successfully transmitted after more than one retransmission. This parameter is based on dot11MultipleRetryCount from [802.11-2012]. */
    ULONG ssid_ACKFailureCount;         /**< The number of expected ACKs that were never received. This parameter is based on dot11ACKFailureCount from [802.11-2012]. */
    ULONG ssid_AggregatedPacketCount;  /**< The number of aggregated packets that were transmitted. This applies only to 802.11n and 802.11ac. */
    ULONG ssid_ErrorsSent;            /**< The total number of outbound packets that could not be transmitted because of errors. */
    ULONG ssid_ErrorsReceived;        /**< The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol. */
    ULONG ssid_UnicastPacketsSent;    /**< The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol. */
    ULONG ssid_UnicastPacketsReceived; /**< The total number of received packets, delivered by this layer to a higher layer, which were not addressed to a multicast or broadcast address at this layer. */
    ULONG ssid_DiscardedPacketsSent;   /**< The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG ssid_DiscardedPacketsReceived; /**< The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG ssid_MulticastPacketsSent;   /**< The total number of packets that higher-level protocols requested for transmission and which were addressed to a multicast address at this layer, including those that were discarded or not sent. */
    ULONG ssid_MulticastPacketsReceived; /**< The total number of received packets, delivered by this layer to a higher layer, which were addressed to a multicast address at this layer. */
    ULONG ssid_BroadcastPacketsSent;   /**< The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent. */
    ULONG ssid_BroadcastPacketsRecevied; /**< The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent. */
    ULONG ssid_UnknownPacketsReceived;  /**< The total number of packets received via the interface which were discarded because of an unknown or unsupported protocol. */
} wifi_ssidTrafficStats2_t;

/**
 * @brief Neighboring Access Point information.
 * Do not edit the elements for this data structure 
 */
typedef struct _wifi_neighbor_ap2
{
    CHAR ap_SSID[64];               /**< The current Service Set Identifier (SSID) in use by the neighboring Wi-Fi AP. The value may be empty for hidden SSIDs. */
    CHAR ap_BSSID[64];              /**< The BSSID used for the neighboring Wi-Fi SSID. */
    CHAR ap_Mode[64];               /**< The mode the neighboring Wi-Fi radio is operating in. Enumeration of: AdHoc, Infrastructure. */
    UINT ap_Channel;                /**< The current radio channel used by the neighboring Wi-Fi radio. */
    INT ap_SignalStrength;           /**< An indicator of radio signal strength (RSSI) of the neighboring Wi-Fi radio measured in dBm, as an average of the last 100 packets received. */
    CHAR ap_SecurityModeEnabled[64];  /**< The type of encryption the neighboring Wi-Fi SSID advertises. Enumeration of: None, WPA-WPA2 etc. */
    CHAR ap_EncryptionMode[64];       /**< Comma-separated list of strings. The type of encryption the neighboring Wi-Fi SSID advertises. Each list item is an enumeration of: TKIP, AES. */
    CHAR ap_OperatingFrequencyBand[16]; /**< Indicates the frequency band at which the radio this SSID instance is operating. Enumeration of: 2.4GHz, 5GHz. */
    CHAR ap_SupportedStandards[64];   /**< Comma-separated list of strings. List items indicate which IEEE 802.11 standards this instance can support simultaneously, in the frequency band specified by ap_OperatingFrequencyBand. */
    CHAR ap_OperatingStandards[16];   /**< Comma-separated list of strings. Each list item MUST be a member of the list reported by the ap_SupportedStandards parameter. List items indicate which IEEE 802.11 standard that is detected for this instance. */
    CHAR ap_OperatingChannelBandwidth[16]; /**< Indicates the bandwidth at which the channel is operating. */
    UINT ap_BeaconPeriod;             /**< Time interval (in ms) between transmitting beacons. */
    INT ap_Noise;                    /**< Indicator of average noise strength (in dBm) received from the neighboring Wi-Fi radio. */
    CHAR ap_BasicDataTransferRates[256]; /**< Comma-separated list (maximum list length 256) of strings. Basic data transmit rates (in Mbps) for the SSID. For example, if ap_BasicDataTransferRates is "1,2", this indicates that the SSID is operating with basic rates of 1 Mbps and 2 Mbps. */
    CHAR ap_SupportedDataTransferRates[256]; /**< Comma-separated list (maximum list length 256) of strings. Data transmit rates (in Mbps) for unicast frames at which the SSID will permit a station to connect. For example, if ap_SupportedDataTransferRates is "1,2,5.5", this indicates that the SSID will only permit connections at 1 Mbps, 2 Mbps and 5.5 Mbps. */
    UINT ap_DTIMPeriod;               /**< The number of beacon intervals that elapse between transmission of Beacon frames containing a TIM element whose DTIM count field is 0. This value is transmitted in the DTIM Period field of beacon frames. [802.11-2012] */
    UINT ap_ChannelUtilization;       /**< Indicates the fraction of the time the AP senses that the channel is in use by the neighboring AP for transmissions. */
    UINT ap_freq;                        /**< Frequency. */
} wifi_neighbor_ap2_t;

/*    Explanation:
                             these are actually 3 host-endian integers
                            in this example they are big-endian because
                             the piranha's host cpu is big-endian MIPS
                                    _____________|____________
                                   /             |            \
                                  |              |            |
                             _____|______    ____|____    ____|_____
                            |            |  |         |  |          |
     ap1       glastackrssi:75  74  73  77  2  3  68  1  0  0  0  136
                            ^^^^^^^^^^^^^^  ^^^^^^^^^^^  ^^^^^^^^^^^^
                                  |              |            |
                         last 4 rssi values      |      sample counter
                                                 |
                                         last 4 rssi's age
    
                                the "77" rssi is 1 second old
                                         ______|______
                                        /             \
                                        |             |
     ap1       glastackrssi:75  74  73  77  2  3  68  1  0  0  0  136
                                     |             |
                                     \____________/
                                           |
                                 the 2nd most recent rssi of "73"
                                 is 68 seconds old *in relation*
                                 to the 1st ("77") therefore it is
                                 68 + 1 seconds old *now*   */
/**
 * @brief RSSI snapshot.
 */
typedef struct _wifi_rssi_snapshot
{
    UCHAR  rssi[4];    /**< Last 4 RSSI values received. These are host-endian integers.
                         *   In this example, they are big-endian because the CPU is big-endian MIPS. */
    UCHAR  time_s[4];  /**< Relative age of the last 4 RSSI values, in seconds.
                         *   These are host-endian integers.
                         *   In this example, they are big-endian because the CPU is big-endian MIPS. */
    USHORT count;      /**< Sequence number of received management (beacon, ACK) frames. */
} wifi_rssi_snapshot_t;

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Access Point RSSI information.
 */
typedef struct _wifi_apRssi
{
    CHAR ap_BSSID[6]; /**< BSSID. */
    wifi_channelBandwidth_t ap_channelWidth; /**< The channel width; 1 for 20MHz, 2 for 40MHz, 4 for 80MHz, 8 for 160MHz, 10 for 80+80MHz. */
    INT ap_rssi; /**< RSSI of the neighboring AP in dBm. */
} wifi_apRssi_t;
#else
/**
 * @brief Access Point RSSI information.
 */
typedef struct _wifi_apRssi
{
    CHAR ap_BSSID[6]; /**< BSSID. */
    UINT ap_channelWidth; /**< The channel width; 1 for 20MHz, 2 for 40MHz, 4 for 80MHz, 8 for 160MHz, 10 for 80+80MHz. */
    INT ap_rssi; /**< RSSI of the neighboring AP in dBm. */
} wifi_apRssi_t;
#endif

// VAP telemetry report structures and function prototypes
/**
 * @brief Maximum number of VAPs.
 */
#define MAX_VAP (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)

/**
 * @brief VAP telemetry information.
 *
 * Structure that holds the VAP telemetry information.
 */
typedef struct
{
    UINT txOverflow; /**< Wi-Fi TX overflow counter. */
} wifi_VAPTelemetry_t;

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */

/**
 * @brief Gets detailed radio traffic statistics.
 *
 * This function retrieves detailed traffic statistics for the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex    Index of the Wi-Fi radio channel.
 * @param[out] output_struct Pointer to a `wifi_radioTrafficStats2_t` structure
 *                           to store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *output_struct);

/**
 * @brief Gets basic SSID traffic statistics.
 *
 * This function retrieves basic traffic statistics for the specified SSID.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] ssidIndex     SSID index.
 * @param[out] output_struct Pointer to a `wifi_ssidTrafficStats2_t` structure to
 *                           store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getSSIDTrafficStats2(INT ssidIndex, wifi_ssidTrafficStats2_t *output_struct);


#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Gets neighboring Wi-Fi status.
 *
 * This function retrieves the status of neighboring Wi-Fi networks.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex        Radio index.
 * @param[in] scan              Whether to start a neighbor scan.
 * @param[out] neighbor_ap_array Pointer to a pointer to an array of
 *                               `wifi_neighbor_ap2_t` structures to store the
 *                               neighboring AP information.
 * @param[out] output_array_size Pointer to a variable to store the size of the
 *                               returned array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getNeighboringWiFiStatus(INT radioIndex, BOOL scan, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);
#endif

/**
 * @brief Gets the radio band utilization.
 *
 * This function retrieves the utilization of the radio band as a percentage.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex         Radio index.
 * @param[out] output_percentage Pointer to a variable to store the utilization
 *                               percentage.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioBandUtilization (INT radioIndex, INT *output_percentage);

/**
 * @brief Gets diagnostic results for all associated devices on an Access Point.
 *
 * @param[in] apIndex              Index of the Access Point.
 * @param[out] associated_dev_array Pointer to a pointer to an array of
 *                                   `wifi_associated_dev3_t` structures to store
 *                                   the diagnostic results.
 * @param[out] output_array_size    Pointer to a variable to store the size of the
 *                                   returned array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Gets diagnostic results for a specific associated client on an Access Point.
 *
 * @param[in] apIndex    Index of the Access Point.
 * @param[in] mac_addr   MAC address of the associated client.
 * @param[out] dev_conn  Pointer to a `wifi_associated_dev3_t` structure to store
 *                       the diagnostic results.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedClientDiagnosticResult(INT apIndex, mac_address_t mac_addr, wifi_associated_dev3_t *dev_conn);
#endif

/**
 * @brief Enables or disables the collection of detailed statistics for associated clients.
 *
 * This function enables or disables the collection of detailed statistics
 * for clients associated with the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[in] enable      Whether to enable (true) or disable (false) the collection
 *                        of detailed statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setClientDetailedStatisticsEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the radio statistics enable status.
 *
 * This function retrieves the enable status of radio statistics collection.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex    Index of the radio.
 * @param[out] output_enable Pointer to a variable to store the enable status
 *                           (true if enabled, false if disabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioStatsEnable(INT radioIndex, BOOL *output_enable);

/**
 * @brief Enables or disables radio statistics collection.
 *
 * This function enables or disables the collection of radio statistics.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[in] enable      Whether to enable (true) or disable (false) radio statistics
 *                        collection.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioStatsEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets VAP telemetry data.
 *
 * @param[in] apIndex   Access Point index.
 * @param[out] telemetry Pointer to a `wifi_VAPTelemetry_t` structure to store the
 *                       VAP telemetry data.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getVAPTelemetry(UINT apIndex, wifi_VAPTelemetry_t *telemetry);

/** @} */  //END OF GROUP WIFI_HAL_APIS

#ifdef __cplusplus
}
#endif

#endif