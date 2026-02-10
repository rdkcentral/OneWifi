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
#ifndef __WIFI_HAL_RADIO_H__
#define __WIFI_HAL_RADIO_H__

#ifdef __cplusplus
extern "C"{
#endif

#include "wifi_hal_ap.h"

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Guard interval types.
 */
typedef enum
{
    wifi_guard_interval_400 = 0x01,   /**< 400ns guard interval. */
    wifi_guard_interval_800 = 0x02,   /**< 800ns guard interval. */
    wifi_guard_interval_1600 = 0x04,  /**< 1600ns guard interval. */
    wifi_guard_interval_3200 = 0x08,  /**< 3200ns guard interval. */
    wifi_guard_interval_auto = 0x10,  /**< Automatic guard interval selection. */
} wifi_guard_interval_t;

/**
 * @brief Maximum number of secondary channels.
 */
#define MAXNUMSECONDARYCHANNELS 7
#define MAX_NUM_CHANNELBANDWIDTH_SUPPORTED  6

/**
 * @brief Radar event types.
 */
typedef enum
{
    WIFI_EVENT_RADAR_DETECTED,       /**< Radar detected. */
    WIFI_EVENT_RADAR_CAC_FINISHED,   /**< Radar Channel Availability Check (CAC) finished. */
    WIFI_EVENT_RADAR_CAC_ABORTED,    /**< Radar CAC aborted. */
    WIFI_EVENT_RADAR_NOP_FINISHED,   /**< Radar Non-Occupancy Period (NOP) finished. */
    WIFI_EVENT_RADAR_PRE_CAC_EXPIRED, /**< Radar pre-CAC expired. */
    WIFI_EVENT_RADAR_CAC_STARTED     /**< Radar CAC started. */
} wifi_radar_eventType_t;

/**
 * @brief Channel states.
 */
typedef enum
{
    CHAN_STATE_AVAILABLE = 1,        /**< Channel is available. */
    CHAN_STATE_DFS_NOP_FINISHED,     /**< DFS NOP finished. */
    CHAN_STATE_DFS_NOP_START,       /**< DFS NOP started. */
    CHAN_STATE_DFS_CAC_START,       /**< DFS CAC started. */
    CHAN_STATE_DFS_CAC_COMPLETED    /**< DFS CAC completed. */
} wifi_channelState_t;

/**
 * @brief Channel map entry.
 */
typedef struct _wifi_channelMap_t
{
    INT ch_number;              /**< Channel number. */
    wifi_channelState_t ch_state; /**< Channel state. */
} wifi_channelMap_t;

/**
 * @brief Radio 11be puncturing information.
 */
typedef struct
{
    USHORT punct_bitmap; /**< A bitmap of disabled 20MHz channels. */
    UCHAR punct_acs_threshold; /**< Puncturing ACS threshold. */
} __attribute__((packed)) wifi_radio_11be_puncturing_info_t;

/**
 * @brief Maximum number of non operable channels in a channel.
 * (TODO: Name to be changed in future revisions of interface for
 * readability)
 */
#define MAXNUMNONOPERABLECHANNELS 10

/**
 * @brief Maximum number of operating classes in a band.
 * (TODO: Name to be changed in future revisions of interface for
 * readability)
 */
#define MAXNUMOPERCLASSESPERBAND 20

/**
 * @brief Operating Classes information.
 *
 * Structure that holds information of the operating class,
 * such as maximum transmit power, array of non-operable channel
 * associated with that operating class.
 */
typedef struct
{
    UINT opClass;                                /**< Global operating Class value */
    INT maxTxPower;                              /**< Max Tx Power */
    UINT numberOfNonOperChan;                    /**< Number of Nonoperable channels */
    UINT nonOperable[MAXNUMNONOPERABLECHANNELS]; /**< Array of Non Operable channel value */
} __attribute__((packed)) wifi_operating_classes_t;

/**
 * @brief Radio temperature information.
 *
 * Structure that holds the radio temperature information.
 */
typedef struct _wifi_radioTemperature_t
{
    UINT radio_Temperature; /**< Wi-Fi radio chipset temperature. */
} wifi_radioTemperature_t;

/**
 * @brief Wi-Fi radio operation parameters.
 *
 * This structure contains the operation parameters for a Wi-Fi radio.
 */
typedef struct 
{
    BOOL enable;                /**< Whether the radio is enabled. */
    wifi_freq_bands_t band;    /**< The radio frequency band. */
    BOOL autoChannelEnabled;     /**< Whether auto channel selection is enabled. */
    UINT channel;               /**< The radio primary channel. */
    UINT numSecondaryChannels;  /**< The number of secondary channels in the list. */
    UINT channelSecondary[MAXNUMSECONDARYCHANNELS]; /**< The list of secondary radio channels. */
    wifi_channelBandwidth_t channelWidth; /**< The channel bandwidth. */
    wifi_ieee80211Variant_t variant; /**< The radio operating mode. */
    UINT csa_beacon_count; /**< Specifies how long Channel Switch Announcement (CSA) needs to be announced. */
    wifi_countrycode_type_t countryCode; /**< The country code. */
    UINT regDomain; /**< The regulatory domain. */
    wifi_operating_env_t operatingEnvironment; /**< The Wi-Fi operating environment. */
    wifi_channelMap_t channel_map[64]; /**< Channel map. */
    BOOL DCSEnabled; /**< Whether Dynamic Channel Selection (DCS) is enabled. */
    UINT dtimPeriod; /**< The DTIM period. */
    UINT beaconInterval; /**< The beacon interval. */
    UINT operatingClass; /**< The operating class. */
    UINT basicDataTransmitRates; /**< The basic data transmit rates in Mbps. It uses bitmask to return multiple bitrates and wifi_bitrate_t has the definition of valid values. */
    UINT operationalDataTransmitRates; /**< The operational data transmit rates in Mbps. It uses bitmask to return multiple bitrates and wifi_bitrate_t has the definition of valid values. */
    UINT fragmentationThreshold; /**< The fragmentation threshold in bytes. */
    wifi_guard_interval_t guardInterval; /**< The guard interval. */
    UINT transmitPower; /**< The transmit power in percentage, e.g., "75", "100". */
    UINT rtsThreshold; /**< The packet size threshold in bytes to apply RTS/CTS backoff rules. */
    BOOL factoryResetSsid; /**< Whether to factory reset the SSID. */
    UINT radioStatsMeasuringRate; /**< The rate at which radio statistics are measured. */
    UINT radioStatsMeasuringInterval; /**< The interval at which radio statistics are measured. */
    BOOL ctsProtection; /**< Whether CTS protection is enabled. */
    BOOL obssCoex; /**< Whether OBSS coex is enabled. */
    BOOL stbcEnable; /**< Whether STBC is enabled. */
    BOOL greenFieldEnable; /**< Whether greenfield is enabled. */
    UINT userControl; /**< User control. */
    UINT adminControl; /**< Admin control. */
    UINT chanUtilThreshold; /**< Channel utilization threshold. */
    BOOL chanUtilSelfHealEnable; /**< Whether channel utilization self-healing is enabled. */
    BOOL DfsEnabled; /**< Whether DFS is enabled. */
    BOOL DfsEnabledBootup; /**< Whether DFS is enabled on bootup. */
    BOOL EcoPowerDown; /**< Whether eco power down is enabled. */
    wifi_radio_11be_puncturing_info_t puncturingInfo; /**< Puncturing information. */
    UINT autoChanRefreshPeriod; /**< Auto channel refresh period. */
    INT mcs; /**< MCS index. */
    BOOL amsduEnable; /**< Whether AMSDU is enabled. */
    UINT DFSTimer; /**< DFS timer. */
    char radarDetected[256]; /**< Radar detected information. */
    BOOL acs_keep_out_reset; /**< ACS Keep Out Channels list to be reset */
    wifi_channels_list_per_bandwidth_t  channels_per_bandwidth[MAX_NUM_CHANNELBANDWIDTH_SUPPORTED]; /**< All the channel list for a particular channel bandwidth */
    UINT numOperatingClasses; /**< Number of valid operating classes in the array operatingClasses */
    wifi_operating_classes_t operatingClasses[MAXNUMOPERCLASSESPERBAND]; /**< Array of supported Operating classes as per Data elements Schema */
} __attribute__((packed)) wifi_radio_operationParam_t;

/**
 * @brief Enhanced Distributed Channel Access (EDCA) parameters.
 */
typedef struct
{
    CHAR aifsn; /**< Arbitration Inter-Frame Space (AIFS) number. */
    CHAR cw_min; /**< Minimum contention window size. */
    CHAR cw_max; /**< Maximum contention window size. */
    CHAR timer; /**< Timer value. */
} wifi_edca_t;

/**
 * @brief Downlink data acknowledgement types.
 */
typedef enum
{
    wifi_dl_data_ack_immediate, /**< Immediate acknowledgement. */
    wifi_dl_data_block_ack_immediate, /**< Immediate block acknowledgement. */
    wifi_dl_data_block_ack_deferred, /**< Deferred block acknowledgement. */
} wifi_dl_data_ack_type_t;

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Gets the radio reset count.
 *
 * This function retrieves the number of times the specified radio has been reset.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio channel.
 * @param[out] output_int Pointer to a variable to store the reset count.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioResetCount(INT radioIndex, ULONG *output_int);

/**
 * @brief Resets all radios to factory defaults.
 *
 * This function restores all radio parameters to their factory default values,
 * without affecting Access Point parameters.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_factoryResetRadios();

/**
 * @brief Resets a specific radio to factory defaults.
 *
 * This function restores the specified radio's parameters to their factory
 * default values, without affecting Access Point parameters.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_factoryResetRadio(int radioIndex);

/**
 * @brief Gets the radio enable status.
 *
 * This function retrieves the enabled/disabled status of the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio channel.
 * @param[out] output_bool Pointer to a variable to store the radio enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Sets the radio enable status.
 *
 * This function enables or disables the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[in] enable    Whether to enable or disable the radio.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the radio operational status.
 *
 * This function retrieves the operational status of the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio channel.
 * @param[out] output_bool Pointer to a variable to store the radio operational status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool);

/**
 * @brief Gets the radio interface name.
 *
 * This function retrieves the interface name of the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex    Index of the Wi-Fi radio channel.
 * @param[out] output_string Pointer to a buffer to store the interface name.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Gets the list of channels currently in use by a radio.
 *
 * This function retrieves a list of channels currently in use by the
 * specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio.
 * @param[out] channel_list Pointer to a `wifi_channels_list_t` structure to store
 *                          the list of channels.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioChannelsInUse(wifi_radio_index_t radioIndex, wifi_channels_list_t* channel_list);
#endif

/**
 * @brief Gets the DFS enable status for a radio.
 *
 * This function retrieves whether Dynamic Frequency Selection (DFS) is enabled
 * for the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio channel.
 * @param[out] output_bool Pointer to a variable to store the DFS enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Sets the DFS enable status for a radio.
 *
 * This function sets whether Dynamic Frequency Selection (DFS) is enabled for
 * the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[in] enable    Whether to enable or disable DFS.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enabled);

/**
 * @brief Gets the DFS enable on bootup status for a radio.
 *
 * This function retrieves whether Dynamic Frequency Selection (DFS) is enabled
 * on bootup for the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[out] enable    Pointer to a variable to store the DFS enable on bootup
 *                       status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioDfsAtBootUpEnable(INT radioIndex, BOOL *enable);

/**
 * @brief Sets the DFS enable on bootup status for a radio.
 *
 * This function sets whether Dynamic Frequency Selection (DFS) is enabled on
 * bootup for the specified radio.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[in] enable    Whether to enable or disable DFS on bootup.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the Modulation Coding Scheme (MCS) index for a radio.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio channel.
 * @param[out] output_INT Pointer to a variable to store the MCS index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioMCS(INT radioIndex, INT *output_INT);

/**
 * @brief Sets the Modulation Coding Scheme (MCS) index for a radio.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[in] MCS        MCS index to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioMCS(INT radioIndex, INT MCS);

/**
 * @brief Gets the current transmit power for a radio.
 *
 * This function retrieves the current transmit power for the specified radio,
 * in dBm units.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio channel.
 * @param[out] output_ulong Pointer to a variable to store the transmit power
 *                          in dBm.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong);

/**
 * @brief Gets the current transmit power for a radio as a percentage.
 *
 * This function retrieves the current transmit power for the specified radio,
 * as a percentage of the full power.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex  Index of the Wi-Fi radio channel.
 * @param[out] output_ulong Pointer to a variable to store the transmit power
 *                          percentage.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioPercentageTransmitPower(INT radioIndex, ULONG *output_ulong);

/**
 * @brief Sets the transmit power for a radio.
 *
 * This function sets the transmit power for the specified radio, as a
 * percentage of the full power.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex    Index of the Wi-Fi radio channel.
 * @param[in] TransmitPower Transmit power to set, as a percentage.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower);

/**
 * @brief Gets the carrier sense threshold range for a radio.
 *
 * This function retrieves the carrier sense threshold range supported by the
 * specified radio, in dBm.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[out] output     Pointer to a variable to store the carrier sense
 *                        threshold range.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output);

/**
 * @brief Gets the carrier sense threshold in use for a radio.
 *
 * This function retrieves the RSSI signal level at which the radio's
 * CS/CCA (Carrier Sense/Clear Channel Assessment) detects a busy condition.
 * This attribute enables Access Points to increase minimum sensitivity to
 * avoid detecting a busy condition from multiple/weak Wi-Fi sources in dense
 * Wi-Fi environments.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[out] output     Pointer to a variable to store the carrier sense
 *                        threshold in use, in dBm.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output);

/**
 * @brief Sets the carrier sense threshold in use for a radio.
 *
 * This function sets the RSSI signal level at which the radio's CS/CCA
 * (Carrier Sense/Clear Channel Assessment) detects a busy condition.
 * This attribute enables Access Points to increase minimum sensitivity to
 * avoid detecting a busy condition from multiple/weak Wi-Fi sources in dense
 * Wi-Fi environments.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[in] threshold  Carrier sense threshold to set, in dBm.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold);

/**
 * @brief Applies the radio settings.
 *
 * This function applies all previously set radio-level variables and makes
 * these settings active in the hardware.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_applyRadioSettings(INT radioIndex);

/**
 * @brief Enables or disables OBSS Coexistence for a radio.
 *
 * This function enables or disables OBSS (Overlapping Basic Service Set)
 * Coexistence for the radio used by the specified Access Point. If enabled,
 * the radio will fall back to a 20MHz channel width if necessary to avoid
 * interference with neighboring BSSs.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex Index of the Access Point.
 * @param[in] enable  Whether to enable or disable OBSS Coexistence.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable);

/**
 * @brief Sets the fragmentation threshold for a radio.
 *
 * This function sets the fragmentation threshold, in bytes, for the radio
 * used by the specified Access Point.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the radio.
 * @param[in] threshold  Fragmentation threshold to set, in bytes.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioFragmentationThreshold(INT radioIndex, UINT threshold);

/**
 * @brief Enables or disables Space-Time Block Coding (STBC) for a radio.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[in] STBC_Enable Whether to enable or disable STBC.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable);

/**
 * @brief Gets the A-MSDU enable status for a radio.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[out] output_bool Pointer to a variable to store the A-MSDU enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables Aggregated-MSDU (A-MSDU) for a radio.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[in] amsduEnable Whether to enable or disable A-MSDU.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable);

/**
 * @brief Gets the radio uptime.
 *
 * This function retrieves the number of seconds that have elapsed since the
 * specified radio was started.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] radioIndex Index of the radio.
 * @param[out] uptime    Pointer to a variable to store the radio uptime, in seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioUpTime(INT radioIndex, ULONG *uptime);

/**
 * @brief Checks whether Reverse Direction Grant (RDG) is supported by a radio.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[out] output_bool Pointer to a variable to store whether RDG is supported.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioReverseDirectionGrantSupported(INT radioIndex, BOOL *output_bool);

/**
 * @brief Gets the auto block ACK enable status for a radio.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[out] output_bool Pointer to a variable to store the auto block ACK enable
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Sets the auto block ACK enable status for a radio.
 *
 * @param[in] radioIndex Index of the radio.
 * @param[in] enable     Whether to enable or disable auto block ACK.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the IGMP snooping enable status for a radio.
 *
 * @param[in] radioIndex  Index of the radio.
 * @param[out] output_bool Pointer to a variable to store the IGMP snooping enable
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Sets the IGMP snooping enable status for a radio.
 *
 * @param[in] radioIndex Index of the radio.
 * @param[in] enable     Whether to enable or disable IGMP snooping.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable);

/**
 * @brief Sets the Zero DFS state for a radio.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio.
 * @param[in] enabled    Whether to enable Zero DFS.
 * @param[in] precac     Whether to enable pre-CAC (valid only for the EU
 *                       regulatory domain).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setZeroDFSState(UINT radioIndex, BOOL enable, BOOL precac);

/**
 * @brief Gets the Zero DFS state for a radio.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio.
 * @param[out] enabled    Pointer to a variable to store the Zero DFS enable status.
 * @param[out] precac     Pointer to a variable to store the pre-CAC enable status
 *                        (valid only for the EU regulatory domain).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getZeroDFSState(UINT radioIndex, BOOL *enable, BOOL *precac);

/* 802.11ax HAL API prototypes */

/**
 * @brief Sets the downlink MU-MIMO type for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[in] mu_type     Downlink MU-MIMO type to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setDownlinkMuType(INT radio_index, wifi_dl_mu_type_t mu_type);

/**
 * @brief Gets the downlink MU-MIMO type for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[out] mu_type    Pointer to a variable to store the downlink MU-MIMO type.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getDownlinkMuType(INT radio_index, wifi_dl_mu_type_t *mu_type);

/**
 * @brief Sets the uplink MU-MIMO type for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[in] mu_type     Uplink MU-MIMO type to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setUplinkMuType(INT radio_index, wifi_ul_mu_type_t mu_type);

/**
 * @brief Gets the uplink MU-MIMO type for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[out] mu_type    Pointer to a variable to store the uplink MU-MIMO type.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getUplinkMuType(INT radio_index, wifi_ul_mu_type_t *mu_type);

/**
 * @brief Sets the guard interval for a radio.
 *
 * @param[in] radio_index    Index of the radio.
 * @param[in] guard_interval Guard interval to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setGuardInterval(INT radio_index, wifi_guard_interval_t guard_interval);

/**
 * @brief Gets the guard interval for a radio.
 *
 * @param[in] radio_index    Index of the radio.
 * @param[out] guard_interval Pointer to a variable to store the guard interval.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getGuardInterval(INT radio_index, wifi_guard_interval_t *guard_interval);

/**
 * @brief Sets the BSS color for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[in] color       BSS color to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBSSColor(INT radio_index, UCHAR color);

/**
 * @brief Gets the BSS color for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[out] color      Pointer to a variable to store the BSS color.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBSSColor(INT radio_index, UCHAR *color);

/**
 * @brief Gets the list of available BSS colors for a radio.
 *
 * @param[in] radio_index      Index of the Wi-Fi radio.
 * @param[in] maxNumberColors  Maximum number of colors that can be returned.
 * @param[out] colorList        Pointer to an array to store the available BSS colors.
 * @param[out] numColorReturned Pointer to a variable to store the number of colors
 *                             returned in the list.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getAvailableBSSColor(INT radio_index, INT maxNumberColors, UCHAR* colorList, INT *numColorReturned);

/**
 * @brief Gets the MU EDCA parameter for a radio.
 *
 * @param[in] radio_index Index of the Wi-Fi radio.
 * @param[in] ac          Access category.
 * @param[out] edca        Pointer to a `wifi_edca_t` structure to store the MU EDCA
 *                         parameters.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getMuEdca(INT radio_index, wifi_access_category_t ac, wifi_edca_t *edca);

/**
 * @brief Sets the downlink data acknowledgement type for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[in] ack_type    Acknowledgement type to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setDownlinkDataAckType(INT radio_index, wifi_dl_data_ack_type_t ack_type);

/**
 * @brief Gets the 802.11ax default parameters for a radio.
 *
 * @param[in] radio_index Index of the radio.
 * @param[out] params     Pointer to a `wifi_80211ax_params_t` structure to store the
 *                        802.11ax default parameters.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_get80211axDefaultParameters(INT radio_index, wifi_80211ax_params_t *params);

/////////////////////////// tri radio definitions /////////////////////////////////

/**
 * @brief Sets the radio operating parameters.
 *
 * This function configures all radio operating parameters in a single set,
 * including channel number, channel width, mode, and auto channel configuration.
 *
 * @param[in] index         Index of the Wi-Fi radio.
 * @param[in] operationParam Pointer to a `wifi_radio_operationParam_t` structure
 *                          containing the radio operating parameters to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);

/**
 * @brief Gets the radio operating parameters.
 *
 * @param[in] index         Index of the Wi-Fi radio.
 * @param[out] operationParam Pointer to a `wifi_radio_operationParam_t` structure to
 *                          store the radio operating parameters.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);

/**
 * @brief Gets scan results.
 *
 * @param[in] index    Index of the radio.
 * @param[in] channel  Pointer to a `wifi_channel_t` structure containing the channel
 *                     to scan.
 * @param[out] bss     Pointer to a pointer to an array of `wifi_bss_info_t`
 *                     structures to store the scan results.
 * @param[out] num_bss Pointer to a variable to store the number of BSSs found.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR If any error is detected.
 */
INT wifi_getScanResults(wifi_radio_index_t index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss);

/**
 * @brief Callback function invoked when scan results are available.
 *
 * @param[in] index    Index of the radio.
 * @param[out] bss     Pointer to a pointer to an array of `wifi_bss_info_t`
 *                     structures to store the scan results.
 * @param[out] num_bss Pointer to a variable to store the number of BSSs found.
 *
 * @returns The status of the operation. (TODO: Need to set return values)
 */
typedef INT ( * wifi_scanResults_callback)(wifi_radio_index_t index, wifi_bss_info_t **bss, UINT *num_bss);

/**
 * @brief Registers a callback function for scan results.
 *
 * @param[in] callback_proc Pointer to the callback function to register.
 */
void wifi_scanResults_callback_register(wifi_scanResults_callback callback_proc);

/**
 * @brief Gets the radio temperature.
 *
 * @param[in] radioIndex    Index of the Wi-Fi radio channel.
 * @param[out] output_struct Pointer to a `wifi_radioTemperature_t` structure to store
 *                           the radio temperature information.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_hal_getRadioTemperature(wifi_radio_index_t radioIndex, wifi_radioTemperature_t *output_struct);


/** @} */  //END OF GROUP WIFI_HAL_APIS

#ifdef __cplusplus
}
#endif

#endif
