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

/**********************************************************************

    module: wifi_hal.h

        For CCSP Component:  Wifi_Provisioning_and_management

    ---------------------------------------------------------------

    description:

        This header file gives the function call prototypes and 
        structure definitions used for the RDK-Broadband 
        Wifi radio hardware abstraction layer

    ---------------------------------------------------------------

    environment:

        This HAL layer is intended to support Wifi drivers 
        through an open API.  

    ---------------------------------------------------------------

    HAL version:

        The version of the Wifi HAL is specified in #defines below.

    --------------------------------------------------------------- 

    author:

        zhicheng_qiu@cable.comcast.com 
        Charles Moreman, moremac@cisco.com
		
    ---------------------------------------------------------------

	Notes:

	What is new for 2.2.0
	  1. Add Country Code support
	  2. Add more DCS function
	  3. Move RadiusSecret from struct wifi_radius_setting_t to wifi_getApSecurityRadiusServer function
	  4. Add wifi_getApSecuritySecondaryRadiusServer
	What is new for 2.2.1
	  1. Add wifi_setRadioTrafficStatsMeasure, wifi_setRadioTrafficStatsRadioStatisticsEnable
**********************************************************************/
/**
* @file wifi_hal_emu.h
* @author zhicheng_qiu@cable.comcast.com
* @brief For CCSP Component:  Wifi_Provisioning_and_management
*
* @description Wifi subsystem level APIs that are common to Client and Access Point devices. This HAL layer is intended to support Wifi drivers through an open API. This sample implementation file gives the function call prototypes and structure definitions used for the RDK-Broadband Wifi hardware abstraction layer.
* This header file gives the function call prototypes and structure definitions used for the RDK-Broadband Wifi radio hardware abstraction layer.
*/

#ifndef __WIFI_HAL_H__
#define __WIFI_HAL_H__

#ifndef ULONG
#define ULONG unsigned long /**< Unsigned long type. */
#endif

#ifndef BOOL
#define BOOL unsigned char /**< Boolean type. */
#endif

#ifndef CHAR
#define CHAR char /**< Character type. */
#endif

#ifndef UCHAR
#define UCHAR unsigned char /**< Unsigned character type. */
#endif

#ifndef INT
#define INT int /**< Integer type. */
#endif

#ifndef UINT
#define UINT unsigned int /**< Unsigned integer type. */
#endif

#ifndef TRUE
#define TRUE 1 /**< Boolean true value. */
#endif

#ifndef FALSE
#define FALSE 0 /**< Boolean false value. */
#endif

#ifndef ENABLE
#define ENABLE 1 /**< Enable value. */
#endif

#ifndef RETURN_OK
#define RETURN_OK 0 /**< Return value indicating success. */
#endif

#ifndef RETURN_ERR
#define RETURN_ERR -1 /**< Return value indicating an error. */
#endif

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

#ifndef RADIO_INDEX_1
#define RADIO_INDEX_1 1 /**< Radio index 1. */
#define RADIO_INDEX_2 2 /**< Radio index 2. */
#define AP_INDEX_1 1 /**< Access Point index 1. */
#define AP_INDEX_2 2 /**< Access Point index 2. */
#define AP_INDEX_3 3 /**< Access Point index 3. */
#define AP_INDEX_4 4 /**< Access Point index 4. */
#define AP_INDEX_5 5 /**< Access Point index 5. */
#define AP_INDEX_6 6 /**< Access Point index 6. */
#define AP_INDEX_7 7 /**< Access Point index 7. */
#define AP_INDEX_8 8 /**< Access Point index 8. */
#define AP_INDEX_9 9 /**< Access Point index 9. */
#define AP_INDEX_10 10 /**< Access Point index 10. */
#define AP_INDEX_11 11 /**< Access Point index 11. */
#define AP_INDEX_12 12 /**< Access Point index 12. */
#define AP_INDEX_13 13 /**< Access Point index 13. */
#define AP_INDEX_14 14 /**< Access Point index 14. */
#define AP_INDEX_15 15 /**< Access Point index 15. */
#define AP_INDEX_16 16 /**< Access Point index 16. */
#endif

/**
 * @brief Maximum length of a COSA DML alias name.
 */
#define COSA_DML_ALIAS_NAME_LENGTH 64

/**
 * @brief Maximum number of MAC filters.
 */
#define MAX_MAC_FILT 16

// Defines for HAL version 2.2.1
/**
 * @brief Wi-Fi HAL major version.
 */
#define WIFI_HAL_MAJOR_VERSION 2

/**
 * @brief Wi-Fi HAL minor version.
 */
#define WIFI_HAL_MINOR_VERSION 2

/**
 * @brief Wi-Fi HAL maintenance version.
 */
#define WIFI_HAL_MAINTENANCE_VERSION 1

/**
 * @brief Path to the hostapd configuration file.
 */
#define HOSTAPD_CONF_FILE_PATH "/etc/hostapd.conf"

/**
 * @brief Default file size.
 */
#define FILE_SIZE 1024

/**
 * @brief ASCII code for space.
 */
#define SPACE 32

/**
 * @brief ASCII code for new line.
 */
#define NEW_LINE 10

/**
 * @brief Buffer adjustment value.
 */
#define BUFFER_ADJUSTMENT 128

/**
 * @brief Word size.
 */
#define WORD_SIZE 50

/**
 * @brief Size of a MAC address.
 */
#define MACADDRESS_SIZE 6

/**********************************************************************
                STRUCTURE DEFINITIONS
**********************************************************************/

/**
 * @brief Host details.
 */
struct hostDetails
{
    char hostName[20]; /**< Host name. */
    char InterfaceType[50]; /**< Interface type. */
};

/**
 * @brief COSA DML Wi-Fi AP MAC filter.
 */
typedef struct _COSA_DML_WIFI_AP_MAC_FILTER
{
    ULONG InstanceNumber; /**< Instance number. */
    char Alias[COSA_DML_ALIAS_NAME_LENGTH]; /**< Alias. */
    char MACAddress[18]; /**< MAC address. */
    char DeviceName[64]; /**< Device name. */
} COSA_DML_WIFI_AP_MAC_FILTER;

//>> Deprecated: used for old RDKB code. 
// TODO: Review Required
/**
 * @brief Basic traffic statistics (deprecated).
 * @deprecated: used for old RDKB code.
 */
typedef struct _wifi_basicTrafficStats
{
    ULONG wifi_BytesSent; /**< Number of bytes sent. */
    ULONG wifi_BytesReceived; /**< Number of bytes received. */
    ULONG wifi_PacketsSent; /**< Number of packets sent. */
    ULONG wifi_PacketsReceived; /**< Number of packets received. */
    ULONG wifi_Associations; /**< Number of associations. */
} wifi_basicTrafficStats_t;

/**
 * @brief Traffic statistics.
 * @deprecated: used for old RDKB code.
 */
typedef struct _wifi_trafficStats
{
    ULONG wifi_ErrorsSent; /**< Number of errors sent. */
    ULONG wifi_ErrorsReceived; /**< Number of errors received. */
    ULONG wifi_UnicastPacketsSent; /**< Number of unicast packets sent. */
    ULONG wifi_UnicastPacketsReceived; /**< Number of unicast packets received. */
    ULONG wifi_DiscardedPacketsSent; /**< Number of discarded packets sent. */
    ULONG wifi_DiscardedPacketsReceived; /**< Number of discarded packets received. */
    ULONG wifi_MulticastPacketsSent; /**< Number of multicast packets sent. */
    ULONG wifi_MulticastPacketsReceived; /**< Number of multicast packets received. */
    ULONG wifi_BroadcastPacketsSent; /**< Number of broadcast packets sent. */
    ULONG wifi_BroadcastPacketsRecevied; /**< Number of broadcast packets received. */
    ULONG wifi_UnknownPacketsReceived; /**< Number of unknown packets received. */
} wifi_trafficStats_t;

/**
 * @brief Radio traffic statistics.
 * @deprecated: used for old RDKB code.
 */
typedef struct _wifi_radioTrafficStats
{
    ULONG wifi_ErrorsSent; /**< Number of errors sent. */
    ULONG wifi_ErrorsReceived; /**< Number of errors received. */
    ULONG wifi_DiscardPacketsSent; /**< Number of discarded packets sent. */
    ULONG wifi_DiscardPacketsReceived; /**< Number of discarded packets received. */
    ULONG wifi_PLCPErrorCount; /**< Number of PLCP errors. */
    ULONG wifi_FCSErrorCount; /**< Number of FCS errors. */
    ULONG wifi_InvalidMACCount; /**< Number of invalid MAC addresses. */
    ULONG wifi_PacketsOtherReceived; /**< Number of packets received from other devices. */
    INT wifi_Noise; /**< Noise level. */
} wifi_radioTrafficStats_t;

/**
 * @brief SSID traffic statistics.
 * @deprecated: used for old RDKB code.
 */
typedef struct _wifi_ssidTrafficStats
{
    ULONG wifi_RetransCount; /**< Number of retransmissions. */
    ULONG wifi_FailedRetransCount; /**< Number of failed retransmissions. */
    ULONG wifi_RetryCount; /**< Number of retries. */
    ULONG wifi_MultipleRetryCount; /**< Number of multiple retries. */
    ULONG wifi_ACKFailureCount; /**< Number of ACK failures. */
    ULONG wifi_AggregatedPacketCount; /**< Number of aggregated packets. */
} wifi_ssidTrafficStats_t;

/**
 * @brief Neighboring access point information.
 * @deprecated Used for old RDKB code.
 *
 * This structure contains information about a neighboring access point.
 */
typedef struct _wifi_neighbor_ap {
  CHAR ap_Radio[64];                     /**< Radio interface name. */
  CHAR ap_SSID[64];                      /**< Service Set Identifier (SSID). */
  CHAR ap_BSSID[64];                     /**< Basic Service Set Identifier (BSSID). */
  CHAR ap_Mode[64];                      /**< Operating mode (e.g., Infrastructure, Adhoc). */
  UINT ap_Channel;                      /**< Channel number. */
  INT ap_SignalStrength;               /**< Signal strength (e.g., in dBm). */
  CHAR ap_SecurityModeEnabled[64];     /**< Security mode enabled (e.g., WPA2-PSK). */
  CHAR ap_EncryptionMode[64];          /**< Encryption mode (e.g., CCMP). */
  CHAR ap_OperatingFrequencyBand[16];   /**< Operating frequency band (e.g., 2.4GHz). */
  CHAR ap_SupportedStandards[64];      /**< Supported standards (e.g., 802.11n). */
  CHAR ap_OperatingStandards[16];      /**< Operating standards (e.g., 802.11ac). */
  CHAR ap_OperatingChannelBandwidth[16]; /**< Channel bandwidth (e.g., 20MHz). */
  UINT ap_BeaconPeriod;                 /**< Beacon period in milliseconds. */
  INT ap_Noise;                         /**< Noise level (e.g., in dBm). */
  CHAR ap_BasicDataTransferRates[256];   /**< Basic data transfer rates. */
  CHAR ap_SupportedDataTransferRates[256]; /**< Supported data transfer rates. */
  UINT ap_DTIMPeriod;                    /**< Delivery Traffic Indication Message (DTIM) period. */
  UINT ap_ChannelUtilization;            /**< Channel utilization percentage. */
} wifi_neighbor_ap_t;
//<<

typedef struct _wifi_radioTrafficStats2
{
    ULONG radio_BytesSent;           /**< The total number of bytes transmitted out of the interface, including framing characters. */
    ULONG radio_BytesReceived;       /**< The total number of bytes received on the interface, including framing characters. */
    ULONG radio_PacketsSent;         /**< The total number of packets transmitted out of the interface. */
    ULONG radio_PacketsReceived;     /**< The total number of packets received on the interface. */

    ULONG radio_ErrorsSent;          /**< The total number of outbound packets that could not be transmitted because of errors. */
    ULONG radio_ErrorsReceived;      /**< The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol. */
    ULONG radio_DiscardPacketsSent;   /**< The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted.
                                             One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG radio_DiscardPacketsReceived; /**< The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered.
                                                One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG radio_PLCPErrorCount;      /**< The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.   */
    ULONG radio_FCSErrorCount;       /**< The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012]. */
    ULONG radio_InvalidMACCount;     /**< The number of packets that were received with a detected invalid MAC header error. */
    ULONG radio_PacketsOtherReceived;/**< The number of packets that were received, but which were destined for a MAC address that is not associated with this interface. */
    INT   radio_NoiseFloor;          /**< The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).
                                             Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded.
                                             Measured in dBm */
    ULONG radio_ChannelUtilization; /**< Percentage of time the channel was occupied by the radio's own activity (Activity Factor) or the activity of other radios.
                                            Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.
                                            The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".
                                            The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.
                                            Units in Percentage */
    INT   radio_ActivityFactor;     /**< Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients.
                                            Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.
                                            The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.
                                            If this metric is queried before it has been updated with an initial calculation, it MUST return -1.
                                            Units in Percentage */
    INT   radio_CarrierSenseThreshold_Exceeded; /**< Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA).
                                                     The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".
                                                     The calculation of this metric MUST only use the data collected from the just completed interval.
                                                     If this metric is queried before it has been updated with an initial calculation, it MUST return -1.
                                                     Units in Percentage */
    INT   radio_RetransmissionMetirc; /**< Percentage of packets that had to be re-transmitted.
                                            Multiple re-transmissions of the same packet count as one.
                                            The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".
                                            The calculation of this metric MUST only use the data collected from the just completed interval.
                                            If this metric is queried before it has been updated with an initial calculation, it MUST return -1.
                                            Units  in percentage */
    INT   radio_MaximumNoiseFloorOnChannel; /**< Maximum Noise on the channel during the measuring interval.
                                                 The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".
                                                 The calculation of this metric MUST only use the data collected in the just completed interval.
                                                 If this metric is queried before it has been updated with an initial calculation, it MUST return -1.
                                                 Units in dBm */
    INT   radio_MinimumNoiseFloorOnChannel; /**< Minimum Noise on the channel.
                                                 The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".
                                                 The calculation of this metric MUST only use the data collected in the just completed interval.
                                                 If this metric is queried before it has been updated with an initial calculation, it MUST return -1.
                                                 Units in dBm */
    INT   radio_MedianNoiseFloorOnChannel; /**< Median Noise on the channel during the measuring interval.  
                                                The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".
                                                The calculation of this metric MUST only use the data collected in the just completed interval.
                                                If this metric is queried before it has been updated with an initial calculation, it MUST return -1.
                                                Units in dBm */
    ULONG radio_StatisticsStartTime;    /**< The date and time at which the collection of the current set of statistics started.
                                             This time must be updated whenever the radio statistics are reset. */

} wifi_radioTrafficStats2_t;    //for radio only

typedef struct _wifi_radioTrafficStatsMeasure
{
    INT   radio_RadioStatisticsMeasuringRate;     /**< The rate at which radio related statistics are periodically collected.
                                                        Only statistics that explicitly indicate the use of this parameter MUST use the rate set in this parameter.
                                                        Other parameter's are assumed to collect data in real-time or nearly real-time. Default value is 30 seconds.
                                                        This parameter MUST be persistent across reboots. If this parameter is changed, then use of the new rate MUST be deferred until the start of the next interval and all metrics using this rate MUST return -1 until the completion of the next full interval.
                                                        Units in Seconds" */
    INT   radio_RadioStatisticsMeasuringInterval; /**< The interval for which radio data MUST be retained in order and at the end of which appropriate calculations are executed and reflected in the associated radio object's.
                                                        Only statistics that explicitly indicate the use of this parameter MUST use the interval set in this parameter.
                                                        Default value is 30 minutes.  This parameter MUST be persistent across reboots.
                                                        If this item is modified, then all metrics leveraging this interval as well as the metrics Total number 802.11 packet of TX and Total number 802.11 packet of RX MUST be re-initialized immediately.
                                                        Additionally, the Statistics Start Time must be reset to the current time.
                                                        Units in Seconds */
} wifi_radioTrafficStatsMeasure_t;  //for radio only


typedef struct _wifi_ssidTrafficStats2
{
    ULONG ssid_BytesSent;           /**< The total number of bytes transmitted out of the interface, including framing characters. */
    ULONG ssid_BytesReceived;       /**< The total number of bytes received on the interface, including framing characters. */
    ULONG ssid_PacketsSent;         /**< The total number of packets transmitted out of the interface. */
    ULONG ssid_PacketsReceived;     /**< The total number of packets received on the interface. */

    ULONG ssid_RetransCount;        /**< The total number of transmitted packets which were retransmissions. Two retransmissions of the same packet results in this counter incrementing by two. */
    ULONG ssid_FailedRetransCount;  /**< The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit.
                                          This parameter is based on dot11FailedCount from [802.11-2012]. */
    ULONG ssid_RetryCount;          /**< The number of packets that were successfully transmitted after one or more retransmissions.
                                          This parameter is based on dot11RetryCount from [802.11-2012]. */
    ULONG ssid_MultipleRetryCount;  /**< The number of packets that were successfully transmitted after more than one retransmission.
                                          This parameter is based on dot11MultipleRetryCount from [802.11-2012]. */
    ULONG ssid_ACKFailureCount;     /**< The number of expected ACKs that were never received.
                                          This parameter is based on dot11ACKFailureCount from [802.11-2012]. */
    ULONG ssid_AggregatedPacketCount; /**< The number of aggregated packets that were transmitted. This applies only to 802.11n and 802.11ac. */

    ULONG ssid_ErrorsSent;          /**< The total number of outbound packets that could not be transmitted because of errors. */
    ULONG ssid_ErrorsReceived;      /**< The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol. */
    ULONG ssid_UnicastPacketsSent;   /**< The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol. */
    ULONG ssid_UnicastPacketsReceived;  /**< The total number of received packets, delivered by this layer to a higher layer, which were not addressed to a multicast or broadcast address at this layer. */
    ULONG ssid_DiscardedPacketsSent;   /**< The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted.
                                             One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG ssid_DiscardedPacketsReceived; /**< The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered.
                                                One possible reason for discarding such a packet could be to free up buffer space. */
    ULONG ssid_MulticastPacketsSent;   /**< The total number of packets that higher-level protocols requested for transmission and which were addressed to a multicast address at this layer, including those that were discarded or not sent. */
    ULONG ssid_MulticastPacketsReceived; /**< The total number of received packets, delivered by this layer to a higher layer, which were addressed to a multicast address at this layer. */
    ULONG ssid_BroadcastPacketsSent;    /**< The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent. */
    ULONG ssid_BroadcastPacketsRecevied; /**< The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent. */
    ULONG ssid_UnknownPacketsReceived;  /**< The total number of packets received via the interface which were discarded because of an unknown or unsupported protocol. */

} wifi_ssidTrafficStats2_t;  //for ssid only


//Please do not edit the elements for this data structure 
typedef struct _wifi_neighbor_ap2
{
    //CHAR  ap_Radio[64];  //The value MUST be the path name of a row in theDevice.WiFi.Radiotable. The Radio that detected the neighboring WiFi SSID.  
    CHAR  ap_SSID[64]; /**< The current service set identifier in use by the neighboring WiFi SSID. The value MAY be empty for hidden SSIDs. */
    CHAR  ap_BSSID[64];    /**< [MACAddress] The BSSID used for the neighboring WiFi SSID. */
    CHAR  ap_Mode[64]; /**< The mode the neighboring WiFi radio is operating in. Enumeration of: AdHoc, Infrastructure */
    UINT  ap_Channel;  /**< The current radio channel used by the neighboring WiFi radio. */
    INT   ap_SignalStrength;   /**< An indicator of radio signal strength (RSSI) of the neighboring WiFi radio measured indBm, as an average of the last 100 packets received. */
    CHAR  ap_SecurityModeEnabled[64];  /**< The type of encryption the neighboring WiFi SSID advertises. Enumeration of:None, WPA-WPA2 etc. */
    CHAR  ap_EncryptionMode[64];   /**< Comma-separated list of strings. The type of encryption the neighboring WiFi SSID advertises. Each list item is an enumeration of: TKIP, AES */
    CHAR  ap_OperatingFrequencyBand[16];   /**< Indicates the frequency band at which the radio this SSID instance is operating. Enumeration of:2.4GHz, 5GHz */
    CHAR  ap_SupportedStandards[64];   /**< Comma-separated list of strings. List items indicate which IEEE 802.11 standards thisResultinstance can support simultaneously, in the frequency band specified byOperatingFrequencyBand. Each list item is an enumeration of: */
    CHAR  ap_OperatingStandards[16];   /**< Comma-separated list of strings. Each list item MUST be a member of the list reported by theSupportedStandardsparameter. List items indicate which IEEE 802.11 standard that is detected for thisResult. */
    CHAR  ap_OperatingChannelBandwidth[16];    /**< Indicates the bandwidth at which the channel is operating. Enumeration of: */
    UINT  ap_BeaconPeriod; /**< Time interval (inms) between transmitting beacons. */
    INT   ap_Noise;    /**< Indicator of average noise strength (indBm) received from the neighboring WiFi radio. */
    CHAR  ap_BasicDataTransferRates[256];  /**< Comma-separated list (maximum list length 256) of strings. Basic data transmit rates (in Mbps) for the SSID. For example, ifBasicDataTransferRatesis "1,2", this indicates that the SSID is operating with basic rates of 1 Mbps and 2 Mbps. */
    CHAR  ap_SupportedDataTransferRates[256];  /**< Comma-separated list (maximum list length 256) of strings. Data transmit rates (in Mbps) for unicast frames at which the SSID will permit a station to connect. For example, ifSupportedDataTransferRatesis "1,2,5.5", this indicates that the SSID will only permit connections at 1 Mbps, 2 Mbps and 5.5 Mbps. */
    UINT  ap_DTIMPeriod;   /**< The number of beacon intervals that elapse between transmission of Beacon frames containing a TIM element whose DTIM count field is 0. This value is transmitted in the DTIM Period field of beacon frames. [802.11-2012] */
    UINT  ap_ChannelUtilization;   /**< Indicates the fraction of the time AP senses that the channel is in use by the neighboring AP for transmissions. */
    
} wifi_neighbor_ap2_t;  //COSA_DML_NEIGHTBOURING_WIFI_RESULT

typedef struct _wifi_diag_ipping_setting
{
    CHAR  ipping_Interface[256];   /**< The value MUST be the path name of a row in the IP.Interface table. The IP-layer interface over which the test is to be performed.
                                         This identifies the source IP address to use when performing the test. Example: Device.IP.Interface.1.
                                         If an empty string is specified, the CPE MUST use the interface as directed by its routing policy (Forwarding table entries) to determine the appropriate interface. */
    CHAR  ipping_Host[256];    /**< Host name or address of the host to ping. In the case where Host is specified by name, and the name resolves to more than one address, it is up to the device implementation to choose which address to use. */
    UINT  ipping_NumberOfRepetitions;  /**< Number of repetitions of the ping test to perform before reporting the results. */
    UINT  ipping_Timeout;  /**< Timeout in milliseconds for the ping test. */
    UINT  ipping_DataBlockSize;    /**< Size of the data block in bytes to be sent for each ping. */
    UINT  ipping_DSCP; /**< DiffServ codepoint to be used for the test packets. By default the CPE SHOULD set this value to zero. */

} wifi_diag_ipping_setting_t;   

typedef struct _wifi_diag_ipping_result
{
    CHAR  ipping_DiagnosticsState[64]; /**< Indicates availability of diagnostic data.
                                             Enumeration of: Complete, Error_CannotResolveHostName,  Error_Internal, Error_Other */
    UINT  ipping_SuccessCount; /**< Result parameter indicating the number of successful pings (those in which a successful response was received prior to the timeout) in the most recent ping test. */
    UINT  ipping_FailureCount; /**< Result parameter indicating the number of failed pings in the most recent ping test. */
    UINT  ipping_AverageResponseTime;  /**< Result parameter indicating the average response time in milliseconds over all repetitions with successful responses of the most recent ping test.
                                            If there were no successful responses, this value MUST be zero. */
    UINT  ipping_MinimumResponseTime;  /**< Result parameter indicating the minimum response time in milliseconds over all repetitions with successful responses of the most recent ping test.
                                            If there were no successful responses, this value MUST be zero. */
    UINT  ipping_MaximumResponseTime;  /**< Result parameter indicating the maximum response time in milliseconds over all repetitions with successful responses of the most recent ping test.
                                            If there were no successful responses, this value MUST be zero. */
    
} wifi_diag_ipping_result_t;

//>> -------------------------------- wifi_ap_hal --------------------------------------------
//>> Deprecated: used for old RDKB code. 
// TODO: Review Required
/**
 * @brief Wi-Fi device information.
 * @deprecated Used for old RDKB code.
 *
 * This structure contains information about a Wi-Fi device.
 */
typedef struct _wifi_device {
  UCHAR wifi_devMacAddress[6]; /**< Device MAC address. */
  CHAR wifi_devIPAddress[64];   /**< Device IP address. */
  BOOL wifi_devAssociatedDeviceAuthentiationState; /**< Associated device authentication state. */
  INT wifi_devSignalStrength; /**< Signal strength (dBm). */
  INT wifi_devTxRate;         /**< Transmit rate (kbps). */
  INT wifi_devRxRate;         /**< Receive rate (kbps). */
} wifi_device_t;
//<<

//Please do not edit the elements for this data structure 
typedef struct _wifi_associated_dev
{
    //UCHAR cli_devMacAddress[6];
    //CHAR  cli_devIPAddress[64];
    //BOOL  cli_devAssociatedDeviceAuthentiationState;
    //INT   cli_devSignalStrength;
    //INT   cli_devTxRate;
    //INT   cli_devRxRate;

    UCHAR cli_MACAddress[6];       /**< The MAC address of an associated device. */
    CHAR  cli_IPAddress[64];       /**< IP of the associated device */
    BOOL  cli_AuthenticationState; /**< Whether an associated device has authenticated (true) or not (false). */
    UINT  cli_LastDataDownlinkRate; /**< The data transmit rate in kbps that was most recently used for transmission from the access point to the associated device. */
    UINT  cli_LastDataUplinkRate;  /**< The data transmit rate in kbps that was most recently used for transmission from the associated device to the access point. */
    INT   cli_SignalStrength;      /**< An indicator of radio signal strength of the uplink from the associated device to the access point, measured in dBm, as an average of the last 100 packets received from the device. */
    UINT  cli_Retransmissions;     /**< The number of packets that had to be re-transmitted, from the last 100 packets sent to the associated device. Multiple re-transmissions of the same packet count as one. */
    BOOL  cli_Active;              /**<    boolean -   Whether or not this node is currently present in the WiFi AccessPoint network. */

    CHAR  cli_OperatingStandard[64];   /**< Radio standard the associated Wi-Fi client device is operating under. Enumeration of: */
    CHAR  cli_OperatingChannelBandwidth[64];   /**< The operating channel bandwidth of the associated device. The channel bandwidth (applicable to 802.11n and 802.11ac specifications only). Enumeration of: */
    INT   cli_SNR;     /**< A signal-to-noise ratio (SNR) compares the level of the Wi-Fi signal to the level of background noise. Sources of noise can include microwave ovens, cordless phone, bluetooth devices, wireless video cameras, wireless game controllers, fluorescent lights and more. It is measured in decibels (dB). */
    CHAR  cli_InterferenceSources[64]; /**< Wi-Fi operates in two frequency ranges (2.4 Ghz and 5 Ghz) which may become crowded other radio products which operate in the same ranges. This parameter reports the probable interference sources that this Wi-Fi access point may be observing. The value of this parameter is a comma seperated list of the following possible sources: eg: MicrowaveOven,CordlessPhone,BluetoothDevices,FluorescentLights,ContinuousWaves,Others */
    ULONG cli_DataFramesSentAck;   /**< The DataFramesSentAck parameter indicates the total number of MSDU frames marked as duplicates and non duplicates acknowledged. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_DataFramesSentNoAck; /**< The DataFramesSentNoAck parameter indicates the total number of MSDU frames retransmitted out of the interface (i.e., marked as duplicate and non-duplicate) and not acknowledged, but does not exclude those defined in the DataFramesLost parameter. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_BytesSent;   /**< The total number of bytes transmitted to the client device, including framing characters. */
    ULONG cli_BytesReceived;   /**< The total number of bytes received from the client device, including framing characters. */
    INT   cli_RSSI;    /**< The Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for transmissions from the device averaged over past 100 packets recevied from the device. */
    INT   cli_MinRSSI; /**< The Minimum Received Signal Strength Indicator, RSSI, parameter is the minimum energy observed at the antenna receiver for past transmissions (100 packets). */
    INT   cli_MaxRSSI; /**< The Maximum Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for past transmissions (100 packets). */
    UINT  cli_Disassociations; /**< This parameter  represents the total number of client disassociations. Reset the parameter evey 24hrs or reboot */
    UINT  cli_AuthenticationFailures;  /**< This parameter indicates the total number of authentication failures.  Reset the parameter evey 24hrs or reboot */

} wifi_associated_dev_t;    //~COSA_DML_WIFI_AP_ASSOC_DEVICE

typedef struct _wifi_radius_setting_t
{
    INT  RadiusServerRetries;          /**< Number of retries for Radius requests. */
    INT  RadiusServerRequestTimeout;   /**< Radius request timeout in seconds after which the request must be retransmitted for the # of retries available. */
    INT  PMKLifetime;                  /**< Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs). */
    BOOL PMKCaching;                   /**< Enable or disable caching of PMK.  */
    INT  PMKCacheInterval;             /**< Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes). */
    INT  MaxAuthenticationAttempts;    /**< Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature. */
    INT  BlacklistTableTimeout;        /**< Time interval in seconds for which a client will continue to be blacklisted once it is marked so.  */
    INT  IdentityRequestRetryInterval; /**< Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.   */
    INT  QuietPeriodAfterFailedAuthentication;  /**< The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it. */
    //UCHAR RadiusSecret[64];          //The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

} wifi_radius_setting_t;

//typedef struct wifi_AC_parameters_record  // Access Catagoriy parameters.  see 802.11-2012 spec for descriptions
//{
//     INT CWmin;       // CWmin variable
//     INT CWmax;       // CWmax vairable
//     INT AIFS;        // AIFS
//     ULONG TxOpLimit;  // TXOP Limit
//} wifi_AC_parameters_record_t;


//typedef struct _wifi_qos
//{
//     wifi_AC_parameters_record_t BE_AcParametersRecord;      // Best Effort QOS parameters, ACI == 0
//     wifi_AC_parameters_record_t BK_AcParametersRecord;      // Background QOS parameters, ACI == 1
//     wifi_AC_parameters_record_t VI_AcParametersRecord;      // Video QOS parameters, ACI == 2
//     wifi_AC_parameters_record_t VO_AcParametersRecord;      // Voice QOS parameters, ACI == 3
//}  wifi_qos_t;

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */

//<< -------------------------------- wifi_ap_hal --------------------------------------------

//---------------------------------------------------------------------------------------------------

/**
 * @brief Get the wifi hal version in string,
 *        e.g. "2.0.0".
 *        WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.
 *        WIFI_HAL_MAINTENANCE_VERSION
 *
 * @param[out] output_string WiFi Hal version, to be returned
 *
 * @returns INT
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR If any error is detected.
 */
INT wifi_getHalVersion(CHAR *output_string);

//---------------------------------------------------------------------------------------------------
//
// Wifi subsystem level APIs that are common to Client and Access Point devices.
//
//---------------------------------------------------------------------------------------------------

/**
 * @brief Resets the Wi-Fi subsystem to its factory default state.
 *
 * This function clears internal variables to perform a factory reset of the 
 * Wi-Fi subsystem. The specific implementation may vary depending on the 
 * hardware requirements. This function must not suspend or invoke any 
 * blocking system calls.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_factoryReset();

/**
 * @brief Restores all radio parameters to their factory defaults.
 * 
 * This function resets all radio parameters without affecting access point 
 * parameters. The specific implementation may vary depending on the hardware 
 * requirements. This function must not suspend or invoke any blocking system 
 * calls.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_factoryResetRadios();

/**
 * @brief Restores the selected radio parameters to their factory defaults.
 *
 * This function resets the specified radio parameters without affecting
 * access point parameters. This function must not suspend or invoke any
 * blocking system calls.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_factoryResetRadio(int radioIndex);

/**
 * @brief Sets the system LED status.
 *
 * This function sets the system LED status for the specified radio. This
 * function must not suspend or invoke any blocking system calls.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The LED status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setLED(INT radioIndex, BOOL enable);

/**
 * @brief Initializes all Wi-Fi radios.
 *
 * This function initializes all Wi-Fi radios. The specific implementation may 
 * vary depending on the hardware requirements. This function must not suspend 
 * or invoke any blocking system calls.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_init();

/**
 * @brief Resets the Wi-Fi subsystem.
 *
 * This function resets the Wi-Fi subsystem, including all AP variables. The 
 * specific implementation may vary depending on the hardware requirements. 
 * This function must not suspend or invoke any blocking system calls.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_reset();

/**
 * @brief Turns off transmit power for the entire Wi-Fi subsystem.
 *
 * This function turns off transmit power for all radios in the Wi-Fi 
 * subsystem. The specific implementation may vary depending on the hardware 
 * requirements. This function must not suspend or invoke any blocking system 
 * calls.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_down();

/**
 * @brief Creates initial Wi-Fi configuration files.
 *
 * This function creates Wi-Fi configuration files. The format and content of 
 * these files are implementation-dependent. This function is used to trigger 
 * this task if necessary. Some implementations may not need this function. If 
 * an implementation does not need to create config files, this function can do 
 * nothing and return WIFI_HAL_SUCCESS. This function must not suspend or 
 * invoke any blocking system calls.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_createInitialConfigFiles();                                                                       

/**
 * @brief Gets the country code for the specified Wi-Fi radio.
 *
 * This function retrieves the country code for the specified Wi-Fi radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer to store the country code.
 *                          The buffer must be at least 64 characters long.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string);

/**
 * @brief Sets the country code for the specified Wi-Fi radio.
 *
 * This function sets the country code for the specified Wi-Fi radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] CountryCode A pointer to the country code string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode);

//---------------------------------------------------------------------------------------------------
//Wifi Tr181 API

//Device.WiFi.

/**
 * @brief Gets the total number of radios in the Wi-Fi subsystem.
 *
 * This function retrieves the total number of radios in the Wi-Fi subsystem.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.RadioNumberOfEntries`.
 *
 * @param[out] output A pointer to a variable to store the number of radios.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioNumberOfEntries(ULONG *output);

/**
 * @brief Gets the total number of SSID entries in the Wi-Fi subsystem.
 *
 * This function retrieves the total number of SSID entries in the Wi-Fi
 * subsystem.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.SSIDNumberOfEntries`.
 *
 * @param[out] output A pointer to a variable to store the number of SSID
 *                    entries.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDNumberOfEntries(ULONG *output);

//Device.WiFi.AccessPointNumberOfEntries

//Device.WiFi.EndPointNumberOfEntries
//End points are managed by RDKB
//INT wifi_getEndPointNumberOfEntries(INT radioIndex, ULONG *output); //Tr181

//---------------------------------------------------------------------------------------------------
//
// Wifi radio level APIs that are common to Client and Access Point devices
//
//---------------------------------------------------------------------------------------------------

//Device.WiFi.Radio.

/**
 * @brief Gets the radio enable configuration parameter.
 *
 * This function retrieves the radio enable configuration parameter for the
 * specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.Enable`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Sets the radio enable configuration parameter.
 *
 * This function sets the radio enable configuration parameter for the
 * specified radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the radio enable status.
 *
 * This function retrieves the radio enable status for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.Status`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool);

/**
 * @brief Gets the radio interface name.
 *
 * This function retrieves the interface name for the specified radio, e.g.,
 * "wifi0".
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.Radio.{i}.Alias`
 *       * `Device.WiFi.Radio.{i}.Name`
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer to store the interface name.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string);

/**
 * @brief Gets the maximum PHY bit rate supported by the radio.
 *
 * This function retrieves the maximum PHY bit rate supported by the specified
 * radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.MaxBitRate`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the maximum bit rate, e.g., "216.7
 *                           Mb/s", "1.3 Gb/s". Implementations must ensure
 *                           that strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string);

/**
 * @brief Gets the supported frequency bands for the radio.
 *
 * This function retrieves the supported frequency bands at which the
 * specified radio can operate.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.SupportedFrequencyBands`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the supported frequency bands, e.g.,
 *                           "2.4GHz,5GHz". Implementations must ensure that
 *                           strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string);

/**
 * @brief Gets the operating frequency band for the radio.
 *
 * This function retrieves the frequency band at which the specified radio
 * is operating.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.OperatingFrequencyBand`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the operating frequency band, e.g.,
 *                           "2.4GHz". Implementations must ensure that
 *                           strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string);

/**
 * @brief Gets the supported radio modes.
 *
 * This function retrieves the supported radio modes for the specified
 * radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.SupportedStandards`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the supported radio modes, e.g.,
 *                           "b,g,n", "n,ac". Implementations must ensure that
 *                           strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string);

/**
 * @brief Gets the radio operating mode and pure mode flag.
 *
 * This function retrieves the operating mode and pure mode flag for the
 * specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.OperatingStandards`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the operating mode, e.g., "ac".
 *                           Implementations must ensure that strings are not
 *                           longer than this.
 * @param[out] gOnly A pointer to a boolean variable to store the g-only flag.
 * @param[out] nOnly A pointer to a boolean variable to store the n-only flag.
 * @param[out] acOnly A pointer to a boolean variable to store the ac-only
 *                    flag.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly,
                          BOOL *nOnly, BOOL *acOnly);

/**
 * @brief Sets the radio operating mode and pure mode flag.
 *
 * This function sets the operating mode and pure mode flag for the specified
 * radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] channelMode The channel mode to set.
 * @param[in] gOnlyFlag The g-only flag to set.
 * @param[in] nOnlyFlag The n-only flag to set.
 * @param[in] acOnlyFlag The ac-only flag to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag,
                             BOOL nOnlyFlag, BOOL acOnlyFlag);

/**
 * @brief Gets the list of possible channels for the radio.
 *
 * This function retrieves the list of possible channels for the specified
 * radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.PossibleChannels`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the list of possible channels, e.g.,
 *                           "1-11". Implementations must ensure that strings
 *                           are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string);

/**
 * @brief Gets the list of channels currently in use for the radio.
 *
 * This function retrieves the list of channels currently in use for the
 * specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.ChannelsInUse`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 256 octets)
 *                           to store the list of channels in use, e.g.,
 *                           "1,6,9,11". Implementations must ensure that
 *                           strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string);

/**
 * @brief Gets the current channel number for the radio.
 *
 * This function retrieves the current channel number for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.Channel`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_ulong A pointer to a variable to store the channel
 *                          number.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioChannel(INT radioIndex, ULONG *output_ulong);

/**
 * @brief Sets the current channel number for the radio.
 *
 * This function sets the current channel number for the specified radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] channel The channel number to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioChannel(INT radioIndex, ULONG channel);

/**
 * @brief Enables or disables auto channel selection for the radio.
 *
 * This function enables or disables a driver-level variable to indicate if
 * auto channel selection is enabled on the specified radio. This "auto
 * channel" refers to the auto channel selection when the radio is up, which
 * is different from the dynamic channel/frequency selection (DFC/DCS).
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The enable/disable status of auto channel selection.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable);

/**
 * @brief Checks if the driver supports auto channel selection.
 *
 * This function checks if the driver supports auto channel selection for the
 * specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.AutoChannelSupported`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the auto channel
 *                         support status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool);

/**
 * @brief Gets the auto channel enable status for the radio.
 *
 * This function retrieves the auto channel enable status for the specified
 * radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the auto channel
 *                         enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables auto channel selection for the radio.
 *
 * This function enables or disables a driver-level variable to indicate if
 * auto channel selection is enabled on the specified radio. This "auto
 * channel" refers to the auto channel selection when the radio is up, which
 * is different from the dynamic channel/frequency selection (DFC/DCS).
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The enable/disable status of auto channel selection.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable);

/**
 * @brief Checks if the driver supports Dynamic Channel Selection (DCS).
 *
 * This function checks if the driver supports DCS for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_DCSSupported`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the DCS support
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool);

/**
 * @brief Gets the DCS enable status for the radio.
 *
 * This function retrieves the DCS enable status for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_DCSEnable`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the DCS enable
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables DCS for the radio.
 *
 * This function enables or disables DCS for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_DCSEnable`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The enable/disable status of DCS.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the DCS channel pool for the radio.
 *
 * This function retrieves the DCS channel pool for the specified radio. The
 * value of this parameter is a comma-separated list of channel numbers.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_pool A pointer to a buffer (max length: 256 octets) to
 *                         store the DCS channel pool. Implementations must
 *                         ensure that strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool);

/**
 * @brief Sets the DCS channel pool for the radio.
 *
 * This function sets the DCS channel pool for the specified radio. The value
 * of this parameter is a comma-separated list of channel numbers.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] pool A pointer to a buffer (max length: 256 octets) containing
 *                 the DCS channel pool to set. Implementations must ensure
 *                 that strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool);

/**
 * @brief Gets the DCS scan time for the radio.
 *
 * This function retrieves the DCS scan time for the specified radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_interval_seconds A pointer to a variable to store the
 *                                    interval time in seconds.
 * @param[out] output_dwell_milliseconds A pointer to a variable to store the
 *                                      dwell time in milliseconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds,
                              INT *output_dwell_milliseconds);

/**
 * @brief Sets the DCS scan time for the radio.
 *
 * This function sets the DCS scan time for the specified radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] interval_seconds The interval time in seconds.
 * @param[in] dwell_milliseconds The dwell time in milliseconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds,
                             INT dwell_milliseconds);

/**
 * @brief Gets the DFS support status for the radio.
 *
 * This function retrieves the DFS support status for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_DfsSupported`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the DFS support
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioDfsSupport(INT radioIndex, BOOL *output_bool);

/**
 * @brief Gets the DFS enable status for the radio.
 *
 * This function retrieves the DFS enable status for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_DfsEnable`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the DFS enable
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables DFS for the radio.
 *
 * This function enables or disables DFS for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_DfsEnable`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The enable/disable status of DFS.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enable);

/**
 * @brief Checks if the driver supports the auto channel refresh period.
 *
 * This function checks if the driver supports the auto channel refresh period
 * for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_bool A pointer to a variable to store the auto channel
 *                         refresh period support status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex,
                                                  BOOL *output_bool);

/**
 * @brief Gets the auto channel refresh period for the radio.
 *
 * This function retrieves the auto channel refresh period for the specified
 * radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_ulong A pointer to a variable to store the auto channel
 *                          refresh period in seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong);

/**
 * @brief Sets the auto channel refresh period for the radio.
 *
 * This function sets the auto channel refresh period for the specified radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] seconds The auto channel refresh period in seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds);

/**
 * @brief Gets the operating channel bandwidth for the radio.
 *
 * This function retrieves the operating channel bandwidth for the specified
 * radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.OperatingChannelBandwidth`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the operating channel bandwidth, e.g.,
 *                           "20MHz", "40MHz", "80MHz", "80+80", "160".
 *                           Implementations must ensure that strings are not
 *                           longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string);

/**
 * @brief Sets the operating channel bandwidth for the radio.
 *
 * This function sets the operating channel bandwidth for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.OperatingChannelBandwidth`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] bandwidth A pointer to a buffer containing the operating channel
 *                      bandwidth string to set, e.g., "20MHz", "40MHz",
 *                      "80MHz", "80+80", "160".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth);

/**
 * @brief Gets the secondary extension channel position for the radio.
 *
 * This function retrieves the secondary extension channel position for the
 * specified radio. This is applicable only for 40MHz and 80MHz bandwidths.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.ExtensionChannel`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the secondary extension channel
 *                           position, e.g., "AboveControlChannel" or
 *                           "BelowControlChannel". Implementations must ensure
 *                           that strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string);

/**
 * @brief Sets the secondary extension channel position for the radio.
 *
 * This function sets the secondary extension channel position for the
 * specified radio. This is applicable only for 40MHz and 80MHz bandwidths.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.ExtensionChannel`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] string A pointer to a buffer containing the secondary extension
 *                   channel position string to set, e.g.,
 *                   "AboveControlChannel" or "BelowControlChannel".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string);

/**
 * @brief Gets the guard interval value for the radio.
 *
 * This function retrieves the guard interval value for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.GuardInterval`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_string A pointer to a buffer (max length: 64 octets)
 *                           to store the guard interval value, e.g.,
 *                           "400nsec" or "800nsec". Implementations must
 *                           ensure that strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string);

/**
 * @brief Sets the guard interval value for the radio.
 *
 * This function sets the guard interval value for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.GuardInterval`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] string A pointer to a buffer containing the guard interval value
 *                   string to set, e.g., "400nsec" or "800nsec".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string);

/**
 * @brief Gets the Modulation Coding Scheme (MCS) index for the radio.
 *
 * This function retrieves the MCS index for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.MCS`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_INT A pointer to a variable to store the MCS index, e.g.,
 *                        "-1", "1", "15".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioMCS(INT radioIndex, INT *output_INT);

/**
 * @brief Sets the Modulation Coding Scheme (MCS) index for the radio.
 *
 * This function sets the MCS index for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.MCS`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] MCS The MCS index value to set, e.g., "-1", "1", "15".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioMCS(INT radioIndex, INT MCS);

/**
 * @brief Gets the supported transmit power levels for the radio.
 *
 * This function retrieves the supported transmit power levels for the
 * specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.TransmitPowerSupported`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_list A pointer to a buffer (max length: 64 octets) to
 *                         store the supported transmit power levels, e.g.,
 *                         "0,25,50,75,100". Implementations must ensure that
 *                         strings are not longer than this.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list);

/**
 * @brief Gets the current transmit power level for the radio.
 *
 * This function retrieves the current transmit power level for the specified
 * radio. The transmit power level is in units of full power for this radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.TransmitPower`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_ulong A pointer to a variable to store the transmit power
 *                          level, e.g., "75", "100".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong);

/**
 * @brief Sets the transmit power level for the radio.
 *
 * This function sets the transmit power level for the specified radio. The
 * transmit power level is in units of full power for this radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.TransmitPower`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] TransmitPower The transmit power level to set, e.g., "75", "100".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower);

/**
 * @brief Checks if the radio supports IEEE 802.11h.
 *
 * This function checks if the specified radio supports IEEE 802.11h, which
 * solves interference with satellites and radar using the same 5 GHz
 * frequency band.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.IEEE80211hSupported`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] Supported A pointer to a variable to store the IEEE 802.11h
 *                       support status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported);

/**
 * @brief Gets the IEEE 802.11h enable status for the radio.
 *
 * This function retrieves the IEEE 802.11h enable status for the specified
 * radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.IEEE80211hEnabled`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] enable A pointer to a variable to store the IEEE 802.11h enable
 *                    status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable);

/**
 * @brief Enables or disables IEEE 802.11h for the radio.
 *
 * This function enables or disables IEEE 802.11h for the specified radio.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.IEEE80211hEnabled`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The enable/disable status of IEEE 802.11h.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable);

/**
 * @brief Gets the carrier sense threshold range for the radio.
 *
 * This function retrieves the carrier sense threshold range supported by the
 * specified radio. It is measured in dBm. Refer to section A.2.3.2 of
 * CableLabs Wi-Fi MGMT Specification.
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.Radio.{i}.RegulatoryDomain`
 *       * `Device.WiFi.Radio.{i}.X_COMCAST-COM_CarrierSenseThresholdRange`
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output A pointer to a variable to store the carrier sense
 *                    threshold range.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output);

/**
 * @brief Gets the carrier sense threshold currently in use for the radio.
 *
 * This function retrieves the RSSI signal level at which CS/CCA detects a
 * busy condition for the specified radio. It is measured in dBm. This
 * attribute enables APs to increase minimum sensitivity to avoid detecting
 * busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi
 * environments. Refer to section A.2.3.2 of CableLabs Wi-Fi MGMT
 * Specification.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_CarrierSenseThresholdInUse`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output A pointer to a variable to store the carrier sense
 *                    threshold in use.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output);

/**
 * @brief Sets the carrier sense threshold for the radio.
 *
 * This function sets the RSSI signal level at which CS/CCA detects a busy
 * condition for the specified radio. It is measured in dBm. This attribute
 * enables APs to increase minimum sensitivity to avoid detecting busy
 * condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.X_COMCAST-COM_CarrierSenseThresholdInUse`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] threshold The carrier sense threshold to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold);

//Device.WiFi.Radio.{i}.X_COMCAST-COM_ChannelSwitchingCount
//This parameter indicates the total number of Channel Changes.  Reset the parameter every 24 hrs or reboot
//INT wifi_getRadioChannelSwitchingCount(INT radioIndex, INT *output); 	//P3


/**
 * @brief Gets the beacon period for the radio.
 *
 * This function retrieves the time interval between transmitting beacons
 * for the specified radio. It is expressed in milliseconds. This parameter
 * is based on dot11BeaconPeriod from [802.11-2012].
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.BeaconPeriod`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output A pointer to a variable to store the beacon period.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output);

/**
 * @brief Sets the beacon period for the radio.
 *
 * This function sets the time interval between transmitting beacons for the
 * specified radio. It is expressed in milliseconds. This parameter is based
 * on dot11BeaconPeriod from [802.11-2012].
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.BeaconPeriod`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] BeaconPeriod The beacon period to set, in milliseconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod);

/**
 * @brief Gets the basic data transmit rates for the radio.
 *
 * This function retrieves the set of data rates, in Mbps, that have to be
 * supported by all stations that desire to join this BSS. The stations have
 * to be able to receive and transmit at each of the data rates listed in
 * BasicDataTransmitRates. For example, a value of "1,2" indicates that
 * stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in
 * BasicDataTransmitRates.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.BasicDataTransmitRates`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output A pointer to a buffer to store the comma-separated list
 *                    of data rates.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output);

/**
 * @brief Sets the basic data transmit rates for the radio.
 *
 * This function sets the set of data rates, in Mbps, that have to be supported
 * by all stations that desire to join this BSS. The stations have to be able
 * to receive and transmit at each of the data rates listed in
 * BasicDataTransmitRates. For example, a value of "1,2" indicates that
 * stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in
 * BasicDataTransmitRates.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.BasicDataTransmitRates`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] TransmitRates A pointer to the comma-separated list of data
 *                          rates.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates);

//---------------------------------------------------------------------------------------------------
//Device.WiFi.Radio.{i}.Stats.

//Device.WiFi.Radio.{i}.Stats.BytesSent
//Device.WiFi.Radio.{i}.Stats.BytesReceived
//Device.WiFi.Radio.{i}.Stats.PacketsSent
//Device.WiFi.Radio.{i}.Stats.PacketsReceived
//Device.WiFi.Radio.{i}.Stats.ErrorsSent
//Device.WiFi.Radio.{i}.Stats.ErrorsReceived
//Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent
//Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived
//Device.WiFi.Radio.{i}.Stats.PLCPErrorCount
//Device.WiFi.Radio.{i}.Stats.FCSErrorCount
//Device.WiFi.Radio.{i}.Stats.InvalidMACCount
//Device.WiFi.Radio.{i}.Stats.PacketsOtherReceived
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_NoiseFloor
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_ChannelUtilization
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_ActivityFactor
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_CarrierSenseThreshold_Exceeded
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_RetransmissionMetirc
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_MaximumNoiseFloorOnChannel
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_MinimumNoiseFloorOnChannel
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_MedianNoiseFloorOnChannel
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_StatisticsStartTime

/**
 * @brief Gets detailed radio traffic statistics.
 *
 * This function retrieves detailed radio traffic statistics for the specified
 * radio.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_struct A pointer to a `wifi_radioTrafficStats2_t`
 *                           structure to store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioTrafficStats2(INT radioIndex,
                               wifi_radioTrafficStats2_t *output_struct);

/**
 * @brief Sets radio traffic statistics measurement rules.
 *
 * This function sets the measurement rules for radio traffic statistics.
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_RadioStatisticsMeasuringRate`
 *       * `Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_RadioStatisticsMeasuringInterval`
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] input_struct A pointer to a `wifi_radioTrafficStatsMeasure_t`
 *                         structure containing the measurement rules.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioTrafficStatsMeasure(
    INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct);

/**
 * @brief Enables or disables radio traffic statistics collection.
 *
 * This function enables or disables the collection of radio traffic
 * statistics.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_RadioStatisticsEnable`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] enable The enable/disable status of traffic statistics
 *                   collection.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioTrafficStatsRadioStatisticsEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the received signal level statistics for the radio.
 *
 * This function retrieves the received signal level statistics for the
 * specified radio. The statistics are represented as a histogram with a
 * range from -110 to 0 dBm, divided into bins of 3 dBm. If any of the
 * parameter's representing this histogram is queried before the histogram has
 * been updated with an initial set of data, it must return -1. Units dBm.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_ReceivedSignalLevel.{i}.ReceivedSignalLevel`.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[in] signalIndex The index of the signal level bin.
 * @param[out] SignalLevel A pointer to a variable to store the signal level
 *                         value for the specified bin.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex,
                                          INT *SignalLevel);

/**
 * @brief Applies the radio settings.
 *
 * This function applies all previously set radio-level variables and makes
 * these settings active in the hardware. Not all implementations may need
 * this function. If not needed for a particular implementation, simply return
 * no error (0).
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_applyRadioSettings(INT radioIndex);

/**
 * @brief Gets the radio reset count.
 *
 * This function retrieves the number of times the specified radio has been
 * reset.
 *
 * @param[in] radioIndex The index of the Wi-Fi radio channel.
 * @param[out] output_int A pointer to a variable to store the reset count.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioResetCount(INT radioIndex, ULONG *output_int);

//---------------------------------------------------------------------------------------------------
//
// Wifi SSID level APIs common to Client and Access Point devices.
//
//---------------------------------------------------------------------------------------------------

//Device.WiFi.SSID.{i}.

/**
 * @brief Gets the radio index associated with the SSID entry.
 *
 * This function retrieves the radio index associated with the specified SSID
 * entry.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[out] radioIndex A pointer to a variable to store the radio index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex);

/**
 * @brief Gets the SSID enable configuration parameter.
 *
 * This function retrieves the SSID enable configuration parameter for the
 * specified SSID. This is not the same as the SSID enable status.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.SSID.{i}.Enable`.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[out] output_bool A pointer to a variable to store the enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool);

/**
 * @brief Sets the SSID enable configuration parameter.
 *
 * This function sets the SSID enable configuration parameter for the
 * specified SSID.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.SSID.{i}.Enable`.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[in] enable The enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable);

/**
 * @brief Gets the SSID enable status.
 *
 * This function retrieves the SSID enable status for the specified SSID.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.SSID.{i}.Status`.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[out] output_string A pointer to a buffer to store the enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string);

/**
 * @brief Gets the SSID name associated with the Access Point.
 *
 * This function retrieves the SSID name associated with the specified Access
 * Point.
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.SSID.{i}.Name`
 *       * `Device.WiFi.SSID.{i}.Alias`
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer (max length: 32 bytes) to
 *                           store the SSID name. The string buffer must be
 *                           preallocated by the caller.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDName(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the SSID name associated with the Access Point.
 *
 * This function sets the SSID name associated with the specified Access Point.
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.SSID.{i}.Name`
 *       * `Device.WiFi.SSID.{i}.Alias`
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] ssid_string A pointer to a buffer (max length: 32 bytes)
 *                        containing the SSID name to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string);

// push the ssid name to the hardware //repleaced by wifi_applySSIDSettings
//INT wifi_pushSSIDName(INT apIndex, CHAR *ssid);                         


/**
 * @brief Gets the base BSSID for the SSID.
 *
 * This function retrieves the base BSSID for the specified SSID.
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.SSID.{i}.LastChange`
 *       * `Device.WiFi.SSID.{i}.LowerLayers`
 *       * `Device.WiFi.SSID.{i}.BSSID`
 *
 * @param[in] ssidIndex The SSID index.
 * @param[out] output_string A pointer to a buffer to store the BSSID.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string);

/**
 * @brief Gets the MAC address associated with the SSID.
 *
 * This function retrieves the MAC address associated with the specified SSID.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.SSID.{i}.MACAddress`.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[out] output_string A pointer to a buffer to store the MAC address.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string);

//Device.WiFi.SSID.{i}.SSID

//-----------------------------------------------------------------------------------------------
//Device.WiFi.SSID.{i}.Stats.
//Device.WiFi.SSID.{i}.Stats.BytesSent
//Device.WiFi.SSID.{i}.Stats.BytesReceived
//Device.WiFi.SSID.{i}.Stats.PacketsSent
//Device.WiFi.SSID.{i}.Stats.PacketsReceived

//Device.WiFi.SSID.{i}.Stats.RetransCount		
//Device.WiFi.SSID.{i}.Stats.FailedRetransCount	
//Device.WiFi.SSID.{i}.Stats.RetryCount	
//Device.WiFi.SSID.{i}.Stats.MultipleRetryCount	
//Device.WiFi.SSID.{i}.Stats.ACKFailureCount	
//Device.WiFi.SSID.{i}.Stats.AggregatedPacketCount	
	 
//Device.WiFi.SSID.{i}.Stats.ErrorsSent
//Device.WiFi.SSID.{i}.Stats.ErrorsReceived
//Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent
//Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived
//Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent
//Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived
//Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent
//Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived
//Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent
//Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived
//Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived	

/**
 * @brief Gets basic SSID traffic statistics.
 *
 * This function retrieves basic SSID traffic statistics for the specified
 * SSID.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[out] output_struct A pointer to a `wifi_ssidTrafficStats2_t`
 *                           structure to store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDTrafficStats2(INT ssidIndex,
                              wifi_ssidTrafficStats2_t *output_struct);

/**
 * @brief Applies the SSID and AP settings to the hardware.
 *
 * This function applies the SSID and AP settings to the hardware. This
 * function may not be needed for all implementations. If not needed for a
 * particular implementation, it can return `WIFI_HAL_SUCCESS`.
 *
 * @param[in] ssidIndex The SSID index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_applySSIDSettings(INT ssidIndex);


//-----------------------------------------------------------------------------------------------
//Device.WiFi.NeighboringWiFiDiagnostic.	
//Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState
//Device.WiFi.NeighboringWiFiDiagnostic.ResultNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.	
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Radio
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SSID
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BSSID
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Mode						
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Channel
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SignalStrength
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SecurityModeEnabled
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.EncryptionMode	
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingFrequencyBand
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SupportedStandards		
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingStandards
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingChannelBandwidth
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BeaconPeriod	
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Noise
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BasicDataTransferRates
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SupportedDataTransferRates
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.DTIMPeriod
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.X_COMCAST-COM_ChannelUtilization

/**
 * @brief Starts a Wi-Fi scan and retrieves the results.
 *
 * This function starts a Wi-Fi scan and retrieves the results into an output
 * buffer for parsing. The results will be used to manage the endpoint list.
 * The HAL function should allocate a data structure array and return it to the
 * caller with `neighbor_ap_array`.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] neighbor_ap_array A pointer to a pointer to a
 *                               `wifi_neighbor_ap2_t` array to store the
 *                               neighboring access point information.
 * @param[out] output_array_size A pointer to a variable to store the size of
 *                               the returned array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getNeighboringWiFiDiagnosticResult2(
    INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array,
    UINT *output_array_size);

// TODO: deprecated functions review Required

/**
 * @brief Gets basic SSID traffic statistics.
 * @deprecated This function is deprecated and should not be used in new code.
 *
 * This function retrieves basic SSID traffic statistics for the specified
 * SSID.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[out] output_struct A pointer to a `wifi_ssidTrafficStats_t` structure
 *                           to store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getSSIDTrafficStats(INT ssidIndex,
                              wifi_ssidTrafficStats_t *output_struct);

// TODO: Review Required

/**
 * @brief Gets basic traffic statistics per AP.
 * @deprecated This function is deprecated and should not be used in new code.
 *
 * This function retrieves basic traffic statistics for the specified AP.
 *
 * @param[in] apIndex The AP index.
 * @param[out] output_struct A pointer to a `wifi_basicTrafficStats_t` structure
 *                           to store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getBasicTrafficStats(INT apIndex,
                             wifi_basicTrafficStats_t *output_struct);

// TODO: Review Required

/**
 * @brief Gets detailed traffic statistics per AP.
 * @deprecated This function is deprecated and should not be used in new code.
 *
 * This function retrieves detailed traffic statistics for the specified AP.
 *
 * @param[in] apIndex The AP index.
 * @param[out] output_struct A pointer to a `wifi_trafficStats_t` structure to
 *                           store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct);

// TODO: Review Required

/**
 * @brief Starts a Wi-Fi scan and retrieves the results.
 * @deprecated This function is deprecated and should not be used in new code.
 *
 * This function starts a Wi-Fi scan and retrieves the results into an output
 * buffer for parsing.
 *
 * @param[out] neighbor_ap_array A pointer to a pointer to a
 *                               `wifi_neighbor_ap_t` array to store the
 *                               neighboring access point information.
 * @param[out] output_array_size A pointer to a variable to store the size of
 *                               the returned array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getNeighboringWiFiDiagnosticResult(
    wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size);

// TODO: Review Required

/**
 * @brief Gets details for all associated devices.
 * @deprecated This function is deprecated and should not be used in new code.
 *
 * This function retrieves details for all associated devices for the
 * specified AP.
 *
 * @param[in] apIndex The AP index.
 * @param[out] output_ulong A pointer to a variable to store the number of
 *                          associated devices.
 * @param[out] output_struct A pointer to a pointer to a `wifi_device_t` array
 *                           to store the device details.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getAllAssociatedDeviceDetail(INT apIndex, ULONG *output_ulong,
                                      wifi_device_t **output_struct);
//<<

//>> -------------------- wifi_ap_hal -----------------------------------
//---------------------------------------------------------------------------------------------------
//
// Additional Wifi radio level APIs used for RDKB Access Point devices
//
//---------------------------------------------------------------------------------------------------

	
/**
 * @brief Resets the AP parameters to factory defaults.
 *
 * This function restores the AP parameters to factory defaults without
 * changing other AP or radio parameters. A Wi-Fi reboot is not required.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_factoryResetAP(int apIndex);

/**
 * @brief Enables or disables CTS protection for the radio.
 *
 * This function enables or disables CTS protection for the radio used by the
 * specified AP.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] enable The CTS protection enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioCtsProtectionEnable(INT radioIndex, BOOL enable);

/**
 * @brief Enables or disables OBSS Coexistence for the radio.
 *
 * This function enables or disables OBSS Coexistence, which falls back to
 * 20MHz if necessary, for the radio used by the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The OBSS Coexistence enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable);

/**
 * @brief Sets the fragmentation threshold for the radio.
 *
 * This function sets the fragmentation threshold, in bytes, for the radio
 * used by the specified AP.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] threshold The fragmentation threshold value to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioFragmentationThreshold(INT radioIndex, UINT threshold);

/**
 * @brief Enables or disables STBC mode for the radio.
 *
 * This function enables or disables Space-Time Block Coding (STBC) mode for
 * the radio used by the specified AP.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] STBC_Enable The STBC mode enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable);

/**
 * @brief Gets the A-MSDU enable status for the radio.
 *
 * This function retrieves the Aggregated MAC Service Data Unit (A-MSDU)
 * enable status for the radio used by the specified AP.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the A-MSDU enable
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables A-MSDU for the radio.
 *
 * This function enables or disables A-MSDU for the radio used by the
 * specified AP.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] amsduEnable The A-MSDU enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable);

/**
 * @brief Gets the number of transmit chains for the radio.
 *
 * This function retrieves the number of transmit chains for the specified
 * radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_int A pointer to a variable to store the number of
 *                        transmit chains.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int);

/**
 * @brief Sets the number of transmit chains for the radio.
 *
 * This function sets the number of transmit chains for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] numStreams The number of transmit chains to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams);

/**
 * @brief Gets the number of receive chains for the radio.
 *
 * This function retrieves the number of receive chains for the specified
 * radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_int A pointer to a variable to store the number of
 *                        receive chains.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int);

/**
 * @brief Sets the number of receive chains for the radio.
 *
 * This function sets the number of receive chains for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] numStreams The number of receive chains to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams);

//>> Deprecated:
// TODO: deprecated functions review Required

/**
 * @brief Pushes bridge information to the hardware.
 * @deprecated This function is deprecated and should not be used.
 *
 * This function pushes bridge information to the hardware for the specified
 * Access Point.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushBridgeInfo(INT apIndex);

/**
 * @brief Pushes the radio channel number to the hardware.
 * @deprecated This function is deprecated and should not be used.
 *
 * This function pushes the radio channel number setting to the hardware.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] channel The channel number to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushRadioChannel(INT radioIndex, UINT channel);

/**
 * @brief Pushes the radio channel mode to the hardware.
 * @deprecated This function is deprecated and should not be used.
 *
 * This function pushes the radio channel mode environment variable to the
 * hardware.
 *
 * @param[in] radioIndex The radio index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushRadioChannelMode(INT radioIndex);

/**
 * @brief Pushes the radio transmit chain mask to the hardware.
 * @deprecated This function is deprecated and should not be used.
 *
 * This function pushes the radio transmit chain mask environment variable
 * to the hardware.
 *
 * @param[in] radioIndex The radio index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushRadioTxChainMask(INT radioIndex);

/**
 * @brief Pushes the radio receive chain mask to the hardware.
 * @deprecated This function is deprecated and should not be used.
 *
 * This function pushes the radio receive chain mask environment variable
 * to the hardware.
 *
 * @param[in] radioIndex The radio index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushRadioRxChainMask(INT radioIndex);
//<<

/**
 * @brief Pushes the SSID environment variable to the hardware.
 *
 * This function pushes the SSID environment variable, which is set by
 * `wifi_setSsidName`, to the hardware.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] ssid The WiFi SSID value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushSSID(INT apIndex, CHAR *ssid);

/**
 * @brief Pushes the SSID advertisement enable environment variable to the
 *        hardware.
 *
 * This function pushes the SSID advertisement enable environment variable,
 * which is set by `wifi_setApSsidAdvertisementEnable`, to the hardware.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The SSID advertisement enable value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushSsidAdvertisementEnable(INT apIndex, BOOL enable);

/**
 * @brief Gets the radio uptime.
 *
 * This function retrieves the number of seconds elapsed since the radio
 * was started.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] uptime A pointer to a variable to store the radio uptime in
 *                    seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioUpTime(INT radioIndex, ULONG *uptime);

/**
 * @brief Checks if the radio supports Reverse Direction Grant (RDG).
 *
 * This function checks if the specified radio supports RDG.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the RDG support
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioReverseDirectionGrantSupported(INT radioIndex,
                                                BOOL *output_bool);

/**
 * @brief Gets the Reverse Direction Grant (RDG) enable setting for the radio.
 *
 * This function retrieves the RDG enable setting for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the RDG enable
 *                         setting.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables Reverse Direction Grant (RDG) for the radio.
 *
 * This function enables or disables RDG for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] enable The RDG enable setting to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the decline Block Ack Request (BA Request) setting for the
 *        radio.
 *
 * This function retrieves the decline BA Request setting for the specified
 * radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the decline BA
 *                         Request setting.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables declining Block Ack Requests (BA Requests) for
 *        the radio.
 *
 * This function enables or disables declining BA Requests for the specified
 * radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] enable The decline BA Request setting to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the auto block acknowledgement (auto block ack) setting for the
 *        radio.
 *
 * This function retrieves the auto block ack setting for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the auto block ack
 *                         setting.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables auto block acknowledgement (auto block ack) for
 *        the radio.
 *
 * This function enables or disables auto block ack for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] enable The auto block ack setting to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable);

/**
 * @brief Checks if the radio supports 802.11n greenfield mode.
 *
 * This function checks if the specified radio supports 802.11n greenfield
 * mode.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the greenfield mode
 *                         support status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadio11nGreenfieldSupported(INT radioIndex, BOOL *output_bool);

/**
 * @brief Gets the 802.11n greenfield mode enable setting for the radio.
 *
 * This function retrieves the 802.11n greenfield mode enable setting for the
 * specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the greenfield mode
 *                         enable setting.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable);

/**
 * @brief Gets the IGMP snooping enable setting for the radio.
 *
 * This function retrieves the IGMP snooping enable setting for the specified
 * radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_bool A pointer to a variable to store the IGMP snooping
 *                         enable setting.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool);

/**
 * @brief Enables or disables IGMP snooping for the radio.
 *
 * This function enables or disables IGMP snooping for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] enable The IGMP snooping enable setting to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable);
//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------


//AP HAL
/**
 * @brief Creates a new Access Point (AP).
 *
 * This function creates a new AP and pushes the parameters to the hardware.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] radioIndex The radio index.
 * @param[in] essid The SSID name.
 * @param[in] hideSsid The SSID advertisement enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid);

/**
 * @brief Deletes an AP.
 *
 * This function deletes the specified AP entry on the hardware and clears all
 * internal variables associated with it.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_deleteAp(INT apIndex);

/**
 * @brief Gets the AP name.
 *
 * This function retrieves the name associated with the specified AP. The
 * output string is a maximum length of 16 octets.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer to store the AP name.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApName(INT apIndex, CHAR *output_string);

/**
 * @brief Gets the AP index from the SSID name.
 *
 * This function retrieves the index number corresponding to the given SSID
 * string.
 *
 * @param[in] inputSsidString The WiFi SSID name.
 * @param[out] ouput_int A pointer to a variable to store the AP index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApIndexFromName(CHAR *inputSsidString, INT *ouput_int);

/**
 * @brief Gets the AP beacon type.
 *
 * This function retrieves the beacon type for the specified AP. The output
 * string is a maximum length of 32 octets.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer to store the beacon type,
 *                           e.g., "None", "Basic", "WPA", "11i", "WPAand11i".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the AP beacon type.
 *
 * This function sets the beacon type environment variable for the specified
 * AP. Allowed input strings are "None", "Basic", "WPA", "11i", "WPAand11i".
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] beaconTypeString A pointer to the beacon type string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString);

/**
 * @brief Sets the AP beacon interval.
 *
 * This function sets the beacon interval on the hardware for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] beaconInterval The beacon interval to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval);

/**
 * @brief Checks if the AP supports RTS threshold.
 *
 * This function checks if the specified AP supports the RTS threshold
 * parameter.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_bool A pointer to a variable to store the RTS threshold
 *                         support status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApRtsThresholdSupported(INT apIndex, BOOL *output_bool);

/**
 * @brief Sets the AP RTS threshold.
 *
 * This function sets the packet size threshold, in bytes, to apply RTS/CTS
 * backoff rules for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] threshold The packet size threshold to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold);

/**
 * @brief Gets the AP WPA encryption mode.
 *
 * This function retrieves the WPA encryption mode for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer (max length: 32 bytes) to
 *                           store the WPA encryption mode, e.g.,
 *                           "TKIPEncryption", "AESEncryption", or
 *                           "TKIPandAESEncryption".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWpaEncryptoinMode(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the AP WPA encryption mode.
 *
 * This function sets the WPA encryption mode environment variable for the
 * specified AP. Valid string formats are "TKIPEncryption", "AESEncryption",
 * or "TKIPandAESEncryption".
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] encMode A pointer to the WPA encryption mode string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode);

/**
 * @brief Removes the AP security variables.
 *
 * This function deletes the internal security variable settings for the
 * specified AP.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_removeApSecVaribles(INT apIndex);

/**
 * @brief Disables AP encryption.
 *
 * This function changes the hardware settings to disable encryption for the
 * specified AP.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_disableApEncryption(INT apIndex);

/**
 * @brief Sets the AP authorization mode.
 *
 * This function sets the authorization mode for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] mode The authorization mode to set. The valid values are:
 *                 * 1: Open
 *                 * 2: Shared
 *                 * 4: Auto
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApAuthMode(INT apIndex, INT mode);

/**
 * @brief Sets the AP basic authentication mode.
 *
 * This function sets an environment variable for the authentication mode.
 * Valid strings are "None", "EAPAuthentication" or "SharedAuthentication".
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] authMode A pointer to the authentication mode string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode);

/**
 * @brief Gets the number of devices associated with the AP.
 *
 * This function retrieves the number of stations associated with the specified
 * AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_ulong A pointer to a variable to store the number of
 *                          associated devices.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong);

/**
 * @brief Manually removes the association with a device.
 *
 * This function manually removes any active Wi-Fi association with the
 * specified device on the given Access Point.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] client_mac The client device MAC address.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac);

/**
 * @brief Gets the radio index for the AP.
 *
 * This function retrieves the radio index for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_int A pointer to a variable to store the radio index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApRadioIndex(INT apIndex, INT *output_int);

/**
 * @brief Sets the radio index for the AP.
 *
 * This function sets the radio index for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] radioIndex The radio index to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex);

/**
 * @brief Gets the Access Control List (ACL) devices for the AP.
 *
 * This function retrieves the ACL MAC list for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] macArray A pointer to a buffer to store the MAC address list.
 * @param[in] buf_size The size of the buffer.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size);

/**
 * @brief Adds a device to the AP ACL.
 *
 * This function adds the specified MAC address to the AP's ACL.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] DeviceMacAddress The MAC address of the device to add.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress);

/**
 * @brief Deletes a device from the AP ACL.
 *
 * This function deletes the specified MAC address from the AP's ACL.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] DeviceMacAddress The MAC address of the device to delete.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress);

/**
 * @brief Gets the number of devices in the AP ACL.
 *
 * This function retrieves the number of devices in the AP's ACL.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_uint A pointer to a variable to store the number of
 *                         devices.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint);

/**
 * @brief Enables or disables kicking devices on the ACL blacklist.
 *
 * This function enables or disables kicking devices that are on the ACL
 * blacklist.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The enable/disable status of kicking devices.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable);

/**
 * @brief Sets the AP MAC address control mode.
 *
 * This function sets the MAC address filter control mode for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] filterMode The MAC address filter control mode to set. The valid
 *                       values are:
 *                         * 0: Filter disabled
 *                         * 1: Filter as whitelist
 *                         * 2: Filter as blacklist
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode);

/**
 * @brief Enables or disables AP VLAN mode.
 *
 * This function enables or disables internal gateway VLAN mode for the
 * specified AP. In this mode, a VLAN tag is added to upstream (received) data
 * packets before exiting the Wi-Fi driver. VLAN tags in downstream data are
 * stripped from data packets before transmission. The default value is false.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] VlanEnabled The VLAN mode enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled);

/**
 * @brief Sets the AP VLAN ID.
 *
 * This function sets the VLAN ID for the specified AP to an internal
 * environment variable.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] vlanId The VLAN ID to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApVlanID(INT apIndex, INT vlanId);

/**
 * @brief Gets the AP bridge information.
 *
 * This function retrieves the bridge name, IP address, and subnet for the
 * specified AP.
 *
 * @param[in] index The Access Point index.
 * @param[out] bridgeName A pointer to a buffer to store the bridge name.
 * @param[out] IP A pointer to a buffer to store the IP address.
 * @param[out] subnet A pointer to a buffer to store the subnet.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet);

/**
 * @brief Sets the AP bridge information.
 *
 * This function sets the bridge name, IP address, and subnet for the specified
 * AP to internal environment variables. The bridge name is a maximum of 32
 * characters.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] bridgeName A pointer to the bridge name string.
 * @param[in] IP A pointer to the IP address string.
 * @param[in] subnet A pointer to the subnet string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet);

/**
 * @brief Resets the AP VLAN configuration.
 *
 * This function resets the VLAN configuration for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_resetApVlanCfg(INT apIndex);

//INT wifi_setApBridging(INT apIndex, BOOL bridgeEnable);             // set the enviornment variables to control briding.  If isolation is requried then disable bridging.  //use wifi_setApIsolationEnable instead
//INT wifi_getApRouterEnable(INT apIndex, BOOL *output_bool);           //P4 // Outputs a bool that indicates if router is enabled for this ap
//INT wifi_setApRouterEnable(INT apIndex, BOOL routerEnabled);          //P4 // sets the routerEnabled variable for this ap

/**
 * @brief Creates hostapd configuration variables.
 *
 * This function creates configuration variables needed for WPA/WPS. These
 * variables are implementation-dependent and, in some implementations, are
 * used by hostapd when it is started. Specific variables that are needed are
 * dependent on the hostapd implementation. These variables are set by WPA/WPS
 * security functions in this Wi-Fi HAL. If not needed for a particular
 * implementation, this function can return `WIFI_HAL_SUCCESS`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] createWpsCfg Enable or disable WPS configuration creation.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg);

/**
 * @brief Starts hostapd.
 *
 * This function starts hostapd, using the variables in the hostapd
 * configuration with a format compatible with the specific hostapd
 * implementation.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_startHostApd();

/**
 * @brief Stops hostapd.
 *
 * This function stops hostapd.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_stopHostApd();

//-----------------------------------------------------------------------------------------------

/**
 * @brief Sets the AP enable status.
 *
 * This function sets the AP enable status variable for the specified AP.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Enable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The AP enable status to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApEnable(INT apIndex, BOOL enable);

/**
 * @brief Gets the AP enable status.
 *
 * This function retrieves the setting of the internal AP enable status
 * variable, which is set by `wifi_setApEnable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_bool A pointer to a variable to store the AP enable
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief Gets the AP status.
 *
 * This function retrieves the AP "Enabled" or "Disabled" status from the
 * driver.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Status`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer to store the AP status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApStatus(INT apIndex, CHAR *output_string);

/**
 * @brief Checks if SSID advertisement is enabled for the AP.
 *
 * This function indicates whether or not beacons include the SSID name. It
 * outputs 1 if the SSID on the AP is enabled, otherwise it outputs 0.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.SSIDAdvertisementEnabled`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_bool A pointer to a variable to store the SSID
 *                         advertisement enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief Enables or disables SSID advertisement for the AP.
 *
 * This function sets an internal variable for SSID advertisement for the
 * specified AP. Set to 1 to enable, set to 0 to disable.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.SSIDAdvertisementEnabled`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The SSID advertisement enable value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable);

/**
 * @brief Pushes the SSID advertisement enable variable to the hardware.
 *
 * This function pushes the SSID advertisement enable variable to the hardware.
 * Changes are applied with `wifi_applyRadioSettings()`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The SSID advertisement enable value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_pushApSsidAdvertisementEnable(INT apIndex, BOOL enable);

/**
 * @brief Gets the AP retry limit.
 *
 * This function retrieves the maximum number of retransmissions for a packet
 * for the specified AP. This corresponds to the IEEE 802.11 parameter
 * dot11ShortRetryLimit.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.RetryLimit`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the maximum number of
 *                    retransmissions for a packet.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApRetryLimit(INT apIndex, UINT *output);

/**
 * @brief Sets the AP retry limit.
 *
 * This function sets the maximum number of retransmissions for a packet for
 * the specified AP. This corresponds to the IEEE 802.11 parameter
 * dot11ShortRetryLimit.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.RetryLimit`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] number The maximum number of retransmissions for a packet to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApRetryLimit(INT apIndex, UINT number);

/**
 * @brief Checks if the AP supports Wi-Fi Multimedia (WMM).
 *
 * This function checks if the specified Access Point supports WMM Access
 * Categories (AC).
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.WMMCapability`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the WMM capability
 *                    status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWMMCapability(INT apIndex, BOOL *output);

/**
 * @brief Checks if the AP supports Unscheduled Automatic Power Save Delivery
 *        (U-APSD).
 *
 * This function checks if the specified Access Point supports WMM U-APSD.
 * Note that U-APSD support implies WMM support.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.UAPSDCapability`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the U-APSD capability
 *                    status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApUAPSDCapability(INT apIndex, BOOL *output);

/**
 * @brief Checks if WMM is enabled for the AP.
 *
 * This function checks if WMM support is currently enabled for the specified
 * AP. When enabled, this is indicated in beacon frames.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.WMMEnable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the WMM enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWmmEnable(INT apIndex, BOOL *output);

/**
 * @brief Enables or disables WMM for the AP.
 *
 * This function enables or disables WMM on the hardware for the specified AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The WMM support enabled status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWmmEnable(INT apIndex, BOOL enable);

/**
 * @brief Checks if U-APSD is enabled for the AP.
 *
 * This function checks if U-APSD support is currently enabled for the
 * specified AP. When enabled, this is indicated in beacon frames. Note that
 * U-APSD can only be enabled if WMM is also enabled.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.UAPSDEnable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the U-APSD enable
 *                    status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output);

/**
 * @brief Enables or disables U-APSD for the AP.
 *
 * This function enables or disables U-APSD on the hardware for the specified
 * AP.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The U-APSD enable/disable value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable);

/**
 * @brief Sets the WMM ACK policy for the AP.
 *
 * This function sets the WMM ACK policy on the hardware. `ackPolicy` false
 * means do not acknowledge, true means acknowledge.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] class The class.
 * @param[in] ackPolicy The acknowledge policy.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWmmOgAckPolicy(INT apIndex, INT class, BOOL ackPolicy);

/**
 * @brief Checks if AP isolation is enabled.
 *
 * This function checks if device isolation is enabled for the specified AP.
 * A value of true means that the devices connected to the Access Point are
 * isolated from all other devices within the home network (as is typically
 * the case for a Wireless Hotspot).
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.IsolationEnable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the AP isolation enable
 *                    status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output);

/**
 * @brief Enables or disables AP isolation.
 *
 * This function enables or disables device isolation for the specified AP.
 * A value of true means that the devices connected to the Access Point are
 * isolated from all other devices within the home network (as is typically
 * the case for a Wireless Hotspot).
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.IsolationEnable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enable The AP isolation enable value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable);		

/**
 * @brief Gets the maximum number of associated devices for the AP.
 *
 * This function retrieves the maximum number of devices that can
 * simultaneously be connected to the specified AP. A value of 0 means that
 * there is no specific limit.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the maximum number of
 *                    associated devices.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output);

/**
 * @brief Sets the maximum number of associated devices for the AP.
 *
 * This function sets the maximum number of devices that can simultaneously
 * be connected to the specified AP. A value of 0 means that there is no
 * specific limit.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] number The maximum number of associated devices to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number);

/**
 * @brief Gets the associated devices high watermark threshold for the AP.
 *
 * This function retrieves the high watermark threshold for the number of
 * associated devices for the specified AP. Setting this parameter does not
 * actually limit the number of clients that can associate with this access
 * point as that is controlled by MaxAssociatedDevices. The default value of
 * this parameter should be equal to MaxAssociatedDevices. In case
 * MaxAssociatedDevices is 0 (zero), the default value of this parameter should
 * be 50. A value of 0 means that there is no specific limit and the watermark
 * calculation algorithm should be turned off.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the
 *                    HighWatermarkThreshold value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output);

/**
 * @brief Sets the associated devices high watermark threshold for the AP.
 *
 * This function sets the high watermark threshold for the number of associated
 * devices for the specified AP. Setting this parameter does not actually limit
 * the number of clients that can associate with this access point as that is
 * controlled by MaxAssociatedDevices. The default value of this parameter
 * should be equal to MaxAssociatedDevices. In case MaxAssociatedDevices is 0
 * (zero), the default value of this parameter should be 50. A value of 0 means
 * that there is no specific limit and the watermark calculation algorithm
 * should be turned off.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] Threshold The HighWatermarkThreshold value to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex,
                                                      UINT Threshold);

/**
 * @brief Gets the number of times the associated devices high watermark
 *        threshold was reached for the AP.
 *
 * This function retrieves the number of times the current total number of
 * associated devices has reached the HighWatermarkThreshold value. This
 * calculation can be based on the parameter AssociatedDeviceNumberOfEntries as
 * well. Implementation specifics about this parameter are left to the product
 * group and the device vendors. It can be updated whenever there is a new
 * client association request to the access point.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkThresholdReached`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the number of times the
 *                    current total number of associated devices has reached
 *                    the HighWatermarkThreshold value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex,
                                                            UINT *output);

/**
 * @brief Gets the associated devices high watermark for the AP.
 *
 * This function retrieves the maximum number of associated devices that have
 * ever been associated with the access point concurrently since the last reset
 * of the device or Wi-Fi module.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermark`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a variable to store the maximum number of
 *                    associated devices that have ever associated with the
 *                    access point concurrently.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output);

/**
 * @brief Gets the date and time when the associated devices high watermark
 *        was reached for the AP.
 *
 * This function retrieves the date and time at which the maximum number of
 * associated devices ever associated with the access point concurrently since
 * the last reset of the device or Wi-Fi module (or in short when was
 * X_COMCAST-COM_AssociatedDevicesHighWatermark updated). This date and time
 * value is in UTC.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkDate`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_in_seconds A pointer to a variable to store the date and
 *                               time in seconds since the epoch.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex,
                                                 ULONG *output_in_seconds);

					
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingServiceCapability	boolean	R	
//When true, indicates whether the access point supports interworking with external networks.	

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingServiceEnable	boolean	W	
//Enables or disables capability of the access point to intework with external network. When enabled, the access point includes Interworking IE in the beacon frames.	

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_PasspointCapability	boolean	R	
//Indicates whether this access point supports Passpoint (aka Hotspot 2.0). The Passpoint enabled AccessPoint must use WPA2-Enterprise security and WPS must not be enabled.	

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_PasspointEnable	boolean	W	
//Whether Passpoint (aka Hotspot 2.0) support is currently enabled. When enabled, Passpoint specific information elemenets are indicated in beacon frames.	

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_MAC_FilteringMode	string	R	
//"The current operational state of the MAC Filtering Mode, Enumeration of:    Allow-ALL, Allow, Deny			

//-----------------------------------------------------------------------------------------------				  
//Device.WiFi.AccessPoint.{i}.Security.	

/**
 * @brief Gets the supported security modes for the AP.
 *
 * This function retrieves the supported security modes for the specified AP.
 * Each list item is an enumeration of: None, WEP-64, WEP-128, WPA-Personal,
 * WPA2-Personal, WPA-WPA2-Personal, WPA-Enterprise, WPA2-Enterprise,
 * WPA-WPA2-Enterprise.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.ModesSupported`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a buffer to store the comma-separated list of
 *                    security modes.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output);

/**
 * @brief Gets the enabled security mode for the AP.
 *
 * This function retrieves the enabled security mode for the specified AP. The
 * value must be a member of the list reported by the `ModesSupported`
 * parameter.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.ModeEnabled`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a buffer to store the enabled security mode.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output);

/**
 * @brief Sets the enabled security mode for the AP.
 *
 * This function sets the enabled security mode for the specified AP. The value
 * must be a member of the list reported by the `ModesSupported` parameter.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.ModeEnabled`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] encMode A pointer to the security mode string to enable.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode);

/**
 * @brief Gets the preshared key for the AP.
 *
 * This function retrieves the preshared key for the specified AP. The key is
 * expressed as a hexadecimal string.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.PreSharedKey`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer to store the preshared key.
 *                           The buffer must be preallocated as a 64-character
 *                           string by the caller.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the preshared key for the AP.
 *
 * This function sets the preshared key for the specified AP. The key is
 * expressed as a hexadecimal string.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.PreSharedKey`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] preSharedKey A pointer to the preshared key string. The input
 *                         string must be a maximum of 64 characters.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey);

/**
 * @brief Gets the key passphrase for the AP.
 *
 * This function retrieves the key passphrase for the specified AP. The
 * passphrase is used to generate the preshared key for WPA-Personal,
 * WPA2-Personal, or WPA-WPA2-Personal security modes.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.KeyPassphrase`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer to store the key passphrase.
 *                           The buffer must be preallocated as a 63-character
 *                           string by the caller.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the key passphrase for the AP.
 *
 * This function sets the key passphrase for the specified AP. The passphrase
 * is used to generate the preshared key for WPA-Personal, WPA2-Personal, or
 * WPA-WPA2-Personal security modes.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.KeyPassphrase`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] passPhrase A pointer to the key passphrase string. The input
 *                       string must be a maximum of 63 characters.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase);

/**
 * @brief Resets the AP security settings to factory defaults.
 *
 * This function resets the Wi-Fi security settings for the specified Access
 * Point to their factory default values. The affected settings include
 * `ModeEnabled`, `WEPKey`, `PreSharedKey`, and `KeyPassphrase`.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.Reset`.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSecurityReset(INT apIndex);

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_KeyPassphrase	string(63)	RW	
//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.	If KeyPassphrase is written, then PreSharedKey is immediately generated. The ACS SHOULD NOT set both the KeyPassphrase and the PreSharedKey directly (the result of doing this is undefined). The key is generated as specified by WPA, which uses PBKDF2 from PKCS #5: Password-based Cryptography Specification Version 2.0 ([RFC2898]).	This custom parameter is defined to enable reading the Passphrase via TR-069 /ACS. When read it should return the actual passphrase			
//INT wifi_getApKeyPassphrase(INT apIndex, CHAR *output); //Tr181	
//INT wifi_setApKeyPassphrase(INT apIndex, CHAR *passphase); //Tr181	

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_WEPKey	string	RW	
//A WEP key expressed as a hexadecimal string.	WEPKey is used only if ModeEnabled is set to WEP-64 or WEP-128.	A 5 byte WEPKey corresponds to security mode WEP-64 and a 13 byte WEPKey corresponds to security mode WEP-128.	This custom parameter is defined to enable reading the WEPKey via TR-069/ACS. When read it should return the actual WEPKey.	If User enters 10 or 26 Hexadecimal characters, it should return keys as Hexadecimal characters.	If user enters 5 or 13 ASCII character key it should return key as ASCII characters.			

//-----------------------------------------------------------------------------------------------

/**
 * @brief Gets the AP RADIUS server settings.
 *
 * This function retrieves the IP address, port number, and shared secret of the
 * RADIUS server used for WLAN security. The `RadiusServerIPAddr` parameter is
 * only applicable when `ModeEnabled` is an Enterprise type (i.e.,
 * WPA-Enterprise, WPA2-Enterprise, or WPA-WPA2-Enterprise).
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr`
 *       * `Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort`
 *       * `Device.WiFi.AccessPoint.{i}.Security.RadiusSecret`
 *
 * @param apIndex The Access Point index.
 * @param IP_output A pointer to a buffer to store the RADIUS server IP
 *                  address. The buffer must be at least 64 bytes in length.
 * @param Port_output A pointer to a variable to store the RADIUS server port
 *                    number.
 * @param RadiusSecret_output A pointer to a buffer to store the RADIUS shared
 *                            secret.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output,
                                   UINT *Port_output,
                                   CHAR *RadiusSecret_output);

/**
 * @brief Sets the AP RADIUS server settings.
 *
 * This function sets the IP address, port number, and shared secret of the
 * RADIUS server used for WLAN security. The `RadiusServerIPAddr` parameter is
 * only applicable when `ModeEnabled` is an Enterprise type (i.e.,
 * WPA-Enterprise, WPA2-Enterprise, or WPA-WPA2-Enterprise).
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr`
 *       * `Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort`
 *       * `Device.WiFi.AccessPoint.{i}.Security.RadiusSecret`
 *
 * @param apIndex The Access Point index.
 * @param IPAddress A pointer to the RADIUS server IP address string. The
 *                  string must be a maximum of 64 bytes in length.
 * @param port The RADIUS server port number.
 * @param RadiusSecret A pointer to the RADIUS shared secret string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port,
                                   CHAR *RadiusSecret);

/**
 * @brief Gets the AP secondary RADIUS server settings.
 *
 * This function retrieves the IP address, port number, and shared secret of the
 * secondary RADIUS server used for WLAN security. The `RadiusServerIPAddr`
 * parameter is only applicable when `ModeEnabled` is an Enterprise type (i.e.,
 * WPA-Enterprise, WPA2-Enterprise, or WPA-WPA2-Enterprise).
 *
 * @param apIndex The Access Point index.
 * @param IP_output A pointer to a buffer to store the RADIUS server IP
 *                  address. The buffer must be at least 64 bytes in length.
 * @param Port_output A pointer to a variable to store the RADIUS server port
 *                    number.
 * @param RadiusSecret_output A pointer to a buffer to store the RADIUS shared
 *                            secret.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IP_output,
                                           UINT *Port_output,
                                           CHAR *RadiusSecret_output);

/**
 * @brief Sets the AP secondary RADIUS server settings.
 *
 * This function sets the IP address, port number, and shared secret of the
 * secondary RADIUS server used for WLAN security. The `RadiusServerIPAddr`
 * parameter is only applicable when `ModeEnabled` is an Enterprise type (i.e.,
 * WPA-Enterprise, WPA2-Enterprise, or WPA-WPA2-Enterprise).
 *
 * @param apIndex The Access Point index.
 * @param IPAddress A pointer to the RADIUS server IP address string. The
 *                  string must be a maximum of 64 bytes in length.
 * @param port The RADIUS server port number.
 * @param RadiusSecret A pointer to the RADIUS shared secret string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IPAddress,
                                           UINT port, CHAR *RadiusSecret);

/**
 * @brief Gets the AP RADIUS settings.
 *
 * This function retrieves the RADIUS settings for the specified Access Point.
 *
 * @note This function corresponds to the following TR-181 parameters:
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusServerRetries`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusServerRequestTimeout`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKLifetime`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKCaching`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKCacheInterval`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.MaxAuthenticationAttempts`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.BlacklistTableTimeout`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.IdentityRequestRetryInterval`
 *       * `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.QuietPeriodAfterFailedAuthentication`
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a `wifi_radius_setting_t` structure to store
 *                    the RADIUS settings.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output);

/**
 * @brief Sets the AP RADIUS settings.
 *
 * This function sets the RADIUS settings for the specified Access Point.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] input A pointer to a `wifi_radius_setting_t` structure
 *                  containing the RADIUS settings to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input);


//-----------------------------------------------------------------------------------------------

/**
 * @brief Gets the WPS enable status for the AP.
 *
 * This function retrieves the WPS enable status for the specified Access
 * Point.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.WPS.Enable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_bool A pointer to a variable to store the WPS enable
 *                         status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief Enables or disables WPS for the AP.
 *
 * This function enables or disables WPS functionality for the specified Access
 * Point. It sets the WPS enable environment variable for this AP to the value
 * of `enableValue`, where 1 means enabled and 0 means disabled.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.WPS.Enable`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] enableValue The WPS enable state to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWpsEnable(INT apIndex, BOOL enableValue);

/**
 * @brief Gets the supported WPS configuration methods for the AP.
 *
 * This function retrieves the supported WPS configuration methods for the
 * specified Access Point. Each list item is an enumeration of: USBFlashDrive,
 * Ethernet, ExternalNFCToken, IntegratedNFCToken, NFCInterface, PushButton,
 * PIN.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsSupported`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output A pointer to a buffer to store the comma-separated list
 *                    of supported WPS configuration methods.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output);

/**
 * @brief Gets the enabled WPS configuration methods for the AP.
 *
 * This function retrieves the enabled WPS configuration methods for the
 * specified Access Point. Each list item must be a member of the list reported
 * by the `ConfigMethodsSupported` parameter.
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer to store the comma-separated
 *                           list of enabled WPS configuration methods.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the enabled WPS configuration methods for the AP.
 *
 * This function sets the enabled WPS configuration methods for the specified
 * Access Point. Each list item must be a member of the list reported by the
 * `ConfigMethodsSupported` parameter. This function sets an environment
 * variable that specifies the WPS configuration method(s).
 *
 * @note This function corresponds to the TR-181 parameter
 *       `Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled`.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] methodString A pointer to the comma-separated list of WPS
 *                         configuration methods to enable. The valid methods
 *                         are: USBFlashDrive, Ethernet, ExternalNFCToken,
 *                         IntegratedNFCToken, NFCInterface, PushButton, PIN.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString);

/**
 * @brief Gets the WPS device PIN for the AP.
 *
 * This function retrieves the WPS PIN value for the specified Access Point.
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_ulong A pointer to a variable to store the WPS device PIN
 *                          value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong);

/**
 * @brief Sets the WPS device PIN for the AP.
 *
 * This function sets an environment variable for the WPS PIN for the specified
 * Access Point.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] pin The WPS device PIN value to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin);

/**
 * @brief Gets the WPS configuration state for the AP.
 *
 * This function retrieves the WPS configuration state for the specified
 * Access Point. The output string is either "Not configured" or "Configured".
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] output_string A pointer to a buffer to store the WPS
 *                           configuration state. The buffer must be at least
 *                           32 bytes in length.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the WPS enrollee PIN for the AP.
 *
 * This function sets the WPS enrollee PIN for the specified Access Point.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] pin A pointer to the WPS enrollee PIN string to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin);

/**
 * @brief Simulates a WPS button push for the AP.
 *
 * This function simulates a WPS button push for the specified Access Point.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setApWpsButtonPush(INT apIndex);

/**
 * @brief Cancels WPS mode for the AP.
 *
 * This function cancels WPS mode for the specified Access Point.
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_cancelApWPS(INT apIndex);

//-----------------------------------------------------------------------------------------------

/**
 * @brief Gets the associated device diagnostic results for the AP.
 *
 * This function retrieves diagnostic results for devices associated with the
 * specified Access Point. The HAL function should allocate a data structure
 * array and return it to the caller with `associated_dev_array`. This function
 * corresponds to the following TR-181 parameters:
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_OperatingStandard`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_OperatingChannelBandwidth`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_SNR`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_InterferenceSources`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_DataFramesSentAck`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_DataFramesSentNoAck`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_BytesSent`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_BytesReceived`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_RSSI`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_MinRSSI`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_MaxRSSI`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_Disassociations`
 *  * `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_AuthenticationFailures`
 *
 * @param[in] apIndex The Access Point index.
 * @param[out] associated_dev_array A pointer to a pointer to a
 *                                  `wifi_associated_dev_t` array to store the
 *                                  associated device diagnostic results.
 * @param[out] output_array_size A pointer to a variable to store the size of
 *                              the returned array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_getApAssociatedDeviceDiagnosticResult(
    INT apIndex, wifi_associated_dev_t **associated_dev_array,
    UINT *output_array_size);

//------------------------------------------------------------------------------------------------------
////SSID stearing APIs using blacklisting
//TOOD: Review
//INT wifi_setSsidSteeringPreferredList(INT radioIndex,INT apIndex, INT *preferredAPs[32]);  // prevent any client device from assocating with this ipIndex that has previously had a valid assocation on any of the listed "preferred" SSIDs unless SsidSteeringTimeout has expired for this device. The array lists all APs that are preferred over this AP.  Valid AP values are 1 to 32. Unused positions in this array must be set to 0. This setting becomes active when committed.  The wifi subsystem must default to no preferred SSID when initalized.  
////Using the concept of an preferred list provides a solution to most use cases that requrie SSID Steering.  To implement this approach, the AP places the STA into the Access Control DENY list for a given SSID only if the STA has previously associated to one of the SSIDs in the preferred list that for SSID.
//INT wifi_setSsidSteeringTimout(INT radioIndex,INT apIndex, ULONG SsidSteeringTimout);  // only prevent the client device from assocatign with this apIndex if the device has connected to a preferred SSID within this timeout period - in units of hours.  This setting becomes active when committed.  

/**
 * @brief Callback function invoked when a new device associates with an AP.
 *
 * This callback function is invoked when a new Wi-Fi client associates with
 * the specified Access Point.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] associated_dev A pointer to a `wifi_associated_dev_t` structure
 *                           containing information about the associated
 *                           device.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
typedef INT (*wifi_newApAssociatedDevice_callback)(INT apIndex,
                                                   wifi_associated_dev_t *associated_dev);

/**
 * @brief Registers a callback function for new AP associated device events.
 *
 * This function registers a callback function that will be invoked when a new
 * Wi-Fi client associates with an Access Point.
 *
 * @param[in] callback_proc The callback function to register.
 */
void wifi_newApAssociatedDevice_callback_register(
    wifi_newApAssociatedDevice_callback callback_proc);

/**
 * @brief Kills and restarts hostapd.
 *
 * This function kills the running hostapd process and restarts it with the
 * current configuration.
 */
void KillHostapd();

/**
 * @brief Checks if hostapd is running.
 *
 * This function checks if the hostapd process is currently running.
 *
 * @returns True if hostapd is running, false otherwise.
 */
BOOL checkWifi();

/**
 * @brief Checks if the wlan0 interface is up.
 *
 * This function checks if the wlan0 interface is currently up.
 *
 * @returns True if the wlan0 interface is up, false otherwise.
 */
BOOL checkLanInterface();

/**
 * @brief Changes a configuration value in the hostapd configuration file.
 *
 * This function changes the value of the specified field in the hostapd
 * configuration file.
 *
 * @param[in] field_name The name of the field to change.
 * @param[in] field_value The new value for the field.
 * @param[out] buf A buffer to store the modified configuration file content.
 * @param[in,out] nbytes A pointer to a variable that specifies the size of the
 *                       buffer on input, and is updated with the actual number
 *                       of bytes written to the buffer on output.
 *
 * @returns The status of the operation.
 * @retval 0 if successful.
 * @retval -1 if an error occurred.
 */
INT CcspHal_change_config_value(char *field_name, char *field_value, char *buf,
                                unsigned int *nbytes);

/***********************************************************************************************
			MAC FILTERING FUNCTION DEFINITION
***********************************************************************************************/
/**
 * @brief Adds a Wi-Fi MAC filtering rule chain.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int do_MacFilter_Addrule();

/**
 * @brief Deletes a Wi-Fi MAC filtering rule chain.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int do_MacFilter_Delrule();

/**
 * @brief Updates a Wi-Fi MAC filtering rule chain.
 *
 * @param[in] Operation The operation to perform to update the MAC filtering
 *                       rule chain.
 * @param[in] i_macFiltCnt The MAC filter count.
 * @param[in] i_macFiltTabPtr A pointer to a `COSA_DML_WIFI_AP_MAC_FILTER`
 *                            structure containing the MAC filter table.
 * @param[in] count The count.
 * @param[in] hostPtr A pointer to a `hostDetails` structure containing host
 *                    details.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int do_MacFilter_Update(char *Operation, int i_macFiltCnt,COSA_DML_WIFI_AP_MAC_FILTER  *i_macFiltTabPtr,int count,struct hostDetails *hostPtr);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Wi-Fi band enumeration.
 *
 * This enumeration defines the possible Wi-Fi bands.
 */
typedef enum {
  band_invalid = -1, /**< Invalid band. */
  band_2_4 = 0,     /**< 2.4 GHz band. */
  band_5 = 1,       /**< 5 GHz band. */
} wifi_band;

/**
 * @brief Gets the AP index for the specified Wi-Fi band.
 *
 * This function retrieves the Access Point index for the specified Wi-Fi
 * band.
 *
 * @param[in] band The Wi-Fi band.
 *
 * @returns The AP index for the requested Wi-Fi band.
 */
INT wifi_getApIndexForWiFiBand(wifi_band band);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Hostapd configuration file path.
 */
#define HOSTAPD_FNAME "/nvram/hostapd"

/**
 * @brief Security file path.
 */
#define SEC_FNAME "/etc/sec_file.txt"

/**
 * @brief Hostapd parameter names.
 */
enum hostap_names {
  ssid = 0,       /**< SSID parameter name. */
  passphrase = 1, /**< Passphrase parameter name. */
};

/**
 * @brief Hostapd parameter structure.
 */
struct params {
  char name[64];  /**< Parameter name. */
  char value[64]; /**< Parameter value. */
};

/**
 * @brief Hostapd parameter list structure.
 */
typedef struct __param_list {
  unsigned int count;       /**< Number of parameters in the list. */
  struct params *parameter_list; /**< Pointer to the array of parameters. */
} param_list_t;

/**
 * @brief Hostapd configuration structure.
 */
struct hostap_conf {
  char ssid[32];       /**< SSID. */
  char *passphrase;    /**< Passphrase. */
  char *wpa_pairwise; /**< WPA pairwise ciphers. */
  char *wpa;          /**< WPA protocols. */
  char *wpa_keymgmt;  /**< WPA key management. */
};
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */

/**
 * @brief Converts a WLAN encryption mode to a string representation.
 *
 * This function converts the given WLAN encryption mode to a string
 * representation. Each list item is an enumeration of: TKIP, AES.
 *
 * @param[in] encryption_mode The encryption mode to convert.
 * @param[out] string A pointer to a buffer to store the string
 *                    representation.
 */
void wlan_encryption_mode_to_string(char *encryption_mode, char *string);

/**
 * @brief Reads a line from a file.
 *
 * This function opens the specified file and reads the specified line.
 *
 * @param[in] file The path to the file to read.
 * @param[out] Value A pointer to a buffer to store the line read from the
 *                  file.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT File_Reading(CHAR *file, char *Value);

/**
 * @brief Converts a wireless mode to a supported standards string.
 *
 * This function converts the given wireless mode to a supported standards
 * string representation.
 *
 * @param[in] wireless_mode The wireless mode to convert.
 * @param[out] string A pointer to a buffer to store the supported standards
 *                    string.
 * @param[in] freq The frequency band.
 */
void wlan_wireless_mode_to_supported_standards_string(char *wireless_mode, char *string, char *freq);

/**
 * @brief Converts a bitrate to an operated standards string.
 *
 * This function converts the given bitrate to an operated standards string
 * representation.
 *
 * @param[in] bitrate The bitrate to convert.
 * @param[out] string A pointer to a buffer to store the operated standards
 *                    string.
 * @param[in] freq The frequency band.
 */
void wlan_bitrate_to_operated_standards_string(char *bitrate, char *string, char *freq);

/**
 * @brief Converts operated standards to an operating channel bandwidth string.
 *
 * This function converts the given operated standards to an operating channel
 * bandwidth string representation.
 *
 * @param[in] wireless_mode The operated standards to convert.
 * @param[out] string A pointer to a buffer to store the operating channel
 *                    bandwidth string.
 */
void wlan_operated_standards_to_channel_bandwidth_string(char *wireless_mode, char *string);


/***************************************************************
        Checking Hostapd status(whether it's running or not)
****************************************************************/
//TODO: Review
/*
*       Procedure       : Checking Hostapd status(whether it's running or not)
*       Purpose         : Restart the Hostapd with updated configuration parameter
*       Parameter       :
*        status         : Having Hostapd status
*       Return_values   : None
*/

/**
 * @brief Gets the status of the public Wi-Fi.
 *
 * This function retrieves the status of the public Wi-Fi.
 *
 * @param[out] status A buffer to store the public Wi-Fi status. The buffer must
 *                    be at least 50 bytes in length.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT Hostapd_PublicWifi_status(char status[50]);

/**
 * @brief Gets the status of the private Wi-Fi.
 *
 * This function retrieves the status of the private Wi-Fi.
 *
 * @param[out] status A buffer to store the private Wi-Fi status. The buffer
 *                    must be at least 50 bytes in length.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT Hostapd_PrivateWifi_status(char status[50]);

/**
 * @brief Gets the interface name from the hostapd configuration file.
 *
 * This function retrieves the interface name from the specified hostapd
 * configuration file.
 *
 * @param[out] interface_name A buffer to store the interface name. The buffer
 *                            must be at least 50 bytes in length.
 * @param[in] conf_file The path to the hostapd configuration file.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT GetInterfaceName(char interface_name[50], char conf_file[100]);

/**
 * @brief Gets the virtual interface name for the 2.4 GHz Xfinity Wi-Fi.
 *
 * This function retrieves the virtual interface name for the 2.4 GHz Xfinity
 * Wi-Fi.
 *
 * @param[out] interface_name A buffer to store the interface name. The buffer
 *                            must be at least 50 bytes in length.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT GetInterfaceName_virtualInterfaceName_2G(char interface_name[50]);

/**
 * @brief Restarts the hostapd process.
 *
 * This function restarts the hostapd process.
 */
void RestartHostapd();

/**
 * @brief Kills the hostapd process.
 *
 * This function kills the existing hostapd process.
 */
void KillHostapd();

/**
 * @brief Restarts the 2.4 GHz Xfinity Wi-Fi.
 *
 * This function restarts the 2.4 GHz Xfinity Wi-Fi for the specified SSID
 * index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void xfinitywifi_2g(int ssidIndex);

/**
 * @brief Restarts the 2.4 GHz private Wi-Fi.
 *
 * This function restarts the 2.4 GHz private Wi-Fi for the specified SSID
 * index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void privatewifi_2g(int ssidIndex);

/**
 * @brief Kills the 2.4 GHz hostapd process.
 *
 * This function kills the 2.4 GHz hostapd process for the specified SSID
 * index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void KillHostapd_2g(int ssidIndex);

/**
 * @brief Kills the 2.4 GHz Xfinity Wi-Fi hostapd process.
 *
 * This function kills the 2.4 GHz Xfinity Wi-Fi hostapd process for the
 * specified SSID index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void KillHostapd_xfinity_2g(int ssidIndex);

/**
 * @brief Restarts the 5 GHz Xfinity Wi-Fi.
 *
 * This function restarts the 5 GHz Xfinity Wi-Fi for the specified SSID
 * index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void xfinitywifi_5g(int ssidIndex);

/**
 * @brief Restarts the 5 GHz private Wi-Fi.
 *
 * This function restarts the 5 GHz private Wi-Fi for the specified SSID
 * index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void privatewifi_5g(int ssidIndex);

/**
 * @brief Kills the 5 GHz hostapd process.
 *
 * This function kills the 5 GHz hostapd process for the specified SSID
 * index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void KillHostapd_5g(int ssidIndex);

/**
 * @brief Kills the 5 GHz Xfinity Wi-Fi hostapd process.
 *
 * This function kills the 5 GHz Xfinity Wi-Fi hostapd process for the
 * specified SSID index.
 *
 * @param[in] ssidIndex The SSID index.
 */
void KillHostapd_xfinity_5g(int ssidIndex);

/**
 * @brief Kills the Xfinity Wi-Fi setup.
 *
 * This function kills the existing Xfinity Wi-Fi setup.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT killXfinityWiFi();

/**
 * @brief Restarts the hostapd process with factory reset settings.
 *
 * This function restarts the hostapd process with the factory reset
 * configuration.
 */
void defaultwifi_restarting_process();

/**
 * @brief Restarts the hostapd process with dongle identification.
 *
 * This function restarts the hostapd process with dongle identification
 * (Tenda/Tp-link).
 *
 * @param[in] apIndex The Access Point index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int hostapd_restarting_process(int apIndex);

/**
 * @brief Gets the MAC address of the WAN interface.
 *
 * This function retrieves the MAC address of the WAN interface.
 *
 * @param[out] mac A buffer to store the MAC address.
 */
void get_mac(unsigned char *mac);

/**
 * @brief Checks if the hostapd process is running.
 *
 * This function checks if the hostapd process is currently running.
 *
 * @returns True if hostapd is running, false otherwise.
 */
BOOL checkWifi();

/**
 * @brief Checks if the wireless interface is up.
 *
 * This function checks if the wireless interface is currently up.
 *
 * @returns True if the wireless interface is up, false otherwise.
 */
BOOL checkLanInterface();

/**
 * @brief Gets the SSID name from the hostapd configuration file.
 *
 * This function retrieves the SSID name from the specified hostapd
 * configuration file.
 *
 * @param[in] ssidIndex The SSID index.
 * @param[in] hostapd_conf The path to the hostapd configuration file.
 * @param[out] val A buffer to store the SSID name.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT GettingHostapdSsid(INT ssidIndex, char *hostapd_conf, char *val);

/**
 * @brief Disables the Wi-Fi interface.
 *
 * This function disables the Wi-Fi interface for the specified instance
 * number.
 *
 * @param[in] InstanceNumber The instance number of the Wi-Fi interface.
 */
void DisableWifi(int InstanceNumber);

/**
 * @brief Reads the hostapd configuration.
 *
 * This function reads the hostapd configuration file with the corresponding
 * parameters.
 *
 * @param[in] ap The Access Point index.
 * @param[in] params A pointer to a `params` structure containing the
 *                   parameters to read.
 * @param[out] output A buffer to store the configuration values.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int wifi_hostapdRead(int ap, struct params *params, char *output);

/**
 * @brief Writes the hostapd configuration.
 *
 * This function writes the hostapd configuration with the corresponding
 * parameters.
 *
 * @param[in] ap The Access Point index.
 * @param[in] list A pointer to a `param_list_t` structure containing the
 *                 parameters to write.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int wifi_hostapdWrite(int ap, param_list_t *list);

/**
 * @brief Gets the Wi-Fi maximum bitrate.
 *
 * This function retrieves the maximum bitrate for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[out] output_string A buffer to store the maximum bitrate.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT get_wifiMaxbitrate(int radioIndex, char *output_string);

/**
 * @brief Updates the radio channel number.
 *
 * This function updates the radio channel number for the specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] channel The new channel number.
 */
void wifi_updateRadiochannel(INT radioIndex, ULONG channel);

/**
 * @brief Sets the auto channel enable configuration parameter.
 *
 * This function sets the auto channel enable configuration parameter for the
 * specified radio.
 *
 * @param[in] radioIndex The radio index.
 * @param[in] channel The channel number.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_setAutoChannelEnableVal(INT radioIndex, ULONG channel);

/**
 * @brief Stores the previous channel value for auto channel enable.
 *
 * This function stores the previous channel value for the specified radio.
 * This is used for the auto channel enable feature.
 *
 * @param[in] radioIndex The radio index.
 */
void wifi_storeprevchanval(INT radioIndex);

/**
 * @brief Gets the radio channel bandwidth.
 *
 * This function retrieves the radio channel bandwidth from the specified file.
 *
 * @param[in] file The path to the file containing the channel bandwidth.
 * @param[out] Value A buffer to store the channel bandwidth value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_halgetRadioChannelBW(CHAR *file, CHAR *Value);

/**
 * @brief Sets the radio channel bandwidth to 40 MHz.
 *
 * This function sets the radio channel bandwidth to 40 MHz in the specified
 * file.
 *
 * @param[in] file The path to the file containing the channel bandwidth.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_halsetRadioChannelBW_40(char *file);

/**
 * @brief Sets the radio channel bandwidth to 20 MHz.
 *
 * This function sets the radio channel bandwidth to 20 MHz in the specified
 * file.
 *
 * @param[in] file The path to the file containing the channel bandwidth.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_halsetRadioChannelBW_20(char *file);

/**
 * @brief Gets the radio extension channel.
 *
 * This function retrieves the radio extension channel from the specified file.
 *
 * @param[in] file The path to the file containing the extension channel.
 * @param[out] Value A buffer to store the extension channel value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_halgetRadioExtChannel(CHAR *file, CHAR *Value);

/**
 * @brief Gets the wireless interface statistics.
 *
 * This function retrieves the wireless interface statistics for the specified
 * interface name.
 *
 * @param[in] ifname The name of the wireless interface.
 * @param[out] pStats A pointer to a `wifi_radioTrafficStats2_t` structure to
 *                    store the interface statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_halGetIfStats(char *ifname, wifi_radioTrafficStats2_t *pStats);

/**
 * @brief Gets the interface status.
 *
 * This function retrieves the status of the specified interface.
 *
 * @param[in] interface_name The name of the interface.
 * @param[out] status A buffer to store the interface status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT GetIfacestatus(CHAR *interface_name, CHAR *status);

/**
 * @brief Gets null interface statistics.
 *
 * This function retrieves null interface statistics.
 *
 * @param[out] output_struct A pointer to a `wifi_radioTrafficStats2_t`
 *                           structure to store the null interface statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifi_halGetIfStatsNull(wifi_radioTrafficStats2_t *output_struct);

/**
 * @brief Gets the BSSID of the SSID.
 *
 * This function retrieves the BSSID of the SSID for the specified interface.
 *
 * @param[in] interface_name The name of the interface.
 * @param[out] mac A buffer to store the BSSID.
 * @param[in] index The index of the SSID.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifihal_getBaseBSSID(CHAR *interface_name, CHAR *mac, INT index);

/**
 * @brief Scans for nearby Wi-Fi devices.
 *
 * This function scans for nearby Wi-Fi devices and retrieves the scanning
 * values from the specified file.
 *
 * @param[in] file The path to the file containing the scanning values.
 * @param[out] value A buffer to store the scanning values.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int GetScanningValues(char *file, char *value);

/**
 * @brief Converts a string to uppercase.
 *
 * This function converts the given string to uppercase.
 *
 * @param[in,out] Value The string to convert to uppercase.
 */
void converting_lowercase_to_uppercase(char *Value);

/**
 * @brief Gets neighboring AP scanning details.
 *
 * This function retrieves neighboring AP scanning details for the specified
 * interface.
 *
 * @param[in] interface_name The name of the interface.
 * @param[out] neighbor_ap_array A pointer to a pointer to a
 *                               `wifi_neighbor_ap2_t` array to store the
 *                               neighboring AP scanning details.
 * @param[out] output_array_size A pointer to a variable to store the size of
 *                              the returned array.
 */
void wifihal_GettingNeighbouringAPScanningDetails(
    char *interface_name, wifi_neighbor_ap2_t **neighbor_ap_array,
    UINT *output_array_size);

/**
 * @brief Presses the virtual WPS button.
 *
 * This function simulates a press of the virtual WPS button for the specified
 * interface.
 *
 * @param[in] interface_name The name of the interface.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT SetWPSButton(char *interface_name);

/**
 * @brief Gets associated device statistics.
 *
 * This function retrieves associated device statistics for the specified
 * interface.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] interface_name The name of the interface.
 * @param[out] associated_dev_array A pointer to a pointer to a
 *                                  `wifi_associated_dev_t` array to store the
 *                                  associated device statistics.
 * @param[out] output_array_size A pointer to a variable to store the size of
 *                              the returned array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
INT wifihal_AssociatedDevicesstats(
    INT apIndex, CHAR *interface_name,
    wifi_associated_dev_t **associated_dev_array, UINT *output_array_size);

/**
 * @brief Gets the interface status.
 *
 * This function retrieves the status of the specified interface.
 *
 * @param[out] wifi_status A buffer to store the interface status.
 * @param[in] interface_name The name of the interface.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
int wifihal_interfacestatus(CHAR *wifi_status, CHAR *interface_name);



//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService. 
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.AccessNetworkType	
//Access Network Type value to be included in the Interworking IE in the beaconds. (refer 8.4.2.94 of IEEE Std 802.11-2012). Possible values are: 0 - Private network;1 - Private network with guest access;2 - Chargeable public network;3 - Free public network;4 - Personal device network;5 - Emergency services only network;6-13 - Reserved;14 - Test or experimental;15 - Wildcard
//INT wifi_setAccessNetworkType(INT apIndex, INT accessNetworkType);   // P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.Internet	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueGroupCode	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueTypeCode	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.HESSID	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.DGAFEnable	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.ANQPDomainID
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueNamesNumberOfEntries	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.OperatorNamesNumberOfEntries	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.ConsortiumOIsNumberOfEntries	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.DomainNamesNumberOfEntries	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.3GPPNetworksNumberOfEntries	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.NAIRealmsNumberOfEntries	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.VanueName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.OperatorName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.ConsortiumOIs.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.ConsortiumOIs.{i}.OI	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.DomainNames.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.DomainNames.{i}.DomainName	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.MCC	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.MNC	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.NAIRealmEncodingType	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.NAIRealm	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethodsNumberOfEntries	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.EAPMethod	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParametersNumberOfEntries	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.ID	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.Value	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.LinkStatus	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.AtCapacity	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.DownlinkSpeed	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.UplinkSpeed	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.DownlinkLoad	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.UplinkLoad	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProvidersNumberOfEntries	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUServerURI	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUMethodsList	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUNAI	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.NamesNumberOfEntries	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.IconsNumberOfEntries	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}ServiceDescriptionsNumberOfEntries	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.LanguageCode	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.OSUProviderFriendlyName	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.IconWidth	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.IconHeight	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.LanguageCode	

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.LanguageCode	
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.ServiceDescription	

//-----------------------------------------------------------------------------------------------
//Device.IP.Diagnostics.	
//Device.IP.Diagnostics.IPPing.	
//Device.IP.Diagnostics.IPPing.DiagnosticsState	
//Device.IP.Diagnostics.IPPing.Interface
//Device.IP.Diagnostics.IPPing.Host	
//Device.IP.Diagnostics.IPPing.NumberOfRepetitions		
//Device.IP.Diagnostics.IPPing.Timeout	
//Device.IP.Diagnostics.IPPing.DataBlockSize	
//Device.IP.Diagnostics.IPPing.DSCP			

//Device.IP.Diagnostics.IPPing.SuccessCount	
//Device.IP.Diagnostics.IPPing.FailureCount		
//Device.IP.Diagnostics.IPPing.AverageResponseTime		
//Device.IP.Diagnostics.IPPing.MinimumResponseTime		
//Device.IP.Diagnostics.IPPing.MaximumResponseTime			

//TODO: Review
//Start the ping test and get the result
//INT wifi_getIPDiagnosticsIPPingResult(wifi_diag_ipping_setting_t *input, wifi_diag_ipping_result_t *result); //Tr181		
//--------------------------------------------------------------------------------------------------
// Wifi Airtime Management and QOS APIs to control contention based access to airtime
//INT wifi_clearDownLinkQos(INT apIndex);                             // clears the QOS parameters to the WMM default values for the downlink direction (from the access point to the stations.  This set must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_setDownLinkQos(INT apIndex, wifi_qos_t qosStruct);        // sets the QOS variables used in the downlink direction (from the access point to the stations).  Values must be allowable values per IEEE 802.11-2012 section 8.4.2.31.  Note:  Some implementations may requrie that all downlink APs on the same radio are set to the same QOS values. Default values are per the WMM spec.  This set must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_clearUpLinkQos(INT apIndex);                               // clears the QOS parameters to the WMM default values for the uplink direction (from the Wifi stations to the ap.  This must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_setUpLinkQos (INT apIndex, wifi_qos_t qosStruct);         // sets the QOS variables used in the uplink direction (from the Wifi stations to the AP). Values must be allowable values per IEEE 802.11-2012 section 8.4.2.31. The default values must be per the WMM spec.  This set must take affect when the api wifi_applySSIDSettings() is called.

//--------------------------------------------------------------------------------------------------
// Wifi Airtime Management and QOS APIs to control downlink queue prioritization
//INT wifi_getDownLinkQueuePrioritySupport (INT apIndex, INT *supportedPriorityLevels);  //This api is used to get the the number of supported downlink queuing priority levels for each AP/SSID.  If priority queuing levels for AP/SSIDs are not supported, the output should be set to 1. A value of 1 indicates that only the same priority level is supported for all AP/SSIDs.
//INT wifi_setDownLinkQueuePriority(INT apIndex, INT priorityLevel); // this sets the queue priority level for each AP/SSID in the downlink direction.  It is used with the downlink QOS api to manage priority access to airtime in the downlink direction.  This set must take affect when the api wifi_applySSIDSettings() is called.

//<< ------------------------------ wifi_ap_hal -----------------------

/**
 * @brief Callback function invoked when a client authentication fails.
 *
 * This callback function is invoked when the driver detects that a client
 * authentication has failed.
 *
 * @param[in] apIndex The Access Point index.
 * @param[in] MAC The MAC address of the client that failed authentication.
 * @param[in] event_type The type of authentication failure event:
 *                       * 0: Unknown reason
 *                       * 1: Wrong password
 *                       * 2: Timeout
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS The operation was successful.
 * @retval WIFI_HAL_ERROR An error occurred during the operation.
 */
typedef INT (*wifi_apAuthEvent_callback)(INT apIndex, char *MAC, INT event_type);

/**
 * @brief Registers a callback function for AP authentication events.
 *
 * This function registers a callback function that will be invoked when a
 * client authentication fails.
 *
 * @param[in] callback_proc The callback function to register.
 */
void wifi_apAuthEvent_callback_register(wifi_apAuthEvent_callback callback_proc);
/** @} */  //END OF GROUP WIFI_HAL_APIS


#else
#error "! __WIFI_HAL_H__"
#endif
