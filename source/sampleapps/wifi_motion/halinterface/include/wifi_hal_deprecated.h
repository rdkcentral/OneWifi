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
 *
 * Some material is:
 * Copyright [2014] [Cisco Systems, Inc.]
 * Licensed under the Apache License, Version 2.0
 *
*/
#ifndef __WIFI_HAL_DEPRECATED_H__
#define __WIFI_HAL_DEPRECATED_H__

#ifdef __cplusplus
extern "C"{
#endif

typedef struct _wifi_basicTrafficStats
{
     ULONG wifi_BytesSent;
     ULONG wifi_BytesReceived;
     ULONG wifi_PacketsSent;
     ULONG wifi_PacketsReceived;
     ULONG wifi_Associations;     
} wifi_basicTrafficStats_t;

typedef struct _wifi_radioTrafficStats
{
     ULONG wifi_ErrorsSent;    
     ULONG wifi_ErrorsReceived;   
     ULONG wifi_DiscardPacketsSent; 
     ULONG wifi_DiscardPacketsReceived; 
     ULONG wifi_PLCPErrorCount;    
     ULONG wifi_FCSErrorCount;    
     ULONG wifi_InvalidMACCount;    
     ULONG wifi_PacketsOtherReceived;    
     INT   wifi_Noise;     
     
} wifi_radioTrafficStats_t;    

typedef struct _wifi_ssidTrafficStats
{
     ULONG wifi_RetransCount;    
     ULONG wifi_FailedRetransCount;     
     ULONG wifi_RetryCount;  
     ULONG wifi_MultipleRetryCount;     
     ULONG wifi_ACKFailureCount;      
     ULONG wifi_AggregatedPacketCount;     
     
} wifi_ssidTrafficStats_t;  

typedef struct _wifi_neighbor_ap
{
     CHAR  ap_Radio[64];    
     CHAR  ap_SSID[64];    
     CHAR  ap_BSSID[64];    
     CHAR  ap_Mode[64];    
     UINT  ap_Channel;
     INT   ap_SignalStrength;
     CHAR  ap_SecurityModeEnabled[64];    
     CHAR  ap_EncryptionMode[64];    
     CHAR  ap_OperatingFrequencyBand[16];    
     CHAR  ap_SupportedStandards[64];    
     CHAR  ap_OperatingStandards[16];    
     CHAR  ap_OperatingChannelBandwidth[16];    
     UINT  ap_BeaconPeriod;    
     INT   ap_Noise;    
     CHAR  ap_BasicDataTransferRates[256];    
     CHAR  ap_SupportedDataTransferRates[256];
     UINT  ap_DTIMPeriod;
     UINT  ap_ChannelUtilization;    
     
} wifi_neighbor_ap_t;
//<<

typedef struct _wifi_diag_ipping_setting
{
     CHAR  ipping_Interface[256];    /**< The value MUST be the path name of a row in the IP.Interface table. The IP-layer interface over which the test is to be performed. This identifies the source IP address to use when performing the test. Example: Device.IP.Interface.1. If an empty string is specified, the CPE MUST use the interface as directed by its routing policy (Forwarding table entries) to determine the appropriate interface. */
     CHAR  ipping_Host[256];    /**< Host name or address of the host to ping. In the case where Host is specified by name, and the name resolves to more than one address, it is up to the device implementation to choose which address to use. */
     UINT  ipping_NumberOfRepetitions;    /**< Number of repetitions of the ping test to perform before reporting the results. */
     UINT  ipping_Timeout;    /**< Timeout in milliseconds for the ping test.    */
     UINT  ipping_DataBlockSize;    /**< Size of the data block in bytes to be sent for each ping. */
     UINT  ipping_DSCP;    /**< DiffServ codepoint to be used for the test packets. By default the CPE SHOULD set this value to zero. */

} wifi_diag_ipping_setting_t;    

typedef struct _wifi_diag_ipping_result
{
     CHAR  ipping_DiagnosticsState[64];    /**< Indicates availability of diagnostic data. Enumeration of:    Complete, Error_CannotResolveHostName,     Error_Internal, Error_Other */
     UINT  ipping_SuccessCount;    /**< Result parameter indicating the number of successful pings (those in which a successful response was received prior to the timeout) in the most recent ping test.    */
     UINT  ipping_FailureCount;    /**< Result parameter indicating the number of failed pings in the most recent ping test. */
     UINT  ipping_AverageResponseTime;    /**< Result parameter indicating the average response time in milliseconds over all repetitions with successful responses of the most recent ping test. If there were no successful responses, this value MUST be zero. */
     UINT  ipping_MinimumResponseTime;    /**< Result parameter indicating the minimum response time in milliseconds over all repetitions with successful responses of the most recent ping test. If there were no successful responses, this value MUST be zero. */
     UINT  ipping_MaximumResponseTime;    /**< Result parameter indicating the maximum response time in milliseconds over all repetitions with successful responses of the most recent ping test. If there were no successful responses, this value MUST be zero. */
     
} wifi_diag_ipping_result_t;


//----------------ASSO. DEV-------------------------------------------
//>> Deprecated: used for old RDKB code. 
typedef struct _wifi_device
{
     UCHAR wifi_devMacAddress[6];
     CHAR wifi_devIPAddress[64];
     BOOL wifi_devAssociatedDeviceAuthentiationState;
     INT  wifi_devSignalStrength;
     INT  wifi_devTxRate;
     INT  wifi_devRxRate;
} wifi_device_t;
//<<

typedef struct athstat_results{
    u_int32_t    rtx_total;
    u_int32_t    tx_total;
    u_int32_t    rx_total;
    u_int32_t    rx_own;
    u_int32_t    d_rx_t; // delta rx_total
    u_int32_t    d_rx_o; // delta rx_own
} athstat_results_t;

typedef enum
{
    WIFI_CSA_DEAUTH_MODE_NONE = 0,
    WIFI_CSA_DEAUTH_MODE_UCAST,
    WIFI_CSA_DEAUTH_MODE_BCAST
} wifi_csaDeauthMode_t;

typedef enum
{
    WIFI_SCANFILTER_MODE_DISABLED = 0,
    WIFI_SCANFILTER_MODE_ENABLED,
    WIFI_SCANFILTER_MODE_FIRST
} wifi_scanFilterMode_t;

typedef enum
{
    WIFI_MAC_ACL_MODE_DISABLED  = 0,
    WIFI_MAC_ACL_MODE_WHITELIST = 1,
    WIFI_MAC_ACL_MODE_BLACKLIST = 2
} wifi_macAclMode_t;

// The pulling function to retrieve the existing authenticated device Mac for specified VAP
typedef struct _mac_t {
    unsigned char byte[6];
} mac_t;

typedef struct _wifi_channelStats2 { 
    UINT    ch_Frequency;               /**< Current primary channel centre frequency */
    INT     ch_NoiseFloor;              /**< Current noise floor on channel */
    INT     ch_Non80211Noise;           /**< Current non 802.11 noise on channel */
    INT     ch_Max80211Rssi;            /**< Max RSSI from the neighbor AP in dbm on this channel */
    UINT    ch_ObssUtil;                /**< Other bss utilization for last interval */
    UINT    ch_SelfBssUtil;             /**< Self bss utilization for last interval */
} wifi_channelStats2_t;

typedef struct _wifi_channelMetrics {
    INT  channel_number;        /**< Each channel is only 20MHz bandwidth */
    BOOL channel_in_pool;       /**< If channel_in_pool is false, driver do not need to scan this channel */
    INT  channel_noise;         /**< This is used to return the average noise floor in dbm */
    BOOL channel_radar_noise;   /**< If channel_number is in DFS channel, this is used to return if radar signal is present on DFS channel (5G only) */
    INT  channel_non_80211_noise;   /**< Average non 802.11 noise */
    INT  channel_utilization;   /**< This is used to return the 802.11 utilization in percent */
    INT  channel_txpower;       /**< This is used to return the current txpower in dbm on this channel    */

    wifi_apRssi_t channel_rssi_list[64];    /**< RSSI list from the neighbor AP on this channel. The list should be sorted descendly based on ap_rssi. If there are more than 64 AP on this channel, return first 64.  */
    UINT channel_rssi_count;        /**< RSSI counter in channel_rssi_list */
} wifi_channelMetrics_t;

typedef struct _wifi_radioTrafficStatsMeasure
{
     INT   radio_RadioStatisticsMeasuringRate; /**< Input //"The rate at which radio related statistics are periodically collected.  Only statistics that explicitly indicate the use of this parameter MUST use the rate set in this parameter  Other parameter's are assumed to collect data in real-time or nearly real-time. Default value is 30 seconds.  This parameter MUST be persistent across reboots. If this parameter is changed,  then use of the new rate MUST be deferred until the start of the next interval and all metrics using this rate MUST return -1 until the completion of the next full interval Units in Seconds" */
     INT   radio_RadioStatisticsMeasuringInterval; /**< Input //The interval for which radio data MUST be retained in order and at the end of which appropriate calculations are executed and reflected in the associated radio object's.  Only statistics that explicitly indicate the use of this parameter MUST use the interval set in this parameter  Default value is 30 minutes.  This parameter MUST be persistent across reboots.   If this item is modified, then all metrics leveraging this interval as well as the metrics "Total number 802.11 packet of TX" and "Total number 802.11 packet of RX" MUST be re-initialized immediately.  Additionally, the "Statistics Start Time" must be reset to the current time. Units in Seconds */
} wifi_radioTrafficStatsMeasure_t;    //for radio only

//---------------------------------------------------------------------------------------------------

INT wifi_getTWTParams(CHAR *sta, wifi_twt_params_t *twt_params);
INT wifi_setBSSColorEnabled (INT apIndex, BOOL enabled);
INT wifi_getBSSColorEnabled(INT apIndex, BOOL *enabled);

INT wifi_getRadioChannelStats2(INT radioIndex, wifi_channelStats2_t *outputChannelStats2);

/* wifi_getHalVersion() function */
/**
* @brief Get the wifi hal version in string.
*
* Eg "2.0.0". WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
*
* @param[out] output_string  WiFi Hal version to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @sideeffect None
*/
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string);


/* wifi_getRadioCountryCode() function */
/**
* @brief Outputs the country code to a max 64 character string
*
* @param[in]  radioIndex      Index of Wi-Fi radio channel
* @param[out] output_string   Country code to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string);


/* wifi_setRadioCountryCode() function */
/**
* @brief Set the country code for selected Wi-Fi radio channel.
*
* @param[in] radioIndex    Index of Wi-Fi radio channel
* @param[in] CountryCode   Country code
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode);       


/* wifi_pushCountryCode() function */
/**
* @brief Set the country code for both wifi radios and apply them. wifi reset automatically if necessary.
*        The function need to return immediately.
*
* @param[in] CountryCode   Country code
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_pushCountryCode(CHAR *CountryCode);


typedef struct _wifi_associated_dev2
{
    mac_address_t cli_MACAddress;   /**< The MAC address of an associated device. */
    CHAR  cli_IPAddress[64];        /**< IP of the associated device */
    BOOL  cli_AuthenticationState;  /**< Whether an associated device has authenticated (true) or not (false). */
    UINT  cli_LastDataDownlinkRate; /**< The data transmit rate in kbps that was most recently used for transmission from the access point to the associated device. */
    UINT  cli_LastDataUplinkRate;   /**< The data transmit rate in kbps that was most recently used for transmission from the associated device to the access point. */
    INT   cli_SignalStrength;       /**< An indicator of radio signal strength of the uplink from the associated device to the access point, measured in dBm, as an average of the last 100 packets received from the device. */
    UINT  cli_Retransmissions;      /**< The number of packets that had to be re-transmitted, from the last 100 packets sent to the associated device. Multiple re-transmissions of the same packet count as one. */
    BOOL  cli_Active;               /**<    boolean-Whether or not this node is currently present in the WiFi AccessPoint network. */

    CHAR  cli_OperatingStandard[64];    /**< Radio standard the associated Wi-Fi client device is operating under. Enumeration of: */
    CHAR  cli_OperatingChannelBandwidth[64];    /**< The operating channel bandwidth of the associated device. The channel bandwidth (applicable to 802.11n and 802.11ac specifications only). Enumeration of: */
    INT   cli_SNR;      /**< A signal-to-noise ratio (SNR) compares the level of the Wi-Fi signal to the level of background noise. Sources of noise can include microwave ovens, cordless phone, bluetooth devices, wireless video cameras, wireless game controllers, fluorescent lights and more. It is measured in decibels (dB). */
    CHAR  cli_InterferenceSources[64]; /**< Wi-Fi operates in two frequency ranges (2.4 Ghz and 5 Ghz) which may become crowded other radio products which operate in the same ranges. This parameter reports the probable interference sources that this Wi-Fi access point may be observing. The value of this parameter is a comma seperated list of the following possible sources: eg: MicrowaveOven,CordlessPhone,BluetoothDevices,FluorescentLights,ContinuousWaves,Others */
    ULONG cli_DataFramesSentAck;    /**< The DataFramesSentAck parameter indicates the total number of MSDU frames marked as duplicates and non duplicates acknowledged. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_DataFramesSentNoAck;  /**< The DataFramesSentNoAck parameter indicates the total number of MSDU frames retransmitted out of the interface (i.e., marked as duplicate and non-duplicate) and not acknowledged, but does not exclude those defined in the DataFramesLost parameter. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_BytesSent;    /**< The total number of bytes transmitted to the client device, including framing characters. */
    ULONG cli_BytesReceived;    /**< The total number of bytes received from the client device, including framing characters. */
    INT   cli_RSSI;     /**< The Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for transmissions from the device averaged over past 100 packets recevied from the device. */
    INT   cli_MinRSSI;  /**< The Minimum Received Signal Strength Indicator, RSSI, parameter is the minimum energy observed at the antenna receiver for past transmissions (100 packets). */
    INT   cli_MaxRSSI;  /**< The Maximum Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for past transmissions (100 packets). */
    UINT  cli_Disassociations;  /**< This parameter  represents the total number of client disassociations. Reset the parameter evey 24hrs or reboot */
    UINT  cli_AuthenticationFailures;   /**< This parameter indicates the total number of authentication failures.  Reset the parameter evey 24hrs or reboot */

    ULLONG   cli_Associations;  /**<  Stats handle used to determine reconnects; increases for every association (stat delta calcualtion) */
} wifi_associated_dev2_t;

typedef enum
{
    WIFI_RADIO_QUEUE_TYPE_VI = 0,
    WIFI_RADIO_QUEUE_TYPE_VO,
    WIFI_RADIO_QUEUE_TYPE_BE,
    WIFI_RADIO_QUEUE_TYPE_BK,
    WIFI_RADIO_QUEUE_TYPE_CAB,
    WIFI_RADIO_QUEUE_TYPE_BCN,
    WIFI_RADIO_QUEUE_MAX_QTY,
    WIFI_RADIO_QUEUE_TYPE_NONE = -1
} wifi_radioQueueType_t;

// Structure to return BTM extended capability from devices on the LAN.
// The peer and capability arrays are parallel
// and have the same number of entries.
typedef struct {
    UINT                entries;                        /**< Number of entries in each of the following arrays. */
    mac_address_t       peer[MAX_BTM_DEVICES];          /**< Array a peer device MAC addresses. */
    BOOL                capability[MAX_BTM_DEVICES];    /**< Array of bool indicating peer BSS transition capability. */
} wifi_BTMCapabilities_t;

//---------------------------------------------------------------------------------------------------
// Air Time Management HAL.
//---------------------------------------------------------------------------------------------------
/**
* @brief Get the ATM(Air Time Management) Capable.
*
* @param[out] output_bool  Indication as to whether  Air Time Management is supported.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getATMCapable(BOOL *output_bool);

/**
* @brief Set ATM Enable.
*
* The type of algorithm to apply across the configured Access Points and/or clients;
*
* @param[in]  enable  Boolean value to set/unset ATM.
*                     False indicates  Disabled
                      True  indicates  Dynamic (Sharing of unused Airtime Between AP Groups allowed)
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setATMEnable(BOOL enable); 


/**
* @brief Get ATM Enable status.
*
* @param[out] output_enable  Returns the ATM enable status.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getATMEnable(BOOL *output_enable); 

/**
* @brief Set Access Point Air Time Percent.
*
* @param[in]  apIndex             Index of Access Point array.
* @param[in]  ap_AirTimePercent   The Percentage of Available Airtime assigned to this ATM Access Point Group (5%-100%)
*                                 The sum of all percentages assigned to all groups must be <= 100%"
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApATMAirTimePercent(INT apIndex, UINT ap_AirTimePercent); 

/**
* @brief Get Ap Air Time Percent.
*
* @param[in]   apIndex                    The index  of Access Point array.
* @param[out]  output_ap_AirTimePercent   The Percentage of Available Airtime assigned to this
*                                         ATM Access Point Group (5%-100%)
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApATMAirTimePercent(INT apIndex, UINT *output_ap_AirTimePercent);

/**
* @brief Get the list for Air Time Percent for each Station.
*
* @param[in]  apIndex                   The index of Access Point array.
* @param[out] output_sta_MAC_ATM_array  Caller allocated buffer.
*            output_sta_MAC_ATM_array contains the atm array in format
*           of "$MAC $ATM_percent|$MAC $ATM_percent|$MAC $ATM_percent"
* @param[out] buf_size                  The size for output_sta_MAC_ATM_array
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApATMSta(INT apIndex, UCHAR *output_sta_MAC_ATM_array, UINT  buf_size);  //output_sta_MAC_ATM_array contains the atm array in format of "$MAC $ATM_percent|$MAC $ATM_percent|$MAC $ATM_percent"
                                                                                //buf_size is the size for output_sta_MAC_ATM_array
/* wifi_getRadioNumberOfEntries() function */
/**
* @brief Get the total number of radios in this wifi subsystem.
*
* @param[out] output  Total number of radios to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the total number of radios in this wifi subsystem
INT wifi_getRadioNumberOfEntries(ULONG *output);


/* wifi_getSSIDNumberOfEntries() function */
/**
* @brief Get the total number of SSID entries in this wifi subsystem.
*
* @param[out] output Total number of SSID entries to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the total number of SSID entries in this wifi subsystem 
INT wifi_getSSIDNumberOfEntries(ULONG *output);



/**
* @brief Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]   radioIndex     Index of Wi-Fi radio channel.
* @param[out]  output_string  Maximum bit rate supported, to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string);

/* wifi_getRadioSupportedFrequencyBands() function */
/**
* @brief Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.  
* Implementations must ensure that strings are not longer than this.
* 
* @param[in]  radioIndex     Index of Wi-Fi radio channel
* @param[out] output_string  Supported frequency bands, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string);


/* wifi_getRadioOperatingFrequencyBand() function */
/**
* @brief Get the frequency band at which the radio is operating, eg: "2.4GHz".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex      Index of Wi-Fi radio channel.
* @param[out] output_string   Operating frequency band, to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string);

/* wifi_getRadioSupportedStandards() function */
/**
* @brief Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"; "ax"; "a,n,ac,ax".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex      Index of Wi-Fi radio channel.
* @param[out] output_string   Supported radio mode, to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"; "ax"; "a,n,ac,ax"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string);

/** Deprecated: used for old RDKB code. **/
/* wifi_getRadioStandard() function */
/**
* @brief Get the radio operating mode, and pure mode flag. eg: "ac".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex      Index of Wi-Fi radio channel
* @param[out] output_string   Radio operating mode, to be returned
* @param[out] gOnly           Boolean pointer variable need to be updated based on the "output_string"
* @param[out] nOnly           Boolean pointer variable need to be updated based on the "output_string"
* @param[out] acOnly          Boolean pointer variable need to be updated based on the "output_string"
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly);

/* wifi_getRadioMode() function */
/**
* @brief Get the radio operating mode, and pure mode flag. eg: "ac".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex      Index of Wi-Fi radio channel
* @param[out] output_string   Radio operating mode, to be returned
* @param[out] pureMode        Pointer to pure mode bit map starting from LSB b only, g only, a only, 
*                                 n only, ac only, ax only, e.g. n only will be 8, ax only will be 32
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMode(INT radioIndex, CHAR *output_string, UINT *pureMode);

/** Deprecated: used for old RDKB code. **/
/* wifi_setRadioChannelMode() function */
/**
* @brief Set the radio operating mode, and pure mode flag.
*
* @param[in] radioIndex   Index of Wi-Fi radio channel
* @param[in] channelMode  Pass the channelMode for specified radio index
* @param[in] gOnlyFlag    Pass operating mode flag for setting pure mode flag
* @param[in] nOnlyFlag    Pass operating mode flag for setting pure mode flag
* @param[in] acOnlyFlag   Pass operating mode flag for setting pure mode flag
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Set the radio operating mode, and pure mode flag.
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag);

/* wifi_setRadioMode() function */
/**
* @brief Set the radio operating mode, and pure mode flag.
*
* @param[in] radioIndex   Index of Wi-Fi radio channel
* @param[in] channelMode  Pass the channelMode for specified radio index
* @param[in] pureMode     Pass flag for setting pure mode bit map starting from LSB b only, g only, a only, 
*                           n only, ac only, ax only, e.g. n only will be 8, ax only will be 32
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Set the radio operating mode, and pure mode flag.
INT wifi_setRadioMode(INT radioIndex, CHAR *channelMode, UINT pureMode);

/* wifi_getRadioPossibleChannels() function */
/**
* @brief Get the list of supported channel. eg: "1-11".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex      Index of Wi-Fi radio channel
* @param[out] output_string   List of supported radio channels, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 128 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string);

#ifndef WIFI_HAL_VERSION_3_PHASE2
/* wifi_getRadioChannelsInUse() function */
/**
* @brief Get the list of supported channel. eg: "1-11".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex     Index of Wi-Fi radio channel
* @param[out] output_string  List of supported radio channels, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string);

#endif
/* wifi_getRadioChannel() function */
/**
* @brief Get the running channel number.
*
* @param[in]  radioIndex     Index of Wi-Fi radio channel
* @param[out] output_ulong   Running channel number, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong);

/* wifi_setRadioChannel() function */
/**
* @brief Set the running channel number.
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] channel     Channel number to be set as running wifi radio channel
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioChannel(INT radioIndex, ULONG channel);  //AP only


/* wifi_setRadioAutoChannelEnable() function */
/**
* @brief Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio.
*
* This "auto channel" means the auto channel selection when radio is up.
* (which is different from the dynamic channel/frequency selection (DFC/DCS))
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] enable      Enable/Disable selected radio channel as auto channel radio
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable);

/* wifi_getRadioAutoChannelSupported() function */
/**
* @brief Check if the driver support the AutoChannel.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_bool  Value of Auto Channel Supported, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Check if the driver support the AutoChannel
INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool);

/* wifi_getRadioAutoChannelEnable() function */
/**
* @brief Get the AutoChannel enable status.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_bool  Auto Channel Enabled status, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get the AutoChannel enable status
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool);

/* wifi_getRadioDCSSupported() function */
/**
* @brief Check if the driver support the DCS.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_bool  DCS Supported flag for the radio index, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Check if the driver support the DCS
INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool);


/* wifi_getRadioDCSEnable() function */
/**
* @brief Get DCS of the selected wifi radio channel's enable/disable status.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_bool  DCS Enable flag for the selected radio index, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool);

/* wifi_setRadioDCSEnable() function */
/**
* @brief Enable/Disable selected wifi radio channel's DCS.
*
* @param[in]  radioIndex  Index of Wi-Fi radio channel
* @param[out] enable      Set the value of DCS Enable flag for the selected radio index
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable);

/* wifi_getRadioDCSChannelPool() function */
/**
* @brief Get radio DCS channel pool.
*
* The output_string is a max length 256 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
* The value of this parameter is a comma seperated list of channel number.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_pool  DCS channel pool for the selected radio index,to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
//The value of this parameter is a comma seperated list of channel number
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool);

/* wifi_setRadioDCSChannelPool() function */
/**
* @brief Set radio DCS channel pool.
*
* The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
* The value of this parameter is a comma seperated list of channel number.
*
* @param[in] radioIndex Index of Wi-Fi radio channel
* @param[in] pool       Set DCS channel pool for the selected radio index
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool);

/* wifi_getRadioDCSScanTime() function */
/**
* @brief Get radio DCS scan time.
*
* @param[in]  radioIndex                 Index of Wi-Fi radio channel
* @param[out] output_interval_seconds    Get the interval time in seconds
* @param[out] output_dwell_milliseconds  Get the dwell time in milliseconds
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds, INT *output_dwell_milliseconds);

/* wifi_setRadioDCSScanTime() function */
/**
* @brief Set radio DCS scan time.
*
* @param[in]  radioIndex          Index of Wi-Fi radio channel
* @param[in]  interval_seconds    Set the interval time in seconds
* @param[in]  dwell_milliseconds  Set the dwell time in milliseconds
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds, INT dwell_milliseconds);

/**
* @brief Set radio Dcs Dwell time.
*
* @param[in]  radioIndex   Index of Wi-Fi radio 
* @param[in]  millisecond  Dwell time on each channel
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioDcsDwelltime(INT radioIndex, INT millisecond); 

/**
* @brief Get radio Dcs Dwell time.
*
* @param[in] radioIndex           Index of Wi-Fi radio 
* @param[in] output_millisecond   Dwell time on each channel
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioDcsDwelltime(INT radioIndex, INT *output_millisecond);

/* wifi_setRadioDcsScanning() function */
/**
* @brief Enable/Disable selected wifi radio channel's DCS.
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] enable      Set the value of DCS Enable flag for the selected radio index
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioDcsScanning(INT radioIndex, BOOL enable);

/* wifi_getRadioDcsScanning() function */
/**
* @brief Get DCS of the selected wifi radio channel's enable/disable status.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_bool  DCS Enable flag for the selected radio index, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioDcsScanning(INT radioIndex, BOOL *output_bool);

/**
* @brief Get radio Channel Metrics.
*
* @param[in]  radioIndex                          Index of Wi-Fi radio 
* @param[out] input_output_channelMetrics_array   caller allocated buffer
* @param[out] array_size                          The count for wifi_channelMetrics_t that caller allocated
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and should not invoke any blocking system
* calls. This is blocking call.
*
*/
INT wifi_getRadioDcsChannelMetrics(INT radioIndex, wifi_channelMetrics_t *input_output_channelMetrics_array, INT array_size);

/**
* @brief Instantlly change the radio Channel.
*
* Use Channels Switch Announcements (CSAs) (in 802.11h) to notify the client, 
* and channel change instantly. Do not save wifi config (channel change is not 
* persistent over wifi reboot).
*
* @param[in] radioIndex  Index of Wi-Fi radio 
* @param[in] channel     net channel
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and should not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_pushRadioChannel(INT radioIndex, UINT channel);
//Dynamic Channel Selection (phase 2) HAL END

/**
* @brief  This HAL API is used to change the channel to destination channel, with destination bandwidth.
*
* @param[in] radioIndex          Index of Wi-Fi radio 
* @param[in] channel             net channel
* @param[in] channel_width_MHz   channel frequency
* @param[in] csa_beacon_count    Specifies how long CSA need to be announced.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and should not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_pushRadioChannel2(INT radioIndex, UINT channel, UINT channel_width_MHz, UINT csa_beacon_count);

/* wifi_getRadioDfsSupport() function */
/**
* @brief Get radio DFS support.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_bool  Get DFS support for the selected radio index in the pre-allocated buffer
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Get radio DFS support
INT wifi_getRadioDfsSupport(INT radioIndex, BOOL *output_bool);

/* wifi_getRadioAutoChannelRefreshPeriodSupported() function */
/**
* @brief Check if the driver support the AutoChannelRefreshPeriod.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_bool  Get auto channel refresh period support for the selected radio channel
*                          in the pre-allocated bool buffer.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex, BOOL *output_bool);

/* wifi_getRadioAutoChannelRefreshPeriod() function */
/**
* @brief Get the DCS refresh period in seconds.
*
* @param[in]  radioIndex    Index of Wi-Fi radio channel
* @param[out] output_ulong  The refresh period.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong);

/* wifi_setRadioAutoChannelRefreshPeriod() function */
/**
* @brief Set the DCS refresh period in seconds.
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] seconds     Set auto channel refresh period in seconds support for the selected radio channel.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds);

/* wifi_getRadioOperatingChannelBandwidth() function */
/**
* @brief Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex      Index of Wi-Fi radio channel
* @param[out] output_string   Get operating channel bandwidth for the selected radio channel in the pre-allocated char buffer.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string);

/* wifi_setRadioOperatingChannelBandwidth() function */
/**
* @brief Set the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160".
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] bandwidth   Set operating channel bandwidth for the selected radio channel
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth); //AP only

/* wifi_getRadioExtChannel() function */
/**
* @brief Get the secondary extension channel position.
*
* "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only).
* The output_string is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex     Index of Wi-Fi radio channel
* @param[out] output_string  Secondary extension channel position, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string);

/* wifi_setRadioExtChannel() function */
/**
* @brief Set the secondary extension channel position.
*
* "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only).
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] string      Secondary extension channel position
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string); //AP only

/* wifi_getRadioGuardInterval() function */
/**
* @brief Get the guard interval value. eg "400nsec" or "800nsec".
*
* The output_string is a max length 64 octet string that is allocated by the RDKB code. 
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex     Index of Wi-Fi radio channel
* @param[out] output_string  Guard interval value, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string);

/* wifi_setRadioGuardInterval() function */
/**
* @brief Set the guard interval value. eg "400nsec" or "800nsec".
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] string      Guard interval value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string);

/* wifi_getRadioTransmitPowerSupported() function */
/**
* @brief Get supported Transmit Power list, eg : "0,25,50,75,100".
*
* The output_list is a max length 64 octet string that is allocated by the RDKB code.
* Implementations must ensure that strings are not longer than this.
*
* @param[in]  radioIndex   Index of Wi-Fi radio channel
* @param[out] output_list  Transmit power list, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list);

/* wifi_getRadioIEEE80211hSupported() function */
/**
* @brief Get 80211h Supported. 
* 
* 80211h solves interference with satellites and radar using the same 5 GHz frequency band.
*
* @param[in]  radioIndex  Index of Wi-Fi radio channel
* @param[out] Supported   80211h Supported, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported);


/* wifi_getRadioIEEE80211hEnabled() function */
/**
* @brief Get 80211h feature enable.
*
* @param[in]  radioIndex  Index of Wi-Fi radio channel
* @param[out] enable      80211h feature enable, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable);

/* wifi_setRadioIEEE80211hEnabled() function */
/**
* @brief Set 80211h feature enable.
*
* @param[in] radioIndex  Index of Wi-Fi radio channel
* @param[in] enable      80211h feature enable
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable);

/* wifi_getRadioBeaconPeriod() function */
/**
* @brief Gets the time interval between transmitting beacons (expressed in milliseconds).
*
* This parameter is based ondot11BeaconPeriod from [802.11-2012].
*
* @param[in]  radioIndex  Index of Wi-Fi radio channel
* @param[out] output      Radio Beacon period, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output);

/* wifi_setRadioBeaconPeriod() function */
/**
* @brief Sets the time interval between transmitting beacons (expressed in milliseconds).
*
* This parameter is based ondot11BeaconPeriod from [802.11-2012].
*
* @param[in] radioIndex    Index of Wi-Fi radio channel
* @param[in] BeaconPeriod  Radio Beacon period
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod); 

/* wifi_getRadioSupportedDataTransmitRates() function */
/**
* @brief Get the supported data transmit rates in Mbps.
*
* That have to be supported by all stations that desire to join this BSS.
* The stations have to be able to receive and transmit at each of the data rates listed in SupportedDataTransmitRates.
* For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps.
* Most control packets use a data rate in SupportedDataTransmitRates
*
* @param[in]  radioIndex    Index of Wi-Fi radio channel
* @param[out] output_rates  Comma-separated list of strings, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Contains a comma separated string of supported rates supported by the radio instance. Must include all rates in the acceptance criteria belonging to the corresponding radio configuration.    
INT wifi_getRadioSupportedDataTransmitRates(INT radioIndex, char *output_rates);

/* wifi_getRadioBasicDataTransmitRates() function */
/**
* @brief Get the set of data rates, in Mbps.
*
* This has to be supported by all stations that desire to join this BSS.
* The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates.
* For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps.
* Most control packets use a data rate in BasicDataTransmitRates.
*
* @param[in]  radioIndex  Index of Wi-Fi radio channel
* @param[out] output      Comma-separated list of strings, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.    
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output);

/* wifi_setRadioBasicDataTransmitRates() function */
/**
* @brief Set the data rates, in Mbps.
*
* This have to be supported by all stations that desire to join this BSS.
* The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. 
* For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps.
* Most control packets use a data rate in BasicDataTransmitRates.
*
* @param[in] radioIndex     Index of Wi-Fi radio channel
* @param[in] TransmitRates  Comma-separated list of strings
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates);

/* getRadioOperationalDataTransmitRates() function */
/**
* @brief Get the set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS.
*
* The stations have to be able to receive and transmit at each of the data rates listed inOperationalDataTransmitRates.
* For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps.
* Most control packets use a data rate in OperationalDataTransmitRates.
*
* @param[in]  radioIndex    Index of Wi-Fi radio channel
* @param[out] output_rates  Comma-separated list of strings, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Contains a comman separated string of operational rates supported by the radio instance. Is either equal to the set of supported rates or a super set.    
INT wifi_getRadioOperationalDataTransmitRates(INT radioIndex, char *output_rates);        

/* wifi_setRadioOperationalDataTransmitRates() function */
/**
 * @brief Set the data rates, in Mbps, that have to be supported by all stations that desire to join this BSS.
 *
 * The stations should be able to receive and transmit at each of the data rates listed in OperationalDataTransmitRates.
 * For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps.
 * Most control packets use a data rate in OperationalDataTransmitRates.
 *
 * @param[in]  radioIndex  Index of Wi-Fi radio channel
 * @param[out] rates       Comma-separated list of strings
 *
 * @return The status of the operation
 * @retval RETURN_OK if successful
 * @retval RETURN_ERR if any error is detected
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls. It should probably just send a message to a driver event handler task.
 *
 */
INT wifi_setRadioOperationalDataTransmitRates(INT radioIndex, char *rates);

/* wifi_setRadioTrafficStatsMeasure() function */
/**
* @brief Set radio traffic static Measuring rules.
*
* @param[in] radioIndex    Index of Wi-Fi radio channel
* @param[in] input_struct  wifi_radioTrafficStatsMeasure_t *input_struct, traffic stats measure info
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct);

/* wifi_setRadioTrafficStatsRadioStatisticsEnable() function */
/**
* @brief Set radio traffic statistics enable.
*
* @param[in]  radioIndex  Index of Wi-Fi radio channel
* @param[out] enable      Enable/disable, traffic stats statistics
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioTrafficStatsRadioStatisticsEnable(INT radioIndex, BOOL enable);

//-----------------------------------------------------------------------------------------------
/* wifi_getRadioStatsReceivedSignalLevel() function */
/**
* @brief Clients associated with the AP over a specific interval.
*
* The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm 
* end of the range.
* Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included
* in the respective bin.
* The bin associated with the clients current received signal level MUST be incremented when a client associates with the AP.
* Additionally, the respective bins associated with each connected clients current received signal level MUST be incremented at
* the interval defined by "Radio Statistics Measuring Rate".
* The histogram  bins MUST NOT be incremented at any other time.
* The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by 
* "Radio Statistics Measuring Interval".
* The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval".
* If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of
* data, it MUST return -1.
* Units dBm.
*
* @param[in] radioIndex   Index of Wi-Fi radio channel
* @param[in] signalIndex  Signal index
* @param[out]SignalLevel  Signal level, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel);

/* wifi_getSSIDEnable() function */
/**
* @brief Get SSID enable configuration parameters (not the SSID enable status).
*
* @param[in]  ssidIndex   SSID index
* @param[out] output_bool SSID enable, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool);

/* wifi_setSSIDEnable() function */
/**
* @brief Set SSID enable configuration parameters.
*
* @param[in] ssidIndex  SSID index
* @param[in] enable     SSID enable value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable);

/* wifi_getSSIDStatus() function */
/**
* @brief Get SSID enable status.
*
* @param[in]  ssidIndex     SSID index
* @param[out] output_string SSID enable status, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string);

/* wifi_getSSIDName() function */
/**
* @brief Get SSID Name associated with the Access Point index.
*
* Outputs a 32 byte or less string indicating the SSID name.
* Sring buffer must be preallocated by the caller.
*
* @param[in]  apIndex         Access Point index
* @param[out] output_string   SSID name, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getSSIDName(INT apIndex, CHAR *output_string);        

/**
* @brief To read the run time ssid name.
*
* @param[in]  apIndex         Access Point index
* @param[out] output_string   SSID name, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getSSIDNameStatus(INT apIndex, CHAR *output_string);


/* wifi_setSSIDName() function */
/**
* @brief Set SSID Name associated with the Access Point index.
*
* Accepts a max 32 byte string and sets an internal variable to the SSID name.
*
* @param[in]  apIndex      Access Point index
* @param[out] ssid_string  SSID Name
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string);

/* wifi_getBaseBSSID() function */
/**
* @brief Get the BSSID.
*
* @param[in]  ssidIndex      SSID index
* @param[out] output_string  Base BSSID, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string);

/* wifi_getSSIDMACAddress() function */
/**
* @brief Get the MAC address associated with this Wifi SSID.
*
* @param[in]  ssidIndex      SSID index
* @param[out] output_string  MAC Address, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string);
//we can use ap_index and replace char* with mac_address_t


/* wifi_getNeighboringWiFiDiagnosticResult2() function */
/**
* @brief Start the wifi scan and get the result into output buffer for RDKB to parser.
*
* The result will be used to manage endpoint list. HAL functon should allocate an data structure array,
* and return to caller with "neighbor_ap_array". 
*
* @param[in]  radioIndex           Radio index
* @param[out] neighbor_ap_array    Neighbour access point info to be returned
* @param[out] output_array_size    Length of the output array.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getNeighboringWiFiDiagnosticResult2(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);

#ifndef WIFI_HAL_VERSION_3_PHASE2
/**
* @brief Returns the Wifi scan status.
*
* @param[in]  radioIndex           Radio index
* @param[out] neighbor_ap_array    Neighbour access point info to be returned
* @param[out] output_array_size    Length of the output array.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);
#endif

//>> Deprecated: used for old RDKB code. 
/** Deprecated: used for old RDKB code. */
INT wifi_getSSIDTrafficStats(INT ssidIndex, wifi_ssidTrafficStats_t *output_struct);
/** Deprecated: used for old RDKB code. */
INT wifi_getBasicTrafficStats(INT apIndex, wifi_basicTrafficStats_t *output_struct);  //!< Outputs basic traffic stats per AP
/** Deprecated: used for old RDKB code. */
INT wifi_getNeighboringWiFiDiagnosticResult(wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size);
/**  Deprecated: used for old RDKB code. */
INT wifi_getAllAssociatedDeviceDetail(INT apIndex, ULONG *output_ulong, wifi_device_t **output_struct);

/* wifi_getBandSteeringCapability() function */
/**
* @brief To get Band Steering Capability.
*
* @param[out] support Band Steering Capability support, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getBandSteeringCapability(BOOL *support); 

#ifndef WIFI_HAL_VERSION_3_PHASE2
/* wifi_getApAssociatedDevice() function */
/**
* @brief Gets the ApAssociatedDevice list for client MAC addresses
*
* @param[in]  apIndex          Access Point index
* @param[out] output_buf       List for client MAC, to be returned
* @param[out] output_buf_size  Buffer length
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
*
*/
INT wifi_getApAssociatedDevice(INT ap_index, CHAR *output_buf, INT output_buf_size);
#endif

/* wifi_getApDeviceRSSI() function */
/**
* @brief Gets the RSSI value associated with the access point.
*
* @param[in]  apIndex      Access Point index
* @param[out] MAC          Client MAC in upcase format
* @param[out] output_RSSI  RSSI is in dbm
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
*
*/
INT wifi_getApDeviceRSSI(INT ap_index, CHAR *MAC, INT *output_RSSI);

/* wifi_getApDeviceRxrate() function */
/**
* @brief Gets the ApAssociatedDevice Rx Rate
*
* @param[in] apIndex       Access Point index
* @param[in] MAC           Client MAC in upcase format
* @param[ut] output_RxMb   Rx Rate in Mb
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
*
*/
INT wifi_getApDeviceRxrate (INT ap_index, CHAR *MAC, INT *output_RxMb);

/* wifi_getApDeviceTxrate() function */
/**
* @brief Gets the ApAssociatedDevice Tx Rate
*
* @param[in]  apIndex       Access Point index
* @param[in]  MAC           Client MAC in upcase format
* @param[out] output_TxMb   Tx Rate in Mb
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
*
*/
INT wifi_getApDeviceTxrate (INT ap_index, CHAR *MAC, INT *output_TxMb);

/* wifi_getRadioTxChainMask() function */
/**
* @brief Outputs the number of Tx streams.
*
* @param[in]  radioIndex  Radio index
* @param[out] output_int  Number of Tx streams, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int);           //P2

/* wifi_setRadioTxChainMask() function */
/**
* @brief Sets the number of Tx streams to an environment variable.
*
* @param[in] radioIndex   Radio index
* @param[in] numStreams   Number of Tx streams
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams);            //P2

/* wifi_getRadioRxChainMask() function */
/**
* @brief Outputs the number of Rx streams.
*
* @param[in]  radioIndex  Radio index
* @param[out] output_int  Number of Rx streams, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int);           //P2  // outputs the number of Rx streams


/* wifi_setRadioRxChainMask() function */
/**
* @brief Sets the number of Rx streams to an environment variable.
*
* @param[in] radioIndex   Radio index
* @param[in]  numStreams  Number of Rx streams
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams);            //P2  // sets the number of Rx streams to an environment variable

/**< Deprecated */
//INT wifi_pushRadioChannel(INT radioIndex, UINT channel);                 //P2  //!<  push the channel number setting to the hardware  //Applying changes with wifi_applyRadioSettings().
/**< Deprecated */
INT wifi_pushRadioChannelMode(INT radioIndex);                           //P2  //!< push the channel mode environment variable that is set by "wifi_setChannelMode()" to the hardware  //Applying changes with wifi_applyRadioSettings().
/**< Deprecated */
INT wifi_pushRadioTxChainMask(INT radioIndex);                           //P2  //!<  push the environment varible that is set by "wifi_setTxChainMask()" to the hardware //Applying changes with wifi_applyRadioSettings().
/**< Deprecated */
INT wifi_pushRadioRxChainMask(INT radioIndex);                           //P2  //!< push the environment varible that is set by "wifi_setRxChainMask()" to the hardware //Applying changes with wifi_applyRadioSettings().
//<<

/* wifi_pushSSID() function */
/**
* @brief Push the environment variable that is set by "wifi_setSsidName" to the hardware.
*
* @param[in] apIndex  Access Point index
* @param[in] ssid     WiFi SSID value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_pushSSID(INT apIndex, CHAR *ssid);                          // push the environment varible that is set by "wifi_setSsidName" to the hardware    

/* wifi_pushSsidAdvertisementEnable() function */
/**
* @brief Push the environment variable that is set by "wifi_setApSsidAdvertisementEnable" to the hardware.
*
* @param[in] apIndex  Access Point index
* @param[in] enable   SSID Advertisement value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_pushSsidAdvertisementEnable(INT apIndex, BOOL enable);             // push the environment varible that is set by "wifi_setApSsidAdvertisementEnable" to the hardware    

/* wifi_getRadioReverseDirectionGrantEnable() function */
/**
* @brief Get radio RDG enable setting.
*
* @param[in]  radioIndex   Radio index
* @param[out] output_bool  RDG enable setting value, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool);    //Get radio RDG enable setting

/* wifi_setRadioReverseDirectionGrantEnable() function */
/**
* @brief Set radio RDG enable setting.
*
* @param[in] radioIndex  Radio index
* @param[in] enable      RDG enable setting value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable);              //Set radio RDG enable setting

/* wifi_getRadioDeclineBARequestEnable() function */
/**
* @brief Get radio ADDBA (ADD Block Acknowledgement) enable setting.
*
* @param[in]  radioIndex   Radio index
* @param[out] output_bool  Radio ADDBA enable setting value, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool);             //Get radio ADDBA enable setting

/* wifi_setRadioDeclineBARequestEnable() function */
/**
* @brief Set radio ADDBA (ADD Block Acknowledgement) enable setting.
*
* @param[in] radioIndex  Radio index
* @param[in] enable      Radio ADDBA enable setting value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable);                   //Set radio ADDBA enable setting

/* wifi_getRadio11nGreenfieldSupported() function */
/**
* @brief Get radio 11n pure mode enable support.
*
* @param[in]  radioIndex   Radio index
* @param[out] output_bool  Radio 11n pure mode enable support value, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadio11nGreenfieldSupported(INT radioIndex, BOOL *output_bool);             //Get radio 11n pure mode enable Support

/* wifi_getRadio11nGreenfieldEnable() function */
/**
* @brief Get radio 11n pure mode enable setting.
*
* @param[in]  radioIndex   Radio index
* @param[out] output_bool  Radio 11n pure mode enable setting, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool);            //Get radio 11n pure mode enable setting

/* wifi_setRadio11nGreenfieldEnable() function */
/**
* @brief Set radio 11n pure mode enable setting.
*
* @param[in] radioIndex  Radio index
* @param[in] enable      Radio 11n pure mode enable setting
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable);              //Set radio 11n pure mode enable setting

/* wifi_createAp() function */
/**
* @brief Creates a new access point and pushes these parameters to the hardware.
*
* @param[in] apIndex     Access Point index
* @param[in] radioIndex  Radio index
* @param[in] essid       SSID Name
* @param[in] hideSsid    True/False, to SSID advertisement enable value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid);  // creates a new ap and pushes these parameters to the hardware

/* wifi_getApIndexFromName() function */
/**
* @brief Outputs the index number in that corresponds to the SSID string.
*
* @param[in]  inputSsidString  WiFi SSID Name
* @param[out] ouput_int        Access Point index, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApIndexFromName(CHAR *inputSsidString, INT *ouput_int);     // Outputs the index number in that corresponds to the SSID string

/* wifi_setApDTIMInterval() function */
/**
* @brief Sets the DTIM interval for this Access Point.
*
* DTIM (Delivery Traffic Indication Message)
*
* @param[in] apIndex        Access Point index
* @param[in] dtimInterval   DTIM interval 
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApDTIMInterval(INT apIndex, INT dtimInterval);                    // Sets the DTIM interval for this AP

/* wifi_getApBeaconType() function */
/**
* @brief Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i".
*
* @param[in]  apIndex        Access Point index
* @param[out] output_string  Beacon type, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string);           // Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i"

/* wifi_setApBeaconType() function */
/**
* @brief Sets the beacon type environment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i".
*
* @param[in] apIndex            Access Point index
* @param[in] beaconTypeString   Beacon type 
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString);        // Sets the beacon type environment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"


/* wifi_setApBeaconInterval() function */
/**
* @brief Sets the beacon interval on the hardware for this Access Point.
*
* @param[in] apIndex          Access Point index
* @param[in] beaconInterval   Beacon interval 
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval);        // sets the beacon interval on the hardware for this AP

/* wifi_getApRtsThresholdSupported() function */
/**
* @brief Get the packet size threshold supported.
*
* @param[in]  apIndex       Access Point index
* @param[out] output_bool   Packet size threshold supported, to be returned 
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApRtsThresholdSupported(INT apIndex, BOOL *output_bool);  // Get the packet size threshold supported. 

/* wifi_getApWpaEncryptionMode() function */
/**
* @brief Ouputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption".
*
* @param[in]  apIndex        Access Point index
* @param[out] output_string  WPA Encryption mode, to be returned 
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApWpaEncryptionMode(INT apIndex, CHAR *output_string);    // ouputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"

/* wifi_setApWpaEncryptionMode() function */
/**
* @brief Sets the encyption mode environment variable.
*
* Valid string format are:
*
* - TKIPEncryption
* - AESEncryption
* - TKIPandAESEncryption
*
* @param[in] apIndex  Access Point index
* @param[in] encMode  WPA Encryption mode
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode);          // sets the encyption mode environment variable.  Valid string format is "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"

/* wifi_setApAuthMode() function */
/**
* @brief Set the authorization mode on this access point.
*
* Mode mapping as:
* -1 open
* -2 shared
* -4 auto
*
* @param[in] apIndex Access Point index
* @param[in] mode    Authorization mode
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApAuthMode(INT apIndex, INT mode);                        // set the authorization mode on this ap. mode mapping as: 1: open, 2: shared, 4:auto

/* wifi_setApBasicAuthenticationMode() function */
/**
* @brief Sets an environment variable for the authMode.
*
* Valid strings are "None", "EAPAuthentication" or "SharedAuthentication".
*
* @param[in] apIndex   Access Point index
* @param[in] authMode  Authentication mode
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode);   // sets an environment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"

#ifndef WIFI_HAL_VERSION_3_PHASE2
/* wifi_kickApAssociatedDevice() function */
/**
* @brief Manually removes any active wi-fi association with the device specified on this access point.
*
* @param[in] apIndex     Access Point index
* @param[in] client_mac  Client device MAC address
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac);         // manually removes any active wi-fi association with the device specified on this ap
#endif

/* wifi_setApRadioIndex() function */
/**
* @brief Sets the radio index for the specific access point.
*
* @param[in] apIndex     Access Point index
* @param[in] radioIndex  Radio index
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex);                // sets the radio index for the specific ap

#ifndef WIFI_HAL_VERSION_3_PHASE2
/* wifi_getApAclDevices() function */
/**
* @brief Get the ACL MAC list per Access Point.
*
* @param[in]  apIndex   Access Point index
* @param[out] macArray  Mac Array list, to be returned // in formate as "11:22:33:44:55:66\n11:22:33:44:55:67\n"
* @param[out] buf_size  Buffer size for the mac array list
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size);           // Get the ACL MAC list per AP

/* wifi_addApAclDevice() function */
/**
* @brief Adds the mac address to the filter list.
*
* @param[in] apIndex            Access Point index
* @param[in] DeviceMacAddress   Mac Address of a device
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress);         // adds the mac address to the filter list

/* wifi_delApAclDevice() function */
/**
* @brief Deletes the Device MAC address from the Access control filter list.
*
* @param[in]  apIndex           Access Point index
* @param[in]  DeviceMacAddress  Mac Address of a device
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress);
#endif 

/* wifi_setApVlanEnable() function */
/**
* @brief Enables internal gateway VLAN mode.
*
* In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.
* VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE.
*
* @param[in] apIndex      Access Point index
* @param[in] VlanEnabled  Internal gateway VLAN mode
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled);              // enables internal gateway VLAN mode.  In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.  VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE. 

/* wifi_getApBridgeInfo() function */
/**
* @brief Gets bridgeName, IP address and Subnet.
*
* BridgeName is a maximum of 32 characters.
*
* @param[in]  index       Access Point index
* @param[out] bridgeName  Bridge name, to be returned
* @param[out] IP          IP Address, to be returned
* @param[out] subnet      Subnet, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet);    // gets bridgeName, IP address and Subnet.

/* wifi_setApBridgeInfo() function */
/**
* @brief Sets bridgeName, IP address and Subnet to internal environment variables.
*
* BridgeName is a maximum of 32 characters.
*
* @param[in] apIndex     Access Point index
* @param[in] bridgeName  Bridge name
* @param[in] IP          IP Address
* @param[in] subnet      Subnet
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet);   //sets bridgeName, IP address and Subnet to internal environment variables. bridgeName is a maximum of 32 characters, 

INT wifi_pushBridgeInfo(INT apIndex);                                      //P2  //!< Push the BridgeInfo environment variables to the hardware

/**
* @brief Dynamically enable/disable access point.
*
* @param[in] apIndex  Access Point index
* @param[in] enable   Enable/Disable AP enable status variable
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_pushApEnable(INT apIndex, BOOL Enable);

/* wifi_pushApSsidAdvertisementEnable() function */
/**
* @brief Push the ssid advertisement enable variable to the hardware.
*
* Applying changs with wifi_applyRadioSettings().
*
* @param[in] apIndex  Access Point index
* @param[in] enable   SSID Advertisement enable value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_pushApSsidAdvertisementEnable(INT apIndex, BOOL enable);     // push the ssid advertisement enable variable to the hardware //Applying changs with wifi_applyRadioSettings()

/* wifi_getApWMMCapability() function */
/**
* @brief Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
*
* @param[in]  apIndex  Access Point index
* @param[out] output   WMM capability, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApWMMCapability(INT apIndex, BOOL *output); 

/* wifi_getApUAPSDCapability() function */
/**
* @brief Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD).
*
* U-APSD support implies WMM support.
*
* @param[in]  apIndex  Access Point index
* @param[out] output   U-APSD capability, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD). Note: U-APSD support implies WMM support.
INT wifi_getApUAPSDCapability(INT apIndex, BOOL *output);             

/* wifi_getApSecurityModesSupported() function */
/**
* @brief Indicates which security modes this AccessPoint instance is capable of supporting.
*
* Each list item is an enumeration of:
* - None
* - WEP-64
* - WEP-128
* - WPA-Personal
* - WPA2-Personal
* - WPA-WPA2-Personal
* - WPA-Enterprise
* - WPA2-Enterprise
* - WPA-WPA2-Enterprise.
*
* @param[in]  apIndex  Access Point index
* @param[out] output   Comma-separated list of security modes, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output);             

/* wifi_getApSecurityModeEnabled() function */
/**
* @brief Get the Security modes supported.
*
* The value MUST be a member of the list reported by the ModesSupported parameter.
* Indicates which security mode is enabled.
*
* @param[in]  apIndex  Access Point index
* @param[out] output   Enabled security mode, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output);    

/* wifi_setApSecurityModeEnabled() function */
/**
* @brief Enable supported security mode.
*
* The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
*
* @param[in] apIndex  Access Point index
* @param[in] encMode  Supported security mode
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode);        

/* wifi_getApSecurityPreSharedKey() function */
/**
* @brief Get PreSharedKey associated with a Access Point.
*
* A literal PreSharedKey (PSK) expressed as a hexadecimal string.
*
* @param[in]  apIndex        Access Point index
* @param[out] output_string  PreSharedKey, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string);         // output_string must be pre-allocated as 64 character string by caller

/* wifi_setApSecurityPreSharedKey() function */
/**
* @brief Set PreSharedKey associated with a Access Point.
*
* A literal PreSharedKey (PSK) expressed as a hexadecimal string.
*
* @param[in] apIndex       Access Point index
* @param[in] preSharedKey  PreSharedKey
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey);          // sets an environment variable for the psk. Input string preSharedKey must be a maximum of 64 characters

/* wifi_getApSecurityKeyPassphrase() function */
/**
* @brief Get a passphrase from which the PreSharedKey is to be generated for WPA-Personal or WPA2-Personal or
*
* WPA-WPA2-Personal security modes.
*
* @param[in]  apIndex         Access Point index
* @param[out] output_string   Security key passphrase, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string);

/* wifi_setApSecurityKeyPassphrase() function */
/**
* @brief Set a passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or
* WPA-WPA2-Personal security modes.
*
* @param[in] apIndex      Access Point index
* @param[in] passPhrase   Security key passphrase
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase);           // sets the passphrase environment variable, max 63 characters

/* wifi_getApWpsEnable() function */
/**
* @brief Outputs the WPS enable state of this access point  in output_bool.
*
* @param[in]  apIndex       Access Point index
* @param[out] output_bool   WPS enable state, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//Enables or disables WPS functionality for this access point.
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool);   

/* wifi_setApWpsEnable() function */
/**
* @brief Enables or disables WPS functionality for this access point.
*
* Sets the WPS enable environment variable for this ap to the value of enableValue, 1==enabled, 0==disabled.
*
* @param[in] apIndex      Access Point index
* @param[in] enableValue  WPS enable state
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApWpsEnable(INT apIndex, BOOL enableValue);    

/* wifi_getApWpsConfigMethodsSupported() function */
/**
* @brief Indicates WPS configuration methods supported by the device.
*
* Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN.
*
* @param[in]   apIndex  Access Point index
* @param[out]  output   WPS configuration methods supported (Comma-separated list of strings), to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output);

/* wifi_getApWpsConfigMethodsEnabled() function */
/**
* @brief Indicates WPS configuration methods enabled on the device.
*
* Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter.
*
* @param[in]  apIndex         Access Point index
* @param[out] output_string   WPS configuration methods enabled, to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output_string); // Outputs a common separated list of the enabled WPS config methods, 64 bytes max

/* wifi_setApWpsConfigMethodsEnabled() function */
/**
* @brief Enable WPS configuration methods on the device.
*
* Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter.
* Sets an environment variable that specifies the WPS configuration method(s).
* methodString is a comma separated list of methods:
* - USBFlashDrive
* - Ethernet
* - ExternalNFCToken
* - IntegratedNFCToken
* - NFCInterface
* - PushButton
* - PIN
*
* @param[in]  apIndex        Access Point index
* @param[in]  methodString   WPS configuration methods enabled.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/

INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString);
/* wifi_getApWpsDevicePIN() function */
/**
* @brief Outputs the WPS device pin value, ulong_pin must be allocated by the caller.
*
* @param[in] apIndex       Access Point index
* @param[in] output_ulong  WPS Device PIN value, to be returned.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong);

/* wifi_setApWpsDevicePIN() function */
/**
* @brief Set an environment variable for the WPS pin for the selected Access Point.
*
* @param[in] apIndex  Access Point index
* @param[in] pin      WPS Device PIN value
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin);

/* wifi_getApAssociatedDeviceDiagnosticResult() function */
/**
* @brief The function  provides a list of the devices currently associated with the access point.
*
* HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array".
*
* @param[in] apIndex                Access Point index
* @param[in] associated_dev_array   Associated device array, to be returned
* @param[in] output_array_size      Array size, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size);

/**
* @brief The function  provides a list of the devices currently associated with the access point.
*
* HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array".
*
* @param[in] apIndex                Access Point index
* @param[in] associated_dev_array   Associated device array, to be returned
* @param[in] output_array_size      Array size, to be returned
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/

INT wifi_getApAssociatedDeviceDiagnosticResult2(INT apIndex, wifi_associated_dev2_t **associated_dev_array, UINT *output_array_size);

#ifndef WIFI_HAL_VERSION_3_PHASE2
INT wifi_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn);

#endif
/**
 * @brief Steering API Supported.
 *
 * This tells the upper layer if the steering API is supported or not.
 *
 * @return @b TRUE on platforms that support steering, @b FALSE if not
 */
extern BOOL     wifi_steering_supported(void);

#ifndef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Add a Steering Group.
 *
 * A steering group defines a group of apIndex's which can have steering done
 * between them.
 *
 * @param[in] steeringgroupIndex  Wifi Steering Group index
 * @param[in] cfg_2               2.4G apConfig
 * @param[in] cfg_5               5G apConfig
 *
 * @return RETURN_OK on success, RETURN_ERR on failure
 *
 * @warning All apIndex's provided within a group must have the same SSID,
 * encryption, and passphrase configured for steering to function properly.
 *
 * @note The hal need to allocate (no matter static or dynamic) to store those two config
 * if cfg_2 and cfg_5 are NULL, this steering group will be removed
 */
INT wifi_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5);
#endif

typedef INT ( * wifi_apAuthEvent_callback)(INT apIndex, char *MAC, INT event_type);

void wifi_apAuthEvent_callback_register(wifi_apAuthEvent_callback callback_proc);

INT wifi_getApAuthenticatedDevices(INT apIndex, mac_t **mac_array, UINT *output_array_size);

//The call back function to send the notification for new authenticated devices.
typedef INT ( * wifi_apAuthenticatedEvent_callback)(INT apIndex, char *MAC);

//Callback registration function.
void wifi_apAuthenticatedEvent_callback_register(wifi_apAuthEvent_callback callback_proc);

//This call back will be invoked when driver detect the client connection or association happen.
typedef INT ( * wifi_apAssociatedDevice_callback)(INT apIndex, char *MAC, INT event_type);

//Callback registration function.
void wifi_apAssociatedDevice_callback_register(wifi_apAssociatedDevice_callback callback_proc);

//This is used to read the ClientInactivityTimout from driver.
INT wifi_getRadioClientInactivityTimout(INT radioIndex, INT *output_timout_sec);


/**
* @brief Get the Interworking Service Capability of the AP.
*
* @param[in] pIndex        Index of the Access Point.
* @param[in] output_bool    Indication as to whether the AP supports the Interworking Service.
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*/
INT wifi_getApInterworkingServiceCapability(INT apIndex, BOOL *output_bool);

#ifndef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Set a BTM Request to a non-AP STA.  The callback register
 * function should be called first so that the response can be handled by the
 * application.
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param peerMACAddress; MAC address of the peer device to send the request to.
 * @param in_struct; BTM Request Frame to send to the non-AP STA.
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls.
 */


INT wifi_setBTMRequest(UINT apIndex,
                        CHAR       *peerMac,
                        wifi_BTMRequest_t *request);
#endif

/**
 * @brief Get the BTM implemented value.  When not implemented the
 * gateway ignores a BTM query request as defined in 802.11-2016 section
 * 11.11.10.3.
 *
 * @param apIndex - AP Index the setting applies to.
 * @param activate - True for implemented false for not implemented.
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */
INT wifi_getBSSTransitionImplemented(UINT apIndex, BOOL *activate);

/**
 * @description Get the BTM capability of an external STA.  Reports the value
 * of the BSS Transition bit in the Extended Capabilities element, if detected,
 * from an external STA.  Reports the latest value detected in the element
 * received by any vAP in any frame type.
 *
 * @param apIndex - AP the Extended Capabilities elements were received on.
 * @param extBTMCapabilities - structure with parallel arrays of peer MAC
 * addresses and BTM capability indicators.
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */
INT wifi_getBTMClientCapabilityList(UINT apIndex,
                                     wifi_BTMCapabilities_t *extBTMCapabilities);

/* @description Set the neighbor reports to be reported by the AP.  Calling
 * this function over-writes any previously set Neighbor BSSID set.  The set
 * is not persistent.
 *
 * @param apIndex - Index of the vAP to send the request from
 * @param in_NumberNeighborReports - Number of reports in the in_NeighborReports
 *      set.
 * @param in_NeighborReports - One or more neighbor reports to be reported by
 *      the AP.
 *
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */
INT wifi_setNeighborReports(UINT apIndex,
                             UINT numNeighborReports,
                             wifi_NeighborReport_t *neighborReports);

#ifndef WIFI_HAL_VERSION_3_PHASE2
/* @description Set a radio measurement (RM) beacon request.  Causes the
 * request to be sent based on the information in the request parameter.
 * Sent from the AP at apIndex.  Returns an error if a callback has not been
 * registered for the AP.
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param peerMACAddress, MAC address of the peer device to send the request
 *      to.  Must be an external device MAC address.
 * @param in_request; pointer to a Beacon Report request structure.
 * @param out_DialogToken; the token chosen by the STA for the requested
 *      measurement(s);
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.  If the AP can determine that
 *      the target device does not support Radio Measurement, then an error
 *      is returned.
 */
INT wifi_setRMBeaconRequest(UINT apIndex,
                             CHAR *peer,
                             wifi_BeaconRequest_t *in_request,
                             UCHAR *out_DialogToken);


/* @description Get the Radio Measurement Capabilities from another peer
 * device.
 *
 * @param peerMACAddress; MAC Address of the external peer device used to
 * determine if an Radio Measurement Capabiliites Element is available.
 * @param out_Capabilities; array formatted as defined in 802.11-2016
 * Table 9-157.  The Beacon Report Capability is indicated by bit 7.  The
 * Beacon Passive, Active, and Table Capabilities are indicated by bits
 * 4, 5, 6 respectively.
 *
 * @return The capabilities returned in a Radio Measurement Element if
 * received.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.  If the AP has not received
 * a Radio Measurement Element from the peer, then an error is returned.
 */
INT wifi_getRMCapabilities(CHAR *peer, UCHAR out_Capabilities[5]);

#endif

/* @description set STA specific password key
 * Configures STA specific password in AP
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param staMAC, MAC address string of the peer device to send the request
 *      to.  Must be an external device MAC address.
 * @param key
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */

INT wifi_dppSetSTAPassphrase(UINT apIndex, 
                                CHAR *sta,
                                CHAR *key);

/* @description remove STA specific password key
 * Removes STA specific password in AP
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param staMAC, MAC address string of the peer device to send the request
 *      to.  Must be an external device MAC address.
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */

INT wifi_dppRemoveSTAPassphrase(UINT apIndex,
                                CHAR *sta);


/* wifi_getRadioChannels() function */
/*
 * Description: This function returns a map of current states of each possible channel for given radio.
 * The implementation must fill the map for each channel reported by wifi_getRadioPossibleChannels().
 *
 * Parameters :
 * radioIndex - The index of the radio. First radio is index 0. 2nd radio is index 1 - type INT
 * output_map - a pointer to an array of wifi_channelMap_t structures, preallocated by the caller.
 *              This is where the output is written. If the item in the array is not used,
 *              the "ch_number" should be set to 0.
 * output_map_size - The size of the output_map array in array items.
 *
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls. It should probably just send a message to a driver event handler task.
 */
INT wifi_getRadioChannels(INT radioIndex, wifi_channelMap_t *output_map, INT output_map_size);

/************* DPP *************************/
typedef enum {
    WIFI_DPP_TECH_INFRA
} wifi_dpp_technology_t;

typedef enum {
    WIFI_DPP_KEY_MGMT_PSK,
    WIFI_DPP_KEY_MGMT_DPP,
    WIFI_DPP_KEY_MGMT_SAE,
    WIFI_DPP_KEY_MGMT_PSKSAE,
    WIFI_DPP_KEY_MGMT_DPPPSKSAE
} wifi_dpp_key_management_t;

typedef struct {
      wifi_dpp_key_management_t keyManagement;
      union {
        unsigned char    preSharedKey[128];
        char    passPhrase[64];
      } creds;
} wifi_dpp_credential_object_t;

typedef ssid_t        wifi_dpp_discovery_object_t;

// DPP Configuration Object
typedef struct {
    wifi_dpp_technology_t             wifiTech;
    wifi_dpp_discovery_object_t         discovery;
    wifi_dpp_credential_object_t        credentials;
    void     *reconfigCtx;
    void     *cSignInstance;        
} wifi_dpp_configuration_object_t;

typedef enum {
    STATE_DPP_UNPROVISIONED,
    STATE_DPP_AUTH_RSP_PENDING,
    STATE_DPP_AUTH_FAILED,
    STATE_DPP_AUTHENTICATED,
    STATE_DPP_CFG_RSP_SENT,
    STATE_DPP_CFG_FAILED,
    STATE_DPP_CFG_ASSOC_IND_RECEIVED,
    STATE_DPP_PROVISIONED = STATE_DPP_CFG_ASSOC_IND_RECEIVED,
    STATE_DPP_RECFG_AUTH_RSP_PENDING,
    STATE_DPP_RECFG_AUTH_FAILED,
} wifi_dpp_state_t;

typedef enum {
    RESPONDER_STATUS_OK,
    RESPONDER_STATUS_NOT_COMPATIBLE,
    RESPONDER_STATUS_AUTH_FAILURE,
    RESPONDER_STATUS_BAD_CODE,
    RESPONDER_STATUS_BAD_GROUP,
    RESPONDER_STATUS_CONFIGURATION_FAILURE,
    RESPONDER_STATUS_RESPONSE_PENDING,
    RESPONDER_STATUS_INVALID_CONNECTOR,
    RESPONDER_STATUS_NO_MATCH,
    RESPONDER_STATUS_CONFIG_REJECTED,
    RESPONDER_STATUS_NOT_AVAILABLE,
} wifi_enrollee_responder_status_t;

typedef enum {
    ActStatus_Idle,
    ActStatus_Config_Error,
    ActStatus_In_Progress,
    ActStatus_No_Response,
    ActStatus_Failed,
    ActStatus_OK
} wifi_activation_status_t;

typedef struct {
    char            iPubKey[512];
    char            rPubKey[512];
} wifi_dpp_config_data_t;

typedef struct {
    unsigned char     tran_id[120];
    char            iPubKey[512];
    unsigned char match_tran_id;
} wifi_dpp_reconfig_data_t;

typedef enum {
    wifi_dpp_session_type_config,
    wifi_dpp_session_type_reconfig,
} wifi_dpp_session_type_t;

typedef struct {
    mac_address_t           sta_mac;
    wifi_dpp_session_type_t session;
    union {
        wifi_dpp_config_data_t      config_data;
        wifi_dpp_reconfig_data_t    reconfig_data;
    } u;
    unsigned int    channel; // current channel that DPP Authentication request will be sent on
    void            *instance;
    wifi_dpp_state_t    state;
} wifi_dpp_session_data_t;

typedef enum {
    dpp_context_type_session_data,
    dpp_context_type_received_frame_auth_rsp,
    dpp_context_type_received_frame_cfg_req,
    dpp_context_type_received_frame_cfg_result,
    dpp_context_type_received_frame_recfg_announce,
    dpp_context_type_received_frame_recfg_auth_rsp,
} wifi_device_dpp_context_type_t;

typedef enum {
    wifi_dpp_public_action_frame_type_auth_req,
    wifi_dpp_public_action_frame_type_auth_rsp,
    wifi_dpp_public_action_frame_type_auth_cnf,
    wifi_dpp_public_action_frame_type_reserved_1,
    wifi_dpp_public_action_frame_type_reserved_2,
    wifi_dpp_public_action_frame_type_peer_disc_req,
    wifi_dpp_public_action_frame_type_peer_disc_rsp,
    wifi_dpp_public_action_frame_type_pkex_req,
    wifi_dpp_public_action_frame_type_pkex_rsp,
    wifi_dpp_public_action_frame_type_pkex_rev_req,
    wifi_dpp_public_action_frame_type_pkex_rev_rsp,
    wifi_dpp_public_action_frame_type_cfg_result,
    wifi_dpp_public_action_frame_type_conn_status_result,
    wifi_dpp_public_action_frame_type_presence_announcement,
    wifi_dpp_public_action_frame_type_recfg_announcement,
    wifi_dpp_public_action_frame_type_recfg_auth_req,
    wifi_dpp_public_action_frame_type_recfg_auth_rsp,
    wifi_dpp_public_action_frame_type_recfg_auth_cnf,
} wifi_dpp_public_action_frame_type_t;

typedef struct {
    UCHAR *frame;
    UINT     length;
    wifi_dpp_public_action_frame_type_t    frame_type;
} wifi_dpp_received_frame_t;

typedef struct {
    unsigned int ap_index;
    unsigned char configurator_version;
    unsigned char enrollee_version;
    wifi_device_dpp_context_type_t type;
    wifi_dpp_session_data_t        session_data;
    wifi_dpp_received_frame_t    received_frame;
    unsigned int    dpp_init_retries;
    unsigned int    max_retries;
    unsigned char   token;
    wifi_dpp_configuration_object_t config;
    wifi_enrollee_responder_status_t     enrollee_status;
    wifi_activation_status_t    activation_status;
    unsigned int    check_for_associated;
    unsigned int    check_for_config_requested;
    unsigned int    num_channels;    // number of channels that enrollee can listen on
    unsigned int    channels_list[32]; // list of channels that enrollee can listen on
    unsigned int    current_attempts; // number of failed attempts on N different channels off the list
} wifi_device_dpp_context_t;

/* @description This call back is invoked when a STA responds to a DPP Authentication
 * Request from the gateway    with DPP Authentication Response
 *
 * @param apIndex; index of the vAP where the DPP Authentication Response frame is received
 * @param staMAC, MAC address of the peer device
 * @param status, one of wifi_dppAuthResponseStatus_t authentication response status
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls.
 */
typedef void (*wifi_dppAuthResponse_callback_t)(UINT apIndex, 
                                                mac_address_t sta,
                                                UCHAR *frame,
                                                UINT len);

/* @description This call back is invoked when a STA sends DPP Configuration
 * Request to the gateway
 *
 * @param apIndex; index of the vAP where the DPP Configuration Request frame is received
 * @param staMAC, MAC address string of the peer device
 * @param configAttributes, address of memory pointing to configuration attributes
 * @param length, length of memory in bytes
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls.
 */
typedef void (*wifi_dppConfigRequest_callback_t)(UINT apIndex,
                                                mac_address_t sta,
                                                UCHAR token,
                                                UCHAR *attribs,
                                                UINT length);

/* @description This call back is invoked when a STA sends DPP Configuration
 * Result to the gateway
 *
 * @param apIndex; index of the vAP where the DPP Configuration Request frame is received
 * @param staMAC, MAC address string of the peer device
 * @param attributes, address of memory pointing to attributes
 * @param length, length of memory in bytes
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls.
 */
typedef void (*wifi_dppConfigResult_callback_t)(UINT apIndex,
                                                mac_address_t sta,
                                                UCHAR *attribs,
                                                UINT length);

/* @description This call back is invoked when a STA sends DPP Reconfig
 * Announcement to the gateway
 *
 * @param apIndex; index of the vAP where the DPP Configuration Request frame is received
 * @param staMAC, MAC address string of the peer device
 * @param attributes, address of memory pointing to attributes
 * @param length, length of memory in bytes
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls.
 */
typedef void (*wifi_dppReconfigAnnounce_callback_t)(UINT apIndex,
                                                mac_address_t sta,
                                                UCHAR *attribs,
                                                UINT length);

/* @description This call back is invoked when a STA responds to a DPP Reconfig Authentication
 * Request from the gateway    with DPP Authentication Response
 *
 * @param apIndex; index of the vAP where the DPP Authentication Response frame is received
 * @param staMAC, MAC address of the peer device
 * @param status, one of wifi_dppAuthResponseStatus_t authentication response status
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls.
 */
typedef void (*wifi_dppReconfigAuthResponse_callback_t)(UINT apIndex, 
                                                mac_address_t sta,
                                                UCHAR *frame,
                                                UINT len);


/* @description Initiate device provisioning with unprovisioned DPP enabled client.
 * Causes AP to start transmitting DPP Authentication Request unicast message to client on current operating channel.
 * Sent from the AP at apIndex.  Returns an error if message transmission fails.
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param staMAC, MAC address string of the peer device to send the request
 *      to.  Must be an external device MAC address.
 * @param iBootstrapSubjectPubKeyInfoB64; pointer to initiator's DER encoded ASN.1 base64 subject public key info (RFC 5280).
 * @param rBootstrapSubjectPubKeyInfoB64; pointer to responder's DER encoded ASN.1 base64 subject public key info (RFC 5280).
 * @param channel; frequency in Hz of channel on which initiator should send the DPP Authentication Request public action frame

 
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */

INT wifi_dppInitiate(wifi_device_dpp_context_t *ctx);

/* @description Cancel device provisioning if DPP Authentication Response is not receieved after number of sent requets
 * Causes AP to stop transmitting DPP Authentication Request unicast message to client on current operating channel.
 * If DPP Authentication Response has already been received from client, the provisioning sequence can not be cancelled.
 * Sent from the AP at apIndex.  Returns an error if message transmission fails.
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param staMAC, MAC address string of the peer device to send the request
 *      to.  Must be an external device MAC address.
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */
INT wifi_dppCancel(wifi_device_dpp_context_t *ctx);

int mgmt_frame_received_callback(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir);


 /*
 * @description DPP callbacks registration for AuthResponse & dppConfigRequest functions.
 *
 * @param wifi_dppAuthResponse_callback - DPP Authentication Response callback function
 * @param wifi_dppConfigRequest_callback - DPP Config Request callback function
 *
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 *
 * @execution Synchronous
 * @sideeffect None
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls.
 */
 
INT wifi_dpp_frame_received_callbacks_register(wifi_dppAuthResponse_callback_t dppAuthCallback,
                                    wifi_dppConfigRequest_callback_t dppConfigCallback,
                                    wifi_dppConfigResult_callback_t dppConfigResultCallback,
                                    wifi_dppReconfigAnnounce_callback_t dppReconfigAnnounceCallback,
                                    wifi_dppReconfigAuthResponse_callback_t dppReconfigAuthRspCallback);

/* @description send athentication confiration as per DPP specifications
 * Causes AP to transmit DPP Authentication Conf message frame to STA that will cause STA 
 * to request configuration process in case confirmation status is set to success
 * Sent from the AP at apIndex.  Returns an error if message transmission fails.
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param staMAC, MAC address string of the peer device to send the request
 *      to.  Must be an external device MAC address.
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */

INT wifi_dppSendAuthCnf(wifi_device_dpp_context_t *ctx);

/* @description send device specific configuration as per DPP specifications
 * Causes AP to transmit DPP Configuration Response frame to STA with device specific 
 * configuration
 * Sent from the AP at apIndex.  Returns an error if message transmission fails.
 *
 * @param apIndex; index of the vAP to send the request from.
 * @param staMAC, MAC address string of the peer device to send the request
 *      to.  Must be an external device MAC address.
 * @param config, start address of memory pointing to configuration
 * @param length, length in bytes of memory pointing to configuration
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected.
 */

INT wifi_dppSendConfigResponse(wifi_device_dpp_context_t *ctx);

typedef enum {
    wifi_anqp_element_name_reserved_0,
    wifi_anqp_element_name_query_list = 256,
    wifi_anqp_element_name_capability_list,
    wifi_anqp_element_name_venue_name,
    wifi_anqp_element_name_emergency_call_number,
    wifi_anqp_element_name_network_auth_type,
    wifi_anqp_element_name_roaming_consortium,
    wifi_anqp_element_name_ip_address_availabality,
    wifi_anqp_element_name_nai_realm,
    wifi_anqp_element_name_3gpp_cellular_network,
    wifi_anqp_element_name_geo_location,
    wifi_anqp_element_name_civic_location,
    wifi_anqp_element_name_loc_public_id,
    wifi_anqp_element_name_domain_name,
    wifi_anqp_element_name_emergency_alert_id,
    wifi_anqp_element_name_tdls_capability,
    wifi_anqp_element_name_emergency_nai,
    wifi_anqp_element_name_neighbor_report,
    wifi_anqp_element_name_venue_url,
    wifi_anqp_element_name_advice_of_charge,
    wifi_anqp_element_name_local_content,
    wifi_anqp_element_name_network_auth_type_with_timestamp,
    wifi_anqp_element_name_reserved_1 = 273,
    wifi_anqp_element_name_vendor_specific = 56797,
    wifi_anqp_element_name_reserved_2
} wifi_anqp_element_name_t;

typedef enum {
    wifi_anqp_element_hs_subtype_reserved_0,
    wifi_anqp_element_hs_subtype_hs_query_list,
    wifi_anqp_element_hs_subtype_hs_capability_list,
    wifi_anqp_element_hs_subtype_operator_friendly_name,
    wifi_anqp_element_hs_subtype_wan_metrics,
    wifi_anqp_element_hs_subtype_conn_capability,
    wifi_anqp_element_hs_subtype_nai_home_realm_query,
    wifi_anqp_element_hs_subtype_op_class_ind,
    wifi_anqp_element_hs_subtype_osu_providers_list,
    wifi_anqp_element_hs_subtype_reserved_1,
    wifi_anqp_element_hs_subtype_icon_request,
    wifi_anqp_element_hs_subtype_icon_bin_file,
    wifi_anqp_element_hs_subtype_op_icon_metadata,
    wifi_anqp_element_hs_subtype_op_providers_nai_list,
    wifi_anqp_element_hs_subtype_reserved_2
} wifi_anqp_element_hs_subtype_t;

typedef enum {
    wifi_anqp_id_type_anqp,
    wifi_anqp_id_type_hs
} wifi_anqp_id_type_t;

typedef struct {
    wifi_anqp_id_type_t     type;
    union {
        wifi_anqp_element_name_t        anqp_elem_id;
        wifi_anqp_element_hs_subtype_t  anqp_hs_id;
    } u;
    UINT    len;
    UCHAR   *data;
} wifi_anqp_elem_t;

typedef struct wifi_anqp_node {
    struct wifi_anqp_node    *next;
    wifi_anqp_elem_t    *value;
} wifi_anqp_node_t;

typedef void (* wifi_anqp_request_callback_t)   (UINT apIndex, mac_address_t sta, unsigned char token,  wifi_anqp_node_t *list);

INT wifi_anqp_request_callback_register(wifi_anqp_request_callback_t callback);

INT wifi_anqpSendResponse(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *list);


typedef void (*wifi_chan_eventCB_t)(UINT radioIndex, wifi_chan_eventType_t event, UCHAR channel);

INT wifi_chan_eventRegister(wifi_chan_eventCB_t event_cb);

/**
 * @brief Check if Zero DFS is supported
 *
 * Zero DFS (also known as Background CAC) allows Wi-Fi stack to continue
 * operation on main channel and at the same time run background CAC.
 *
 * @param[in]  radioIndex Index of Wi-Fi radio
 * @param[out] supported  True if ZeroDFS is supported, false otherwise.
 *
 * @return The status of the operation
 * @retval RETURN_OK if successful
 * @retval RETURN_ERR if any error is detected
 *
 * @execution Synchronous
 * @sideeffect None
 *
 */
INT wifi_isZeroDFSSupported(UINT radioIndex, BOOL *supported);

#ifdef __cplusplus
}
#endif

#endif
