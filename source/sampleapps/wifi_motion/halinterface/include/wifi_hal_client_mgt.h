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

#ifndef __WIFI_HAL_CLIENTMGT_H__
#define __WIFI_HAL_CLIENTMGT_H__

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Gets the Band Steering enable status.
 *
 * @param[out] enable Pointer to a variable to store the Band Steering enable
 *                    status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBandSteeringEnable(BOOL *enable);

/**
 * @brief Enables or disables Band Steering.
 *
 * @param[in] enable Whether to enable or disable Band Steering.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBandSteeringEnable(BOOL enable);

/**
 * @brief Gets the Band Steering AP group.
 *
 * @param[out] output_ApGroup Pointer to a buffer to store the Band Steering
 *                            AP group.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBandSteeringApGroup(char *output_ApGroup);

/**
 * @brief Sets the Band Steering AP group.
 *
 * This function sets the Access Point (AP) group for Band Steering. The
 * `ApGroup` parameter should be a string containing AP index pairs (starting
 * from 1) in the following format:
 * "$index_2.4G,$index_5G;$index_2.4G,$index_5G".
 *
 * For example, "1,2;3,4;7,8" represents three AP pairs:
 *  - 1,2: Private network APs
 *  - 3,4: XH network APs
 *  - 7,8: LnF network APs
 *
 * `ApGroup` must contain at least one AP pair.
 *
 * @param[in] ApGroup The Band Steering AP group to set.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_setBandSteeringApGroup(char *ApGroup);

/**
 * @brief Gets the Band Steering band utilization threshold.
 *
 * @param[in] radioIndex    Radio index.
 * @param[out] pBuThreshold Pointer to a variable to store the band utilization
 *                          threshold.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBandSteeringBandUtilizationThreshold(INT radioIndex, INT *pBuThreshold);

/**
 * @brief Sets the Band Steering band utilization threshold.
 *
 * @param[in] radioIndex   Radio index.
 * @param[in] buThreshold The band utilization threshold to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBandSteeringBandUtilizationThreshold(INT radioIndex, INT buThreshold);

/**
 * @brief Gets the Band Steering RSSI threshold.
 *
 * @param[in] radioIndex      Radio index.
 * @param[out] pRssiThreshold Pointer to a variable to store the RSSI threshold.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBandSteeringRSSIThreshold(INT radioIndex, INT *pRssiThreshold);

/**
 * @brief Sets the Band Steering RSSI threshold.
 *
 * For 2.4GHz, the expectation is that if the 2.4GHz RSSI is below the set
 * value, the client will be steered to 2.4GHz.
 * For 5GHz, if the 5GHz RSSI is greater than the set threshold value, the
 * client will be steered to 5GHz.
 *
 * @param[in] radioIndex    Radio index.
 * @param[in] rssiThreshold The RSSI threshold to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBandSteeringRSSIThreshold(INT radioIndex, INT rssiThreshold);

/**
 * @brief Gets the Band Steering PHY rate threshold.
 *
 * @param[in] radioIndex    Radio index.
 * @param[out] pPrThreshold Pointer to a variable to store the PHY rate threshold.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBandSteeringPhyRateThreshold(INT radioIndex, INT *pPrThreshold);

/**
 * @brief Sets the Band Steering PHY rate threshold.
 *
 * @param[in] radioIndex  Radio index.
 * @param[in] prThreshold The PHY rate threshold to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBandSteeringPhyRateThreshold(INT radioIndex, INT prThreshold);

/**
 * @brief Gets the inactivity time for steering under overload conditions.
 *
 * @param[in] radioIndex            Radio index.
 * @param[out] overloadInactiveTime Pointer to a variable to store the inactivity
 *                                 time, in seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBandSteeringOverloadInactiveTime(INT radioIndex, INT *overloadInactiveTime);

/**
 * @brief Sets the inactivity time for steering under overload conditions.
 *
 * @param[in] radioIndex            Radio index.
 * @param[in] overloadInactiveTime The inactivity time to set, in seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBandSteeringOverloadInactiveTime(INT radioIndex, INT overloadInactiveTime);

/**
 * @brief Gets the inactivity time for steering under idle conditions.
 *
 * @param[in] radioIndex       Radio index.
 * @param[out] idleInactiveTime Pointer to a variable to store the inactivity
 *                             time, in seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBandSteeringIdleInactiveTime(INT radioIndex, INT *idleInactiveTime);

/**
 * @brief Sets the inactivity time for steering under idle conditions.
 *
 * @param[in] radioIndex       Radio index.
 * @param[in] idleInactiveTime The inactivity time to set, in seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBandSteeringIdleInactiveTime(INT radioIndex, INT idleInactiveTime);

/**
 * @brief Gets a Band Steering log entry.
 *
 * @param[in] record_index    Index of the log entry to retrieve.
 * @param[out] pSteeringTime   Pointer to a variable to store the steering time,
 *                            in UTC seconds.
 * @param[out] pClientMAC      Pointer to a buffer to store the client MAC address.
 * @param[out] pSourceSSIDIndex Pointer to a variable to store the source SSID index.
 * @param[out] pDestSSIDIndex  Pointer to a variable to store the destination SSID
 *                            index.
 * @param[out] pSteeringReason  Pointer to a variable to store the steering reason.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected or if no steering occurred or
 *                          the record index is out of bounds.
 */
INT wifi_getBandSteeringLog(INT record_index, ULONG *pSteeringTime, CHAR *pClientMAC, INT *pSourceSSIDIndex, INT *pDestSSIDIndex, INT *pSteeringReason);

/**
 * @brief Gets the high watermark threshold for associated devices on an AP.
 * 
 * This function retrieves the `HighWatermarkThreshold` value for the 
 * specified Access Point (AP). This value represents a threshold for the 
 * number of associated devices, and is used to trigger certain actions or 
 * notifications when the number of connected clients reaches this level.
 * 
 * The `HighWatermarkThreshold` should be less than or equal to 
 * `MaxAssociatedDevices`, which defines the absolute maximum number of 
 * clients allowed to connect to the AP. Setting the `HighWatermarkThreshold`
 * does not limit the number of associated clients; it simply provides a 
 * means of monitoring and reacting to changes in the number of connected 
 * devices.
 * 
 * The default value of `HighWatermarkThreshold` should be equal to 
 * `MaxAssociatedDevices`, unless `MaxAssociatedDevices` is 0, in which 
 * case the default value should be 50. A `HighWatermarkThreshold` of 0 
 * indicates that there is no specific limit and the watermark calculation 
 * algorithm should be disabled.
 *
 * @param[in] apIndex  Access Point index.
 * @param[out] output  Pointer to a variable to store the retrieved 
 *                     `HighWatermarkThreshold` value.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output);

/**
 * @brief Sets the high watermark threshold for associated devices on an AP.
 *
 * This function sets the `HighWatermarkThreshold` value for the specified
 * Access Point (AP). This value represents a threshold for the number of
 * associated devices and is used to trigger certain actions or notifications
 * when the number of connected clients reaches this level.
 *
 * The `HighWatermarkThreshold` should be less than or equal to
 * `MaxAssociatedDevices`, which defines the absolute maximum number of clients
 * allowed to connect to the AP. Setting the `HighWatermarkThreshold` does not
 * limit the number of associated clients; it simply provides a means of
 * monitoring and reacting to changes in the number of connected devices.
 *
 * The default value of `HighWatermarkThreshold` should be equal to
 * `MaxAssociatedDevices`, unless `MaxAssociatedDevices` is 0, in which case
 * the default value should be 50. A `HighWatermarkThreshold` of 0 indicates
 * that there is no specific limit and the watermark calculation algorithm
 * should be disabled.
 *
 * @param[in] apIndex   Access Point index.
 * @param[in] Threshold HighWatermarkThreshold value to set.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold);

/**
 * @brief Gets the number of times the high watermark threshold has been reached.
 * 
 * This function retrieves the number of times the current total number of 
 * associated devices on the specified Access Point (AP) has reached the 
 * `HighWatermarkThreshold` value. This counter can be used to track how 
 * often the AP approaches its maximum client capacity.
 * 
 * The calculation of this counter may be based on the 
 * `AssociatedDeviceNumberOfEntries` parameter or other implementation-
 * specific mechanisms. It is typically updated whenever a new client 
 * association request is received by the AP.
 *
 * @param[in] apIndex  Access Point index.
 * @param[out] output  Pointer to a variable to store the number of times the
 *                     high watermark threshold has been reached.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output);

/**
 * @brief Gets the high watermark of associated devices on an AP.
 *
 * This function retrieves the maximum number of devices that have ever been
 * concurrently associated with the Access Point since the last reset of the
 * device or Wi-Fi module.
 *
 * @param[in] apIndex Access Point index.
 * @param[out] output  Pointer to a variable to store the high watermark value.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output);

/**
 * @brief Gets the date and time when the high watermark was reached.
 *
 * This function retrieves the date and time at which the maximum number of
 * associated devices was reached on the Access Point since the last reset
 * of the device or Wi-Fi module.
 *
 * @param[in] apIndex          Access Point index.
 * @param[out] output_in_seconds Pointer to a variable to store the date and
 *                              time, in UTC seconds.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds);

/**
 * @brief Sets the Fast BSS Transition (FT) activation state.
 *
 * This function sets the Fast Transition capability to disabled, full FT
 * support, or adaptive FT support. Adaptive support is the same as full
 * support, except that the Mobility Domain Element is not sent in beacon
 * frames.
 *
 * @param[in] apIndex  AP index that the setting applies to.
 * @param[in] activate FT activation state:
 *                     0 = disabled,
 *                     1 = full FT support,
 *                     2 = adaptive support.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setFastBSSTransitionActivated(INT apIndex, UCHAR activate);

/**
 * @brief Gets the Fast BSS Transition (FT) activation state.
 *
 * @param[in] apIndex  AP index that the setting applies to.
 * @param[out] activate Pointer to a variable to store the FT activation state:
 *                      0 = disabled,
 *                      1 = full FT support,
 *                      2 = adaptive support.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBSSTransitionActivated(INT apIndex, BOOL *activate);
/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief EAP/EAPOL authenticator information.
 *
 * Structure that holds the EAP/EAPOL configuration parameters.
 */
typedef struct _wifi_eap_config_t
{
    unsigned int uiEAPOLKeyTimeout; /**< EAPOL key timeout. */
    unsigned int uiEAPOLKeyRetries; /**< EAPOL key retries. */
    unsigned int uiEAPIdentityRequestTimeout; /**< EAP identity request timeout. */
    unsigned int uiEAPIdentityRequestRetries; /**< EAP identity request retries. */
    unsigned int uiEAPRequestTimeout; /**< EAP request timeout. */
    unsigned int uiEAPRequestRetries; /**< EAP request retries. */
} wifi_eap_config_t;
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
 /**
 * @brief Sets an EAP parameter.
 *
 * This function sets the EAP authentication and EAPOL handshake parameters,
 * including:
 *   - EAPOL Key Timeout and maximum retries (for M1 and M3 messages)
 *   - EAP Identity Request timeout and maximum retries
 *   - EAP Request timeout and maximum retries
 *
 * @param[in] apIndex VAP index.
 * @param[in] value   Value to set (either timeout or retry value).
 * @param[in] param   Parameter name to configure:
 *                      - "eapolkey" (for timeout or retries)
 *                      - "eapidentityrequest" (for timeout or retries)
 *                      - "eaprequest" (for timeout or retries)
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_setEAP_Param(UINT apIndex, UINT value, char *param);

/**
 * @brief Gets the EAP authentication and EAPOL handshake parameters.
 *
 * This function retrieves the EAP authentication and EAPOL handshake
 * parameters, including:
 *   - EAPOL Key Timeout and maximum retries (for M1 and M3 messages)
 *   - EAP Identity Request timeout and maximum retries
 *   - EAP Request timeout and maximum retries
 *
 * @param[in] apIndex VAP index.
 * @param[out] output Pointer to a `wifi_eap_config_t` structure to be filled
 *                    with the EAP parameters.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_getEAP_Param(UINT apIndex, wifi_eap_config_t *output);

/**
 * @brief Gets the Fast Transition over DS activation state.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex   AP index.
 * @param[out] activate Pointer to a variable to store the activation state.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getFTOverDSActivated(INT apIndex, BOOL *activate);

/**
 * @brief Sets the Fast Transition over DS activation state.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex   AP index.
 * @param[in] activate  Whether FT over DS is activated.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setFTOverDSActivated(INT apIndex, BOOL *activate);

/**
 * @brief Gets the FT Mobility Domain ID.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex        AP index.
 * @param[out] mobilityDomain FT Mobility Domain ID.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getFTMobilityDomainID(INT apIndex, UCHAR mobilityDomain[2]);

/**
 * @brief Sets the FT Mobility Domain ID.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex        AP index.
 * @param[in] mobilityDomain FT Mobility Domain ID to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setFTMobilityDomainID(INT apIndex, UCHAR mobilityDomain[2]);

/**
 * @brief Gets the FT Resource Request support status.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex   AP index.
 * @param[out] supported Whether FT Resource Request is supported.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getFTResourceRequestSupported(INT apIndex, BOOL *supported);

/**
 * @brief Sets the FT Resource Request support status.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex   AP index.
 * @param[in] supported Whether FT Resource Request is supported.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setFTResourceRequestSupported(INT apIndex, BOOL *supported);

/**
 * @brief Gets the Fast Transition R0 Key Lifetime value.
 *
 * See 802.11-2016 section 13.4.2.
 *
 * @param[in] apIndex  AP index.
 * @param[out] lifetime Pointer to a variable to store the R0 Key Lifetime.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getFTR0KeyLifetime(INT apIndex, UINT *lifetime);

/**
 * @brief Sets the Fast Transition R0 Key Lifetime value.
 *
 * See 802.11-2016 section 13.4.2.
 *
 * @param[in] apIndex  AP index.
 * @param[in] lifetime R0 Key Lifetime to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setFTR0KeyLifetime(INT apIndex, UINT *lifetime);

/**
 * @brief Gets the Fast Transition R0 Key Holder ID.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex    AP index.
 * @param[out] keyHolderID Pointer to a buffer to store the R0 Key Holder ID
 *                        string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getFTR0KeyHolderID(INT apIndex, UCHAR *keyHolderID);

/**
 * @brief Sets the Fast Transition R0 Key Holder ID.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex    AP index.
 * @param[in] keyHolderID R0 Key Holder ID string to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setFTR0KeyHolderID(INT apIndex, UCHAR *keyHolderID);

/**
 * @brief Gets the Fast Transition R1 Key Holder ID.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex    AP index.
 * @param[out] keyHolderID Pointer to a buffer to store the R1 Key Holder ID
 *                        string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getFTR1KeyHolderID(INT apIndex, UCHAR *keyHolderID);

/**
 * @brief Sets the Fast Transition R1 Key Holder ID.
 *
 * See 802.11-2016 section 13.3.
 *
 * @param[in] apIndex    AP index.
 * @param[in] keyHolderID R1 Key Holder ID string to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setFTR1KeyHolderID(INT apIndex, UCHAR *keyHolderID);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Fast transition support types.
 */
typedef enum
{
    FT_SUPPORT_DISABLED, /**< Fast transition disabled. */
    FT_SUPPORT_FULL, /**< Full fast transition support. */
    FT_SUPPORT_ADAPTIVE /**< Adaptive fast transition support. */
} wifi_fastTrasitionSupport_t;

/**
 * @brief Maximum number of key holders.
 */
#define MAX_KEY_HOLDERS 8

/**
 * @brief R0 key holder information.
 */
typedef struct
{
    mac_address_t mac; /**< MAC address. */
    nas_id_t nasId; /**< NAS ID. */
    r0r1_key_t key; /**< Key. */
} wifi_r0KH_t;

/**
 * @brief R1 key holder information.
 */
typedef struct
{
    mac_address_t mac; /**< MAC address. */
    mac_address_t r1khId; /**< R1 key holder ID. */
    r0r1_key_t key; /**< Key. */
} wifi_r1KH_t;

/**
 * @brief Fast transition configuration.
 */
typedef struct
{
    wifi_fastTrasitionSupport_t support; /**< Fast transition support type. */
    USHORT mobilityDomain; /**< Mobility domain. */
    BOOL overDS; /**< Whether FT over DS is enabled. */
    nas_id_t r0KeyHolder; /**< R0 key holder. */
    USHORT r0KeyLifeTime; /**< R0 key lifetime. */
    mac_address_t r1KeyHolder; /**< R1 key holder. */
    USHORT reassocDeadLine; /**< Reassociation deadline. */
    BOOL pmkR1Push; /**< Whether PMK R1 push is enabled. */
    UCHAR numR0KHs; /**< Number of R0 key holders. */
    wifi_r0KH_t r0KH[MAX_KEY_HOLDERS]; /**< R0 key holders. */
    UCHAR numR1KHs; /**< Number of R1 key holders. */
    wifi_r1KH_t r1KH[MAX_KEY_HOLDERS]; /**< R1 key holders. */
} wifi_FastTransitionConfig_t;

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @brief Pushes the fast transition configuration to an AP.
 *
 * @param[in] apIndex AP index.
 * @param[in] ftData  Pointer to a `wifi_FastTransitionConfig_t` structure
 *                    containing the fast transition configuration data.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_pushApFastTransitionConfig(INT apIndex, wifi_FastTransitionConfig_t *ftData);

/**
 * @brief Sets the BSS Transition activation state.
 *
 * This function sets the BSS Transition capability to activated or
 * deactivated, which is the same as enabled or disabled. The term
 * "activated" is used here because that is the terminology used in the
 * 802.11 specification.
 *
 * When deactivated, the gateway ignores BTM (BSS Transition Management) report
 * requests, as defined in 802.11-2016 section 11.11.10.3. The AP's
 * (specified by `apIndex`) BSS Transition bit in any Extended Capabilities
 * element sent out is set according to the `activate` parameter.
 *
 * @param[in] apIndex  AP index that the setting applies to.
 * @param[in] activate True to activate (enable) BSS Transition, false to
 *                     deactivate (disable).
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_setBSSTransitionActivation(UINT apIndex, BOOL activate);

/**
 * @brief Gets the BSS Transition activation state.
 *
 * @param[in] apIndex  AP index.
 * @param[out] activate Pointer to a variable to store the BSS Transition
 *                      activation state.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBSSTransitionActivation(UINT apIndex, BOOL *activate);

/**
 * @brief Sets the Neighbor Report activation state.
 *
 * This function sets the Neighbor Report capability to activated or
 * deactivated, which is the same as enabled or disabled. The term "activated"
 * is used here because that is the terminology used in the 802.11
 * specification.
 *
 * When deactivated, the gateway ignores neighbor report requests, as defined
 * in 802.11-2016 section 11.11.10.3.
 *
 * @param[in] apIndex  AP index that the setting applies to.
 * @param[in] activate True to activate (enable) Neighbor Report, false to
 *                     deactivate (disable).
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_setNeighborReportActivation(UINT apIndex, BOOL activate);

/**
 * @brief Gets the Neighbor Report activation state.
 *
 * @param[in] apIndex  AP index.
 * @param[out] activate Pointer to a variable to store the Neighbor Report
 *                      activation state.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getNeighborReportActivation(UINT apIndex, BOOL *activate);

/** @} */  //END OF GROUP WIFI_HAL_APIS

#ifdef __cplusplus
}
#endif

#endif