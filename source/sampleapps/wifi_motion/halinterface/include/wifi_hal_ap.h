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
#ifndef __WIFI_HAL_AP_H__
#define __WIFI_HAL_AP_H__

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Wi-Fi traffic statistics.
 */
typedef struct _wifi_trafficStats
{
    ULONG wifi_ErrorsSent;            /**< Number of errors sent. */
    ULONG wifi_ErrorsReceived;         /**< Number of errors received. */
    ULONG wifi_UnicastPacketsSent;    /**< Number of unicast packets sent. */
    ULONG wifi_UnicastPacketsReceived; /**< Number of unicast packets received. */
    ULONG wifi_DiscardedPacketsSent;   /**< Number of discarded packets sent. */
    ULONG wifi_DiscardedPacketsReceived; /**< Number of discarded packets received. */
    ULONG wifi_MulticastPacketsSent;   /**< Number of multicast packets sent. */
    ULONG wifi_MulticastPacketsReceived; /**< Number of multicast packets received. */
    ULONG wifi_BroadcastPacketsSent;   /**< Number of broadcast packets sent. */
    ULONG wifi_BroadcastPacketsRecevied; /**< Number of broadcast packets received. */
    ULONG wifi_UnknownPacketsReceived; /**< Number of unknown packets received. */
} wifi_trafficStats_t;

/**
 * @brief IPv4 field values.
 */
typedef enum
{
    wifi_ipv4_field_values_not_available, /**< IPv4 field values are not available. */
    wifi_ipv4_field_values_available, /**< IPv4 field values are available. */
    wifi_ipv4_field_values_post_restricted, /**< IPv4 field values are restricted after NAT. */
    wifi_ipv4_field_values_single_nated_private, /**< IPv4 field values are private and have undergone single NAT. */
    wifi_ipv4_field_values_double_nated_private, /**< IPv4 field values are private and have undergone double NAT. */
    wifi_ipv4_field_values_port_restricted_single_nated, /**< IPv4 field values are port-restricted and have undergone single NAT. */
    wifi_ipv4_field_values_port_restricted_double_nated, /**< IPv4 field values are port-restricted and have undergone double NAT. */
    wifi_ipv4_field_values_not_known /**< IPv4 field values are not known. */
} wifi_ipv4_field_values_t;

/**
 * @brief IPv6 field values.
 */
typedef enum
{
    wifi_ipv6_field_values_not_available, /**< IPv6 field values are not available. */
    wifi_ipv6_field_values_available, /**< IPv6 field values are available. */
    wifi_ipv6_field_values_not_known /**< IPv6 field values are not known. */
} wifi_ipv6_field_values_t;

/**
 * @brief IP address availability.
 */
typedef struct
{
    UCHAR field_format; /**< Field format. */
} __attribute__((packed)) wifi_ipAddressAvailabality_t;

/**
 * @brief Authentication ID values.
 */
typedef enum
{
    wifi_auth_id_reserved, /**< Reserved. */
    wifi_auth_id_expanded_eap, /**< Expanded EAP. */
    wifi_auth_id_inner_auth_eap, /**< Inner authentication EAP. */
    wifi_auth_id_expanded_inner_auth_eap, /**< Expanded inner authentication EAP. */
    wifi_auth_id_credential_type, /**< Credential type. */
    wifi_auth_id_tunneled_eap, /**< Tunneled EAP. */
} wifi_auth_id_t;

/**
 * @brief Authentication method.
 */
typedef struct
{
    UCHAR id; /**< ID. */
    UCHAR length; /**< Length. */
    UCHAR val[16]; /**< Value. */
} __attribute__((packed)) wifi_authMethod_t;

/**
 * @brief EAP method.
 */
typedef struct
{
    UCHAR length; /**< Length. */
    UCHAR method; /**< Method. */
    UCHAR auth_param_count; /**< Number of authentication parameters. */
    wifi_authMethod_t auth_method[16]; /**< Authentication methods. */
} __attribute__((packed)) wifi_eapMethod_t;

/**
 * @brief NAI realm information.
 */
typedef struct
{
    USHORT data_field_length; /**< Data field length. */
    UCHAR encoding; /**< Encoding. */
    UCHAR realm_length; /**< Realm length. */
    UCHAR realm[256]; /**< Realm. */
    UCHAR eap_method_count; /**< Number of EAP methods. */
    wifi_eapMethod_t eap_method[16]; /**< EAP methods. */
} __attribute__((packed)) wifi_naiRealm_t;

/**
 * @brief NAI realm element.
 */
typedef struct
{
    USHORT nai_realm_count; /**< Number of NAI realms. */
    wifi_naiRealm_t nai_realm_tuples[20]; /**< NAI realm tuples. */
} __attribute__((packed)) wifi_naiRealmElement_t;

/**
 * @brief Venue name.
 */
typedef struct
{
    UCHAR length; /**< Length. */
    UCHAR language[3]; /**< Language. */
    UCHAR name[256]; /**< Name. */
} __attribute__((packed)) wifi_venueName_t;

/**
 * @brief Venue name element.
 */
typedef struct
{
    UCHAR venueGroup; /**< Venue group. */
    UCHAR venueType; /**< Venue type. */
    wifi_venueName_t venueNameTuples[16]; /**< Venue name tuples. */
} __attribute__((packed)) wifi_venueNameElement_t;

/**
 * @brief PLMN (Public Land Mobile Network) information.
 */
typedef struct
{
    UCHAR PLMN[3]; /**< PLMN identifier. */
} __attribute__((packed)) wifi_plmn_t;

/**
 * @brief 3GPP PLMN list information element.
 */
typedef struct
{
    UCHAR iei; /**< Information Element Identifier (copy zero for now). */
    UCHAR plmn_length; /**< Length of the PLMN list. */
    UCHAR number_of_plmns; /**< Number of PLMNs in the list. */
    wifi_plmn_t plmn[16]; /**< PLMNs. */
} __attribute__((packed)) wifi_3gpp_plmn_list_information_element_t;

/**
 * @brief 3GPP cellular network information.
 */
typedef struct
{
    UCHAR gud; /**< Globally Unique Identifier. */
    UCHAR uhdLength; /**< Length of the remaining fields. */
    wifi_3gpp_plmn_list_information_element_t plmn_information; /**< PLMN list information element. */
} __attribute__((packed)) wifi_3gppCellularNetwork_t;

/**
 * @brief Domain name tuple.
 */
typedef struct
{
    UCHAR length; /**< Length. */
    UCHAR domainName[255]; /**< Domain name (maximum allowed based on the specification). */
} __attribute__((packed)) wifi_domainNameTuple_t;

/**
 * @brief Domain name.
 */
typedef struct
{
    wifi_domainNameTuple_t domainNameTuple[4]; /**< Domain name tuples. */
} __attribute__((packed)) wifi_domainName_t;

/**
 * @brief OUI (Organizationally Unique Identifier) duple.
 */
typedef struct
{
    UCHAR length; /**< Length. */
    UCHAR oui[15]; /**< OUI. */
} __attribute__((packed)) wifi_ouiDuple_t;

/**
 * @brief Roaming consortium.
 */
typedef struct
{
    wifi_ouiDuple_t ouiDuple[32]; /**< OUI duples. */
} __attribute__((packed)) wifi_roamingConsortium_t;

/**
 * @brief Capability list ANQP.
 */
typedef struct
{
    USHORT capabilityList[64]; /**< Capability list. */
} __attribute__((packed)) wifi_capabilityListANQP_t;

/**
 * @brief Roaming consortium element.
 */
typedef struct
{
    UCHAR wifiRoamingConsortiumCount; /**< Number of roaming consortia. */
    UCHAR wifiRoamingConsortiumOui[3][15 + 1]; /**< Only 3 OIs are allowed in beacon and probe responses. OI length is variable between 3 and 15. */
    UCHAR wifiRoamingConsortiumLen[3]; /**< Lengths of the roaming consortia OIs. */
} __attribute__((packed)) wifi_roamingConsortiumElement_t;


// HS2 Related ANQP Elements start


// =========================================Start-HS2-Operator Friendly Name=========================================================================
// HS2.0 Operator Name Duple #1     HS2.0 Operator Name Duple #2        ......    HS2.0 Operator Name Duple #n
//           variable                            variable                                      variable
// HS2.0 Operator name Duple
// Length                                  Language Code                                     Operator Name
//    1   (3+ operator name)                   3                                               variable

/**
 * @brief HS2.0 Operator Name Duple (figure 9-595).
 */
typedef struct _wifi_HS2_OperatorNameDuple_t
{
    UCHAR length; /**< Length is 3 (language code) + number of octets in operator name field. For example, if operatorName = "aaaa", length is 4 + 3 = 7. */
    UCHAR languageCode[3]; /**< Language code. */
    UCHAR operatorName[252]; /**< Operator name (based on the specification, the maximum length is 252). */
} __attribute__((packed)) wifi_HS2_OperatorNameDuple_t;

/**
 * @brief HS2.0 Operator Friendly Name.
 */
typedef struct
{
    wifi_HS2_OperatorNameDuple_t operatorNameDuple[16]; /**< Operator name duples (16 duples are supported for now). */
} __attribute__((packed)) wifi_HS2_OperatorFriendlyName_t;

// =========================================End-HS2-Operator Friendly Name=========================================================================

// =========================================Start-HS2-WAN Metrics Element=========================================================================
// WAN Info                 Downlink Speed           Uplink Speed     Downlink Load       Uplink Load        LMD
//    1                            4                       4                  1                1               2

/**
 * @brief HS2.0 WAN Metrics Element (figure 9-595).
 */
typedef struct
{
    UCHAR wanInfo; /**< WAN information. */
    UINT downLinkSpeed; /**< Downlink speed in kbps. */
    UINT upLinkSpeed; /**< Uplink speed in kbps. */
    UCHAR downLinkLoad; /**< Downlink load as a percentage. */
    UCHAR upLinkLoad; /**< Uplink load as a percentage. */
    USHORT lmd; /**< Load Measurement Duration in seconds. */
} __attribute__((packed)) wifi_HS2_WANMetrics_t;

/**
 * @brief WAN Info bit field values.
 *
 * Bits:
 *  - B0-B1: Link Status
 *  - B2: Symmetric Link
 *  - B3: At Capacity
 *  - B4-B7: Reserved
 */
typedef enum
{
    wifi_hs2_wan_info_reserved, /**< Reserved. */
    wifi_hs2_wan_info_linkup, /**< Link is up. */
    wifi_hs2_wan_info_linkdown, /**< Link is down. */
    wifi_hs2_wan_info_link_in_test_state /**< Link is in test state. */
} wifi_HS2_Wan_Info_Link_Status_t;

// =========================================End-HS2-WAN Metrics Element=========================================================================

// =========================================Start-HS2-Connection Capability Element=========================================================================
// Proto Port Tuple #1        Proto Port Tuple #2  ............. Proto Port Tuple #n
//          4                        4(optional)                   4(optional)
// Proto Port Tuple Format
// IP Protocol                             Port Number                  Status
//      1                                       2                         1

/**
 * @brief HS2.0 Protocol and Port Tuple (figure 9-595).
 */
typedef struct
{
    UCHAR ipProtocol; /**< IP protocol. */
    USHORT portNumber; /**< Port number. */
    UCHAR status; /**< Status. */
} __attribute__((packed)) wifi_HS2_Proto_Port_Tuple_t;

/**
 * @brief HS2.0 Connection Capability Element (figure 9-595).
 */
typedef struct
{
    wifi_HS2_Proto_Port_Tuple_t protoPortTuple[16]; /**< Protocol and port tuples (16 tuples are supported for now). */
} __attribute__((packed)) wifi_HS2_ConnectionCapability_t;

/**
 * @brief HS2.0 Connection Capability Status values.
 */
typedef enum
{
    wifi_hs2_connection_capability_closed, /**< Closed. */
    wifi_hs2_connection_capability_open, /**< Open. */
    wifi_hs2_connection_capability_unknown, /**< Unknown. */
    wifi_hs2_connection_capability_reserved /**< Reserved. */
} wifi_HS2_ConnectionCapability_Status_t;

// =========================================End-HS2-Connection Capability Element=========================================================================

// =========================================Start-HS2-NAI Realm Query Element=========================================================================

// NAI Realm Count                          NAI Home Realm                    NAI Home Realm   ....  NAI Home Realm
//                                         Name Data #1                        Name Data #2            Name Data #n
//       1                                   variable                         (variable optional)       (variable optional)

// NAI Realm Encoding                                 NAI Home Realm Name Length              NAI Home Realm
//          1                                                      1                               variable

/**
 * @brief HS2.0 NAI Home Realm Data (figure 9-595).
 */
typedef struct
{
    UCHAR encoding; /**< Encoding. */
    UCHAR length; /**< Length. */
    UCHAR name[255]; /**< Name (maximum length is 255 according to the specification). */
} __attribute__((packed)) wifi_HS2_NAI_Home_Realm_Data_t;

/**
 * @brief HS2.0 NAI Home Realm Query (figure 9-595).
 */
typedef struct
{
    UCHAR realmCount; /**< Realm count. */
    wifi_HS2_NAI_Home_Realm_Data_t homeRealmData[20]; /**< Home realm data (up to 255 realms are supported). */
} __attribute__((packed)) wifi_HS2_NAI_Home_Realm_Query_t;

// =========================================End-HS2-NAI Realm Query Element=========================================================================

// =========================================Start-HS2-Capability List=========================================================================
// HS2.0 Capability #1     HS2.0 Capability #2        ......    HS2.0 Capability #n
//             1             0 or 1 (optional)                      0 or 1 (optional)
// =========================================End-HS2-Capability List=========================================================================

/**
 * @brief HS2.0 Capability List.
 */
typedef struct
{
    UCHAR capabilityList[64]; /**< Capability list. */
} __attribute__((packed)) wifi_HS2_CapabilityList_t;

/**
 * @brief EAPOL key frame.
 */
typedef struct
{
    unsigned char descriptor; /**< Descriptor type. */
    unsigned char key_info[2]; /**< Key information. */
    unsigned short key_len; /**< Key length. */
    unsigned char replay[8]; /**< Replay counter. */
    unsigned char nonce[32]; /**< Nonce. */
    unsigned char init_vector[16]; /**< Initialization vector. */
    unsigned char rsc[8]; /**< Receive Sequence Counter. */
    unsigned char key_id[8]; /**< Key identifier. */
    unsigned char mic[16]; /**< Message Integrity Check. */
    unsigned short len; /**< Length of the data. */
    unsigned char data[0]; /**< Data. */
} wifi_eapol_key_frame_t;

/**
 * @brief EAP codes.
 */
typedef enum
{
    wifi_eap_code_request = 1, /**< Request. */
    wifi_eap_code_response, /**< Response. */
    wifi_eap_code_success, /**< Success. */
    wifi_eap_code_failure, /**< Failure. */
} wifi_eap_code_t;

/**
 * @brief EAP frame.
 */
typedef struct
{
    unsigned char code; /**< Code. */
    unsigned char id; /**< ID. */
    unsigned short len; /**< Length of the data. */
    unsigned char data[0]; /**< Data. */
} __attribute__((__packed__)) wifi_eap_frame_t;

/**
 * @brief EAPOL types.
 */
typedef enum
{
    wifi_eapol_type_eap_packet, /**< EAP packet. */
    wifi_eapol_type_eapol_start, /**< EAPOL start. */
    wifi_eapol_type_eapol_logoff, /**< EAPOL logoff. */
    wifi_eapol_type_eapol_key, /**< EAPOL key. */
} wifi_eapol_type_t;

/**
 * @brief 802.1x frame.
 */
typedef struct
{
    unsigned char version; /**< Version. */
    unsigned char type; /**< Type. */
    unsigned short len; /**< Length of the data. */
    unsigned char data[0]; /**< Data. */
} __attribute__((__packed__)) wifi_8021x_frame_t;

/**
 * @brief Wi-Fi direction values.
 */
typedef enum
{
    wifi_direction_unknown, /**< Unknown direction. */
    wifi_direction_uplink, /**< Uplink. */
    wifi_direction_downlink /**< Downlink. */
} wifi_direction_t;

/**
 * @brief RADIUS Server information.
 *
 * Structure that holds the RADIUS server settings.
 */
typedef struct _wifi_radius_setting_t
{
    INT RadiusServerRetries;           /**< Number of retries for RADIUS requests. */
    INT RadiusServerRequestTimeout;    /**< RADIUS request timeout in seconds after which the request must be retransmitted for the number of retries available. */
    INT PMKLifetime;                   /**< Default time in seconds after which a Wi-Fi client is forced to re-authenticate (default: 8 hours). */
    BOOL PMKCaching;                  /**< Enable or disable caching of PMK. */
    INT PMKCacheInterval;              /**< Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (default: 5 minutes). */
    INT MaxAuthenticationAttempts;     /**< Indicates the number of times a client can attempt to log in with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt logging into the network. Setting this parameter to 0 (zero) disables the blacklisting feature. */
    INT BlacklistTableTimeout;         /**< Time interval in seconds for which a client will continue to be blacklisted once it is marked so. */
    INT IdentityRequestRetryInterval;  /**< Time interval in seconds between identity requests retries. A value of 0 (zero) disables it. */
    INT QuietPeriodAfterFailedAuthentication; /**< The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it. */
    //UCHAR RadiusSecret[64];         //<! The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

} wifi_radius_setting_t;

/**
 * @brief Represents the Wi-Fi scan modes.
 */
typedef enum
{
    WIFI_RADIO_SCAN_MODE_NONE = 0,    /**< No scan. */
    WIFI_RADIO_SCAN_MODE_FULL,      /**< Full scan. */
    WIFI_RADIO_SCAN_MODE_ONCHAN,    /**< On-channel scan. */
    WIFI_RADIO_SCAN_MODE_OFFCHAN,   /**< Off-channel scan. */
    WIFI_RADIO_SCAN_MODE_SURVEY,     /**< Survey scan. */
    WIFI_RADIO_SCAN_MODE_SELECT_CHANNELS    /**< Selected channels scan. */
} wifi_neighborScanMode_t;

/**
 * @brief EAP types.
 */
typedef enum
{
    WIFI_EAP_TYPE_NONE = 0,        /**< No EAP type. */
    WIFI_EAP_TYPE_IDENTITY = 1,    /**< EAP-Identity (RFC 3748). */
    WIFI_EAP_TYPE_NOTIFICATION = 2, /**< EAP-Notification (RFC 3748). */
    WIFI_EAP_TYPE_NAK = 3,        /**< EAP-NAK (Response only, RFC 3748). */
    WIFI_EAP_TYPE_MD5 = 4,         /**< EAP-MD5 (RFC 3748). */
    WIFI_EAP_TYPE_OTP = 5,         /**< EAP-OTP (RFC 3748). */
    WIFI_EAP_TYPE_GTC = 6,         /**< EAP-GTC (RFC 3748). */
    WIFI_EAP_TYPE_TLS = 13,        /**< EAP-TLS (RFC 2716). */
    WIFI_EAP_TYPE_LEAP = 17,       /**< EAP-LEAP (Cisco proprietary). */
    WIFI_EAP_TYPE_SIM = 18,        /**< EAP-SIM (RFC 4186). */
    WIFI_EAP_TYPE_TTLS = 21,       /**< EAP-TTLS (RFC 5281). */
    WIFI_EAP_TYPE_AKA = 23,        /**< EAP-AKA (RFC 4187). */
    WIFI_EAP_TYPE_PEAP = 25,       /**< EAP-PEAP (draft-josefsson-pppext-eap-tls-eap-06.txt). */
    WIFI_EAP_TYPE_MSCHAPV2 = 26,    /**< EAP-MSCHAPv2 (draft-kamath-pppext-eap-mschapv2-00.txt). */
    WIFI_EAP_TYPE_TLV = 33,        /**< EAP-TLV (draft-josefsson-pppext-eap-tls-eap-07.txt). */
    WIFI_EAP_TYPE_TNC = 38,        /**< EAP-TNC (TNC IF-T v1.0-r3). Note: Tentative assignment; type 38 has previously been allocated for EAP-HTTP Digest (funk.com). */
    WIFI_EAP_TYPE_FAST = 43,       /**< EAP-FAST (RFC 4851). */
    WIFI_EAP_TYPE_PAX = 46,        /**< EAP-PAX (RFC 4746). */
    WIFI_EAP_TYPE_PSK = 47,        /**< EAP-PSK (RFC 4764). */
    WIFI_EAP_TYPE_SAKE = 48,       /**< EAP-SAKE (RFC 4763). */
    WIFI_EAP_TYPE_IKEV2 = 49,      /**< EAP-IKEv2 (RFC 5106). */
    WIFI_EAP_TYPE_AKA_PRIME = 50,   /**< EAP-AKA' (RFC 5448). */
    WIFI_EAP_TYPE_GPSK = 51,       /**< EAP-GPSK (RFC 5433). */
    WIFI_EAP_TYPE_PWD = 52,        /**< EAP-PWD (RFC 5931). */
    WIFI_EAP_TYPE_EKE = 53,        /**< EAP-EKE (RFC 6124). */
    WIFI_EAP_TYPE_TEAP = 55,       /**< EAP-TEAP (RFC 7170). */
    WIFI_EAP_TYPE_EXPANDED = 254   /**< EAP-Expanded (RFC 3748). */
} wifi_eap_t;

typedef enum {
    WIFI_EAP_PHASE2_EAP,        /**< Enterprise EAP. */
    WIFI_EAP_PHASE2_MSCHAPV2,   /**< Enterprise MSCHAPV2. */
    WIFI_EAP_PHASE2_MSCHAP,     /**< Enterprise MSCHAP. */
    WIFI_EAP_PHASE2_PAP,        /**< Enterprise PAP. */
    WIFI_EAP_PHASE2_CHAP,       /**< Enterprise CHAP. */
    WIFI_EAP_PHASE2_GTC         /**< Enterprise GTC. */
} phase2_type;

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Gets detailed traffic statistics for a specific Access Point (AP).
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[out] output_struct Pointer to a structure to store the traffic statistics.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Gets the list of associated devices for a specific Access Point (AP).
 *
 * Retrieves a list of MAC addresses for devices associated with the specified AP.
 *
 * @param[in] ap_index                  Index of the Access Point.
 * @param[out] output_deviceMacAddressArray  Pointer to an array to store the MAC addresses of associated devices.
 * @param[in] maxNumDevices             Maximum number of devices that can be stored in the array.
 * @param[out] output_numDevices         Pointer to a variable to store the actual number of devices returned in the array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAssociatedDevice(INT ap_index, mac_address_t *output_deviceMacAddressArray, UINT maxNumDevices, UINT *output_numDevices);
#endif

/**
 * @brief Restores Access Point parameters to factory defaults.
 *
 * This function resets the parameters of the specified Access Point (AP)
 * to their factory default values, without affecting other APs or radio
 * parameters. It does not require a Wi-Fi reboot.
 *
 * @param[in] apIndex Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_factoryResetAP(int apIndex);

/**
 * @brief Deletes an Access Point.
 *
 * This function deletes the specified Access Point (AP) entry on the
 * hardware and clears all internal variables associated with it.
 *
 * @param[in] apIndex Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_deleteAp(INT apIndex);

/**
 * @brief Gets the name of an Access Point.
 *
 * This function retrieves the name associated with the specified Access Point (AP).
 * The output string buffer must be pre-allocated by the caller with a size of
 * at least 16 bytes.
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[out] output_string Pointer to a buffer to store the AP name.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApName(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the RTS/CTS threshold for an Access Point.
 *
 * This function sets the packet size threshold, in bytes, for applying
 * RTS/CTS (Request to Send/Clear to Send) backoff rules on the specified
 * Access Point (AP).
 *
 * @param[in] apIndex    Index of the Access Point.
 * @param[in] threshold  Packet size threshold in bytes.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold);

/**
 * @brief Removes internal security settings for an Access Point.
 *
 * This function deletes the internal security variable settings for the
 * specified Access Point (AP).
 *
 * @param[in] apIndex Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_removeApSecVaribles(INT apIndex);

/**
 * @brief Disables encryption for an Access Point.
 *
 * This function changes the hardware settings to disable encryption on the
 * specified Access Point (AP).
 *
 * @param[in] apIndex Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_disableApEncryption(INT apIndex);

/**
 * @brief Gets the number of associated devices for an Access Point.
 *
 * This function retrieves the number of stations currently associated with
 * the specified Access Point (AP).
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[out] output_ulong  Pointer to a variable to store the number of associated stations.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Disassociates a device from an Access Point.
 *
 * This function manually removes any active Wi-Fi association between the
 * specified client device and the Access Point (AP).
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[in] client_mac  MAC address of the client device to disassociate.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_kickApAssociatedDevice(INT apIndex, mac_address_t client_mac);
#endif

/**
 * @brief Gets the radio index for an Access Point.
 *
 * This function retrieves the index of the radio associated with the
 * specified Access Point (AP).
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[out] output_int Pointer to a variable to store the radio index.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApRadioIndex(INT apIndex, INT *output_int);

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Gets the ACL MAC list for an Access Point.
 *
 * This function retrieves the list of MAC addresses in the Access Control List (ACL)
 * for the specified Access Point (AP).
 *
 * @param[in] apIndex          Index of the Access Point.
 * @param[out] macArray       Pointer to an array to store the MAC addresses.
 * @param[in] maxArraySize    Maximum number of MAC addresses that can be stored in the array.
 * @param[out] output_numEntries Pointer to a variable to store the actual number of MAC addresses returned in the array.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAclDevices(INT apIndex, mac_address_t *macArray, UINT maxArraySize, UINT* output_numEntries);
#endif

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Adds a MAC address to the Access Control List (ACL) for an Access Point.
 *
 * This function adds the specified MAC address to the filter list for the given Access Point (AP).
 *
 * @param[in] apIndex           Index of the Access Point.
 * @param[in] DeviceMacAddress  MAC address of the device to add to the ACL.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_addApAclDevice(INT apIndex, mac_address_t DeviceMacAddress);
#endif

#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Deletes a MAC address from the Access Control List (ACL) for an Access Point.
 *
 * This function removes the specified device's MAC address from the ACL for the given Access Point (AP).
 * This function must not block or invoke any long-running tasks.
 *
 * @param[in] apIndex           Index of the Access Point.
 * @param[in] deviceMacAddress  MAC address of the device to remove from the ACL.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_delApAclDevice(INT apIndex, mac_address_t deviceMacAddress);
#endif

/**
 * @brief Deletes all MAC addresses from the Access Control List (ACL) for an Access Point.
 *
 * This function removes all device MAC addresses from the ACL for the given Access Point (AP).
 *
 * @param[in] apIndex  Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_delApAclDevices(INT apIndex);

/**
 * @brief Gets the number of devices in the Access Control List (ACL) for an Access Point.
 *
 * This function retrieves the number of devices in the filter list for the specified Access Point (AP).
 * This function must not block or invoke any long-running tasks.
 *
 * @param[in] apIndex      Index of the Access Point.
 * @param[out] output_uint Pointer to a variable to store the number of devices in the ACL.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint);

/**
 * @brief Enables or disables the "kick" feature for devices on the ACL blacklist for an Access Point.
 *
 * This function controls whether devices on the Access Control List (ACL) blacklist
 * for the specified Access Point (AP) should be actively kicked (disassociated).
 * This function must not block or invoke any long-running tasks.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enable   Boolean value indicating whether to enable (true) or disable (false) the kick feature.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable);

/**
 * @brief Sets the MAC address filter control mode for an Access Point.
 *
 * This function sets the MAC address filtering mode for the specified Access Point (AP).
 * The valid filter modes are:
 *  - 0: Filter disabled.
 *  - 1: Filter as whitelist.
 *  - 2: Filter as blacklist.
 *
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[in] filterMode  MAC address filter control mode.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode);

/**
 * @brief Gets the MAC address filter control mode for an Access Point.
 *
 * This function retrieves the MAC address filtering mode for the specified
 * Access Point (AP). The returned value indicates the current filter mode:
 *  - 0: Filter disabled.
 *  - 1: Filter as whitelist.
 *  - 2: Filter as blacklist.
 *
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex            Index of the Access Point.
 * @param[out] output_filterMode Pointer to a variable to store the MAC address control mode.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApMacAddressControlMode(INT apIndex, INT *output_filterMode);

/**
 * @brief Sets the VLAN ID for an Access Point.
 *
 * This function sets the VLAN ID for the specified Access Point (AP).
 * The VLAN ID is stored in an internal environment variable.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] vlanId   VLAN ID to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApVlanID(INT apIndex, INT vlanId);

/**
 * @brief Resets the VLAN configuration for an Access Point.
 *
 * This function resets the VLAN configuration for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_resetApVlanCfg(INT apIndex);

/**
 * @brief Sets the enable status for an Access Point.
 *
 * This function sets the enable status variable for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enable   Boolean value indicating whether to enable (true) or disable (false) the AP.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApEnable(INT apIndex, BOOL enable);

/**
 * @brief Gets the enable status for an Access Point.
 *
 * This function retrieves the setting of the internal enable status variable
 * for the specified Access Point (AP), which is set by the `wifi_setApEnable()` function.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[out] output_bool Pointer to a variable to store the AP enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief Gets the operational status of an Access Point.
 *
 * This function retrieves the operational status of the specified Access Point (AP)
 * from the driver. The output string will be set to either "Enabled" or "Disabled".
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[out] output_string Pointer to a buffer to store the AP status string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApStatus(INT apIndex, CHAR *output_string);

/**
 * @brief Checks whether SSID advertisement is enabled for an Access Point.
 *
 * This function indicates whether or not the beacons transmitted by the
 * specified Access Point (AP) include the SSID name.
 * It returns true if SSID advertisement is enabled, and false otherwise.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[out] output_bool Pointer to a variable to store the SSID advertisement status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief Enables or disables SSID advertisement for an Access Point.
 *
 * This function sets an internal variable to control whether the specified
 * Access Point (AP) includes the SSID name in its beacon frames.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enable   Boolean value indicating whether to enable (true) or disable (false) SSID advertisement.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable);

/**
 * @brief Gets the retry limit for an Access Point.
 *
 * This function retrieves the maximum number of retransmissions allowed for a packet
 * on the specified Access Point (AP). This corresponds to the IEEE 802.11 parameter
 * `dot11ShortRetryLimit`.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] output  Pointer to a variable to store the retry limit.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApRetryLimit(INT apIndex, UINT *output);

/**
 * @brief Sets the retry limit for an Access Point.
 *
 * This function sets the maximum number of retransmissions allowed for a packet
 * on the specified Access Point (AP). This corresponds to the IEEE 802.11 parameter
 * `dot11ShortRetryLimit`.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex Index of the Access Point.
 * @param[in] number  Retry limit to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApRetryLimit(INT apIndex, UINT number);

/**
 * @brief Checks whether WMM is enabled for an Access Point.
 *
 * This function indicates whether Wi-Fi Multimedia (WMM) support is currently
 * enabled on the specified Access Point (AP). When enabled, WMM support is
 * indicated in the AP's beacon frames.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] output  Pointer to a variable to store the WMM enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApWmmEnable(INT apIndex, BOOL *output);   

/**
 * @brief Enables or disables WMM for an Access Point.
 *
 * This function enables or disables Wi-Fi Multimedia (WMM) support on the
 * hardware for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enable   Boolean value indicating whether to enable (true) or disable (false) WMM.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApWmmEnable(INT apIndex, BOOL enable);

/**
 * @brief Checks whether U-APSD is enabled for an Access Point.
 *
 * This function indicates whether Unscheduled Automatic Power Save Delivery (U-APSD)
 * support is currently enabled on the specified Access Point (AP). When enabled,
 * U-APSD support is indicated in the AP's beacon frames.
 * Note that U-APSD can only be enabled if Wi-Fi Multimedia (WMM) is also enabled.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] output  Pointer to a variable to store the U-APSD enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output);

/**
 * @brief Enables or disables U-APSD for an Access Point.
 *
 * This function enables or disables Unscheduled Automatic Power Save Delivery
 * (U-APSD) on the hardware for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enable   Boolean value indicating whether to enable (true) or disable (false) U-APSD.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable);

/**
 * @brief Sets the WMM ACK policy for an Access Point.
 *
 * This function sets the Wi-Fi Multimedia (WMM) acknowledgment (ACK) policy
 * on the hardware for the specified Access Point (AP).
 * An `ackPolicy` of false means do not acknowledge, and true means acknowledge.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex   Index of the Access Point.
 * @param[in] class     Class of service.
 * @param[in] ackPolicy Acknowledgement policy.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApWmmOgAckPolicy(INT apIndex, INT cla, BOOL ackPolicy);

/**
 * @brief Gets the device isolation status for an Access Point.
 *
 * This function retrieves the device isolation status for the specified Access Point (AP).
 * A value of true means that devices connected to the AP are isolated from other devices
 * within the home network (as is typical for a wireless hotspot).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] output  Pointer to a variable to store the isolation enable status.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output);

/**
 * @brief Enables or disables device isolation for an Access Point.
 *
 * This function controls whether devices connected to the specified Access Point (AP)
 * are isolated from other devices within the home network.
 * A value of true means that devices connected to the AP are isolated, as is typically
 * the case for a wireless hotspot.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enable   Boolean value indicating whether to enable (true) or disable (false) isolation.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable);

/**
 * @brief Sets the beacon transmission rate for an Access Point.
 *
 * This function sets the beacon transmission rate for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex      Index of the Access Point (valid values: 0, 2, 4, 6, 8, 10, 12, 14 for 2.4 GHz).
 * @param[in] sBeaconRate  Beacon rate string (valid values: "1Mbps", "5.5Mbps", "6Mbps", "2Mbps", "11Mbps", "12Mbps", "24Mbps").
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApBeaconRate(INT apIndex, char *sBeaconRate);

/**
 * @brief Gets the beacon transmission rate for an Access Point.
 *
 * This function retrieves the beacon transmission rate for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex            Index of the Access Point.
 * @param[out] output_BeaconRate Pointer to a buffer to store the beacon rate string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApBeaconRate(INT apIndex, char *output_BeaconRate);

/**
 * @brief Gets the maximum number of associated devices allowed for an Access Point.
 *
 * This function retrieves the maximum number of devices that can simultaneously
 * be connected to the specified Access Point (AP). A value of 0 indicates that
 * there is no specific limit on the number of associated devices.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] output  Pointer to a variable to store the maximum number of associated devices.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output);

/**
 * @brief Sets the maximum number of associated devices allowed for an Access Point.
 *
 * This function sets the maximum number of devices that can simultaneously
 * be connected to the specified Access Point (AP). A value of 0 indicates that
 * there is no specific limit on the number of associated devices.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] number   Maximum number of associated devices to allow.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number);

/**
 * @brief Resets the security settings for an Access Point to factory defaults.
 *
 * This function resets the Wi-Fi security settings for the specified Access Point (AP)
 * to their factory default values. The affected settings include `ModeEnabled`, `WEPKey`,
 * `PreSharedKey`, and `KeyPassphrase`.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApSecurityReset(INT apIndex);

/**
 * @brief Gets the MFP configuration for an Access Point.
 *
 * This function retrieves the Management Frame Protection (MFP) configuration
 * for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex         Index of the Access Point.
 * @param[out] output_string  Pointer to a pre-allocated buffer (at least 64 bytes) to store the MFP configuration string.
 *                            Valid output strings are: "Disabled", "Optional", "Required".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApSecurityMFPConfig(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the MFP configuration for an Access Point.
 *
 * This function sets the Management Frame Protection (MFP) configuration for
 * the specified Access Point (AP). The MFP configuration must be saved in a
 * persistent manner so that it can be automatically applied after a Wi-Fi
 * or VAP restart. The configuration must also be applied immediately.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex    Index of the Access Point.
 * @param[in] MfpConfig  MFP configuration string.
 *                       Valid values are: "Disabled", "Optional", "Required".
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApSecurityMFPConfig(INT apIndex, CHAR *MfpConfig);

/**
 * @brief Gets the RADIUS server settings for an Access Point.
 *
 * This function retrieves the IP address, port number, and secret of the RADIUS
 * server used for WLAN security on the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex              Index of the Access Point.
 * @param[out] IP_output            Pointer to a buffer (at least 64 bytes) to store the RADIUS server IP address.
 * @param[out] Port_output          Pointer to a variable to store the RADIUS server port number.
 * @param[out] RadiusSecret_output  Pointer to a buffer (at least 64 bytes) to store the RADIUS server secret.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output); 

/**
 * @brief Sets the RADIUS server settings for an Access Point.
 *
 * This function sets the IP address, port number, and secret of the RADIUS
 * server used for WLAN security on the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex       Index of the Access Point.
 * @param[in] IPAddress     IP address of the RADIUS server.
 * @param[in] port          Port number of the RADIUS server.
 * @param[in] RadiusSecret  Secret used for authentication with the RADIUS server.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret);

/**
 * @brief Gets the secondary RADIUS server settings for an Access Point.
 *
 * This function retrieves the IP address, port number, and secret of the
 * secondary RADIUS server used for WLAN security on the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex              Index of the Access Point.
 * @param[out] IP_output            Pointer to a buffer (at least 64 bytes) to store the RADIUS server IP address.
 * @param[out] Port_output          Pointer to a variable to store the RADIUS server port number.
 * @param[out] RadiusSecret_output  Pointer to a buffer (at least 64 bytes) to store the RADIUS server secret.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output);

/**
 * @brief Sets the secondary RADIUS server settings for an Access Point.
 *
 * This function sets the IP address, port number, and secret of the secondary RADIUS server
 * used for WLAN security on the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex      Index of the Access Point.
 * @param[in] IPAddress    IP address of the RADIUS server.
 * @param[in] port         Port number of the RADIUS server.
 * @param[in] RadiusSecret Secret used for authentication with the RADIUS server.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret);

/**
 * @brief Gets the RADIUS DAS server settings for an Access Point.
 *
 * This function retrieves the IP address, port number, and secret of the
 * RADIUS DAS server used for WLAN security on the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex               Index of the Access Point.
 * @param[out] IP_output            Pointer to a buffer to store the RADIUS server IP address.
 * @param[out] Port_output          Pointer to a variable to store the RADIUS server port number.
 * @param[out] RadiusdasSecret_output Pointer to a buffer to store the RADIUS DAS server secret.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApDASRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusdasSecret_output);

/**
 * @brief Sets the RADIUS DAS server settings for an Access Point.
 *
 * This function sets the IP address, port number, and secret of the RADIUS DAS
 * server used for WLAN security on the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex         Index of the Access Point.
 * @param[in] IPAddress      IP address of the RADIUS DAS server.
 * @param[in] port           Port number of the RADIUS DAS server.
 * @param[in] RadiusdasSecret Secret used for authentication with the RADIUS DAS server.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApDASRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusdasSecret);

/**
 * @brief Enables or disables greylist access control on all applicable VAPs.
 *
 * This function enables or disables greylist access control on all
 * applicable Virtual Access Points (VAPs).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] enable  Boolean value indicating whether to enable (true) or
 *                    disable (false) greylist access control.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_enableGreylistAccessControl(BOOL enable);

/**
 * @brief Gets the RADIUS settings for an Access Point.
 *
 * This function retrieves the RADIUS settings for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] output  Pointer to a `wifi_radius_setting_t` structure to store the RADIUS settings.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output);

/**
 * @brief Sets the RADIUS settings for an Access Point.
 *
 * This function sets the RADIUS settings for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] input    Pointer to a `wifi_radius_setting_t` structure containing the RADIUS settings to apply.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input);

//-----------------------------------------------------------------------------------------------

/**
 * @brief Gets the WPS configuration state for an Access Point.
 *
 * This function retrieves the Wi-Fi Protected Setup (WPS) configuration state
 * for the specified Access Point (AP).
 * The output string will be set to either "Not configured" or "Configured".
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[out] output_string Pointer to a buffer (at least 32 bytes) to store the WPS configuration state.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string);

/**
 * @brief Sets the WPS enrollee PIN for an Access Point.
 *
 * This function sets the Wi-Fi Protected Setup (WPS) enrollee PIN for the
 * specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] pin      WPS enrollee PIN to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin);

/**
 * @brief Simulates a WPS push button press for an Access Point.
 *
 * This function simulates a Wi-Fi Protected Setup (WPS) push button press
 * for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApWpsButtonPush(INT apIndex);

/**
 * @brief Cancels WPS mode for an Access Point.
 *
 * This function cancels Wi-Fi Protected Setup (WPS) mode for the specified
 * Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_cancelApWPS(INT apIndex);

/**
 * @brief Gets the management frame power control value for an Access Point.
 *
 * This function retrieves the ApManagementFramePowerControl value for the
 * specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[out] output_dBm Pointer to a variable to store the ManagementFramePowerControl value, in dBm.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm);

/**
 * @brief Sets the management frame power control value for an Access Point.
 *
 * This function sets the ApManagementFramePowerControl value for the specified
 * Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] dBm      RadioManagementFramePowerControl value to set, in dBm.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm);
/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Callback function invoked when a new Wi-Fi client associates with an Access Point.
 *
 * This callback function is invoked when a new Wi-Fi client associates with
 * the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex         Index of the Access Point.
 * @param[in] associated_dev  Pointer to a structure containing information about the associated device.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
typedef INT(* wifi_newApAssociatedDevice_callback)(INT apIndex, wifi_associated_dev3_t *associated_dev);
#else

/**
 * @brief Structure containing information about an associated device.
 */
typedef struct _wifi_associated_dev
{
    UCHAR cli_MACAddress[6];             /**< The MAC address of an associated device. */
    CHAR cli_IPAddress[64];              /**< IP address of the associated device. */
    BOOL cli_AuthenticationState;        /**< Whether an associated device has authenticated (true) or not (false). */
    UINT cli_LastDataDownlinkRate;      /**< The data transmit rate in kbps that was most recently used for transmission from the access point to the associated device. */
    UINT cli_LastDataUplinkRate;        /**< The data transmit rate in kbps that was most recently used for transmission from the associated device to the access point. */
    INT cli_SignalStrength;              /**< An indicator of radio signal strength of the uplink from the associated device to the access point, measured in dBm, as an average of the last 100 packets received from the device. */
    UINT cli_Retransmissions;            /**< The number of packets that had to be re-transmitted, from the last 100 packets sent to the associated device. Multiple re-transmissions of the same packet count as one. */
    BOOL cli_Active;                    /**< Whether or not this node is currently present in the WiFi AccessPoint network. */
    CHAR cli_OperatingStandard[64];     /**< Radio standard the associated Wi-Fi client device is operating under. */
    CHAR cli_OperatingChannelBandwidth[64]; /**< The operating channel bandwidth of the associated device. The channel bandwidth (applicable to 802.11n and 802.11ac specifications only). */
    INT cli_SNR;                         /**< A signal-to-noise ratio (SNR) compares the level of the Wi-Fi signal to the level of background noise. Sources of noise can include microwave ovens, cordless phone, bluetooth devices, wireless video cameras, wireless game controllers, fluorescent lights and more. It is measured in decibels (dB). */
    CHAR cli_InterferenceSources[64];    /**< Wi-Fi operates in two frequency ranges (2.4 Ghz and 5 Ghz) which may become crowded with other radio products which operate in the same ranges. This parameter reports the probable interference sources that this Wi-Fi access point may be observing. The value of this parameter is a comma separated list of the following possible sources: e.g., "MicrowaveOven,CordlessPhone,BluetoothDevices,FluorescentLights,ContinuousWaves,Others". */
    ULONG cli_DataFramesSentAck;         /**< The total number of MSDU frames marked as duplicates and non-duplicates acknowledged. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_DataFramesSentNoAck;       /**< The total number of MSDU frames retransmitted out of the interface (i.e., marked as duplicate and non-duplicate) and not acknowledged, but does not exclude those defined in the DataFramesLost parameter. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_BytesSent;                 /**< The total number of bytes transmitted to the client device, including framing characters. */
    ULONG cli_BytesReceived;             /**< The total number of bytes received from the client device, including framing characters. */
    INT cli_RSSI;                        /**< The Received Signal Strength Indicator (RSSI) parameter is the energy observed at the antenna receiver for transmissions from the device averaged over past 100 packets received from the device. */
    INT cli_MinRSSI;                     /**< The minimum Received Signal Strength Indicator (RSSI) parameter is the minimum energy observed at the antenna receiver for past transmissions (100 packets). */
    INT cli_MaxRSSI;                     /**< The maximum Received Signal Strength Indicator (RSSI) parameter is the maximum energy observed at the antenna receiver for past transmissions (100 packets). */
    UINT cli_Disassociations;           /**< The total number of client disassociations. Reset the parameter every 24 hours or on reboot. */
    UINT cli_AuthenticationFailures;     /**< The total number of authentication failures. Reset the parameter every 24 hours or on reboot. */
    UINT cli_CapableNumSpatialStreams;  /**< The number of spatial streams supported by the associated client device. */
} wifi_associated_dev_t;

/**
 * @brief Callback function invoked when a new Wi-Fi client associates with an Access Point.
 *
 * This callback function is invoked when a new Wi-Fi client associates with
 * the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[in] associated_dev Pointer to a structure containing information about the associated device.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
typedef INT(* wifi_newApAssociatedDevice_callback)(INT apIndex, wifi_associated_dev_t *associated_dev);
#endif
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @brief Registers a callback function for new AP associated device events.
 *
 * This function registers a callback function that will be invoked when a new
 * Wi-Fi client associates with an Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] callback_proc Pointer to the callback function to register.
 */
void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc);
/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Callback function invoked when a Wi-Fi client disassociates from an Access Point.
 *
 * This callback function is invoked when a Wi-Fi client disassociates from
 * the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[in] MAC          MAC address of the disassociated device.
 * @param[in] event_type  Type of disassociation, either explicit or due to client inactivity.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
typedef INT ( * wifi_apDisassociatedDevice_callback)(INT apIndex, char *MAC, INT event_type);

/* wifi_stamode_callback() function */
/**
* @brief This call back will be invoked for all of these assoc request,reassoc request,eapol frames
*
* @param[in] apIndex          Access Point Index
* @param[in] mac              MAC address of associated device
* @param[in] key_mgmt         authentication key management  of associated device
* @param[in] type             frame type of associated device
* @param[in] radio            radio to which associated device connected
* @param[in] mode             security mode of gateway with respect to akm
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
typedef INT ( * wifi_stamode_callback)(int apIndex, char *mac, int key_mgmt, int type, int radio, int mode);

/* wifi_hal_ap_max_client_rejection_callback_register() function */
/**
 * @brief This call back will be called whenever an authentication response with reject reason 17
 * is received.
 *
 * @param[in] apIndex          Access Point Index
 * @param[in] mac_address      client_mac_address
 * @param[in] reject_reason    reject reason
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
typedef INT (*wifi_apMaxClientRejection_callback)(INT apIndex, char *MAC, INT reason);

/**
 * @brief Callback function invoked when a RADIUS or EAP failure occurs.
 *
 * This callback function is invoked when a RADIUS or EAP failure occurs on
 * the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex         Index of the Access Point.
 * @param[in] failure_reason  Reason for the failure.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
typedef INT ( * wifi_radiusEapFailure_callback)(INT apIndex, INT failure_reason);

/**
 * @brief Registers a callback function for RADIUS/EAP failure events.
 *
 * This function registers a callback function that will be invoked when a
 * RADIUS or EAP failure occurs.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param callback_proc Pointer to the callback function to register.
 */
void wifi_radiusEapFailure_callback_register(wifi_radiusEapFailure_callback callback_proc);

/* wifi_ap_stamode_callback_register() function */
/**
* @brief Callback registration function.
*
* @param[in] callback_proc  wifi_stamode_callback callback function
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
void wifi_ap_stamode_callback_register(wifi_stamode_callback callback_proc);

/**
 * @brief Callback function invoked when a RADIUS server fallback failure occurs.
 *
 * This callback function is invoked when a RADIUS server fallback failure occurs on
 * the specified Access Point (AP).
 *
 * @param[in] apIndex         Index of the Access Point.
 * @param[in] failure_reason  Reason for the failure.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 *
 * In current implementation return value is WIFI_HAL_SUCCESS and any failure of the operation
 * is updated in the failure_reason code.
 */
typedef INT ( * wifi_radiusFallback_failover_callback)(INT apIndex, INT failure_reason);

/**
 * @brief Registers a callback function for RADIUS server fallback failure events.
 *
 * This function registers a callback function that will be invoked when a
 * RADIUS server fallback failure occurs.
 *
 * @param callback_proc Pointer to the callback function to register.
 */
void wifi_radiusFallback_failover_callback_register(wifi_radiusFallback_failover_callback callback_proc);

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Registers a callback function for AP disassociated device events.
 *
 * This function registers a callback function that will be invoked when a
 * Wi-Fi client disassociates from an Access Point (AP).
 *
 * @param callback_proc Pointer to the callback function to register.
 */
void wifi_apDisassociatedDevice_callback_register(wifi_apDisassociatedDevice_callback callback_proc);
/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Callback function invoked when a deauthentication event occurs.
 *
 * This callback function is invoked when a deauthentication event with reason
 * code 2 (wrong password) is received from a client device.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] ap_index  Index of the Access Point.
 * @param[in] mac       MAC address of the client device.
 * @param[in] reason    Reason code for the deauthentication event.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
typedef INT ( * wifi_apDeAuthEvent_callback)(int ap_index, char *mac, int reason);
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Registers a callback function for deauthentication events.
 *
 * This function registers a callback function that will be invoked when a
 * deauthentication event occurs.
 *
 * @param callback_proc Pointer to the callback function to register.
 */
void wifi_apDeAuthEvent_callback_register(wifi_apDeAuthEvent_callback callback_proc);

/**
 * @brief Sets the interworking access network type for an Access Point.
 *
 * This function sets the access network type that will be included in the
 * Interworking Information Element (IE) in the beacons transmitted by the
 * specified Access Point (AP).
 * Refer to section 8.4.2.94 of IEEE Std 802.11-2012 for the possible values
 * of the access network type:
 *  - 0: Private network
 *  - 1: Private network with guest access
 *  - 2: Chargeable public network
 *  - 3: Free public network
 *  - 4: Personal device network
 *  - 5: Emergency services only network
 *  - 6-13: Reserved
 *  - 14: Test or experimental
 *  - 15: Wildcard
 *
 * @param[in] apIndex            Index of the Access Point.
 * @param[in] accessNetworkType  Access network type to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setInterworkingAccessNetworkType(INT apIndex, INT accessNetworkType);


/**
 * @brief Gets the interworking access network type for an Access Point.
 *
 * This function retrieves the access network type that is included in the
 * Interworking Information Element (IE) in the beacons transmitted by the
 * specified Access Point (AP).
 * Refer to section 8.4.2.94 of IEEE Std 802.11-2012 for the possible values
 * of the access network type:
 *  - 0: Private network
 *  - 1: Private network with guest access
 *  - 2: Chargeable public network
 *  - 3: Free public network
 *  - 4: Personal device network
 *  - 5: Emergency services only network
 *  - 6-13: Reserved
 *  - 14: Test or experimental
 *  - 15: Wildcard
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[out] output_uint  Pointer to a variable to store the access network type.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getInterworkingAccessNetworkType(INT apIndex, UINT *output_uint);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Interworking Element structure.
 *
 * See 802.11-2016 section 9.4.2.92 for field definitions.
 */
typedef struct
{
    BOOL interworkingEnabled;     /**< Indicates whether interworking is enabled. */
    UINT accessNetworkType;      /**< Access network type. */
    BOOL internetAvailable;      /**< Indicates whether internet access is available. */
    BOOL asra;                   /**< Indicates whether Access Network Query Protocol (ANQP) services are supported. */
    BOOL esr;                   /**< Indicates whether Emergency Services Reaching (ESR) is supported. */
    BOOL uesa;                  /**< Indicates whether Unauthenticated Emergency Service Access (UESA) is supported. */
    BOOL venueOptionPresent;     /**< Indicates whether venue information is present. */
    UCHAR venueGroup;            /**< Venue group. */
    UCHAR venueType;             /**< Venue type. */
    BOOL hessOptionPresent;      /**< Indicates whether Hotspot 2.0 Enhanced Security (HESS) information is present. */
    mac_addr_str_t hessid;       /**< HESSID. Optional; use empty string to indicate no value provided. */
} wifi_InterworkingElement_t;

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Gets the Interworking Service enable status for an Access Point.
 *
 * This function retrieves the enable/disable status of the Interworking Service
 * for the specified Access Point (AP).
 *
 * @param[in] apIndex      Index of the Access Point.
 * @param[out] output_bool Pointer to a variable to store the Interworking Service
 *                         enable status (true for enabled, false for disabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApInterworkingServiceEnable(INT apIndex, BOOL *output_bool);

/**
 * @brief Sets the Interworking Service enable status for an Access Point.
 *
 * This function sets the enable/disable status of the Interworking Service
 * for the specified Access Point (AP).
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[in] input_bool  Value to set the Interworking Service enable status to
 *                        (true for enabled, false for disabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApInterworkingServiceEnable(INT apIndex, BOOL input_bool);

/**
 * @brief Gets the Interworking Element for an Access Point.
 *
 * This function retrieves the Interworking Element that will be sent by the
 * specified Access Point (AP).
 *
 * @param[in] apIndex          Index of the Access Point.
 * @param[out] output_struct  Pointer to a `wifi_InterworkingElement_t` structure
 *                            to store the Interworking Element.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct);

/**
 * @brief Sets the Interworking Element for an Access Point.
 *
 * This function sets the Interworking Element that will be sent by the
 * specified Access Point (AP).
 *
 * @param[in] apIndex        Index of the Access Point.
 * @param[in] infoEelement  Pointer to a `wifi_InterworkingElement_t` structure
 *                          containing the Interworking Element to set.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_pushApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *infoEelement);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Wi-Fi management frame types.
 */
typedef enum
{
    WIFI_MGMT_FRAME_TYPE_INVALID = -1, /**< Invalid management frame type. */
    WIFI_MGMT_FRAME_TYPE_PROBE_REQ = 0, /**< Probe request frame. */
    WIFI_MGMT_FRAME_TYPE_PROBE_RSP = 1, /**< Probe response frame. */
    WIFI_MGMT_FRAME_TYPE_ASSOC_REQ = 2, /**< Association request frame. */
    WIFI_MGMT_FRAME_TYPE_ASSOC_RSP = 3, /**< Association response frame. */
    WIFI_MGMT_FRAME_TYPE_AUTH = 4,     /**< Authentication frame. */
    WIFI_MGMT_FRAME_TYPE_DEAUTH = 5,   /**< Deauthentication frame. */
    WIFI_MGMT_FRAME_TYPE_REASSOC_REQ = 6, /**< Reassociation request frame. */
    WIFI_MGMT_FRAME_TYPE_REASSOC_RSP = 7, /**< Reassociation response frame. */
    WIFI_MGMT_FRAME_TYPE_DISASSOC = 8, /**< Disassociation frame. */
    WIFI_MGMT_FRAME_TYPE_ACTION = 9,   /**< Action frame. */
} wifi_mgmtFrameType_t;

/**
 * @brief Wi-Fi data frame types.
 */
typedef enum
{
    WIFI_DATA_FRAME_TYPE_INVALID = -1, /**< Invalid data frame type. */
    WIFI_DATA_FRAME_TYPE_8021x,      /**< 802.1x data frame. */
} wifi_dataFrameType_t;

/**
 * @brief Wi-Fi frame types.
 */
typedef enum
{
    WIFI_FRAME_TYPE_INVALID = -1, /**< Invalid frame type. */
    WIFI_FRAME_TYPE_MGMT,      /**< Management frame. */
    WIFI_FRAME_TYPE_CTRL,      /**< Control frame. */
    WIFI_FRAME_TYPE_DATA,      /**< Data frame. */
} wifi_frameType_t;

/**
 * @brief Structure representing a Wi-Fi frame.
 */
typedef struct
{
    INT ap_index;               /**< Index of the Access Point. */
    mac_address_t sta_mac;      /**< MAC address of the station. */
    wifi_mgmtFrameType_t type;  /**< Type of the frame. */
    wifi_direction_t dir;       /**< Direction of the frame. */
    INT sig_dbm;                /**< Signal strength in dBm. */
    INT phy_rate;               /**< Physical rate. */
    UCHAR token;                /**< Token. */
    UINT len;                   /**< Length of the data. */
    UCHAR *data;                /**< Pointer to the data. */
} __attribute__((packed)) wifi_frame_t;

/**
 * @brief Callback function invoked when an 802.1x frame is received.
 *
 * @param[in] ap_index Index of the Access Point.
 * @param[in] sta      MAC address of the station.
 * @param[in] type     EAPOL type.
 * @param[in] data     Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 */
typedef void (* wifi_received8021xFrame_callback)(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len);


/**
 * @brief Callback function invoked when an 802.1x frame is sent.
 *
 * @param[in] ap_index Index of the Access Point.
 * @param[in] sta      MAC address of the station.
 * @param[in] type     EAPOL type.
 * @param[in] data     Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 */
typedef void (* wifi_sent8021xFrame_callback)(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len);


/**
 * @brief Callback function invoked when an authentication frame is received.
 *
 * @param[in] ap_index Index of the Access Point.
 * @param[in] sta      MAC address of the station.
 * @param[in] data     Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 */
typedef void (* wifi_receivedAuthFrame_callback)(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);


/**
 * @brief Callback function invoked when an authentication frame is sent.
 *
 * @param[in] ap_index Index of the Access Point.
 * @param[in] sta      MAC address of the station.
 * @param[in] data     Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 */
typedef void (* wifi_sentAuthFrame_callback)(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);


/**
 * @brief Callback function invoked when an association request frame is received.
 *
 * @param[in] ap_index Index of the Access Point.
 * @param[in] sta      MAC address of the station.
 * @param[in] data     Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 */
typedef void (* wifi_receivedAssocReqFrame_callback)(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);


/**
 * @brief Callback function invoked when an association response frame is sent.
 *
 * @param[in] ap_index Index of the Access Point.
 * @param[in] sta      MAC address of the station.
 * @param[in] data     Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 */
typedef void (* wifi_sentAssocRspFrame_callback)(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);


/**
 * @brief Frame hook function type.
 *
 * @param[in] ap_index Index of the Access Point.
 * @param[in] type     Type of the management frame.
 *
 * @returns The status of the operation.
 */
typedef INT (* wifi_hal_frame_hook_fn_t)(INT ap_index, wifi_mgmtFrameType_t type);


#ifdef WIFI_HAL_VERSION_3_PHASE2
/**
 * @brief Callback function invoked when a management frame is received.
 *
 * @param[in] apIndex Index of the Access Point.
 * @param[in] frame   Pointer to the received frame.
 *
 * @returns The status of the operation.
 */
typedef INT (* wifi_receivedMgmtFrame_callback)(INT apIndex, wifi_frame_t *frame);


/**
 * @brief Callback function invoked when a data frame is received.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] sta_mac  MAC address of the station.
 * @param[in] frame    Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 * @param[in] type     Type of the data frame.
 * @param[in] dir      Direction of the data frame.
 *
 * @returns The status of the operation.
 */
typedef INT (* wifi_receivedDataFrame_callback)(INT apIndex, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_dataFrameType_t type, wifi_direction_t dir);
#else
/**
 * @brief Callback function invoked when a management frame is received.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] sta_mac  Pointer to the MAC address of the station.
 * @param[in] frame    Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 * @param[in] type     Type of the management frame.
 * @param[in] dir      Direction of the management frame.
 *
 * @returns The status of the operation.
 */
typedef INT (* wifi_receivedMgmtFrame_callback)(INT apIndex, UCHAR *sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir);


/**
 * @brief Callback function invoked when a data frame is received.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] sta_mac  Pointer to the MAC address of the station.
 * @param[in] frame    Pointer to the frame data.
 * @param[in] len      Length of the frame data.
 * @param[in] type     Type of the data frame.
 * @param[in] dir      Direction of the data frame.
 *
 * @returns The status of the operation.
 */
typedef INT (* wifi_receivedDataFrame_callback)(INT apIndex, UCHAR *sta_mac, UCHAR *frame, UINT len, wifi_dataFrameType_t type, wifi_direction_t dir);
#endif


/**
 * @brief Callback function invoked when CSI data is available.
 *
 * @param[in] mac_addr  MAC address of the station.
 * @param[in] csi_data  Pointer to the CSI data.
 *
 * @returns The status of the operation.
 */
typedef INT(* wifi_csi_callback)(mac_address_t mac_addr, wifi_csi_data_t *csi_data);
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */

/**
 * @brief Registers a callback function for received management frames.
 *
 * This function registers a callback function that will be invoked when a
 * management frame is received.
 *
 * @param mgmtRxCallback Pointer to the callback function to register.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback mgmtRxCallback);

/**
 * @brief Registers a callback function for CSI data.
 *
 * This function registers a callback function that will be invoked when CSI
 * data is available from the HAL. If the CSI engine is disabled, this callback
 * function will not be executed.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param callback_proc Pointer to the callback function to register.
 */
void wifi_csi_callback_register(wifi_csi_callback callback_proc);

/**
 * @brief Registers a frame hook function.
 *
 * This function registers a frame hook function that will be executed when a
 * management frame is received from the HAL. This is used by applications;
 * if an application does not define this hook, it will not be executed.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param hook_fn Pointer to the frame hook function to register.
 */
void wifi_hal_register_frame_hook(wifi_hal_frame_hook_fn_t hook_fn);

/**
 * @brief Enables or disables the CSI engine for a specific station on a VAP.
 *
 * This function enables or disables the CSI engine for a specific station
 * associated with a Virtual Access Point (VAP).
 * If the MAC address is null, the enable argument must be false, otherwise
 * the function must return failure.
 * If the MAC address is null, the data engine for all STAs needs to be disabled
 * on this VAP.
 *
 * @param[in] apIndex  Index of the VAP.
 * @param[in] sta      MAC address of the station.
 * @param[in] enable   Boolean value indicating whether to enable (true) or
 *                     disable (false) the CSI engine.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_enableCSIEngine(INT apIndex, mac_address_t sta, BOOL enable);
/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Ethernet type values.
 */
#define WIFI_ETH_TYPE_IP       0x0800  /**< IPv4 */
#define WIFI_ETH_TYPE_ARP      0x0806  /**< Address Resolution Protocol */
#define WIFI_ETH_TYPE_REVARP   0x8035  /**< Reverse Address Resolution Protocol */
#define WIFI_ETH_TYPE_VLAN     0x8100  /**< VLAN tag */
#define WIFI_ETH_TYPE_LOOPBACK 0x9000  /**< Loopback */
#define WIFI_ETH_TYPE_IP6      0x86DD  /**< IPv6 */
#define WIFI_ETH_TYPE_EAPOL    0x888e  /**< EAP over LAN */

/**
 * @brief Wi-Fi data priority values.
 */
typedef enum
{
    wifi_data_priority_be,  /**< Best effort */
    wifi_data_priority_bk,  /**< Background */
    wifi_data_priority_ee,  /**< Excellent effort */
    wifi_data_priority_ca,  /**< Critical applications */
    wifi_data_priority_vi,  /**< Video */
    wifi_data_priority_vo,  /**< Voice */
    wifi_data_prioirty_ic,  /**< Internetwork control */
    wifi_data_priority_nc   /**< Network control */
} wifi_data_priority_t;
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Sends a data frame to a client associated with a VAP.
 *
 * This function sends a data frame to a client associated with the specified
 * Virtual Access Point (VAP) index. If the MAC address is null, the data
 * should be broadcast on the VAP.
 *
 * @param[in] apIndex      Index of the VAP.
 * @param[in] sta          MAC address of the station.
 * @param[in] data         Pointer to the data buffer. The data does not include
 *                         any Layer 2 information but starts with Layer 3.
 * @param[in] len          Length of the data.
 * @param[in] insert_llc   Whether to insert an LLC header. If set to true, the HAL
 *                         implementation must insert the following bytes before
 *                         the type field: DSAP = 0xaa, SSAP = 0xaa, Control = 0x03,
 *                         followed by 3 bytes each = 0x00.
 * @param[in] eth_proto    Ethernet protocol type.
 * @param[in] prio         Priority of the frame.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_sendDataFrame(INT apIndex,
                       mac_address_t sta,
                       UCHAR *data,
                       UINT len,
                       BOOL insert_llc,
                       UINT eth_proto,
                       wifi_data_priority_t prio);

/**
 * @brief Transmits an action frame to a station from a specific VAP.
 *
 * @param[in] apIndex    Index of the VAP to send the frame from.
 * @param[in] sta        MAC address of the peer device to send the frame to.
 * @param[in] frequency  Frequency of the channel on which this action frame
 *                       should be sent (for public action frames that can be
 *                       sent to a device on an off-channel).
 * @param[in] frame      Pointer to the frame buffer.
 * @param[in] len        Length of the buffer.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_sendActionFrame(INT apIndex,
                         mac_address_t sta,
                         UINT frequency,
                         UCHAR *frame,
                         UINT len);

/**
 * @brief Transmits an action frame to a station from a specific VAP.
 *
 * @param[in] apIndex    Index of the VAP to send the frame from.
 * @param[in] sta        MAC address of the peer device to send the frame to.
 * @param[in] frequency  Frequency of the channel on which this action frame
 *                       should be sent (for public action frames that can be
 *                       sent to a device on an off-channel).
 * @param[in] wait       The time (in milliseconds) to wait on the channel 
 *                       (if off-channel) after sending the action frame before
 *                       returning to the original channel.
 * @param[in] frame      Pointer to the frame buffer.
 * @param[in] len        Length of the buffer.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_sendActionFrameExt(INT apIndex,
                            mac_address_t sta,
                            UINT frequency,
                            UINT wait,
                            UCHAR *frame,
                            UINT len);

/**
 * @brief GAS configuration type.
 */
#define GAS_CFG_TYPE_SUPPORTED 1  /**< Indicates that GAS configuration is supported. */

/**
 * @brief GAS configuration structure.
 *
 * Values correspond to the `dot11GASAdvertisementEntry` field definitions;
 * see 802.11-2016 Annex C.3.
 */
typedef struct _wifi_GASConfiguration_t
{
    UINT AdvertisementID;          /**< Advertisement ID. */
    BOOL PauseForServerResponse;   /**< Whether to pause for server response. */
    UINT ResponseTimeout;          /**< Response timeout in seconds. */
    UINT ComeBackDelay;            /**< Comeback delay in seconds. */
    UINT ResponseBufferingTime;    /**< Response buffering time in seconds. */
    UINT QueryResponseLengthLimit; /**< Query response length limit in bytes. */
} __attribute__((packed)) wifi_GASConfiguration_t;

/**
 * @brief Applies GAS configuration.
 *
 * This function applies the specified GAS configuration.
 *
 * @param[in] input_struct Pointer to the GAS configuration structure.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct);

/* Passpoint R1 related APIs */

/**
 * @brief Sets the country code information element in beacon and probe responses.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enabled  Boolean value indicating whether to include (true) or
 *                    exclude (false) the country code IE.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setCountryIe(INT apIndex, BOOL enabled);

/**
 * @brief Gets the status of the country code information element.
 *
 * This function retrieves the status of the country code information element
 * in beacon and probe responses for the specified Access Point (AP).
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] enabled Pointer to a variable to store the enabled status of
 *                    the country code IE (true if included, false if excluded).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getCountryIe(INT apIndex, BOOL *enabled);

/**
 * @brief Enables or disables Layer 2 traffic inspection and filtering.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enabled  Boolean value indicating whether to enable (true) or
 *                    disable (false) Layer 2 traffic inspection and filtering.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setLayer2TrafficInspectionFiltering(INT apIndex, BOOL enabled);

/**
 * @brief Gets the status of Layer 2 traffic inspection and filtering.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] enabled Pointer to a variable to store the enabled status of
 *                    Layer 2 traffic inspection and filtering (true if enabled,
 *                    false if disabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getLayer2TrafficInspectionFiltering(INT apIndex, BOOL *enabled);

/**
 * @brief Disables the DGAF.
 *
 * When set to true, the DGAF disabled bit should be set in the HS2.0 Indication
 * Information Element in beacon and probe responses.
 *
 * @param[in] apIndex   Index of the Access Point.
 * @param[in] disabled  Boolean value indicating whether to disable (true) or
 *                      enable (false) the DGAF.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setDownStreamGroupAddress(INT apIndex, BOOL disabled);

/**
 * @brief Gets the status of DGAF disable.
 *
 * @param[in] apIndex   Index of the Access Point.
 * @param[out] disabled Pointer to a variable to store the disabled status of
 *                      the DGAF (true if disabled, false if enabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled);

/**
 * @brief Enables or disables the BSS Load Information Element.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enabled  Boolean value indicating whether to include (true) or
 *                    exclude (false) the BSS Load IE in beacon and probe responses.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBssLoad(INT apIndex, BOOL enabled);

/**
 * @brief Gets the status of the BSS Load Information Element.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] enabled Pointer to a variable to store the enabled status of the
 *                    BSS Load IE (true if included, false if excluded).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getBssLoad(INT apIndex, BOOL *enabled);

/**
 * @brief Enables or disables proxy ARP on the device driver.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enabled  Boolean value indicating whether to enable (true) or
 *                    disable (false) proxy ARP.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setProxyArp(INT apIndex, BOOL enabled);

/**
 * @brief Gets the status of proxy ARP from the driver.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] enabled Pointer to a variable to store the enabled status of
 *                    proxy ARP (true if enabled, false if disabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getProxyArp(INT apIndex, BOOL *enabled);

/**
 * @brief Sets the Hotspot 2.0 status for an Access Point.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] enabled  Boolean value indicating whether to enable (true) or
 *                    disable (false) Hotspot 2.0.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_pushApHotspotElement(INT apIndex, BOOL enabled);

/**
 * @brief Gets the Hotspot 2.0 status for an Access Point.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[out] enabled Pointer to a variable to store the enabled status of
 *                    Hotspot 2.0 (true if enabled, false if disabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApHotspotElement(INT apIndex, BOOL *enabled);

/**
 * @brief Sets the Roaming Consortium Information Element contents.
 *
 * This function sets the contents of the Roaming Consortium Information
 * Element that will be included in beacon and probe responses when
 * interworking is enabled and the OI count is greater than 0.
 *
 * @param[in] apIndex       Index of the Access Point.
 * @param[in] infoElement  Pointer to a `wifi_roamingConsortiumElement_t`
 *                         structure containing the OI count, length of the
 *                         first 3 OIs, and the first 3 OIs as a hex string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_pushApRoamingConsortiumElement(INT apIndex, wifi_roamingConsortiumElement_t *infoElement);

/**
 * @brief Gets the Roaming Consortium Information Element contents.
 *
 * This function retrieves the contents of the Roaming Consortium Information
 * Element. If the Roaming Consortium IE is not present, the count will be
 * returned as 0, and the length and OI fields can be ignored.
 *
 * @param[in] apIndex      Index of the Access Point.
 * @param[out] infoElement Pointer to a `wifi_roamingConsortiumElement_t`
 *                         structure to store the OI count, length of the
 *                         first 3 OIs, and the first 3 OIs as a hex string.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApRoamingConsortiumElement(INT apIndex, wifi_roamingConsortiumElement_t *infoElement);

/**
 * @brief Disables or enables P2P cross connect.
 *
 * When set to true, this function includes the P2P Information Element in
 * beacon and probe responses, with the P2P Manageability attribute's
 * "Cross Connection Permitted" field set to 0.
 *
 * @param[in] apIndex   Index of the Access Point.
 * @param[in] disabled  Boolean value indicating whether to disable (true) or
 *                      enable (false) P2P cross connect.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setP2PCrossConnect(INT apIndex, BOOL disabled);

/**
 * @brief Gets the P2P cross connect disabled status.
 *
 * @param[in] apIndex   Index of the Access Point.
 * @param[out] disabled Pointer to a variable to store the disabled status of
 *                      P2P cross connect (true if disabled, false if enabled).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getP2PCrossConnect(INT apIndex, BOOL *disabled);

/**
 * @brief Gets all TWT sessions connected to an Access Point.
 *
 * This function retrieves all Target Wake Time (TWT) sessions, both individual
 * and broadcast, that are connected to the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] ap_index            Index of the Access Point.
 * @param[in] maxNumberSessions   Maximum number of sessions to copy to the list.
 * @param[out] twtSessions        Pointer to an array of `wifi_twt_sessions_t`
 *                                structures to store the session information.
 * @param[out] numSessionReturned Pointer to a variable to store the number of
 *                                sessions copied to the list.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getTWTsessions(INT ap_index, UINT maxNumberSessions, wifi_twt_sessions_t * twtSessions, UINT* numSessionReturned);


/**
 * @brief Creates or updates a broadcast TWT session.
 *
 * This function creates or updates a broadcast Target Wake Time (TWT) session
 * for the specified Access Point (AP).
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] ap_index   Index of the Access Point.
 * @param[in] twtParams  TWT parameters to create or update the session.
 * @param[in] create     Flag indicating whether to create a new session (true)
 *                       or update an existing session (false).
 * @param[in,out] sessionID  Input: When `create` is false and the session exists,
 *                           this is the ID of the session to update.
 *                           Output: When `create` is true, this is the ID of
 *                           the newly created session.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setBroadcastTWTSchedule(INT ap_index, wifi_twt_params_t twtParams, BOOL create, INT* sessionID);


/**
 * @brief Tears down a TWT session.
 *
 * This function tears down the individual or broadcast Target Wake Time (TWT)
 * session associated with the specified Access Point (AP) and session ID.
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] ap_index  Index of the Access Point.
 * @param[in] sessionID TWT session ID to tear down.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setTeardownTWTSession(INT ap_index, INT sessionID);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief Structure for storing multi-PSK keys.
 *
 * This structure is a container for multi-PSK keys.
 * It is based on the `hostapd wpa_psk_file` implementation:
 * https://w1.fi/cgit/hostap/tree/hostapd/hostapd.wpa_psk
 */
typedef struct _wifi_key_multi_psk
{
    CHAR wifi_keyId[64]; /**< Key identifier (e.g., "key-15" or "key_example"). */
    CHAR wifi_psk[64];   /**< PSK (ASCII passphrase of 8 to 63 characters). */
} wifi_key_multi_psk_t;

/**
 * @brief Sets the new set of multi-PSK keys for an Access Point.
 *
 * This function sets a new set of multi-PSK keys for the specified Access Point (AP).
 * Previously set keys are removed.
 * This API is for setting all keys except the primary key, which is set by
 * `wifi_setApSecurityKeyPassphrase`.
 *
 * @param[in] apIndex    Index of the Access Point.
 * @param[in] keys       Array of `wifi_key_multi_psk_t` structures containing the keys.
 * @param[in] keysNumber Number of elements in the `keys` array.
 *
 * @returns The status of the operation
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_pushMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber);


/**
 * @brief Gets all multi-PSK keys for an Access Point.
 *
 * This function retrieves all multi-PSK keys that are active on the specified
 * Access Point (AP), except for the primary key.
 *
 * @param[in] apIndex     Index of the Access Point.
 * @param[out] keys       Pointer to an array of `wifi_key_multi_psk_t` structures
 *                        to store the retrieved keys.
 * @param[in] keysNumber  Number of elements in the `keys` array.
 *
 * @returns The status of the operation
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber);


/**
 * @brief Gets the multi-PSK key for a specific client MAC address.
 *
 * This function retrieves the multi-PSK key used by the client with the specified
 * MAC address to authenticate with the specified Access Point (AP).
 * If `wifi_key_multi_psk_t.wifi_keyID` is null, it means that a multi-PSK
 * key was not used for authentication.
 *
 * @param[in] apIndex  Index of the Access Point.
 * @param[in] mac      Client MAC address.
 * @param[out] key     Pointer to a `wifi_key_multi_psk_t` structure to store
 *                     the retrieved key.
 *
 * @returns The status of the operation
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getMultiPskClientKey(INT apIndex, mac_address_t mac, wifi_key_multi_psk_t *key);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Wi-Fi configuration structure.
 */
typedef struct
{
    wifi_GASConfiguration_t gas_config; /**< GAS configuration. */
} __attribute__((packed)) wifi_config_t;

/**
 * @brief Virtual Access Point (VAP) index type.
 */
typedef UINT wifi_vap_index_t;

/**
 * @brief Wi-Fi onboarding methods.
 */
typedef enum
{
    WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE = 0x0001,    /**< USB flash drive. */
    WIFI_ONBOARDINGMETHODS_ETHERNET = 0x0002,        /**< Ethernet. */
    WIFI_ONBOARDINGMETHODS_LABEL = 0x0004,          /**< Label. */
    WIFI_ONBOARDINGMETHODS_DISPLAY = 0x0008,         /**< Display. */
    WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN = 0x0010, /**< External NFC token. */
    WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN = 0x0020, /**< Integrated NFC token. */
    WIFI_ONBOARDINGMETHODS_NFCINTERFACE = 0x0040,    /**< NFC interface. */
    WIFI_ONBOARDINGMETHODS_PUSHBUTTON = 0x0080,      /**< Push button. */
    WIFI_ONBOARDINGMETHODS_PIN = 0x0100,            /**< PIN. */
    WIFI_ONBOARDINGMETHODS_PHYSICALPUSHBUTTON = 0x0200, /**< Physical push button. */
    WIFI_ONBOARDINGMETHODS_PHYSICALDISPLAY = 0x0400,  /**< Physical display. */
    WIFI_ONBOARDINGMETHODS_VIRTUALPUSHBUTTON = 0x0800, /**< Virtual push button. */
    WIFI_ONBOARDINGMETHODS_VIRTUALDISPLAY = 0x1000,   /**< Virtual display. */
    WIFI_ONBOARDINGMETHODS_EASYCONNECT = 0x2000,     /**< Easy Connect. */
} wifi_onboarding_methods_t;

/**
 * @brief Maximum length of a WPS PIN.
 */
#define WIFI_AP_MAX_WPSPIN_LEN 9

/**
 * @brief Wi-Fi Protected Setup (WPS) settings.
 */
typedef struct
{
    BOOL enable;                    /**< Whether WPS is enabled. */
    wifi_onboarding_methods_t methods; /**< Onboarding methods supported by WPS. */
    CHAR pin[WIFI_AP_MAX_WPSPIN_LEN]; /**< WPS PIN. */
} __attribute__((packed)) wifi_wps_t;

/**
 * @brief Management Frame Protection (MFP) configuration options.
 */
typedef enum
{
    wifi_mfp_cfg_disabled, /**< MFP disabled. */
    wifi_mfp_cfg_optional, /**< MFP optional. */
    wifi_mfp_cfg_required, /**< MFP required. */
} wifi_mfp_cfg_t;

/**
 * @brief MAC filter modes.
 */
typedef enum
{
    wifi_mac_filter_mode_black_list, /**< Blacklist mode. */
    wifi_mac_filter_mode_white_list, /**< Whitelist mode. */
} wifi_mac_filter_mode_t;

/**
 * @brief RADIUS settings.
 */
typedef struct
{
#ifdef WIFI_HAL_VERSION_3_PHASE2
    ip_addr_t ip;              /**< Primary RADIUS server IP address. */
#else
    unsigned char ip[45];      /**< Primary RADIUS server IP address. */
#endif
    unsigned short port;        /**< Primary RADIUS server port. */
    char key[64];             /**< Primary RADIUS server secret. */
    char identity[64];        /**< Primary RADIUS server identity. */
#ifdef WIFI_HAL_VERSION_3_PHASE2
    ip_addr_t s_ip;              /**< Secondary RADIUS server IP address. */
    ip_addr_t connectedendpoint; /**< The RADIUS server IP address which is currently in use. */
#else
    unsigned char s_ip[45];     /**< Secondary RADIUS server IP address. */
    unsigned char connectedendpoint[45]; /**< The RADIUS server IP address which is currently in use. */
#endif
    unsigned short s_port;      /**< Secondary RADIUS server port. */
    char s_key[64];           /**< Secondary RADIUS server secret. */
    ip_addr_t dasip;           /**< RADIUS DAS server IP address. */
    USHORT dasport;            /**< RADIUS DAS server port. */
    char daskey[64];          /**< RADIUS DAS server secret. */
    UINT max_auth_attempts;    /**< Maximum number of authentication attempts. */
    UINT blacklist_table_timeout; /**< Blacklist table timeout in seconds. */
    UINT identity_req_retry_interval; /**< Identity request retry interval in seconds. */
    UINT server_retries;        /**< Number of RADIUS server retries. */
    wifi_eap_t eap_type;       /**< EAP type. */
    phase2_type phase2;        /**< Enterprise based eap type */
} __attribute__((packed)) wifi_radius_settings_t;

/**
 * @brief Security key types.
 */
typedef enum
{
    wifi_security_key_type_psk,        /**< Pre-shared key. */
    wifi_security_key_type_pass,       /**< Passphrase. */
    wifi_security_key_type_sae,        /**< Simultaneous Authentication of Equals. */
    wifi_security_key_type_psk_sae,     /**< Pre-shared key with SAE. */
    wifi_security_key_type_saeext,     /**< Extended SAE. */
    wifi_security_key_type_sae_saeext,  /**< SAE with extended SAE. */
    wifi_security_key_type_psk_sae_saeext /**< Pre-shared key with SAE and extended SAE. */
} wifi_security_key_type_t;

/**
 * @brief Security key structure.
 */
typedef struct
{
    wifi_security_key_type_t type; /**< Type of the security key. */
    char key[256];              /**< Security key data. */
} __attribute__((packed)) wifi_security_key_t;

/**
 * @brief VAP security settings.
 */
typedef struct
{
    wifi_security_modes_t mode;     /**< Security mode. */
    wifi_encryption_method_t encr;   /**< Encryption method. */
#if defined(WIFI_HAL_VERSION_3)
    wifi_mfp_cfg_t mfp;            /**< MFP configuration. */
#else
    char mfpConfig[32];           /**< MFP configuration. */
#endif
    BOOL wpa3_transition_disable; /**< Whether WPA3 transition is disabled. */
    UINT rekey_interval;         /**< Rekey interval in seconds. */
    BOOL strict_rekey;           /**< Whether strict rekey is enabled. */
    UINT eapol_key_timeout;      /**< EAPOL key timeout in seconds. */
    UINT eapol_key_retries;      /**< Number of EAPOL key retries. */
    UINT eap_identity_req_timeout; /**< EAP identity request timeout in seconds. */
    UINT eap_identity_req_retries; /**< Number of EAP identity request retries. */
    UINT eap_req_timeout;        /**< EAP request timeout in seconds. */
    UINT eap_req_retries;        /**< Number of EAP request retries. */
    BOOL disable_pmksa_caching;   /**< Whether PMKSA caching is disabled. */
    char key_id[32];            /**< OpenFlow tag associated with a PSK. */
    union
    {
        wifi_radius_settings_t radius; /**< RADIUS settings. */
        wifi_security_key_t key;      /**< Security key. */
    } u;
} __attribute__((packed)) wifi_vap_security_t;

/**
 * @brief ANQP settings.
 */
typedef struct
{
    int capabilityInfoLength;       /**< Length of the capability information. */
    wifi_capabilityListANQP_t capabilityInfo; /**< Capability information. */
    int venueInfoLength;           /**< Length of the venue information. */
    wifi_venueNameElement_t venueInfo; /**< Venue information. */
    int roamInfoLength;            /**< Length of the roaming consortium information. */
    wifi_roamingConsortium_t roamInfo; /**< Roaming consortium information. */
    wifi_ipAddressAvailabality_t ipAddressInfo; /**< IP address availability information. */
    int realmInfoLength;           /**< Length of the NAI realm information. */
    wifi_naiRealmElement_t realmInfo; /**< NAI realm information. */
    int gppInfoLength;             /**< Length of the 3GPP cellular network information. */
    wifi_3gppCellularNetwork_t gppInfo; /**< 3GPP cellular network information. */
    int domainInfoLength;          /**< Length of the domain name information. */
    wifi_domainName_t domainNameInfo; /**< Domain name information. */
    UCHAR passpointStats[1024];    /**< Passpoint statistics. */
    UINT domainRespCount;         /**< Number of successful domain name responses. */
    UINT realmRespCount;          /**< Number of successful NAI realm responses. */
    UINT gppRespCount;            /**< Number of successful 3GPP cellular network responses. */
    UINT domainFailedCount;        /**< Number of failed domain name responses. */
    UINT realmFailedCount;         /**< Number of failed NAI realm responses. */
    UINT gppFailedCount;           /**< Number of failed 3GPP cellular network responses. */
    UCHAR anqpParameters[4096];     /**< ANQP parameters. */
} __attribute__((packed)) wifi_anqp_settings_t;

/**
 * @brief Passpoint settings.
 */
typedef struct
{
    BOOL enable;                 /**< Whether Passpoint is enabled. */
    BOOL gafDisable;              /**< Whether DGAF is disabled. */
    BOOL p2pDisable;              /**< Whether P2P cross connect is disabled. */
    BOOL l2tif;                  /**< Whether Layer 2 Traffic Inspection and Filtering is enabled. */
    BOOL bssLoad;                 /**< Whether BSS Load IE is enabled. */
    BOOL countryIE;               /**< Whether Country IE is enabled. */
    BOOL proxyArp;                /**< Whether proxy ARP is enabled. */
/* vvvv **The following fields should not to be implemented in the HAL** vvvv */
    int capabilityInfoLength;    /**< Length of the capability information. */
    wifi_HS2_CapabilityList_t capabilityInfo; /**< Capability information. */
    int opFriendlyNameInfoLength; /**< Length of the operator friendly name information. */
    wifi_HS2_OperatorFriendlyName_t opFriendlyNameInfo; /**< Operator friendly name information. */
    int connCapabilityLength;    /**< Length of the connection capability information. */
    wifi_HS2_ConnectionCapability_t connCapabilityInfo; /**< Connection capability information. */
    int realmInfoLength;          /**< Length of the NAI home realm query information. */
    wifi_HS2_NAI_Home_Realm_Query_t realmInfo; /**< NAI home realm query information. */
    wifi_HS2_WANMetrics_t wanMetricsInfo; /**< WAN metrics information. */
    UCHAR hs2Parameters[4096];     /**< HS2 parameters. */
/* ^^^^ Not implemented in the hal ^^^^ */
} __attribute__((packed)) wifi_passpoint_settings_t;

/**
 * @brief Interworking settings.
 */
typedef struct
{
    wifi_InterworkingElement_t interworking; /**< Interworking element. */
    wifi_roamingConsortiumElement_t roamingConsortium; /**< Roaming consortium element. */
    wifi_anqp_settings_t anqp;        /**< ANQP settings. >>*should not to be implemented in the HAL**<< */
    wifi_passpoint_settings_t passpoint; /**< Passpoint settings. */
} __attribute__((packed)) wifi_interworking_t;

/**
 * @brief Pre-association control settings.
 */
typedef struct
{
    char rssi_up_threshold[32];           /**< RSSI up threshold. */
    char snr_threshold[32];              /**< SNR threshold. */
    char cu_threshold[32];               /**< CU threshold. */
    char basic_data_transmit_rates[32];  /**< Basic data transmit rates. */
    char operational_data_transmit_rates[32]; /**< Operational data transmit rates. */
    char supported_data_transmit_rates[32]; /**< Supported data transmit rates. */
    char minimum_advertised_mcs[32];     /**< Minimum advertised MCS. */
    char sixGOpInfoMinRate[32];          /**< 6G operating information minimum rate. */
    char client_deny_assoc_info[45];     /**< Client deny association information. */
    int  time_ms;                        /**< Time to wait for meeting minimum mgmt frames for TCM threshold calcultion */
    int  min_num_mgmt_frames;            /**< Minimum number of mgmt frames required to compute the TCM threshold. */
    char tcm_exp_weightage[32];          /**< Alpha/Exponential weight used in the Exponential Moving Average formula. */
    char tcm_gradient_threshold[32];     /**< Threshold against which TCM Exponential Moving Average is computed. */
    char tcm_client_deny_assoc_info[64]; /**< Transient Client Management deny/assoc information. */
    wifi_vap_name_t vap_name;            /**< VAP name. */
} __attribute__((packed)) wifi_preassoc_control_t;

/**
 * @brief Post-association control settings.
 */
typedef struct
{
    char sampling_interval[32];          /**< Sampling interval. */
    char sampling_count[32];             /**< Sampling count. */
    char rssi_up_threshold[32];           /**< RSSI up threshold. */
    char snr_threshold[32];              /**< SNR threshold. */
    char cu_threshold[32];               /**< CU threshold. */
    char client_force_disassoc_info[45]; /**< Client force disassociation information. */
    wifi_vap_name_t vap_name;            /**< VAP name. */
} __attribute__((packed)) wifi_postassoc_control_t;

/**
 * @brief VAP modes.
 */
typedef enum
{
    wifi_vap_mode_ap,      /**< Access Point mode. */
    wifi_vap_mode_sta,     /**< Station mode. */
    wifi_vap_mode_monitor, /**< Monitor mode. */
} wifi_vap_mode_t;

/**
 * @brief Scan parameters.
 */
typedef struct
{
    unsigned int period;   /**< Scan period in seconds. */
    wifi_channel_t channel; /**< Channel to scan (0 means scan all channels in the band). */
} __attribute__((packed)) wifi_scan_params_t;

/**
 * @brief Common MLD information.
 */
typedef struct
{
    BOOL mld_enable;      /**< Whether MLD snooping is enabled. */
    UINT mld_id;          /**< MLD group ID. */
    UINT mld_link_id;     /**< Link ID */
    mac_address_t mld_addr; /**< MLD group MAC address. */
    BOOL mld_apply;       /**< MLD configuration apply indication */
} __attribute__((packed)) wifi_mld_common_info_t;

/**
 * @brief MLD information for a station.
 */
typedef struct
{
    mac_address_t local_addr; /**< Local MAC address. */
    mac_address_t peer_addr;  /**< Peer MAC address. */
    wifi_mld_common_info_t common_info; /**< Common MLD information. */
} __attribute__((packed)) wifi_mld_info_sta_t;

/**
 * @brief MLD information for an Access Point.
 */
typedef struct
{
    wifi_mld_common_info_t common_info; /**< Common MLD information. */
} __attribute__((packed)) wifi_mld_info_ap_t;

/**
 * @brief Backhaul station information.
 */
typedef struct
{
    ssid_t ssid;             /**< SSID. */
    bssid_t bssid;            /**< BSSID (if all 0, scan the SSID with probes, otherwise connect to the specified BSSID). */
    BOOL enabled;            /**< Whether the backhaul station is enabled. */
    wifi_connection_status_t conn_status; /**< Connection status. */
    wifi_scan_params_t scan_params; /**< Scan parameters. */
    wifi_vap_security_t security; /**< Security settings. */
    mac_address_t mac;        /**< MAC address. */
    wifi_mld_info_sta_t mld_info; /**< MLD information. */
} __attribute__((packed)) wifi_back_haul_sta_t;

/**
 * @brief Maximum length of an SSID.
 */
#define WIFI_AP_MAX_SSID_LEN 33

/**
 * @brief Maximum length of the vendor information elements buffer
 *
 * Not a standard value, but a reasonable maximum for vendor elements 
 * Computed by taking Max MPDU size - ~ MAX 802.11 header size - 802.11 FCS size - ~Size of required IEs
 * 2,310 is divisible by the typical Vendor IE size (7 = IE Type[1] + IE Length[1] + OUI[3] + VIE Type[1] + VIE Subtype [1])
 */
#define WIFI_AP_MAX_VENDOR_IE_LEN 2310

/**
 * @brief Fronthaul BSS information.
 *
 * This structure contains information about a fronthaul BSS.
 */
typedef struct {
  CHAR ssid[WIFI_AP_MAX_SSID_LEN]; /**< SSID. */
  BOOL enabled;                  /**< Whether the BSS is enabled. */
  BOOL showSsid;                 /**< Whether to show the SSID. */
  BOOL isolation;                /**< Whether client isolation is enabled. */
  INT mgmtPowerControl;          /**< Management frame power control. */
  UINT bssMaxSta;               /**< Maximum number of stations allowed. */
  BOOL bssTransitionActivated;    /**< Whether BSS transition is activated. */
  BOOL nbrReportActivated;       /**< Whether neighbor report is activated. */

  BOOL rapidReconnectEnable; /**< Whether rapid reconnect is enabled. This field should not be implemented in the HAL. */
  UINT rapidReconnThreshold; /**< Rapid reconnect threshold. This field should not be implemented in the HAL. */
  BOOL vapStatsEnable;      /**< Whether VAP statistics are enabled. This field should not be implemented in the HAL. */

  wifi_vap_security_t security;    /**< Security settings. */
  wifi_interworking_t interworking; /**< Interworking settings. */
  wifi_preassoc_control_t preassoc;  /**< Pre-association control settings. */
  wifi_postassoc_control_t postassoc; /**< Post-association control settings. */
  BOOL mac_filter_enable;           /**< Whether MAC filtering is enabled. */
  wifi_mac_filter_mode_t mac_filter_mode; /**< MAC filter mode. */

  BOOL sec_changed; /**< Whether security settings have changed. This field should not be implemented in the HAL. */

  wifi_wps_t wps;        /**< WPS settings. */
  BOOL wmm_enabled;     /**< Whether WMM is enabled. */
  BOOL UAPSDEnabled;    /**< Whether U-APSD is enabled. */
  wifi_bitrate_t beaconRate; /**< Beacon rate. */
  mac_address_t bssid;    /**< The BSSID. This variable should only be used in the get API. It can't be used to change the interface MAC. */
  UINT wmmNoAck;         /**< WMM no-acknowledgement settings. */
  UINT wepKeyLength;     /**< WEP key length. */
  BOOL bssHotspot;       /**< Whether the BSS is a hotspot. */
  UINT wpsPushButton;    /**< WPS push button configuration. */
  char beaconRateCtl[32]; /**< Beacon rate control string. */
  BOOL network_initiated_greylist; /**< Whether network-initiated greylisting is enabled. */
  BOOL mcast2ucast;              /**< Whether multicast-to-unicast conversion is enabled. */
  BOOL connected_building_enabled; /**< Whether connected building is enabled. */
  wifi_mld_info_ap_t mld_info;        /**< MLD information. */
  BOOL hostap_mgt_frame_ctrl;        /**< Whether hostapd management frame control is enabled. */
  BOOL mbo_enabled;                  /**< Whether MBO is enabled. */
  UCHAR vendor_elements[WIFI_AP_MAX_VENDOR_IE_LEN]; /**< The vendor elements to be added to beacon/probe response frames. Includes IE ID (0xDD), Length, and Payload */
  USHORT vendor_elements_len;        /**< Length of vendor_elements currently stored since it is not null terminated */
} __attribute__((packed)) wifi_front_haul_bss_t;

/**
 * @brief Maximum length of a bridge name.
 */
#define WIFI_BRIDGE_NAME_LEN 32

/**
 * @brief VAP information structure.
 */
typedef struct
{
    wifi_vap_index_t vap_index;     /**< VAP index. */
    wifi_vap_name_t vap_name;      /**< VAP name. */
    wifi_radio_index_t radio_index; /**< Radio index. */
    CHAR bridge_name[WIFI_BRIDGE_NAME_LEN]; /**< Bridge name. */
    wifi_vap_mode_t vap_mode;      /**< VAP mode. */
    wifi_vap_name_t repurposed_vap_name; /**< Repurposed VAP name. */
    union
    {
        wifi_front_haul_bss_t bss_info; /**< Fronthaul BSS information. */
        wifi_back_haul_sta_t sta_info; /**< Backhaul station information. */
    } u;
} __attribute__((packed)) wifi_vap_info_t;

/**
 * @brief VAP information map structure.
 */
typedef struct
{
    unsigned int num_vaps;       /**< Number of VAPs. */
    wifi_vap_info_t vap_array[MAX_NUM_VAP_PER_RADIO]; /**< Array of VAP information structures. */
} __attribute__((packed)) wifi_vap_info_map_t;

/**
 * @brief Wi-Fi AP capabilities.
 */
typedef struct
{
    BOOL rtsThresholdSupported; /**< Whether RTS/CTS threshold is supported. */
    wifi_security_modes_t securityModesSupported; /**< Supported security modes. */
    wifi_onboarding_methods_t methodsSupported; /**< Supported onboarding methods. */
    BOOL WMMSupported; /**< Whether WMM is supported. */
    BOOL UAPSDSupported; /**< Whether U-APSD is supported. */
    BOOL interworkingServiceSupported; /**< Whether interworking service is supported. */
    BOOL BSSTransitionImplemented; /**< Whether BSS transition is implemented. */
} __attribute__((packed)) wifi_ap_capabilities_t;
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Creates a VAP on a radio.
 *
 * @param[in] index Index of the radio.
 * @param[in] map   Pointer to a `wifi_vap_info_map_t` structure containing
 *                  information about the VAPs to create.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map);

/**
 * @brief Gets the VAP information map for a radio.
 *
 * @param[in] index Index of the radio.
 * @param[out] map  Pointer to a `wifi_vap_info_map_t` structure to store the
 *                  VAP information map.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map);

/**
 * @brief Sets the security settings for an Access Point.
 *
 * @param[in] ap_index  Index of the Access Point.
 * @param[in] security  Pointer to a `wifi_vap_security_t` structure containing
 *                      the security settings to apply.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApSecurity(INT ap_index, wifi_vap_security_t *security);

/**
 * @brief Gets the security settings for an Access Point.
 *
 * @param[in] ap_index  Index of the Access Point.
 * @param[out] security Pointer to a `wifi_vap_security_t` structure to store
 *                      the security settings.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApSecurity(INT ap_index, wifi_vap_security_t *security);

/**
 * @brief Gets the capabilities of an Access Point.
 *
 * @param[in] ap_index      Index of the Access Point.
 * @param[out] apCapabilities Pointer to a `wifi_ap_capabilities_t` structure to
 *                            store the AP capabilities.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getAPCapabilities(INT ap_index, wifi_ap_capabilities_t *apCapabilities);

/**
 * @brief Gets the WPS configuration for an Access Point.
 *
 * @param[in] ap_index  Index of the Access Point.
 * @param[out] wpsConfig Pointer to a `wifi_wps_t` structure to store the WPS
 *                       configuration.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getApWpsConfiguration(INT ap_index, wifi_wps_t* wpsConfig);

/**
 * @brief Sets the WPS configuration for an Access Point.
 *
 * @param[in] ap_index  Index of the Access Point.
 * @param[in] wpsConfig Pointer to a `wifi_wps_t` structure containing the WPS
 *                       configuration to apply.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setApWpsConfiguration(INT ap_index, wifi_wps_t* wpsConfig);

/**
 * @brief Checks whether libhostapd is used.
 *
 * @param[out] output_bool Pointer to a variable to store the result (true if
 *                         libhostapd is used, false otherwise).
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_getLibhostapd(BOOL *output_bool);

/**
 * @brief Updates the libhostapd configuration for an Access Point.
 *
 * @param[in] apIndex Index of the Access Point.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_updateLibHostApdConfig(int apIndex);

/**
 * @brief VAP status values.
 */
typedef enum
{
    wifi_vapstatus_down, /**< VAP is down. */
    wifi_vapstatus_up   /**< VAP is up. */
} wifi_vapstatus_t;

/**
 * @brief Callback function invoked when VAP status changes.
 *
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] apIndex Index of the VAP.
 * @param[in] status  Status of the VAP.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
typedef INT(* wifi_vapstatus_callback)(INT apIndex, wifi_vapstatus_t status);

/**
 * @brief Registers a callback function for VAP status changes.
 *
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] callback Pointer to the callback function to register.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_vapstatus_callback_register(wifi_vapstatus_callback callback);

/**
 * @brief Callback function invoked for logging catastrophic failures.
 *
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] fmt Format string for the log message.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
typedef INT(* wifi_analytics_callback)(CHAR *fmt, ...);

/**
 * @brief Registers a callback function for logging catastrophic failures.
 *
 * This function must not suspend and must not invoke any blocking system calls.
 *
 * @param[in] callback Pointer to the callback function to register.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_hal_analytics_callback_register(wifi_analytics_callback callback);

/** @} */  //END OF GROUP WIFI_HAL_APIS

#ifdef __cplusplus
}
#endif

#endif
