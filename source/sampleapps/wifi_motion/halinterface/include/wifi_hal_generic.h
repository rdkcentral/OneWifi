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
    Notes:

    What is new for 3.0.6

      1. Added new security types wifi_security_key_type_saeext, wifi_security_key_type_sae_saeext
         and wifi_security_key_type_psk_sae_saeext to wifi_security_key_type_t structure in
         wifi_hal_ap.h and wifi_encryption_aes_gcmp256 and wifi_encryption_gcmp256 to
         wifi_encryption_method_t structure in wifi_hal_generic.h file.

    What is new for 3.0.5

      1. Added new variables cli_MLDEnable and cli_MLDAddr to wifi_associated_dev3_t structure
         and added new structures wifi_multi_link_info_t, wifi_multi_link_modes_t and modified
         wifi_multi_link_bands_t to include 5GL and 5GH radios in wifi_hal_generic.h file for wifi7.

    What is new for 3.0.4

      1. Added new structure wifi_radioTemperature_t and hal wifi_hal_getRadioTemperature
         in wifi_hal_radio.h file

    What is new for 3.0.3

      1. Added new structures wifi_mld_common_info_t, wifi_mld_info_sta_t, wifi_mld_info_ap_t
         in wifi_hal_ap.h, wifi_radio_11be_puncturing_info_t in wifi_hal_radio.h and
         wifi_multi_link_bands_t in wifi_hal_generic.h file also WIFI_CHANNELBANDWIDTH_320MHZ
         to structure wifi_channelBandwidth_t and WIFI_80211_VARIANT_BE to structure
         wifi_ieee80211Variant_t in wifi_hal_generic.h file to support WiFi 7 functionality.

    What is new for 3.0.2

      1. Added cli_TxFrames, cli_RxRetries, cli_RxErrors field to wifi_associated_dev3_t
         structure in wifi_hal_generic.h file

    What is new for 3.0.1

      1. Added cli_activeNumSpatialStreams field to wifi_associated_dev3_t structure
         in wifi_hal_generic.h file
      2. Added cli_CapableNumSpatialStreams field to wifi_associated_dev_t structure
         in wifi_hal_ap.h file


**********************************************************************/

#ifndef __WIFI_HAL_GENERIC_H__
#define __WIFI_HAL_GENERIC_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
#ifndef ULLONG
#define ULLONG unsigned long long  /**< Unsigned long long type. */
#endif

#ifndef ULONG
#define ULONG unsigned long    /**< Unsigned long type. */
#endif

#ifndef USHORT
#define USHORT unsigned short   /**< Unsigned short type. */
#endif

#ifndef BOOL
#define BOOL unsigned char     /**< Boolean type. */
#endif

#ifndef CHAR
#define CHAR char          /**< Character type. */
#endif

#ifndef UCHAR
#define UCHAR unsigned char    /**< Unsigned character type. */
#endif

#ifndef INT
#define INT int            /**< Integer type. */
#endif

#ifndef UINT
#define UINT unsigned int       /**< Unsigned integer type. */
#endif

#ifndef SHORT
#define SHORT signed short       /**< Unsigned integer type. */
#endif

#ifndef TRUE
#define TRUE 1          /**< Boolean true value. */
#endif

#ifndef FALSE
#define FALSE 0         /**< Boolean false value. */
#endif

#ifndef ENABLE
#define ENABLE 1         /**< Enable value. */
#endif

#ifndef RETURN_OK
#define RETURN_OK 0        /**< Return value indicating success. */
#endif

#ifndef RETURN_ERR
#define RETURN_ERR -1       /**< Return value indicating an error. */
#endif

#define WIFI_HAL_SUCCESS            0  /**< Wi-Fi HAL success status code. */
#define WIFI_HAL_ERROR             -1  /**< Wi-Fi HAL generic error status code. */
#define WIFI_HAL_INTERNAL_ERROR    -2  /**< Wi-Fi HAL internal error status code. */
#define WIFI_HAL_UNSUPPORTED       -3  /**< Wi-Fi HAL unsupported operation status code. */
#define WIFI_HAL_INVALID_ARGUMENTS -4  /**< Wi-Fi HAL invalid arguments status code. */
#define WIFI_HAL_INVALID_VALUE     -5  /**< Wi-Fi HAL invalid value status code. */
#define WIFI_HAL_NOT_READY         -6  /**< Wi-Fi HAL not ready status code. */

#ifndef RADIO_INDEX_1
#define RADIO_INDEX_1 1  /**< Radio index 1. */
#define RADIO_INDEX_2 2  /**< Radio index 2. */
#define RADIO_INDEX_3 3  /**< Radio index 3. */

#define AP_INDEX_1 1    /**< Access Point index 1. */
#define AP_INDEX_2 2    /**< Access Point index 2. */
#define AP_INDEX_3 3    /**< Access Point index 3. */
#define AP_INDEX_4 4    /**< Access Point index 4. */
#define AP_INDEX_5 5    /**< Access Point index 5. */
#define AP_INDEX_6 6    /**< Access Point index 6. */
#define AP_INDEX_7 7    /**< Access Point index 7. */
#define AP_INDEX_8 8    /**< Access Point index 8. */
#define AP_INDEX_9 9    /**< Access Point index 9. */
#define AP_INDEX_10 10   /**< Access Point index 10. */
#define AP_INDEX_11 11   /**< Access Point index 11. */
#define AP_INDEX_12 12   /**< Access Point index 12. */
#define AP_INDEX_13 13   /**< Access Point index 13. */
#define AP_INDEX_14 14   /**< Access Point index 14. */
#define AP_INDEX_15 15   /**< Access Point index 15. */
#define AP_INDEX_16 16   /**< Access Point index 16. */
#define AP_INDEX_17 17   /**< Access Point index 17. */
#define AP_INDEX_18 18   /**< Access Point index 18. */
#define AP_INDEX_19 19   /**< Access Point index 19. */
#define AP_INDEX_20 20   /**< Access Point index 20. */
#define AP_INDEX_21 21   /**< Access Point index 21. */
#define AP_INDEX_22 22   /**< Access Point index 22. */
#define AP_INDEX_23 23   /**< Access Point index 23. */
#define AP_INDEX_24 24   /**< Access Point index 24. */
#endif

#ifdef WIFI_HAL_VERSION_3
#define MAX_NUM_RADIOS 3  /**< Maximum number of radios. */
#else
#define MAX_NUM_RADIOS 2  /**< Maximum number of radios. */
#endif

#define MAX_NUM_VAP_PER_RADIO 8  /**< Maximum number of VAPs per radio. */

#define MAC_STR_LEN 18  /**< Length of a MAC address string. */

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6  /**< Length of an Ethernet address. */
#endif /* ETHER_ADDR_LEN */

#define ACL_MACADDR_SIZE 18  /**< Size of an ACL MAC address. */
#define ACL_MACFLT_NUM 16    /**< Number of ACL MAC filters. */
#define MAC_LIST_SIZE ((ACL_MACADDR_SIZE * WL_MACADDR_SIZE) + 2)  /**< Size of a MAC list. */
#define ACL_MAC_ARRAY_MAX 512    /**< Maximum size of an ACL MAC array. */
#define ASSOC_MAC_ARRAY_MAX 1024 /**< Maximum size of an associated MAC array. */
#define SUPPORTED_STANDARDS_RADIO2_4GHZ "b,g,n"  /**< Supported standards for 2.4GHz radio. */
#define SUPPORTED_STANDARDS_RADIO5GHZ "a,n,ac"  /**< Supported standards for 5GHz radio. */
#define RESTORE_CNFG_FILE_NAME "/data/.nvram_restore_cfg.txt"  /**< Restore configuration file name. */
#define NVRAM_LINE_MAX (1024)  /**< Maximum length of an NVRAM line. */

// Defines for HAL version 3.0.6
#define WIFI_HAL_MAJOR_VERSION 3        /**< Wi-Fi HAL major version. */
#define WIFI_HAL_MINOR_VERSION 0        /**< Wi-Fi HAL minor version. */
#define WIFI_HAL_MAINTENANCE_VERSION 6  /**< Wi-Fi HAL maintenance version. */

#define WIFI_HAL_VERSION \
    (WIFI_HAL_MAJOR_VERSION * 1000 + WIFI_HAL_MINOR_VERSION * 10 + WIFI_HAL_MAINTENANCE_VERSION) /**< Wi-Fi HAL version. */

#define MAX_NUM_TWT_SESSION 50    /**< Maximum number of TWT sessions. */
#define MAX_STA_PER_SESSION 100   /**< Maximum number of stations per TWT session. */
#define MAX_BSR 32            /**< Maximum BSR. */
#define MAX_RU_ALLOCATIONS 74   /**< Maximum RU allocations. */

#define CONN_NEW 1 /**< Mode 1: When a client connect or associate message is received by the AP, then the WiFi HAL layer must invoke `wifi_apAssociatedDevice_callback` with `event_type`: `CONN_NEW`. */
#define CONN_RENEW 2 /**< Mode 2: If the AP status for a client is connected or associated and the AP receives a client connect or associate message from this client, `wifi_apAssociatedDevice_callback` needs to be invoked from the HAL layer to notify RDKB with `event_type`: `CONN_RENEW`. */
#define CONN_RECONN_AFTER_INACTIVITY 3 /**< Mode 3: If the AP changes a client's status to "disconnected" due to the AP's client inactivity timeout (RDKB could read this timeout from `wifi_getRadioClientInactivityTimout`) and then the client re-connects or associates back to the same AP, then the WiFi HAL layer must invoke a `wifi_apAssociatedDevice_callback` with `event_type`: `CONN_RECONN_AFTER_INACTIVITY`. */

#define KI1_VER_MASK 0xf8 /**< Key Information 1 (KI1) version mask. */
#define KI1_PW_KEY 0x08 /**< KI1 pairwise key bit. */
#define KI1_INSTALL 0x40 /**< KI1 install bit. */
#define KI1_ACK 0x80 /**< KI1 acknowledgement bit. */
#define KI1_MSG1_BITS (KI1_PW_KEY | KI1_ACK) /**< KI1 bits for message 1. */
#define KI1_MSG3_BITS (KI1_PW_KEY | KI1_INSTALL | KI1_ACK) /**< KI1 bits for message 3. */
#define KI0_MIC 0x01 /**< Key Information 0 (KI0) MIC bit. */
#define KI0_SECURE 0x02 /**< KI0 secure bit. */
#define KI0_ENCR 0x10 /**< KI0 encryption bit. */
#define KI0_MSG3_BITS (KI0_MIC | KI0_SECURE | KI0_ENCR) /**< KI0 bits for message 3. */
#define KI0_MSG4_BITS (KI0_MIC | KI0_SECURE) /**< KI0 bits for message 4. */

#define KEY_MSG_1_OF_4(msg) \
    ((((msg)->key_info[1] & KI1_VER_MASK) == KI1_MSG1_BITS) && ((msg)->key_info[0] == 0)) /**< Checks if a key message is message 1 of 4. */

#define KEY_MSG_2_OF_4(msg) \
    ((((msg)->key_info[1] & KI1_VER_MASK) == KI1_PW_KEY) && ((msg)->key_info[0] == KI0_MIC)) /**< Checks if a key message is message 2 of 4. */

#define KEY_MSG_3_OF_4(msg) \
    ((((msg)->key_info[1] & KI1_VER_MASK) == KI1_MSG3_BITS) && ((msg)->key_info[0] == KI0_MSG3_BITS)) /**< Checks if a key message is message 3 of 4. */

#define KEY_MSG_4_OF_4(msg) \
    ((((msg)->key_info[1] & KI1_VER_MASK) == KI1_PW_KEY) && ((msg)->key_info[0] == KI0_MSG4_BITS)) /**< Checks if a key message is message 4 of 4. */

/**
 * @brief Default length of device information fields.
 */
#define DEFAULT_DEVICE_FIELD_LEN 64
/**********************************************************************
                STRUCTURE DEFINITIONS
**********************************************************************/
typedef unsigned char mac_address_t[6]; /**< MAC address type. */
typedef char mac_addr_str_t[18]; /**< MAC address string type. */
typedef mac_address_t bssid_t; /**< BSSID type. */
typedef char ssid_t[32]; /**< SSID type. */
typedef UINT wifi_radio_index_t; /**< Wi-Fi radio index type. */
typedef unsigned int u_int32_t; /**< Unsigned 32-bit integer type. */
typedef char nas_id_t[49]; /**< NAS ID type. */
typedef unsigned char r0r1_key_t[16]; /**< R0R1 key type. */
typedef char r0r1_key_str_t[33]; /**< R0R1 key string type. */
typedef char wifi_interface_name_t[32]; /**< Wi-Fi interface name type. */
typedef char wifi_vap_name_t[64]; /**< Wi-Fi VAP name type. */

/**
 * @brief Wi-Fi security mode types.
 */
typedef enum
{
    wifi_security_mode_none = 0x00000001, /**< No security. */
    wifi_security_mode_wep_64 = 0x00000002, /**< WEP 64-bit. */
    wifi_security_mode_wep_128 = 0x00000004, /**< WEP 128-bit. */
    wifi_security_mode_wpa_personal = 0x00000008, /**< WPA Personal. */
    wifi_security_mode_wpa2_personal = 0x00000010, /**< WPA2 Personal. */
    wifi_security_mode_wpa_wpa2_personal = 0x00000020, /**< WPA/WPA2 Personal. */
    wifi_security_mode_wpa_enterprise = 0x00000040, /**< WPA Enterprise. */
    wifi_security_mode_wpa2_enterprise = 0x00000080, /**< WPA2 Enterprise. */
    wifi_security_mode_wpa_wpa2_enterprise = 0x00000100, /**< WPA/WPA2 Enterprise. */
    wifi_security_mode_wpa3_personal = 0x00000200, /**< WPA3 Personal. */
    wifi_security_mode_wpa3_transition = 0x00000400, /**< WPA3 Transition. */
    wifi_security_mode_wpa3_enterprise = 0x00000800, /**< WPA3 Enterprise. */
    wifi_security_mode_enhanced_open = 0x00001000, /**< Enhanced Open. */
    wifi_security_mode_wpa3_compatibility = 0x00002000 /**< WPA3 Personal Compatibility */
} wifi_security_modes_t;

/**
 * @brief Wi-Fi encryption types.
 */
typedef enum
{
    wifi_encryption_none, /**< No encryption. */
    wifi_encryption_tkip = 1, /**< TKIP encryption. */
    wifi_encryption_aes, /**< AES encryption. */
    wifi_encryption_aes_tkip, /**< AES/TKIP encryption. */
    wifi_encryption_aes_gcmp256, /**< AES-GCMP-256 encryption. */
    wifi_encryption_gcmp256, /**< GCMP-256 encryption. */
} wifi_encryption_method_t;

/**
 * @brief Wi-Fi frequency band types.
 */
typedef enum
{
    WIFI_FREQUENCY_2_4_BAND = 0x1, /**< 2.4GHz band. */
    WIFI_FREQUENCY_5_BAND = 0x2, /**< 5GHz band. */
    WIFI_FREQUENCY_5L_BAND = 0x4, /**< 5GHz low band. */
    WIFI_FREQUENCY_5H_BAND = 0x8, /**< 5GHz high band. */
    WIFI_FREQUENCY_6_BAND = 0x10, /**< 6GHz band. */
    WIFI_FREQUENCY_60_BAND = 0x20 /**< 60GHz band. */
} wifi_freq_bands_t;

/**
 * @brief Maximum number of frequency bands.
 */
#define MAX_NUM_FREQ_BAND 4

/**
 * @brief Wi-Fi 802.11 variant types.
 */
typedef enum
{
    WIFI_80211_VARIANT_A = 0x01, /**< 802.11a. */
    WIFI_80211_VARIANT_B = 0x02, /**< 802.11b. */
    WIFI_80211_VARIANT_G = 0x04, /**< 802.11g. */
    WIFI_80211_VARIANT_N = 0x08, /**< 802.11n. */
    WIFI_80211_VARIANT_H = 0x10, /**< 802.11h. */
    WIFI_80211_VARIANT_AC = 0x20, /**< 802.11ac. */
    WIFI_80211_VARIANT_AD = 0x40, /**< 802.11ad. */
    WIFI_80211_VARIANT_AX = 0x80, /**< 802.11ax. */
    WIFI_80211_VARIANT_BE = 0x100 /**< 802.11be. */
} wifi_ieee80211Variant_t;

/**
 * @brief Wi-Fi channel bandwidth types.
 */
typedef enum
{
    WIFI_CHANNELBANDWIDTH_20MHZ = 0x1, /**< 20MHz. */
    WIFI_CHANNELBANDWIDTH_40MHZ = 0x2, /**< 40MHz. */
    WIFI_CHANNELBANDWIDTH_80MHZ = 0x4, /**< 80MHz. */
    WIFI_CHANNELBANDWIDTH_160MHZ = 0x8, /**< 160MHz. */
    WIFI_CHANNELBANDWIDTH_80_80MHZ = 0x10, /**< 80+80MHz. */
    WIFI_CHANNELBANDWIDTH_320MHZ = 0x20 /**< 320MHz. */
} wifi_channelBandwidth_t;

/**
 * @brief Wi-Fi supported bitrates.
 */
typedef enum
{
    WIFI_BITRATE_DEFAULT = 0x0001, /**< Used in the set API to default the bitrate configuration. */
    WIFI_BITRATE_1MBPS = 0x0002, /**< 1Mbps. */
    WIFI_BITRATE_2MBPS = 0x0004, /**< 2Mbps. */
    WIFI_BITRATE_5_5MBPS = 0x0008, /**< 5.5Mbps. */
    WIFI_BITRATE_6MBPS = 0x0010, /**< 6Mbps. */
    WIFI_BITRATE_9MBPS = 0x0020, /**< 9Mbps. */
    WIFI_BITRATE_11MBPS = 0x0040, /**< 11Mbps. */
    WIFI_BITRATE_12MBPS = 0x0080, /**< 12Mbps. */
    WIFI_BITRATE_18MBPS = 0x0100, /**< 18Mbps. */
    WIFI_BITRATE_24MBPS = 0x0200, /**< 24Mbps. */
    WIFI_BITRATE_36MBPS = 0x0400, /**< 36Mbps. */
    WIFI_BITRATE_48MBPS = 0x0800, /**< 48Mbps. */
    WIFI_BITRATE_54MBPS = 0x1000 /**< 54Mbps. */
} wifi_bitrate_t;

/**
 * @brief BSS information.
 */
typedef struct
{
    bssid_t bssid; /**< BSSID. */
    ssid_t ssid; /**< SSID. */
    int rssi; /**< RSSI. */
    unsigned short caps; /**< Capabilities. */
    unsigned int beacon_int; /**< Beacon interval. */
    unsigned int freq; /**< Frequency. */
    unsigned char ie[256]; /**< Information elements. */
    size_t ie_len; /**< Length of the information elements. */
    wifi_security_modes_t sec_mode; /**< Security mode. */
    wifi_encryption_method_t enc_method; /**< Encryption method. */
    wifi_freq_bands_t oper_freq_band; /**< Operating frequency band. */
    wifi_ieee80211Variant_t supp_standards; /**< Supported standards. */
    wifi_ieee80211Variant_t oper_standards; /**< Operating standards. */
    wifi_channelBandwidth_t supp_chan_bw; /**< Supported channel bandwidth. */
    wifi_channelBandwidth_t oper_chan_bw; /**< Operating channel bandwidth. */
    wifi_bitrate_t basic_rates; /**< Basic rates. */
    wifi_bitrate_t supp_rates; /**< Supported rates. */
    unsigned int dtim_period; /**< DTIM period. */
    unsigned int chan_utilization; /**< Channel utilization. */
    int noise; /**< Noise. */
} __attribute__((packed)) wifi_bss_info_t;

/**
 * @brief IP family types.
 */
typedef enum
{
    wifi_ip_family_ipv4, /**< IPv4. */
    wifi_ip_family_ipv6 /**< IPv6. */
} wifi_ip_family_t;

/**
 * @brief IP address structure.
 */
typedef struct
{
    wifi_ip_family_t family; /**< IP family. */
    union
    { /* network byte ordered */
        UINT IPv4addr; /**< 32-bit IPv4 address. */
        UCHAR IPv6addr[16]; /**< 128-bit IPv6 address. */
    } u;
} __attribute__((packed)) ip_addr_t;

/**
 * @brief Wi-Fi enable/disable values.
 */
typedef enum
{
    WIFI_HAL_DISABLE = 0, /**< Disable. */
    WIFI_HAL_ENABLE = 1, /**< Enable. */
} eWifiEnable;

/**
 * @brief Wi-Fi HAL version.
 */
typedef struct
{
    UINT major; /**< Major version. */
    UINT minor; /**< Minor version. */
} __attribute__((packed)) wifi_hal_version_t;

/**
 * @brief Wi-Fi channel information.
 */
typedef struct
{
    INT channel; /**< Channel number. */
    wifi_freq_bands_t band; /**< Frequency band. */
} __attribute__((packed)) wifi_channel_t;

/**
 * @brief Maximum number of channels.
 */
#define MAX_CHANNELS 64

/**
 * @brief Channel list.
 */
typedef struct
{
    INT num_channels; /**< The number of available channels in `channels_list`. */
    INT channels_list[MAX_CHANNELS]; /**< List of channels. */
} __attribute__((packed)) wifi_channels_list_t;

/**
 * @brief Wi-Fi channel lists per bandwidth.
 */
typedef struct {
    wifi_channelBandwidth_t chanwidth; /**< Bandwidth to which the channel blocks are mapped to */
    INT num_channels_list; /**< The number of list of channels contained within a given bandwidth */
    wifi_channels_list_t channels_list[MAX_CHANNELS]; /**< List of channel lists */
}__attribute__((packed)) wifi_channels_list_per_bandwidth_t;

/**
 * @brief Maximum number of transmit power levels supported.
 */
#define MAXNUMBEROFTRANSMIPOWERSUPPORTED 21

/**
 * @brief Radio transmit power supported list.
 */
typedef struct
{
    UINT transmitPowerSupported[MAXNUMBEROFTRANSMIPOWERSUPPORTED]; /**< List of transmit power levels supported. */
    UINT numberOfElements;                                         /**< The number of valid elements in `transmitPowerSupported`. */
} __attribute__((packed)) wifi_radio_trasmitPowerSupported_list_t;

#ifdef WIFI_HAL_RSN_SELECTOR
#undef WIFI_HAL_RSN_SELECTOR
#endif
/**
 * @brief Macro for creating an RSN selector value.
 *
 * @param[in] a First byte of the selector.
 * @param[in] b Second byte of the selector.
 * @param[in] c Third byte of the selector.
 * @param[in] d Fourth byte of the selector.
 */
#define WIFI_HAL_RSN_SELECTOR(a, b, c, d) \
    ((((unsigned int)(a)) << 24) | (((unsigned int)(b)) << 16) | (((unsigned int)(c)) << 8) | (unsigned int)(d))

#define WIFI_HAL_RSN_CIPHER_SUITE_NONE WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 0) /**< RSN cipher suite: None. */
#define WIFI_HAL_RSN_CIPHER_SUITE_TKIP WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 2) /**< RSN cipher suite: TKIP. */
#if 0
#define WIFI_HAL_RSN_CIPHER_SUITE_WRAP WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 3) /**< RSN cipher suite: WRAP. */
#endif
#define WIFI_HAL_RSN_CIPHER_SUITE_CCMP WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 4) /**< RSN cipher suite: CCMP. */
#define WIFI_HAL_RSN_CIPHER_SUITE_AES_128_CMAC WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 6) /**< RSN cipher suite: AES-128-CMAC. */
#define WIFI_HAL_RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 7) /**< RSN cipher suite: No group addressed. */
#define WIFI_HAL_RSN_CIPHER_SUITE_GCMP WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 8) /**< RSN cipher suite: GCMP. */
#define WIFI_HAL_RSN_CIPHER_SUITE_GCMP_256 WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 9) /**< RSN cipher suite: GCMP-256. */
#define WIFI_HAL_RSN_CIPHER_SUITE_CCMP_256 WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 10) /**< RSN cipher suite: CCMP-256. */
#define WIFI_HAL_RSN_CIPHER_SUITE_BIP_GMAC_128 WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 11) /**< RSN cipher suite: BIP-GMAC-128. */
#define WIFI_HAL_RSN_CIPHER_SUITE_BIP_GMAC_256 WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 12) /**< RSN cipher suite: BIP-GMAC-256. */
#define WIFI_HAL_RSN_CIPHER_SUITE_BIP_CMAC_256 WIFI_HAL_RSN_SELECTOR(0x00, 0x0f, 0xac, 13) /**< RSN cipher suite: BIP-CMAC-256. */

#define WIFI_CIPHER_CAPA_ENC_WEP40 0x00000001 /**< Cipher capability: WEP-40 encryption. */
#define WIFI_CIPHER_CAPA_ENC_WEP104 0x00000002 /**< Cipher capability: WEP-104 encryption. */
#define WIFI_CIPHER_CAPA_ENC_TKIP 0x00000004 /**< Cipher capability: TKIP encryption. */
#define WIFI_CIPHER_CAPA_ENC_CCMP 0x00000008 /**< Cipher capability: CCMP encryption. */
#define WIFI_CIPHER_CAPA_ENC_WEP128 0x00000010 /**< Cipher capability: WEP-128 encryption. */
#define WIFI_CIPHER_CAPA_ENC_GCMP 0x00000020 /**< Cipher capability: GCMP encryption. */
#define WIFI_CIPHER_CAPA_ENC_GCMP_256 0x00000040 /**< Cipher capability: GCMP-256 encryption. */
#define WIFI_CIPHER_CAPA_ENC_CCMP_256 0x00000080 /**< Cipher capability: CCMP-256 encryption. */
#define WIFI_CIPHER_CAPA_ENC_BIP 0x00000100 /**< Cipher capability: BIP encryption. */
#define WIFI_CIPHER_CAPA_ENC_BIP_GMAC_128 0x00000200 /**< Cipher capability: BIP-GMAC-128 encryption. */
#define WIFI_CIPHER_CAPA_ENC_BIP_GMAC_256 0x00000400 /**< Cipher capability: BIP-GMAC-256 encryption. */
#define WIFI_CIPHER_CAPA_ENC_BIP_CMAC_256 0x00000800 /**< Cipher capability: BIP-CMAC-256 encryption. */
#define WIFI_CIPHER_CAPA_ENC_GTK_NOT_USED 0x00001000 /**< Cipher capability: GTK not used. */

/**
 * @brief Wi-Fi country code types.
 */
typedef enum {
    wifi_countrycode_AC, /**< ASCENSION ISLAND */
    wifi_countrycode_AD, /**< ANDORRA */
    wifi_countrycode_AE, /**< UNITED ARAB EMIRATES */
    wifi_countrycode_AF, /**< AFGHANISTAN */
    wifi_countrycode_AG, /**< ANTIGUA AND BARBUDA */
    wifi_countrycode_AI, /**< ANGUILLA */
    wifi_countrycode_AL, /**< ALBANIA */
    wifi_countrycode_AM, /**< ARMENIA */
    wifi_countrycode_AN, /**< NETHERLANDS ANTILLES */
    wifi_countrycode_AO, /**< ANGOLA */
    wifi_countrycode_AQ, /**< ANTARCTICA */
    wifi_countrycode_AR, /**< ARGENTINA */
    wifi_countrycode_AS, /**< AMERICAN SAMOA */
    wifi_countrycode_AT, /**< AUSTRIA */
    wifi_countrycode_AU, /**< AUSTRALIA */
    wifi_countrycode_AW, /**< ARUBA */
    wifi_countrycode_AZ, /**< AZERBAIJAN */    
    wifi_countrycode_BA, /**< BOSNIA AND HERZEGOVINA */
    wifi_countrycode_BB, /**< BARBADOS */
    wifi_countrycode_BD, /**< BANGLADESH */
    wifi_countrycode_BE, /**< BELGIUM */
    wifi_countrycode_BF, /**< BURKINA FASO */
    wifi_countrycode_BG, /**< BULGARIA */
    wifi_countrycode_BH, /**< BAHRAIN */
    wifi_countrycode_BI, /**< BURUNDI */
    wifi_countrycode_BJ, /**< BENIN */
    wifi_countrycode_BM, /**< BERMUDA */
    wifi_countrycode_BN, /**< BRUNEI DARUSSALAM */
    wifi_countrycode_BO, /**< BOLIVIA */
    wifi_countrycode_BR, /**< BRAZIL */
    wifi_countrycode_BS, /**< BAHAMAS */
    wifi_countrycode_BT, /**< BHUTAN */
    wifi_countrycode_BV, /**< BOUVET ISLAND */
    wifi_countrycode_BW, /**< BOTSWANA */
    wifi_countrycode_BY, /**< BELARUS */
    wifi_countrycode_BZ, /**< BELIZE */
    wifi_countrycode_CA, /**< CANADA */
    wifi_countrycode_CC, /**< COCOS (KEELING) ISLANDS */
    wifi_countrycode_CD, /**< CONGO, THE DEMOCRATIC REPUBLIC OF THE */
    wifi_countrycode_CF, /**< CENTRAL AFRICAN REPUBLIC */
    wifi_countrycode_CG, /**< CONGO */
    wifi_countrycode_CH, /**< SWITZERLAND */
    wifi_countrycode_CI, /**< COTE D'IVOIRE */
    wifi_countrycode_CK, /**< COOK ISLANDS */
    wifi_countrycode_CL, /**< CHILE */
    wifi_countrycode_CM, /**< CAMEROON */
    wifi_countrycode_CN, /**< CHINA */
    wifi_countrycode_CO, /**< COLOMBIA */
    wifi_countrycode_CP, /**< CLIPPERTON ISLAND */
    wifi_countrycode_CR, /**< COSTA RICA */
    wifi_countrycode_CU, /**< CUBA */
    wifi_countrycode_CV, /**< CAPE VERDE */
    wifi_countrycode_CY, /**< CYPRUS */
    wifi_countrycode_CX, /**< CHRISTMAS ISLAND */
    wifi_countrycode_CZ, /**< CZECH REPUBLIC */
    wifi_countrycode_DE, /**< GERMANY */
    wifi_countrycode_DJ, /**< DJIBOUTI */
    wifi_countrycode_DK, /**< DENMARK */
    wifi_countrycode_DM, /**< DOMINICA */
    wifi_countrycode_DO, /**< DOMINICAN REPUBLIC */
    wifi_countrycode_DZ, /**< ALGERIA */
    wifi_countrycode_EC, /**< ECUADOR */
    wifi_countrycode_EE, /**< ESTONIA */
    wifi_countrycode_EG, /**< EGYPT */
    wifi_countrycode_EH, /**< WESTERN SAHARA */
    wifi_countrycode_ER, /**< ERITREA */
    wifi_countrycode_ES, /**< SPAIN */
    wifi_countrycode_ET, /**< ETHIOPIA */
    wifi_countrycode_FI, /**< FINLAND */
    wifi_countrycode_FJ, /**< FIJI */
    wifi_countrycode_FK, /**< FALKLAND ISLANDS (MALVINAS) */
    wifi_countrycode_FM, /**< MICRONESIA, FEDERATED STATES OF */
    wifi_countrycode_FO, /**< FAROE ISLANDS */
    wifi_countrycode_FR, /**< FRANCE */
    wifi_countrycode_GA, /**< GABON */
    wifi_countrycode_GB, /**< UNITED KINGDOM */
    wifi_countrycode_GD, /**< GRENADA */
    wifi_countrycode_GE, /**< GEORGIA */
    wifi_countrycode_GF, /**< FRENCH GUIANA */
    wifi_countrycode_GG, /**< GUERNSEY */
    wifi_countrycode_GH, /**< GHANA */
    wifi_countrycode_GI, /**< GIBRALTAR */
    wifi_countrycode_GL, /**< GREENLAND */    
    wifi_countrycode_GM, /**< GAMBIA */
    wifi_countrycode_GN, /**< GUINEA */
    wifi_countrycode_GP, /**< GUADELOUPE */
    wifi_countrycode_GQ, /**< EQUATORIAL GUINEA */
    wifi_countrycode_GR, /**< GREECE */
    wifi_countrycode_GS, /**< SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS */
    wifi_countrycode_GT, /**< GUATEMALA */    
    wifi_countrycode_GU, /**< GUAM */
    wifi_countrycode_GW, /**< GUINEA-BISSAU */
    wifi_countrycode_GY, /**< GUYANA */
    wifi_countrycode_HR, /**< CROATIA */
    wifi_countrycode_HT, /**< HAITI */
    wifi_countrycode_HM, /**< HEARD ISLAND AND MCDONALD ISLANDS */
    wifi_countrycode_HN, /**< HONDURAS */
    wifi_countrycode_HK, /**< HONG KONG */
    wifi_countrycode_HU, /**< HUNGARY */
    wifi_countrycode_IS, /**< ICELAND */
    wifi_countrycode_IN, /**< INDIA */
    wifi_countrycode_ID, /**< INDONESIA */
    wifi_countrycode_IR, /**< IRAN, ISLAMIC REPUBLIC OF */
    wifi_countrycode_IQ, /**< IRAQ */
    wifi_countrycode_IE, /**< IRELAND */
    wifi_countrycode_IL, /**< ISRAEL */
    wifi_countrycode_IM, /**< MAN, ISLE OF */
    wifi_countrycode_IT, /**< ITALY */
    wifi_countrycode_IO, /**< BRITISH INDIAN OCEAN TERRITORY */
    wifi_countrycode_JM, /**< JAMAICA */
    wifi_countrycode_JP, /**< JAPAN */
    wifi_countrycode_JE, /**< JERSEY */
    wifi_countrycode_JO, /**< JORDAN */
    wifi_countrycode_KE, /**< KENYA */
    wifi_countrycode_KG, /**< KYRGYZSTAN */
    wifi_countrycode_KH, /**< CAMBODIA */
    wifi_countrycode_KI, /**< KIRIBATI */
    wifi_countrycode_KM, /**< COMOROS */
    wifi_countrycode_KN, /**< SAINT KITTS AND NEVIS */
    wifi_countrycode_KP, /**< KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF */
    wifi_countrycode_KR, /**< KOREA, REPUBLIC OF */
    wifi_countrycode_KW, /**< KUWAIT */
    wifi_countrycode_KY, /**< CAYMAN ISLANDS */
    wifi_countrycode_KZ, /**< KAZAKHSTAN */
    wifi_countrycode_LA, /**< LAO PEOPLE'S DEMOCRATIC REPUBLIC */
    wifi_countrycode_LB, /**< LEBANON */
    wifi_countrycode_LC, /**< SAINT LUCIA */
    wifi_countrycode_LI, /**< LIECHTENSTEIN */
    wifi_countrycode_LK, /**< SRI LANKA */
    wifi_countrycode_LR, /**< LIBERIA */
    wifi_countrycode_LS, /**< LESOTHO */
    wifi_countrycode_LT, /**< LITHUANIA */
    wifi_countrycode_LU, /**< LUXEMBOURG */
    wifi_countrycode_LV, /**< LATVIA */
    wifi_countrycode_LY, /**< LIBYAN ARAB JAMAHIRIYA */
    wifi_countrycode_MA, /**< MOROCCO */
    wifi_countrycode_MC, /**< MONACO */
    wifi_countrycode_MD, /**< MOLDOVA, REPUBLIC OF */
    wifi_countrycode_ME, /**< MONTENEGRO */
    wifi_countrycode_MG, /**< MADAGASCAR */
    wifi_countrycode_MH, /**< MARSHALL ISLANDS */
    wifi_countrycode_MK, /**< MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF */
    wifi_countrycode_ML, /**< MALI */
    wifi_countrycode_MM, /**< MYANMAR */
    wifi_countrycode_MN, /**< MONGOLIA */
    wifi_countrycode_MO, /**< MACAO */
    wifi_countrycode_MQ, /**< MARTINIQUE */
    wifi_countrycode_MR, /**< MAURITANIA */
    wifi_countrycode_MS, /**< MONTSERRAT */
    wifi_countrycode_MT, /**< MALTA */
    wifi_countrycode_MU, /**< MAURITIUS */
    wifi_countrycode_MV, /**< MALDIVES */
    wifi_countrycode_MW, /**< MALAWI */
    wifi_countrycode_MX, /**< MEXICO */
    wifi_countrycode_MY, /**< MALAYSIA */
    wifi_countrycode_MZ, /**< MOZAMBIQUE */
    wifi_countrycode_NA, /**< NAMIBIA */
    wifi_countrycode_NC, /**< NEW CALEDONIA */
    wifi_countrycode_NE, /**< NIGER */
    wifi_countrycode_NF, /**< NORFOLK ISLAND */
    wifi_countrycode_NG, /**< NIGERIA */
    wifi_countrycode_NI, /**< NICARAGUA */
    wifi_countrycode_NL, /**< NETHERLANDS */
    wifi_countrycode_NO, /**< NORWAY */
    wifi_countrycode_NP, /**< NEPAL */    
    wifi_countrycode_NR, /**< NAURU */
    wifi_countrycode_NU, /**< NIUE */    
    wifi_countrycode_NZ, /**< NEW ZEALAND */
    wifi_countrycode_MP, /**< NORTHERN MARIANA ISLANDS */
    wifi_countrycode_OM, /**< OMAN */
    wifi_countrycode_PA, /**< PANAMA */
    wifi_countrycode_PE, /**< PERU */
    wifi_countrycode_PF, /**< FRENCH POLYNESIA */
    wifi_countrycode_PG, /**< PAPUA NEW GUINEA */
    wifi_countrycode_PH, /**< PHILIPPINES */
    wifi_countrycode_PK, /**< PAKISTAN */
    wifi_countrycode_PL, /**< POLAND */
    wifi_countrycode_PM, /**< SAINT PIERRE AND MIQUELON */
    wifi_countrycode_PN, /**< PITCAIRN */
    wifi_countrycode_PR, /**< PUERTO RICO */
    wifi_countrycode_PS, /**< PALESTINIAN TERRITORY, OCCUPIED */
    wifi_countrycode_PT, /**< PORTUGAL */    
    wifi_countrycode_PW, /**< PALAU */
    wifi_countrycode_PY, /**< PARAGUAY */
    wifi_countrycode_QA, /**< QATAR */
    wifi_countrycode_RE, /**< REUNION */
    wifi_countrycode_RO, /**< ROMANIA */
    wifi_countrycode_RS, /**< SERBIA */
    wifi_countrycode_RU, /**< RUSSIAN FEDERATION */
    wifi_countrycode_RW, /**< RWANDA */
    wifi_countrycode_SA, /**< SAUDI ARABIA */
    wifi_countrycode_SB, /**< SOLOMON ISLANDS */
    wifi_countrycode_SD, /**< SUDAN */
    wifi_countrycode_SE, /**< SWEDEN */
    wifi_countrycode_SC, /**< SEYCHELLES */
    wifi_countrycode_SG, /**< SINGAPORE */
    wifi_countrycode_SH, /**< SAINT HELENA */
    wifi_countrycode_SI, /**< SLOVENIA */
    wifi_countrycode_SJ, /**< SVALBARD AND JAN MAYEN */
    wifi_countrycode_SK, /**< SLOVAKIA */
    wifi_countrycode_SL, /**< SIERRA LEONE */
    wifi_countrycode_SM, /**< SAN MARINO */
    wifi_countrycode_SN, /**< SENEGAL */
    wifi_countrycode_SO, /**< SOMALIA */
    wifi_countrycode_SR, /**< SURINAME */
    wifi_countrycode_ST, /**< SAO TOME AND PRINCIPE */
    wifi_countrycode_SV, /**< EL SALVADOR */
    wifi_countrycode_SY, /**< SYRIAN ARAB REPUBLIC */
    wifi_countrycode_SZ, /**< SWAZILAND */
    wifi_countrycode_TA, /**< TRISTAN DA CUNHA */
    wifi_countrycode_TC, /**< TURKS AND CAICOS ISLANDS */
    wifi_countrycode_TD, /**< CHAD */
    wifi_countrycode_TF, /**< FRENCH SOUTHERN TERRITORIES */
    wifi_countrycode_TG, /**< TOGO */
    wifi_countrycode_TH, /**< THAILAND */
    wifi_countrycode_TJ, /**< TAJIKISTAN */
    wifi_countrycode_TK, /**< TOKELAU */
    wifi_countrycode_TL, /**< TIMOR-LESTE (EAST TIMOR) */
    wifi_countrycode_TM, /**< TURKMENISTAN */
    wifi_countrycode_TN, /**< TUNISIA */
    wifi_countrycode_TO, /**< TONGA */
    wifi_countrycode_TR, /**< TURKEY */
    wifi_countrycode_TT, /**< TRINIDAD AND TOBAGO */
    wifi_countrycode_TV, /**< TUVALU */
    wifi_countrycode_TW, /**< TAIWAN, PROVINCE OF CHINA */
    wifi_countrycode_TZ, /**< TANZANIA, UNITED REPUBLIC OF */
    wifi_countrycode_UA, /**< UKRAINE */
    wifi_countrycode_UG, /**< UGANDA */
    wifi_countrycode_UM, /**< UNITED STATES MINOR OUTLYING ISLANDS */
    wifi_countrycode_US, /**< UNITED STATES */
    wifi_countrycode_UY, /**< URUGUAY */
    wifi_countrycode_UZ, /**< UZBEKISTAN */
    wifi_countrycode_VA, /**< HOLY SEE (VATICAN CITY STATE) */
    wifi_countrycode_VC, /**< SAINT VINCENT AND THE GRENADINES */
    wifi_countrycode_VE, /**< VENEZUELA */
    wifi_countrycode_VG, /**< VIRGIN ISLANDS, BRITISH */
    wifi_countrycode_VI, /**< VIRGIN ISLANDS, U.S. */
    wifi_countrycode_VN, /**< VIET NAM */
    wifi_countrycode_VU, /**< VANUATU */
    wifi_countrycode_WF, /**< WALLIS AND FUTUNA */
    wifi_countrycode_WS, /**< SAMOA */
    wifi_countrycode_YE, /**< YEMEN */
    wifi_countrycode_YT, /**< MAYOTTE */
    wifi_countrycode_YU, /**< YUGOSLAVIA */
    wifi_countrycode_ZA, /**< SOUTH AFRICA */
    wifi_countrycode_ZM, /**< ZAMBIA */
    wifi_countrycode_ZW, /**< ZIMBABWE */
    wifi_countrycode_AX, /**< ALAND_ISLANDS */
    wifi_countrycode_BL, /**< SAINT_BARTHELEMY */
    wifi_countrycode_CW, /**< CURACAO */
    wifi_countrycode_MF, /**< SAINT_MARTIN */
    wifi_countrycode_SX, /**< SINT_MAARTEN */
    wifi_countrycode_max /**< Max number of country code */
} wifi_countrycode_type_t;

/**
 * @brief Wi-Fi operating environment types.
 */
typedef enum
{
    wifi_operating_env_all, /**< All environments. */
    wifi_operating_env_indoor, /**< Indoor environment. */
    wifi_operating_env_outdoor, /**< Outdoor environment. */
    wifi_operating_env_non_country /**< Non-country environment. */
} wifi_operating_env_t;

/**
 * @brief Wi-Fi radio CSI capabilities.
 */
typedef struct
{
    UINT maxDevices; /**< The maximum number of stations that can be configured to collect the CSI data. Return 0 if CSI is not supported. */
    BOOL soudingFrameSupported; /**< True if the radio supports sending sounding frames in the MAC layer. */
} __attribute__((packed)) wifi_radio_csi_capabilities_t;

/**
 * @brief Maximum size of an interface name.
 */
#define MAXIFACENAMESIZE 64

/**
 * @brief Wi-Fi radio capabilities.
 */
typedef struct
{
    UINT index; /**< Radio index. */
    CHAR ifaceName[MAXIFACENAMESIZE]; /**< The interface name. */
    UINT numSupportedFreqBand; /**< The number of supported frequency bands. */
    wifi_freq_bands_t band[MAX_NUM_FREQ_BAND]; /**< The frequency band list. */
    wifi_channels_list_t channel_list[MAX_NUM_FREQ_BAND]; /**< The list of supported channels for each frequency band supported. */
    wifi_channelBandwidth_t channelWidth[MAX_NUM_FREQ_BAND]; /**< The channel bandwidth supported (uses bitmask to return multiple bandwidths) for each frequency band supported. */
    wifi_ieee80211Variant_t mode[MAX_NUM_FREQ_BAND]; /**< The supported modes (uses bitmask to return multiple modes) for each frequency band supported. */
    UINT maxBitRate[MAX_NUM_FREQ_BAND]; /**< The maximum PHY bit rate supported for each frequency band supported. */
    UINT supportedBitRate[MAX_NUM_FREQ_BAND]; /**< The supported data transmit rates in Mbps for each frequency band supported. It uses bitmask to return multiple bitrates and wifi_bitrate_t has the definition of valid values. */
    wifi_radio_trasmitPowerSupported_list_t transmitPowerSupported_list[MAX_NUM_FREQ_BAND]; /**< List of transmit power supported for each frequency band supported. */
    BOOL autoChannelSupported; /**< True if auto channel is supported. */
    BOOL DCSSupported; /**< True if DCS is supported. */
    BOOL zeroDFSSupported; /**< True if Zero DFS is supported. Zero DFS (also known as Background CAC) allows the Wi-Fi stack to continue operation on the main channel and at the same time run background CAC. */
    wifi_radio_csi_capabilities_t csi; /**< CSI capabilities. */
    UINT cipherSupported; /**< The list of supported ciphers (uses bitmask to return multiple values). */
    UINT numcountrySupported; /**< Number of supported countries. */
    wifi_countrycode_type_t countrySupported[wifi_countrycode_max]; /**< The supported country list. It should return the current country code on the first entry. */
    UINT maxNumberVAPs; /**< Maximum number of VAPs. */
    BOOL mcast2ucastSupported; /**< True if 'multicast to unicast' conversion is supported. */
} __attribute__((packed)) wifi_radio_capabilities_t;

/**
 * @brief Wi-Fi interface property information.
 */
typedef struct
{
    unsigned int phy_index; /**< Actual index of the PHY device. */
    unsigned int rdk_radio_index; /**< Radio index of the upper layer. */
    wifi_interface_name_t interface_name; /**< Interface name. */
    wifi_interface_name_t bridge_name; /**< Bridge name. */
    int vlan_id; /**< VLAN ID. */
    unsigned int index; /**< Index. */
    wifi_vap_name_t vap_name; /**< VAP name. */
} __attribute__((packed)) wifi_interface_name_idex_map_t;

/**
 * @brief Radio interface mapping.
 */
typedef struct
{
    unsigned int phy_index; /**< PHY index. */
    unsigned int radio_index; /**< Radio index. */
    char radio_name[16]; /**< Radio name. */
    wifi_interface_name_t interface_name; /**< Interface name. */
} __attribute__((packed)) radio_interface_mapping_t;

/**
 * @brief Wi-Fi Multi-Link supported bands.
 */
typedef enum
{
    WIFI_BAND_NONE = 0x1, /**< No band. */
    WIFI_BAND_2_5 = 0x2, /**< 2.4GHz band. */
    WIFI_BAND_2_6 = 0x4, /**< 2.4GHz and 6GHz bands. */
    WIFI_BAND_5_6 = 0x8, /**< 5GHz and 6GHz bands. */
    WIFI_BAND_2_5_6 = 0x10, /**< 2.4GHz, 5GHz, and 6GHz bands. */
    WIFI_BAND_2_5L = 0x20, /**< 2.4GHz and 5GHz low bands. */
    WIFI_BAND_2_5H = 0x40, /**< 2.4GHz and 5GHz high bands. */
    WIFI_BAND_5L_5H = 0x80, /**< 5GHz low and high bands. */
    WIFI_BAND_2_5L_5H = 0x100 /**< 2.4GHz, 5GHz low, and 5GHz high bands. */
} wifi_multi_link_bands_t;

/**
 * @brief Wi-Fi 7 supported modes.
 */
typedef enum
{
    STR = 0x1, /**< Single-user Transmit and Receive (STR). */
    NSTR = 0x2, /**< Non-STR. */
    eMLSR = 0x4, /**< Enhanced Multi-Link Single-user Resource (eMLSR). */
    eMLMR = 0x8 /**< Enhanced Multi-Link Multi-user Resource (eMLMR). */
} wifi_multi_link_modes_t;

/**
 * @brief Wi-Fi Multi-Link information.
 */
typedef struct _wifi_multi_link_info_t
{
    wifi_multi_link_bands_t mu_bands; /**< Supported bands for Multi-Link operation. */
    wifi_multi_link_modes_t mu_modes; /**< Supported modes for Multi-Link operation. */
} wifi_multi_link_info_t;

/**
 * @brief Wi-Fi platform properties.
 *
 * This structure contains information about the Wi-Fi platform properties.
 */
typedef struct 
{
    UINT numRadios; /**< Number of radios. */
    wifi_radio_capabilities_t radiocap[MAX_NUM_RADIOS]; /**< Radio capabilities. */
    wifi_interface_name_idex_map_t interface_map[(MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)]; /**< Interface map. */
    radio_interface_mapping_t radio_interface_map[MAX_NUM_RADIOS]; /**< Radio interface map. */
    BOOL radio_presence[MAX_NUM_RADIOS]; /**< Indicates if the interface is present (not in deep sleep). */
    wifi_multi_link_info_t mu_info; /**< Multi-Link information. */
    UINT BssMaxStaAllow; /**< Maximum number of stations supported for the given platform. Gets populated during bring-up. */

    // Device Information related fields
    CHAR manufacturer[DEFAULT_DEVICE_FIELD_LEN]; /**< Device manufacturer. */
    CHAR serialNo[DEFAULT_DEVICE_FIELD_LEN]; /**< Device serial number. */
    CHAR manufacturerModel[DEFAULT_DEVICE_FIELD_LEN]; /**< Device manufacturer model. */
    CHAR software_version[DEFAULT_DEVICE_FIELD_LEN]; /**< Device software version. */
    mac_address_t cm_mac; /**< Cable modem MAC address. */
    mac_address_t al_1905_mac; /**< 802.11v AL MAC address. */
    int colocated_mode; /**< Easymesh agent mode based on controller configuration */
} __attribute__((packed)) wifi_platform_property_t;

/**
 * @brief Wi-Fi HAL capabilities.
 */
typedef struct
{
    wifi_hal_version_t version; /**< The HAL version. */
    wifi_platform_property_t wifi_prop; /**< The platform property that includes the number of radios and supported frequency bands. */
    BOOL BandSteeringSupported; /**< True if band steering is supported by the HAL. */
} __attribute__((packed)) wifi_hal_capability_t;

/**
 * @brief Wi-Fi TWT agreement type.
 */
typedef enum
{
    wifi_twt_agreement_type_individual, /**< Set an individual TWT session. */
    wifi_twt_agreement_type_broadcast, /**< Set a broadcast TWT session. */
} wifi_twt_agreement_type_t;

/**
 * @brief Wi-Fi TWT operation.
 */
typedef struct
{
    BOOL implicit; /**< True if the TWT session is implicit, false if explicit. */
    BOOL announced; /**< True if the TWT session is announced, false if unannounced. */
    BOOL trigger_enabled; /**< Whether the TWT trigger is enabled. */
    UINT flowID; /**< Agreement identifier. */
} wifi_twt_operation_t;

/**
 * @brief Wi-Fi TWT individual parameters.
 */
typedef struct
{
    UINT wakeTime_uSec; /**< Wake time of the TWT session in microseconds. */
    UINT wakeInterval_uSec; /**< TWT wake interval in microseconds. */
    UINT minWakeDuration_uSec; /**< Minimum TWT wake interval in microseconds. */
    UINT channel; /**< Channel of the TWT session. */
} wifi_twt_individual_params_t;

/**
 * @brief Wi-Fi TWT broadcast parameters.
 */
typedef struct
{
    UINT wakeDuration_uSec; /**< Wake time of the TWT session in microseconds. */
    UINT wakeInterval_uSec; /**< TWT wake interval in microseconds. */
} wifi_twt_broadcast_params_t;

/**
 * @brief Wi-Fi TWT parameters.
 */
typedef struct
{
    wifi_twt_agreement_type_t agreement; /**< Agreement of the TWT session, i.e., individual or broadcast. */
    wifi_twt_operation_t operation; /**< Operation of the TWT session. */
    union
    {
        wifi_twt_individual_params_t individual; /**< Configuration for an individual TWT session. */
        wifi_twt_broadcast_params_t broadcast; /**< Configuration for a broadcast TWT session. */
    } params;
    BOOL sessionPaused; /**< True if the session is paused but has not been torn down. */
} wifi_twt_params_t;

/**
 * @brief 802.11ax parameters.
 */
typedef struct
{
    wifi_twt_params_t twt_params; /**< Configuration of a TWT session. */
} wifi_80211ax_params_t;

/**
 * @brief TWT device information.
 */
typedef struct
{
    UINT numTwtSession; /**< Number of TWT sessions for the device. */
    wifi_twt_params_t twtParams[MAX_NUM_TWT_SESSION]; /**< List of TWT sessions that the device has joined. */
} wifi_twt_dev_info_t;

/**
 * @brief Wi-Fi TWT sessions.
 */
typedef struct
{
    wifi_twt_params_t twtParameters; /**< Configuration of the TWT session. */
    INT IdTWTsession; /**< ID that uniquely identifies a TWT session for the AP. */
    mac_address_t macAddr[MAX_STA_PER_SESSION]; /**< List of MAC addresses connected to the TWT session. */
    UINT numDevicesInSession; /**< Number of devices connected to the TWT session. */
} wifi_twt_sessions_t;

/**
 * @brief Wi-Fi RU types.
 */
typedef enum
{
    WIFI_RU_TYPE_26, /**< 26-tone RU. */
    WIFI_RU_TYPE_52, /**< 52-tone RU. */
    WIFI_RU_TYPE_106, /**< 106-tone RU. */
    WIFI_RU_TYPE_242, /**< 242-tone RU. */
    WIFI_RU_TYPE_484, /**< 484-tone RU. */
    WIFI_RU_TYPE_996, /**< 996-tone RU. */
    WIFI_RU_TYPE_2X996, /**< 2x996-tone RU. */
} wifi_ru_type_t;

/**
 * @brief Wi-Fi access category (AC) type.
 */
typedef enum
{
    wifi_access_category_background, /**< Background access category. */
    wifi_access_category_best_effort, /**< Best effort access category. */
    wifi_access_category_video, /**< Video access category. */
    wifi_access_category_voice, /**< Voice access category. */
} wifi_access_category_t;

/**
 * @brief Wi-Fi BSR (Buffer Status Report) information.
 */
typedef struct
{
    wifi_access_category_t access_category; /**< Access category. */
    UINT queue_size; /**< Queue size. */
} wifi_bsr_t;

/**
 * @brief Wi-Fi RU allocation information.
 */
typedef struct
{
    UCHAR subchannels; /**< Number of subchannels. */
    wifi_ru_type_t type; /**< RU type. */
} wifi_ru_allocation_t;

/**
 * @brief Wi-Fi downlink MU types.
 */
typedef enum
{
    WIFI_DL_MU_TYPE_NONE, /**< No MU. */
    WIFI_DL_MU_TYPE_OFDMA, /**< OFDMA. */
    WIFI_DL_MU_TYPE_MIMO, /**< MIMO. */
    WIFI_DL_MU_TYPE_OFDMA_MIMO /**< OFDMA and MIMO. */
} wifi_dl_mu_type_t;

typedef enum
{
    WIFI_UL_MU_TYPE_NONE, /**< No MU. */
    WIFI_UL_MU_TYPE_OFDMA, /**< OFDMA. */
} wifi_ul_mu_type_t;

typedef struct
{
    wifi_dl_mu_type_t cli_DownlinkMuType; /**< Downlink MU type. */
    wifi_bsr_t cli_BufferStatus[MAX_BSR]; /**< Buffer status reports. */
    UCHAR cli_AllocatedDownlinkRuNum; /**< Number of allocated downlink RUs. */
    wifi_ru_allocation_t cli_DownlinkRuAllocations[MAX_RU_ALLOCATIONS]; /**< Downlink RU allocations. */
} wifi_dl_mu_stats_t;

typedef struct
{
    wifi_ul_mu_type_t cli_UpinkMuType; /**< Uplink MU type. */
    UCHAR cli_ChannelStateInformation; /**< Channel state information. */
    wifi_bsr_t cli_BufferStatus[MAX_BSR]; /**< Buffer status reports. */
    UCHAR cli_AllocatedUplinkRuNum; /**< Number of allocated uplink RUs. */
    wifi_ru_allocation_t cli_UplinkRuAllocations[MAX_RU_ALLOCATIONS]; /**< Uplink RU allocations. */
} wifi_ul_mu_stats_t;

typedef enum
{
    WIFI_EVENT_CHANNELS_CHANGED, /**< Channels changed. */
    WIFI_EVENT_DFS_RADAR_DETECTED /**< DFS radar detected. */
} wifi_chan_eventType_t;

typedef enum
{
    wifi_connection_status_disabled, /**< Disabled. */
    wifi_connection_status_disconnected, /**< Disconnected. */
    wifi_connection_status_connected, /**< Connected. */
    wifi_connection_status_ap_not_found /**< AP not found. */
} wifi_connection_status_t;

typedef enum
{
    RADIUS_ACCESS_REJECT = 1, /**< RADIUS access reject. */
    EAP_FAILURE /**< EAP failure. */
} radius_eap_failure_code_t;

typedef enum{
    RADIUS_INIT, /**< RADIUS Initialization failure. */
    RADIUS_FAILOVER, /**< RADIUS Failover. */
    RADIUS_FALLBACK /**< RADIUS Fallback. */
}radius_fallback_failover_code_t;

#define MAX_NR 4 /**< Maximum number of receive antennas. */
#define MAX_NC 1 /**< Maximum number of transmit antennas. */
#define MAX_SUB_CARRIERS 256 /**< Maximum number of subcarriers. */
#define MAX_PILOTS 26 /**< Maximum number of pilots. */

typedef struct {
	double	re;
	double	im;
} wifi_number_t;

typedef INT wifi_streams_rssi_t[MAX_NR]; /**< RSSI in each of the received streams of the received frame. */
typedef wifi_number_t wifi_carrier_data_t[MAX_NR][MAX_NC]; /**< CSI data for each subcarrier over Nc and Nr. */
typedef wifi_carrier_data_t wifi_csi_matrix_t[MAX_SUB_CARRIERS]; /**< CSI data over 80MHz bandwidth. */
typedef UCHAR wifi_evm_data_t[MAX_NC][MAX_NR]; /**< EVM data. */
typedef wifi_evm_data_t wifi_evm_matrix_t[MAX_PILOTS]; /**< EVM matrix. */

/**
 * @brief This structure holds information about the Wi-Fi frame.
 */
typedef struct _wifi_frame_info
{
    UCHAR bw_mode; /**< Bandwidth mode.
                    * Bit 0-3: 0:20MHz; 1:40MHz; 2:80MHz; 3:160MHz.
                    * Bit 4: 80+80MHz.
                    * Bit 4-7: 0:11n; 1:11ac. */
    UCHAR mcs; /**< Modulation and Coding Scheme (MCS) index, encoded as 11ac numbering. */
    UCHAR Nr; /**< Number of antennas used to receive the frame. */
    UCHAR Nc; /**< Number of streams used to transmit the frame. */
    wifi_streams_rssi_t nr_rssi; /**< RSSI on each of Nr. */
    USHORT valid_mask; /**< Bit mask that determines which regions of CSI capture (tones) are valid. One bit represents a 20MHz chunk. */
    USHORT phy_bw; /**< VAP bandwidth at the time of capture, indicated as 20, 40, 80, 160. */
    USHORT cap_bw; /**< Frame bandwidth at the time of capture. */
    UINT num_sc; /**< Number of subcarriers in the payload. */
    UCHAR decimation; /**< Value to indicate the degree to which the CSI matrix is decimated in terms of the number of subcarriers present. */
    UINT channel; /**< Primary channel of the received frame. */
    INT cfo; /**< Center frequency offset when demodulated. */
    ULLONG time_stamp; /**< PHY timestamp of CSI capture with at least millisecond resolution.
                        * Ideally, this can be resolved to a standard epoch format with millisecond resolution. */
} wifi_frame_info_t;

/**
 * @brief This structure holds information about the Wi-Fi CSI data.
 */
typedef struct _wifi_csi_data
{
    wifi_frame_info_t frame_info; /**< Frame information. */
    wifi_csi_matrix_t csi_matrix; /**< CSI matrix. The NC value representing the number of non-zero columns in the H matrix is equal to the number of spatial streams in the packet.
                                    * The NR value representing the number of rows in the H matrix is equal to the number of antennas at the receiver.
                                    * Irrespective of the NC and NR values, the output H matrix is always of size 4x4.
                                    * For example, if the frame uses 2 spatial streams and the receiver has 3 antennas, NC=2, NR=3.
                                    * However, the H matrix will be of size 4x4 with a 3x2 sub-matrix with non-zero values. The rest of the values of the matrix will be zero. */
    wifi_evm_matrix_t evm_matrix; /**< EVM matrix. Similar scheme to the CSI matrix, Nc represents the number of non-zero columns and Nr represents the number of nonzero rows.
                                    * There are 16 elements to accommodate the full number of pilots in a 160MHz capture. Each element is an EVM value for a pilot expressed in dB. */
} wifi_csi_data_t;

/**
 * @brief Information about an associated device.
 */
typedef struct _wifi_associated_dev3
{
    mac_address_t cli_MACAddress; /**< The MAC address of an associated device. */
    CHAR cli_IPAddress[64]; /**< IP address of the associated device (deprecated, keep it empty). */
    BOOL cli_AuthenticationState; /**< Whether an associated device has authenticated (true) or not (false). */
    UINT cli_LastDataDownlinkRate; /**< The median PHY rate in Mbps of the most recent 16 unicast data frame transmissions from the access point to the associated device. */
    UINT cli_LastDataUplinkRate; /**< The median PHY rate in Mbps of the most recent 16 unicast data frame transmissions from the associated device to the access point. */
    INT cli_SignalStrength; /**< An indicator of radio signal strength of the uplink from the associated device to the access point, measured in dBm, as an average of the last 100 packets received from the device. */
    UINT cli_Retransmissions; /**< The number of packets that had to be re-transmitted, from the last 100 packets sent to the associated device. Multiple re-transmissions of the same packet count as one. */
    BOOL cli_Active; /**< Whether or not this node is currently present in the WiFi AccessPoint network. */
    CHAR cli_OperatingStandard[64]; /**< Radio standard the associated Wi-Fi client device is operating under. Enumeration of: */
    CHAR cli_OperatingChannelBandwidth[64]; /**< The operating channel bandwidth of the associated device. The channel bandwidth (applicable to 802.11n and 802.11ac specifications only). Enumeration of: */
    INT cli_SNR; /**< A signal-to-noise ratio (SNR) compares the level of the Wi-Fi signal to the level of background noise. Sources of noise can include microwave ovens, cordless phone, bluetooth devices, wireless video cameras, wireless game controllers, fluorescent lights and more. It is measured in decibels (dB). */
    CHAR cli_InterferenceSources[64]; /**< Wi-Fi operates in two frequency ranges (2.4 Ghz and 5 Ghz) which may become crowded with other radio products that operate in the same ranges.
                                         * This parameter reports the probable interference sources that this Wi-Fi access point may be observing. The value of this parameter is a comma-separated list of the following possible sources:
                                         * e.g., MicrowaveOven,CordlessPhone,BluetoothDevices,FluorescentLights,ContinuousWaves,Others. */
    ULONG cli_DataFramesSentAck; /**< The DataFramesSentAck parameter indicates the total number of MSDU frames marked as duplicates and non-duplicates acknowledged.
                                    * The value of this counter may be reset to zero when the CPE is rebooted. Refer to section A.2.3.14 of the CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_DataFramesSentNoAck; /**< The DataFramesSentNoAck parameter indicates the total number of MSDU frames retransmitted out of the interface (i.e., marked as duplicate and non-duplicate)
                                     * and not acknowledged, but does not exclude those defined in the DataFramesLost parameter. The value of this counter may be reset to zero when the CPE is rebooted.
                                     * Refer to section A.2.3.14 of the CableLabs Wi-Fi MGMT Specification. */
    ULONG cli_BytesSent; /**< The total number of bytes transmitted to the client device, including framing characters. */
    ULONG cli_BytesReceived; /**< The total number of bytes received from the client device, including framing characters. */
    INT cli_RSSI; /**< The Received Signal Strength Indicator (RSSI) parameter is the energy observed at the antenna receiver for transmissions from the device averaged over the past 100 packets received from the device. */
    INT cli_MinRSSI; /**< The Minimum Received Signal Strength Indicator (RSSI) parameter is the minimum energy observed at the antenna receiver for past transmissions (100 packets). */
    INT cli_MaxRSSI; /**< The Maximum Received Signal Strength Indicator (RSSI) parameter is the energy observed at the antenna receiver for past transmissions (100 packets). */
    UINT cli_Disassociations; /**< This parameter represents the total number of client disassociations. Reset the parameter every 24hrs or reboot. */
    UINT cli_AuthenticationFailures; /**< This parameter indicates the total number of authentication failures. Reset the parameter every 24hrs or reboot. */
    ULLONG cli_Associations; /**< Stats handle used to determine reconnects; increases for every association (stat delta calculation). */
    ULONG cli_PacketsSent; /**< The total number of packets transmitted to the Associated Device. */
    ULONG cli_PacketsReceived; /**< The total number of packets received from the Associated Device. */
    ULONG cli_ErrorsSent; /**< The total number of outbound packets that could not be transmitted because of errors. These might be due to the number of retransmissions exceeding the retry limit, or from other causes. */
    ULONG cli_RetransCount; /**< The total number of transmitted packets that were retransmissions for each client on the vAP.
                             * Two retransmissions of the same packet result in this counter incrementing by two. Three retransmissions of the same packet result in this counter incrementing by three, and so on. */
    ULONG cli_FailedRetransCount; /**< The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit. */
    ULONG cli_RetryCount; /**< The number of packets that were successfully transmitted after one or more retransmissions. */
    ULONG cli_MultipleRetryCount; /**< The number of packets that were successfully transmitted after more than one retransmission. */
    UINT cli_MaxDownlinkRate; /**< The maximum data transmit rate in Mbps for the access point to the associated device. */
    UINT cli_MaxUplinkRate; /**< The maximum data transmit rate in Mbps for the associated device to the access point. */
    wifi_dl_mu_stats_t cli_DownlinkMuStats; /**< Downlink MU statistics. */
    wifi_ul_mu_stats_t cli_UplinkMuStats; /**< Uplink MU statistics. */
    wifi_twt_dev_info_t cli_TwtParams; /**< TWT sessions that the device has joined. */

    /* To facilitate retrieval of CSI data for a specific associated client, an existing RDK-B Wi-Fi HAL
     * function is being extended. In the current implementation, `wifi_getApAssociatedDeviceDiagnosticResult3`
     * retrieves a variety of statistics and state-specific information for associated clients.
     * The `wifi_associated_dev3_t` data structure is filled by native WLAN drivers for each associated client
     * as and when the function is called by the RDK-B application/process. A new component structure,
     * `wifi_csi_data_t`, is being defined that is part of the `wifi_associated_dev3_t` structure and needs to be
     * allocated and filled for a specific client or list of clients when
     * `wifi_getApAssociatedDeviceDiagnosticResult3` API is called by the RDK-B application/process. In cases when
     * the application needs CSI data, the RDK-B application will call
     * `INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)`
     * by allocating the `associated_dev_array` memory for `output_array_size` number of client
     * devices. In other words, `output_array_size` will specify the number of client devices in the array for
     * which CSI data needs to be filled by the driver. The `cli_MACAddress` will specify the client devices in each
     * of `wifi_associated_dev3_t`. The Wi-Fi HAL implementation in such a case MUST allocate memory for `cli_CSIData`
     * and fill in the required fields. The caller in such cases is responsible for deallocating the memory.
     * The `wifi_csi_data_t` is defined above. */
    wifi_csi_data_t *cli_CsiData;

    UINT cli_activeNumSpatialStreams; /**< The number of active spatial streams in the session between the AP and client at the moment of polling. */
    ULLONG cli_TxFrames; /**< The total number of frames transmitted to the client. */
    ULLONG cli_RxRetries; /**< Number of RX retries. */
    ULLONG cli_RxErrors; /**< Number of RX errors. */
    BOOL cli_MLDEnable; /* Indicates whether the connected client uses a single link or multi-link connections, false - single link and true - multi-link. */
    mac_address_t cli_MLDAddr; /* Indicates the MLD MAC address of the connected client, 00's for non-Wi-Fi 7 clients. */
} wifi_associated_dev3_t;

/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/**
 * @brief Gets the HAL capabilities.
 *
 * This function returns the features and configuration supported by the HAL.
 *
 * @param[out] cap  Pointer to a `wifi_hal_capability_t` structure to store the
 *                  HAL capabilities.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If a generic error is detected.
 */
INT wifi_getHalCapability(wifi_hal_capability_t *cap);

/**
 * @brief Performs a factory reset of the Wi-Fi subsystem.
 *
 * This function clears internal variables to implement a factory reset of
 * the Wi-Fi subsystem.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_factoryReset();

/**
 * @brief Sets the system LED status.
 *
 * @param[in] radioIndex Index of the Wi-Fi radio channel.
 * @param[in] enable     Whether to enable or disable the LED.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_setLED(INT radioIndex, BOOL enable);

/**
 * @brief Initializes all Wi-Fi radios.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_init();

/**
 * @brief Resets the Wi-Fi subsystem.
 *
 * This function resets the Wi-Fi subsystem, including all Access Point
 * variables.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_reset();

/**
 * @brief Turns off transmit power for the entire Wi-Fi subsystem.
 *
 * This function turns off transmit power for all radios in the Wi-Fi
 * subsystem.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_down();

/**
 * @brief Creates initial Wi-Fi configuration files.
 *
 * This function creates Wi-Fi configuration files. The format and content
 * of these files are implementation-dependent.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_createInitialConfigFiles();

/**
 * @brief Creates hostapd configuration variables.
 *
 * This function creates configuration variables needed for WPA/WPS. These
 * variables are implementation-dependent and, in some implementations, are
 * used by `hostapd` when it is started.
 *
 * @param[in] apIndex      Access Point index.
 * @param[in] createWpsCfg Whether to create WPS configuration variables.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg);

/**
 * @brief Starts hostapd.
 *
 * This function starts `hostapd`, using the variables in the `hostapd`
 * configuration.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_startHostApd();

/**
 * @brief Stops hostapd.
 *
 * @returns The status of the operation.
 * @retval WIFI_HAL_SUCCESS If successful.
 * @retval WIFI_HAL_ERROR   If any error is detected.
 */
INT wifi_stopHostApd();

/** @} */  //END OF GROUP WIFI_HAL_APIS

#ifdef __cplusplus
}
#endif

#endif
