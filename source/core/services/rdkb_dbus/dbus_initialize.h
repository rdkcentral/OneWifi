#ifndef DBUS_INITIALIZE_H
#define DBUS_INITIALIZE_H

#include "rdkb_dbus/list.h"
#include "rdkb_dbus/ssid.h"
#include <dbus/dbus.h>
#include "common/ieee802_11_defs.h"

#define IEEE80211_CAP_ESS       0x0001
#define IEEE80211_CAP_IBSS      0x0002
#define IEEE80211_CAP_PRIVACY   0x0010
#define IEEE80211_CAP_RRM       0x1000

/* DMG (60 GHz) IEEE 802.11ad */
/* type - bits 0..1 */
#define IEEE80211_CAP_DMG_MASK  0x0003
#define IEEE80211_CAP_DMG_IBSS  0x0001 /* Tx by: STA */
#define IEEE80211_CAP_DMG_PBSS  0x0002 /* Tx by: PCP */
#define IEEE80211_CAP_DMG_AP    0x0003 /* Tx by: AP */

#define WPAS_DBUS_OBJECT_PATH_MAX		150
#define WPAS_DBUS_INTERFACE_MAX			150
#define WPAS_DBUS_METHOD_SIGNAL_PROP_MAX 	50
#define WPAS_DBUS_AUTH_MODE_MAX			64

#define WPAS_DBUS_TYPE_BINARRAY ((int) '@')



#define WPA_SELECTOR_LEN 4
#define WPA_VERSION 1
#define RSN_SELECTOR_LEN 4
#define RSN_VERSION 1

/* IEEE 802.11i */
#define PMKID_LEN 16
#define PMK_LEN 32
#define PMK_LEN_SUITE_B_192 48
#define PMK_LEN_MAX 64
#define WPA_REPLAY_COUNTER_LEN 8
#define WPA_NONCE_LEN 32
#define WPA_KEY_RSC_LEN 8
#define WPA_GMK_LEN 32
#define WPA_GTK_MAX_LEN 32
#define WPA_PASN_PMK_LEN 32
#define WPA_PASN_MAX_MIC_LEN 24
#define WPA_MAX_RSNXE_LEN 4

#define OWE_DH_GROUP 19

#define RSN_SELECTOR(a, b, c, d) \
        ((((u32) (a)) << 24) | (((u32) (b)) << 16) | (((u32) (c)) << 8) | \
         (u32) (d))

#define RSN_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_AUTH_KEY_MGMT_FT_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 3)
#define RSN_AUTH_KEY_MGMT_FT_PSK RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_AUTH_KEY_MGMT_802_1X_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 5)
#define RSN_AUTH_KEY_MGMT_PSK_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 6)
#define RSN_AUTH_KEY_MGMT_TPK_HANDSHAKE RSN_SELECTOR(0x00, 0x0f, 0xac, 7)
#define RSN_AUTH_KEY_MGMT_SAE RSN_SELECTOR(0x00, 0x0f, 0xac, 8)
#define RSN_AUTH_KEY_MGMT_FT_SAE RSN_SELECTOR(0x00, 0x0f, 0xac, 9)
#define RSN_AUTH_KEY_MGMT_802_1X_SUITE_B RSN_SELECTOR(0x00, 0x0f, 0xac, 11)
#define RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192 RSN_SELECTOR(0x00, 0x0f, 0xac, 12)
#define RSN_AUTH_KEY_MGMT_FT_802_1X_SHA384 RSN_SELECTOR(0x00, 0x0f, 0xac, 13)
#define RSN_AUTH_KEY_MGMT_FILS_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 14)
#define RSN_AUTH_KEY_MGMT_FILS_SHA384 RSN_SELECTOR(0x00, 0x0f, 0xac, 15)
#define RSN_AUTH_KEY_MGMT_FT_FILS_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 16)
#define RSN_AUTH_KEY_MGMT_FT_FILS_SHA384 RSN_SELECTOR(0x00, 0x0f, 0xac, 17)
#define RSN_AUTH_KEY_MGMT_OWE RSN_SELECTOR(0x00, 0x0f, 0xac, 18)

#define RSN_AUTH_KEY_MGMT_PASN RSN_SELECTOR(0x00, 0x0f, 0xac, 21)

#define RSN_AUTH_KEY_MGMT_CCKM RSN_SELECTOR(0x00, 0x40, 0x96, 0x00)
#define RSN_AUTH_KEY_MGMT_OSEN RSN_SELECTOR(0x50, 0x6f, 0x9a, 0x01)
#define RSN_AUTH_KEY_MGMT_DPP RSN_SELECTOR(0x50, 0x6f, 0x9a, 0x02)

#define RSN_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x0f, 0xac, 0)
#define RSN_CIPHER_SUITE_WEP40 RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#if 0
#define RSN_CIPHER_SUITE_WRAP RSN_SELECTOR(0x00, 0x0f, 0xac, 3)
#endif
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_CIPHER_SUITE_WEP104 RSN_SELECTOR(0x00, 0x0f, 0xac, 5)
#define RSN_CIPHER_SUITE_AES_128_CMAC RSN_SELECTOR(0x00, 0x0f, 0xac, 6)
#define RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED RSN_SELECTOR(0x00, 0x0f, 0xac, 7)
#define RSN_CIPHER_SUITE_GCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 8)
#define RSN_CIPHER_SUITE_GCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 9)
#define RSN_CIPHER_SUITE_CCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 10)
#define RSN_CIPHER_SUITE_BIP_GMAC_128 RSN_SELECTOR(0x00, 0x0f, 0xac, 11)
#define RSN_CIPHER_SUITE_BIP_GMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 12)
#define RSN_CIPHER_SUITE_BIP_CMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 13)
#define RSN_CIPHER_SUITE_SMS4 RSN_SELECTOR(0x00, 0x14, 0x72, 1)
#define RSN_CIPHER_SUITE_CKIP RSN_SELECTOR(0x00, 0x40, 0x96, 0)
#define RSN_CIPHER_SUITE_CKIP_CMIC RSN_SELECTOR(0x00, 0x40, 0x96, 1)
#define RSN_CIPHER_SUITE_CMIC RSN_SELECTOR(0x00, 0x40, 0x96, 2)
/* KRK is defined for nl80211 use only */
#define RSN_CIPHER_SUITE_KRK RSN_SELECTOR(0x00, 0x40, 0x96, 255)

void* dbus_initialize(void* arg);
int notify_scanning(int num);


#define ETH_ALEN 6
#define SSID_MAX_LEN                32

typedef struct scan_list_bss_info {
    uint32_t network_ssid_id;
    int vap_index;
    int radio_index;
    wifi_bss_info_t external_ap;
    char password[64];
} scan_list_bss_info_t;


typedef struct network_mgr_cfg {
    uint32_t scan_ssid;
    char ssid[32];
    char security_type[32];
    char password[64];
    char bgscan[64];
} network_mgr_cfg_t;

/**             
 * struct wpa_bss - BSS table
 *      
 * This structure is used to store information about neighboring BSSes in
 * generic format. It is mainly updated based on scan results from the driver.
 */     
struct wpa_bss { 
        /** List entry for struct wpa_supplicant::bss */
        struct dl_list list;
        /** List entry for struct wpa_supplicant::bss_id */
        struct dl_list list_id;
        /** Unique identifier for this BSS entry */
        unsigned int id;
        /** Number of counts without seeing this BSS */
        unsigned int scan_miss_count;
        /** Index of the last scan update */
        unsigned int last_update_idx;
        /** Information flags about the BSS/IBSS (WPA_BSS_*) */
        unsigned int flags;
        /** BSSID */
        uint8_t bssid[ETH_ALEN];
        /** HESSID */
        uint8_t hessid[ETH_ALEN];
        /** SSID */
        uint8_t ssid[SSID_MAX_LEN];
        /** Length of SSID */
        size_t ssid_len;
        /** Frequency of the channel in MHz (e.g., 2412 = channel 1) */
        int freq;
        /** Beacon interval in TUs (host byte order) */
        uint16_t beacon_int;
        /** Capability information field in host byte order */
        uint16_t caps;
        /** Signal quality */
        int qual;
        /** Noise level */
        int noise;
        /** Signal level */
        int level;
        /** Timestamp of last Beacon/Probe Response frame */
        uint64_t tsf;
        /** Whether the Beacon frame data is known to be newer */
        bool beacon_newer;
        /** Time of the last update (i.e., Beacon or Probe Response RX) */
//        struct os_reltime last_update;
        /** Estimated throughput in kbps */
        unsigned int est_throughput;
        /** Signal-to-noise ratio in dB */
        int snr;
        /** ANQP data */
        struct wpa_bss_anqp *anqp;
        /** Length of the following IE field in octets (from Probe Response) */
        size_t ie_len;
        /** Length of the following Beacon IE field in octets */
        size_t beacon_ie_len;
        /* followed by ie_len octets of IEs */
        /* followed by beacon_ie_len octets of IEs */
        uint8_t *ies;
        scan_list_bss_info_t  scan_bss_info;
};

struct wpa_supplicant {
	char dbus_new_path[WPAS_DBUS_OBJECT_PATH_MAX];
	char ifname[32];
        unsigned int bss_next_id;
        unsigned int bss_update_idx;
        struct dl_list bss; /* struct wpa_bss::list */
        struct dl_list bss_id; /* struct wpa_bss::list_id */
        size_t num_bss;
        scan_list_bss_info_t  *p_scan_bss_info;
};

struct network_handler_args {
        struct wpa_supplicant *wpa_s;
        //struct wpa_ssid *ssid;
        scan_list_bss_info_t  *scan_bss_info;
};

struct bss_handler_args {
        struct wpa_supplicant *wpa_s;
        unsigned int id;
};

struct sta_handler_args {
        struct wpa_supplicant *wpa_s;
        const u8 *sta;
};

struct wpa_dbus_dict_entry {
        int type;         /** the dbus type of the dict entry's value */
        int array_type;   /** the dbus type of the array elements if the dict
                              entry value contains an array, or the special
                              WPAS_DBUS_TYPE_BINARRAY */
        const char *key;  /** key of the dict entry */

        /** Possible values of the property */
        union {
                char *str_value;
                char byte_value;
                dbus_bool_t bool_value;
                dbus_int16_t int16_value;
                dbus_uint16_t uint16_value;
                dbus_int32_t int32_value;
                dbus_uint32_t uint32_value;
                dbus_int64_t int64_value;
                dbus_uint64_t uint64_value;
                double double_value;
                char *bytearray_value;
                char **strarray_value;
                struct wpabuf **binarray_value;
        };
        dbus_uint32_t array_len; /** length of the array if the dict entry's
                                     value contains an array */
};
struct wpa_ie_data {
        int proto;
        int pairwise_cipher;
        int has_pairwise;
        int group_cipher;
        int has_group;
        int key_mgmt;
        int capabilities;
        size_t num_pmkid;
        const u8 *pmkid;
        int mgmt_group_cipher;
};

struct rsn_ie_hdr {
        u8 elem_id; /* WLAN_EID_RSN */
        u8 len;
        u8 version[2]; /* little endian */
};


#endif

