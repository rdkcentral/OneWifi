/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2021 RDK Management

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

/*************************************************************************
Some material from:
  Copyright (c) 2010, Atheros Communications Inc.
  Licensed under the ISC License
and
  Copyright (c) 2001 Atsushi Onoe
  Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
  All rights reserved.
  Licensed under the BSD-3 License
**************************************************************************/

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "common/sae.h"
#include "common/dpp.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "radius/radius_das.h"
#include "p2p/p2p.h"
#include "fst/fst.h"
#include "crypto/crypto.h"
#include "crypto/tls.h"
#include "hostapd.h"
#include "accounting.h"
#include "ieee802_1x.h"
#include "ieee802_11.h"
#include "ieee802_11_auth.h"
#include "wpa_auth.h"
#include "preauth_auth.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "beacon.h"
#include "ap_mlme.h"
#include "vlan_init.h"
#include "p2p_hostapd.h"
#include "gas_serv.h"
#include "wnm_ap.h"
#include "mbo_ap.h"
#include "ndisc_snoop.h"
#include "sta_info.h"
#include "vlan.h"
#include "wps_hostapd.h"
#include "hostapd/ctrl_iface.h"
#include "wifi_hal.h"
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include "l2_packet/l2_packet.h"
#include "drivers/netlink.h"
#include <linux/wireless.h>	//taken care here net/if.h, removed linux_wext.h
#include <asm/byteorder.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <time.h>
//#include "ieee80211_ioctl.h"

#if defined (_XB7_PRODUCT_REQ_)
#include "drivers/driver_nl80211.h"
#include "hostapd/config_file.h"
#endif

//logger
#define HOSTAPD_LOG_FILE_PATH "/tmp/hostap_auth.txt"

#define ecw2cw(ecw) ((1 << (ecw)) - 1)
#define IEEE80211_IOCTL_SETPARAM        (SIOCIWFIRSTPRIV+0)
#define IEEE80211_IOCTL_SETKEY      (SIOCIWFIRSTPRIV+2)
#define IEEE80211_IOCTL_DELKEY      (SIOCIWFIRSTPRIV+4)
#define IEEE80211_IOCTL_SETMLME     (SIOCIWFIRSTPRIV+6)
#define IEEE80211_IOCTL_SET_APPIEBUF    (SIOCIWFIRSTPRIV+20)
#define IEEE80211_IOCTL_FILTERFRAME (SIOCIWFIRSTPRIV+22)
#define IEEE80211_IOCTL_SEND_MGMT (SIOCIWFIRSTPRIV+26)
#define IEEE80211_IOCTL_STA_INFO    (SIOCDEVPRIVATE+6)
#define IEEE80211_PARAM_SSID_STATUS           452
#define IEEE80211_IOCTL_ADDMAC          (SIOCIWFIRSTPRIV+10)        /* Add ACL MAC Address */
#define IEEE80211_IOCTL_DELMAC          (SIOCIWFIRSTPRIV+12)        /* Del ACL MAC Address */
#define IEEE80211_IOCTL_GETPARAM        (SIOCIWFIRSTPRIV+1)
#define IEEE80211_IOCTL_KICKMAC         (SIOCIWFIRSTPRIV+15)

#define IEEE80211_AUTH_OPEN     1
#define IEEE80211_AUTH_SHARED   2 /* shared-key */
#define IEEE80211_AUTH_8021X    3
#define IEEE80211_AUTH_AUTO     4
#define IEEE80211_AUTH_WPA      5


#define IEEE80211_KEYBUF_SIZE   32 
#define IEEE80211_MICBUF_SIZE   (8+8)   /* space for both tx+rx keys */

#define COSA_DML_WIFI_STR_LENGTH_64  64
#define COSA_DML_WIFI_STR_LENGTH_128 128
#define COSA_DML_WIFI_STR_LENGTH_256 256

#define LIST_STATION_ALLOC_SIZE 32*1024
#define IEEE80211_RATE_MAXSIZE  44              /* max rates we'll handle */

#define DEFAULT_WPA_DISABLE_EAPOL_KEY_RETRIES 0
#define RADIUS_CLIENT_MAX_RETRIES 5
#define RADIUS_CLIENT_MAX_WAIT 120

 /*
  * Cipher types.
  * NB: The values are preserved here to maintain binary compatibility
  * with applications like wpa_supplicant and hostapd.
  */
 typedef enum _ieee80211_cipher_type {
     IEEE80211_CIPHER_WEP          = 0,
     IEEE80211_CIPHER_TKIP         = 1,
     IEEE80211_CIPHER_AES_OCB      = 2,
     IEEE80211_CIPHER_AES_CCM      = 3,
     IEEE80211_CIPHER_WAPI         = 4,
     IEEE80211_CIPHER_CKIP         = 5,
     IEEE80211_CIPHER_AES_CMAC     = 6,
     IEEE80211_CIPHER_AES_CCM_256  = 7,
     IEEE80211_CIPHER_AES_CMAC_256 = 8,
     IEEE80211_CIPHER_AES_GCM      = 9,
     IEEE80211_CIPHER_AES_GCM_256  = 10,
     IEEE80211_CIPHER_AES_GMAC     = 11,
     IEEE80211_CIPHER_AES_GMAC_256 = 12,
     IEEE80211_CIPHER_NONE         = 13,
 } ieee80211_cipher_type;


#define IEEE80211_KEY_XMIT  0x01    /* key used for xmit */
#define IEEE80211_KEY_RECV  0x02    /* key used for recv */
#define IEEE80211_KEYIX_NONE ((u_int16_t) -1)

#define IEEE80211_PARAM_AUTHMODE     3
#define      IEEE80211_PARAM_MCASTCIPHER  5    /* multicast/default cipher */
#define      IEEE80211_PARAM_MCASTKEYLEN  6    /* multicast key length */
#define      IEEE80211_PARAM_UCASTCIPHERS     7    /* unicast cipher suites */
#define IEEE80211_PARAM_WPA     10   /* WPA mode (0,1,2) */
#define         IEEE80211_PARAM_PRIVACY         13   /* privacy invoked */
#define      IEEE80211_PARAM_KEYMGTALGS  21   /* key management algorithms */
#define      IEEE80211_PARAM_RSNCAPS     22   /* RSN capabilities */

#define IEEE80211_REASON_AUTH_LEAVE         3

#define SIOC80211IFCREATE  (SIOCDEVPRIVATE+7)
#define SIOC80211IFDESTROY      (SIOCDEVPRIVATE+8)

#define IEEE80211_MLME_DEAUTH       3
#define IEEE80211_MAX_OPT_IE    512
#define IEEE80211_NWID_LEN 32

#define IEEE80211_CLONE_BSSID           0x0001  /* allocate unique mac/bssid */

#define IEEE80211_ADDR_LEN 6

/* added APPIEBUF related definations */
#define    IEEE80211_APPIE_FRAME_BEACON      0
#define    IEEE80211_APPIE_FRAME_PROBE_REQ   1
#define    IEEE80211_APPIE_FRAME_PROBE_RESP  2
#define    IEEE80211_APPIE_FRAME_ASSOC_REQ   3
#define    IEEE80211_APPIE_FRAME_ASSOC_RESP  4

#define ETH_P_80211_RAW 0x0019

enum ieee80211_opmode {
    IEEE80211_M_STA         = 1,                 /* infrastructure station */
    IEEE80211_M_IBSS        = 0,                 /* IBSS (adhoc) station */
    IEEE80211_M_AHDEMO      = 3,                 /* Old lucent compatible adhoc demo */
    IEEE80211_M_HOSTAP      = 6,                 /* Software Access Point */
    IEEE80211_M_MONITOR     = 8,                 /* Monitor mode */
    IEEE80211_M_WDS         = 2,                 /* WDS link */
    IEEE80211_M_BTAMP       = 9,                 /* VAP for BT AMP */

    IEEE80211_M_P2P_GO      = 33,                /* P2P GO */
    IEEE80211_M_P2P_CLIENT  = 34,                /* P2P Client */
    IEEE80211_M_P2P_DEVICE  = 35,                /* P2P Device */


    IEEE80211_OPMODE_MAX    = IEEE80211_M_BTAMP, /* Highest numbered opmode in the list */

    IEEE80211_M_ANY         = 0xFF               /* Any of the above; used by NDIS 6.x */
};

enum {
    IEEE80211_FILTER_TYPE_BEACON      =   0x1,
    IEEE80211_FILTER_TYPE_PROBE_REQ   =   0x2,
    IEEE80211_FILTER_TYPE_PROBE_RESP  =   0x4,
    IEEE80211_FILTER_TYPE_ASSOC_REQ   =   0x8,
    IEEE80211_FILTER_TYPE_ASSOC_RESP  =   0x10,
    IEEE80211_FILTER_TYPE_AUTH        =   0x20,
    IEEE80211_FILTER_TYPE_DEAUTH      =   0x40,
    IEEE80211_FILTER_TYPE_DISASSOC    =   0x80,
    IEEE80211_FILTER_TYPE_ACTION      =   0x100,
    IEEE80211_FILTER_TYPE_ALL         =   0xFFF  /* used to check the valid filter bits */
};

struct driver_data {
    struct hostapd_data *hapd;      /* back pointer */
    char    iface[IFNAMSIZ + 1];
    int     ifindex;
    struct l2_packet_data *sock_xmit;   /* raw packet xmit socket */
    struct l2_packet_data *sock_recv;   /* raw packet recv socket */
    int ioctl_sock;         /* socket for ioctl() use */
    struct netlink_data *netlink;
    int we_version;
    int fils_en;            /* FILS enable/disable in driver */
    u8  acct_mac[ETH_ALEN];
    struct hostap_sta_driver_data acct_data;
    struct l2_packet_data *sock_raw; /* raw 802.11 management frames */
    struct wpabuf *wpa_ie;
    struct wpabuf *wps_beacon_ie;
    struct wpabuf *wps_probe_resp_ie;
    u8  own_addr[ETH_ALEN];
};

#if defined (_XB7_PRODUCT_REQ_)
typedef struct {
    struct hostapd_data         *hapd;
    struct wpa_driver_ops       driver_ops[0];
    struct hostapd_iface        *iface;
    struct hostapd_config       *conf;
    struct hostapd_bss_config   *bss_conf;
    struct hapd_interfaces      interfaces;
} wifi_hapd_glue_t;

wifi_hapd_glue_t g_hapd_glue[MAX_VAP];
#else
typedef struct {
    struct hostapd_data 	hapd;
    struct wpa_driver_ops	driver_ops[0];
    struct hostapd_iface	iface;
    struct hostapd_config	conf;
    struct hostapd_bss_config	bss_conf;
} wifi_hapd_glue_t;

wifi_hapd_glue_t  g_hapd_glue[MAX_VAP];
#endif

struct ieee80211req_mgmtbuf {
    u_int8_t  macaddr[IEEE80211_ADDR_LEN]; /* mac address to be sent */
    u_int32_t buflen;  /*application supplied buffer length */
    u_int8_t  buf[];
};

struct ieee80211req_mlme {
    u_int8_t    im_op;      /* operation to perform */
#define IEEE80211_MLME_ASSOC        1   /* associate station */
#define IEEE80211_MLME_DISASSOC     2   /* disassociate station */
#define IEEE80211_MLME_DEAUTH       3   /* deauthenticate station */
#define IEEE80211_MLME_AUTHORIZE    4   /* authorize station */
#define IEEE80211_MLME_UNAUTHORIZE  5   /* unauthorize station */
#define IEEE80211_MLME_STOP_BSS     6   /* stop bss */
#define IEEE80211_MLME_CLEAR_STATS  7   /* clear station statistic */
#define IEEE80211_MLME_AUTH         8   /* auth resp to station */
#define IEEE80211_MLME_REASSOC          9   /* reassoc to station */
    u_int8_t    im_ssid_len;    /* length of optional ssid */
    u_int16_t   im_reason;  /* 802.11 reason code */
    u_int16_t   im_seq;         /* seq for auth */
    u_int8_t    im_macaddr[IEEE80211_ADDR_LEN];
    u_int8_t    im_ssid[IEEE80211_NWID_LEN];
    u_int8_t        im_optie[IEEE80211_MAX_OPT_IE];
    u_int16_t       im_optie_len;
};


/*
 * Delete a key either by index or address.  Set the index
 * to IEEE80211_KEYIX_NONE when deleting a unicast key.
 */
struct ieee80211req_del_key {
    u_int8_t    idk_keyix;  /* key index */
    u_int8_t    idk_macaddr[IEEE80211_ADDR_LEN];
};

struct ieee80211req_set_filter {
    u_int32_t app_filterype; /* management frame filter type */
};

struct ieee80211_clone_params {
    char        icp_name[IFNAMSIZ]; /* device name */
    u_int16_t   icp_opmode;     /* operating mode */
    u_int32_t   icp_flags;      /* see IEEE80211_CLONE_BSSID for e.g */
    u_int8_t icp_bssid[IEEE80211_ADDR_LEN];    /* optional mac/bssid address */
    int32_t         icp_vapid;             /* vap id for MAC addr req */
    u_int8_t icp_mataddr[IEEE80211_ADDR_LEN];    /* optional MAT address */
};

struct ieee80211req_key {
    u_int8_t    ik_type;    /* key/cipher type */
    u_int8_t    ik_pad;
    u_int16_t   ik_keyix;   /* key index */
    u_int8_t    ik_keylen;  /* key length in bytes */
    u_int8_t    ik_flags;
    /* NB: IEEE80211_KEY_XMIT and IEEE80211_KEY_RECV defined elsewhere */
#define IEEE80211_KEY_DEFAULT   0x80    /* default xmit key */
    u_int8_t    ik_macaddr[IEEE80211_ADDR_LEN];
    u_int64_t   ik_keyrsc;  /* key receive sequence counter */
    u_int64_t   ik_keytsc;  /* key transmit sequence counter */
    u_int8_t    ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
};

struct ieee80211req_getset_appiebuf {
    u_int32_t app_frmtype; /*management frame type for which buffer is added*/
    u_int32_t app_buflen;  /*application supplied buffer length */
    u_int8_t  identifier;
    u_int8_t  app_buf[];
};

void hostapd_notify_auth_ft_finish(void *ctx, const u8 *dst,
                       const u8 *bssid,
                       u16 auth_transaction, u16 status,
                       const u8 *ies, size_t ies_len);

struct ieee80211req_sta_info {
	u_int16_t       isi_len;                /* length (mult of 4) */
	u_int16_t       isi_freq;               /* MHz */
	u_int32_t   isi_flags;      /* channel flags */
	u_int16_t       isi_state;              /* state flags */
	u_int8_t        isi_authmode;           /* authentication algorithm */
	int8_t          isi_rssi;
	int8_t          isi_min_rssi;
	int8_t          isi_max_rssi;
	u_int16_t       isi_capinfo;            /* capabilities */
	u_int8_t        isi_athflags;           /* Atheros capabilities */
	u_int8_t        isi_erp;                /* ERP element */
	u_int8_t    isi_ps;         /* psmode */
	u_int8_t        isi_macaddr[IEEE80211_ADDR_LEN];

	u_int8_t        isi_nrates;
	/* negotiated rates */
	u_int8_t        isi_rates[IEEE80211_RATE_MAXSIZE];
	u_int8_t        isi_txrate;             /* index to isi_rates[] */
	u_int32_t   isi_txratekbps; /* tx rate in Kbps, for 11n */
	u_int16_t       isi_ie_len;             /* IE length */
	u_int16_t       isi_associd;            /* assoc response */
	u_int16_t       isi_txpower;            /* current tx power */
	u_int16_t       isi_vlan;               /* vlan tag */
	u_int16_t       isi_txseqs[17];         /* seq to be transmitted */
	u_int16_t       isi_rxseqs[17];         /* seq previous for qos frames*/
	u_int16_t       isi_inact;              /* inactivity timer */
	u_int8_t        isi_uapsd;              /* UAPSD queues */
	u_int8_t        isi_opmode;             /* sta operating mode */
	u_int8_t        isi_cipher;
	u_int32_t       isi_assoc_time;         /* sta association time */
	struct timespec isi_tr069_assoc_time;   /* sta association time in timespec format */


	u_int16_t   isi_htcap;      /* HT capabilities */
	u_int32_t   isi_rxratekbps; /* rx rate in Kbps */
	/* We use this as a common variable for legacy rates
	   and lln. We do not attempt to make it symmetrical
	   to isi_txratekbps and isi_txrate, which seem to be
	   separate due to legacy code. */
	/* XXX frag state? */
	/* variable length IE data */
	u_int8_t isi_maxrate_per_client; /* Max rate per client */
	u_int16_t   isi_stamode;        /* Wireless mode for connected sta */
	u_int32_t isi_ext_cap;              /* Extended capabilities */
	u_int8_t isi_nss;         /* number of tx and rx chains */
	u_int8_t isi_is_256qam;    /* 256 QAM support */
};

