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
  Copyright (c) 2004, Sam Leffler <sam@errno.com>
  Copyright (c) 2004, Video54 Technologies
  Copyright (c) 2005-2007, Jouni Malinen <j@w1.fi>
  Copyright (c) 2009, Atheros Communications
  Licensed under the BSD-3 License
**************************************************************************/

#include "cosa_wifi_apis.h"
#include "wifi_hostap_auth.h"

#ifdef QCAPATCH_ACLCHECK_HOSTAPD
typedef int (*wps_acl_get_t)(void *priv, char *buf, size_t buf_len);
#endif /* QCAPATCH_ACLCHECK_HOSTAPD */

/****************************************************
*           FUNCTION DEFINITION(S)                  *
****************************************************/
/* RDKB-30263 Grey List control from RADIUS
This function uses drive ioctl to fetch the SNR value of a client
@arg1 -ifname -Interface on which client associates
@arg2 - assoc_cli_mac - MAC address of connected client
Return value - SNR of the client
*/
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST) && !defined(_XB7_PRODUCT_REQ_)
typedef int (*rdk_greylist_add_del_mac_t)(int apIndex, unsigned char macaddr[ETH_ALEN], int add );

static u8 wifi_get_snr_value(char *ifname,unsigned char *assoc_cli_mac)
{

        unsigned char cli_macaddr[IEEE80211_ADDR_LEN+1]={0};
        int cli_SNR=0;
        int wlanIndex = -1;
        
        int wRet = wifi_getIndexFromName(ifname, &wlanIndex);
        if ( (wRet != RETURN_OK) || (wlanIndex <0) || (wlanIndex >= WIFI_INDEX_MAX) )
            return 1;

        wifi_associated_dev3_t *wifi_associated_dev_array=NULL, *sta_info=NULL;
        ULONG i=0, array_size=0;
        INT diagStatus = RETURN_ERR;

        //heap memory will be alloc in hal
        diagStatus = wifi_getApAssociatedDeviceDiagnosticResult3(wlanIndex, &wifi_associated_dev_array, (unsigned int *)&array_size);
        if(wifi_associated_dev_array && array_size>0 && diagStatus == RETURN_OK) {
            for (i = 0, sta_info = wifi_associated_dev_array; i < array_size; i++, sta_info++) {
                memcpy(cli_macaddr, sta_info->cli_MACAddress, IEEE80211_ADDR_LEN);
                if(strcmp((char *)assoc_cli_mac,(char *)cli_macaddr) ==0 ) {
                    cli_SNR = sta_info->cli_RSSI;
                    wpa_printf(MSG_DEBUG,"%s:%d SNR :%d\n", __func__, __LINE__,cli_SNR);
                    return cli_SNR;
                }
            }
            free(wifi_associated_dev_array);    //freeing heap memory allocated in hal
        } else {
            return 1;
        }
        return 0;
}
#endif //(FEATURE_SUPPORT_RADIUSGREYLIST)

/* Description:
 *      Convert unsigned char mac address to character array.
 * Arguments:
 *      addr - Unsigned char address.
 */
 const char *
ether_sprintf(const u8 *addr)
{
    static char buf[sizeof(MACSTR)];

    if (addr != NULL)
        os_snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
    else
        os_snprintf(buf, sizeof(buf), MACSTR, 0, 0, 0, 0, 0, 0);
    return buf;
}
/* Description:
 *     Callback API for sending EAPOL data frames to client.
 *     Will be called from lib hostap authenticator after necessary
 *     processing of other packets needed before sending EAPOL
 *     packets.
 *     Forumulate ETH headers based on STA information in hostap
 *     authenticator.
 * Arguments:
 *     priv - driver_data information from hostapd authenticator.
 *     addr - Destination mac address.
 *     data - EAPOL data frame
 *     data_len - EAPOL data frame length
 *     encrypt - Packet has to be encrypted or not.[Not used].
 *     own_addr - Source addr - athX interface address.
 *     flags - EAPOL Tx flags information.
 */
#if !defined (_XB7_PRODUCT_REQ_)
int send_eapol(void *priv, const u8 *addr, const u8 *data,
        size_t data_len, int encrypt,
        const u8 *own_addr, u32 flags)
{
    struct driver_data *drv = priv;
    unsigned char buf[3000];
    unsigned char *bp = buf;
    struct l2_ethhdr *eth;
    size_t len;
    int status;

    /*
     * Prepend the Ethernet header.  If the caller left us
     * space at the front we could just insert it but since
     * we don't know we copy to a local buffer.  Given the frequency
     * and size of frames this probably doesn't matter.
     */
    len = data_len + sizeof(struct l2_ethhdr);
    if (len > sizeof(buf)) {
        bp = malloc(len);
        if (bp == NULL) {
            wpa_printf(MSG_ERROR,
                    "EAPOL frame discarded, cannot malloc temp buffer of size %lu! \n",
                    (unsigned long) len);
            return -1;
        }
    }
    eth = (struct l2_ethhdr *) bp;
    memcpy(eth->h_dest, addr, ETH_ALEN);
    memcpy(eth->h_source, own_addr, ETH_ALEN);
    eth->h_proto = host_to_be16(ETH_P_EAPOL);
    memcpy(eth+1, data, data_len);

    wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

    /* Delay added as workaround for handling 500 clients group rekeying */
    os_sleep(0, 10000);
    status = wifi_hostApSendEther(drv->iface, bp, len, ETH_P_EAPOL);

    if (bp != buf)
        free(bp);
    return status;
}

/* Description:
 *     Callback API for receiving EAPOL frames, currently un-used.
 */
void
handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
#if 0
    struct driver_data *drv = ctx;
    eapol_rx(drv->hapd, src_addr, buf + sizeof(struct l2_ethhdr),
            len - sizeof(struct l2_ethhdr));
#endif
}

/* Description:
 *     Callback API for driver init.
 *     Used to allocate space for driver_data in hostapd struct.
 *     Set App filter in driver for receiving data/mgmt frames from driver
 *     to upper layer.
 * Arguments:
 *     hapd - Allocated hostapd struct pointer.
 *     params - Init params needed in hostap authenticator.
 */
void * drv_init(struct hostapd_data *hapd, struct wpa_init_params *params)
{
    struct driver_data *drv;

    drv = os_zalloc(sizeof(struct driver_data));
    if (drv == NULL) {
        wpa_printf(MSG_ERROR,
                "Could not allocate memory for driver data");
        return NULL;
    }

    drv->hapd = hapd;
    drv->ioctl_sock = -1;

    memcpy(drv->iface, params->ifname, sizeof(drv->iface));
    drv->ifindex = wifi_gethostIfIndex(drv->iface);
    _wifi_ioctl_hwaddr(drv->iface, params->own_addr);
    os_memcpy(drv->own_addr, params->own_addr, ETH_ALEN);
    wifi_setIfMode(drv->iface);

    /* mark down during setup */
    linux_set_iface_flags(drv->iface, 0);
    set_privacy(drv, 0); /* default to no privacy */

    if (hapd_receive_pkt(drv))
        goto bad;

    return drv;
bad:
    reset_appfilter(drv);
    os_free(drv);
    return NULL;
}

/* Description:
 *     Callback API for setting privacy mode to driver.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     enabled - Whether privacy is enabled/disabled.
 *     1 - Enable, 0 - Disable
 */
int set_privacy(void *priv, int enabled)
{
    struct driver_data *drv = priv;
    return wifi_sethostApPrivacy(drv->iface, enabled);
}

/* Description:
 *     Callback API for setting SSID for athX interface.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     buf - SSID name buffer.
 *     len - SSID name length
 */
 int set_ssid(void *priv, const u8 *buf, int len)
{
    struct driver_data *drv = priv;
    return wifi_setHostApIfSSID(drv->iface, buf, len);
}

/* Description:
 *     Callback API for sending deauth to specific/all STA in an interface.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     own_addr - Source mac address
 *     addr - Destination mac address.
 *     reason_code - Reason for sending deauth.
 */
 int
sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
        u16 reason_code)
{
    struct driver_data *drv = priv;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d\n",
            __func__, ether_sprintf(addr), reason_code);

    ret = wifi_sethostApStaDeauth(drv->iface, (unsigned char*)addr, (int)reason_code);
    if (ret < 0) {
        wpa_printf(MSG_ERROR, "%s: Failed to deauth STA (addr " MACSTR
                " reason %d)\n",
                __func__, MAC2STR(addr), reason_code);
    }

    return ret;
}

/* Description:
 *     Callback API to flush all the stations connected in an interface
 * Arguments:
 *     priv - driver_data struct pointer.
 */
 int
flush(void *priv)
{
    u8 allsta[IEEE80211_ADDR_LEN];
    memset(allsta, 0xff, IEEE80211_ADDR_LEN);
    return sta_deauth(priv, NULL, allsta,
            IEEE80211_REASON_AUTH_LEAVE);
}

/* Description:
 *     Callback API to delete stored key from driver interface.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     addr - STA address for which stored key has to be deleted.
 *     key_idx - Key index to be deleted.
 */
 int
del_key(void *priv, const u8 *addr, int key_idx)
{
    struct driver_data *drv = priv;
    int ret;

    ret = wifi_sethostApStaDelKey(drv->iface, (unsigned char*)addr, key_idx);
    if (ret < 0) {
        wpa_printf(MSG_ERROR, "%s: Failed to delete key (addr %s"
                " key_idx %d)", __func__, ether_sprintf(addr),
                key_idx);
    }

    return ret;
}

/* Description:
 *     Callback API to set key in driver interface for a station.
 * Arguments:
 *     ifname - athX interface name.
 *     priv - driver_data struct pointer.
 *     wpa_alg - Key algorithm to be used[determines cipher].
 *     addr - STA address for which stored key has to be deleted.
 *     key_idx - Key index to be deleted.
 *     set_tx - set/clear idx.
 *     seq - Sequence number of STA
 *     seq_len - sequence number length.
 *     key - key to be set.
 *     key_len - Length of the key
 */
int
set_key(const char *ifname, void *priv, enum wpa_alg alg,
        const u8 *addr, int key_idx, int set_tx, const u8 *seq,
        size_t seq_len, const u8 *key, size_t key_len)
{
    struct driver_data *drv = priv;
    struct ieee80211req_key wk;
    u_int8_t cipher;
    int ret;

    if (alg == WPA_ALG_NONE)
        return del_key(drv, addr, key_idx);

    wpa_printf(MSG_DEBUG, "%s: alg=%d addr=%s key_idx=%d key_len=%d set_tx=%d\n",
                    __func__, alg, ether_sprintf(addr), key_idx, key_len, set_tx);

    switch (alg) {
        case WPA_ALG_WEP:
            cipher = IEEE80211_CIPHER_WEP;
            break;
        case WPA_ALG_TKIP:
            cipher = IEEE80211_CIPHER_TKIP;
            break;
        case WPA_ALG_CCMP:
            cipher = IEEE80211_CIPHER_AES_CCM;
            break;
#ifdef ATH_GCM_SUPPORT
        case WPA_ALG_CCMP_256:
            cipher = IEEE80211_CIPHER_AES_CCM_256;
            break;
        case WPA_ALG_GCMP:
            cipher = IEEE80211_CIPHER_AES_GCM;
            break;
        case WPA_ALG_GCMP_256:
            cipher = IEEE80211_CIPHER_AES_GCM_256;
            break;
#endif /* ATH_GCM_SUPPORT */
#ifdef CONFIG_IEEE80211W
        case WPA_ALG_IGTK:
            cipher = IEEE80211_CIPHER_AES_CMAC;
            break;
#ifdef ATH_GCM_SUPPORT
        case WPA_ALG_BIP_CMAC_256:
            cipher = IEEE80211_CIPHER_AES_CMAC_256;
            break;
        case WPA_ALG_BIP_GMAC_128:
            cipher = IEEE80211_CIPHER_AES_GMAC;
            break;
        case WPA_ALG_BIP_GMAC_256:
            cipher = IEEE80211_CIPHER_AES_GMAC_256;
            break;
#endif /* ATH_GCM_SUPPORT */
#endif /* CONFIG_IEEE80211W */
        default:
            wpa_printf(MSG_ERROR, "%s: unknown/unsupported algorithm %d",
                    __func__, alg);
            return -1;
    }

    if (key_len > sizeof(wk.ik_keydata)) {
        wpa_printf(MSG_ERROR, "%s: key length %lu too big\n", __func__,
                (unsigned long) key_len);
        return -3;
    }

    ret = wifi_sethostApStaSetKey(drv->iface,  (unsigned char *)addr, (unsigned char *)key, key_len, key_idx, cipher, set_tx);
    if (ret < 0) {
        wpa_printf(MSG_ERROR, "%s: Failed to set key (addr %s"
                " key_idx %d alg %d key_len %lu set_tx %d)\n",
                __func__, ether_sprintf(addr), key_idx,
                alg, (unsigned long) key_len, set_tx);
    }

    return ret;
}

/* Description:
 *     Callback API to set auth mode to driver.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     auth_algs - WPA algorithm value.
 */
int set_authmode(void *priv, int auth_algs)
{
	struct driver_data *drv = priv;
    int authmode;

    if ((auth_algs & WPA_AUTH_ALG_OPEN) &&
            (auth_algs & WPA_AUTH_ALG_SHARED)) {
        authmode = IEEE80211_AUTH_AUTO;
    }
    else if (auth_algs & WPA_AUTH_ALG_OPEN) {
        authmode = IEEE80211_AUTH_OPEN;
    }
    else if (auth_algs & WPA_AUTH_ALG_SHARED) {
        authmode = IEEE80211_AUTH_SHARED;
    }
    else {
        wpa_printf(MSG_ERROR, "%s:%d authmode  return -1\n", __func__, __LINE__);
        return -1;
    }

    return wifi_sethostApAuthMode(drv->iface, authmode);
}

/*
 * Description:
 *     Configure WPA parameters.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     params - BSS param struct pointer to dertermine wpa security
 *     configs.
 */
 int
configure_wpa(struct driver_data *drv,
        struct wpa_bss_params *params)
{
    int cipher = 0, rsncap = 0;

    switch (params->wpa_group) {
        case WPA_CIPHER_CCMP:
            cipher = IEEE80211_CIPHER_AES_CCM;
            break;
#ifdef ATH_GCM_SUPPORT
        case WPA_CIPHER_CCMP_256:
            cipher = IEEE80211_CIPHER_AES_CCM_256;
            break;
        case WPA_CIPHER_GCMP:
            cipher = IEEE80211_CIPHER_AES_GCM;
            break;
        case WPA_CIPHER_GCMP_256:
            cipher = IEEE80211_CIPHER_AES_GCM_256;
            break;
#endif /* ATH_GCM_SUPPORT */
        case WPA_CIPHER_TKIP:
            cipher = IEEE80211_CIPHER_TKIP;
            break;
        case WPA_CIPHER_WEP104:
            cipher = IEEE80211_CIPHER_WEP;
            break;
        case WPA_CIPHER_WEP40:
            cipher = IEEE80211_CIPHER_WEP;
            break;
        case WPA_CIPHER_NONE:
            cipher = IEEE80211_CIPHER_NONE;
            break;
        default:
            wpa_printf(MSG_ERROR, "Unknown group key cipher %u",
                    params->wpa_group);
            return -1;
    }
    if (wifi_sethostApMcastCipher(drv->iface, cipher)) {
        wpa_printf(MSG_ERROR, "Unable to set group key cipher to %u", cipher);
        return -1;
    }
    if (cipher == IEEE80211_CIPHER_WEP) {
        /* key length is done only for specific ciphers */
        cipher = (params->wpa_group == WPA_CIPHER_WEP104 ? 13 : 5);
        if (wifi_sethostApMcastKeyLen(drv->iface, cipher)) {
            wpa_printf(MSG_ERROR,
                    "Unable to set group key length to %u", cipher);
            return -1;
        }
    }

    cipher = 0;
    if (params->wpa_pairwise & WPA_CIPHER_CCMP)
        cipher |= 1<<IEEE80211_CIPHER_AES_CCM;
#ifdef ATH_GCM_SUPPORT
    if (params->wpa_pairwise & WPA_CIPHER_CCMP_256)
        cipher |= 1<<IEEE80211_CIPHER_AES_CCM_256;
    if (params->wpa_pairwise & WPA_CIPHER_GCMP)
        cipher |= 1<<IEEE80211_CIPHER_AES_GCM;
    if (params->wpa_pairwise & WPA_CIPHER_GCMP_256)
        cipher |= 1<<IEEE80211_CIPHER_AES_GCM_256;
#endif /* ATH_GCM_SUPPORT */
    if (params->wpa_pairwise & WPA_CIPHER_TKIP)
        cipher |= 1<<IEEE80211_CIPHER_TKIP;
    if (params->wpa_pairwise & WPA_CIPHER_NONE)
        cipher |= 1<<IEEE80211_CIPHER_NONE;
    wpa_printf(MSG_DEBUG, "%s: pairwise key ciphers=0x%x \n", __func__, cipher);
    if (wifi_sethostApUcastCiphers(drv->iface, cipher)) {
        wpa_printf(MSG_ERROR,
                "Unable to set pairwise key ciphers to 0x%x", cipher);
        return -1;
    }

    wpa_printf(MSG_DEBUG, "%s: key management algorithms=0x%x \n",
            __func__, params->wpa_key_mgmt);
    if (wifi_sethostApKeyMgmtAlgs(drv->iface,
                params->wpa_key_mgmt)) {
        wpa_printf(MSG_ERROR,
                "Unable to set key management algorithms to 0x%x",
                params->wpa_key_mgmt);
        return -1;
    }

    if (params->rsn_preauth)
        rsncap |= BIT(0);
#ifdef CONFIG_IEEE80211W
    if (params->ieee80211w != NO_MGMT_FRAME_PROTECTION) {
        rsncap |= BIT(7);
        if (params->ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED)
            rsncap |= BIT(6);
    }
#endif /* CONFIG_IEEE80211W */

    wpa_printf(MSG_DEBUG, "%s: rsn capabilities=0x%x \n", __func__, rsncap);
    if (wifi_sethostApRSNCaps(drv->iface, rsncap)) {
        wpa_printf(MSG_ERROR, "Unable to set RSN capabilities to 0x%x",
                rsncap);
        return -1;
    }

    wpa_printf(MSG_DEBUG, "%s: enable WPA=0x%x \n", __func__, params->wpa);
    if (wifi_sethostApWPA(drv->iface,  params->wpa)) {
        wpa_printf(MSG_ERROR, "Unable to set WPA to %u", params->wpa);
        return -1;
    }
    return 0;
}

/*
 * Description:
 *     Callback API to set IEEE8021x/WPA configurations
 * Arguments:
 *     priv - driver_data struct pointer.
 *     params - BSS param struct pointer to dertermine wpa security
 *     configs.
 */
 int
set_ieee8021x(void *priv, struct wpa_bss_params *params)
{
    struct driver_data *drv = priv;

    wpa_printf(MSG_DEBUG, "%s: ##enabled=%d", __func__, params->enabled);

    if (!params->enabled) {
        /* XXX restore state */
        if (wifi_sethostApAuthMode(drv->iface,
                    IEEE80211_AUTH_AUTO) < 0)
            return -1;
        /* IEEE80211_AUTH_AUTO ends up enabling Privacy; clear that */
        return set_privacy(drv, 0);
    }
    if (!params->wpa && !params->ieee802_1x) {
        wpa_printf(MSG_ERROR, "No 802.1X or WPA enabled!\n");
        return -1;
    }
    if (params->wpa && configure_wpa(drv, params) != 0) {
        wpa_printf(MSG_ERROR, "Error configuring WPA state!\n");
        return -1;
    }
    if (wifi_sethostApAuthMode(drv->iface,
                (params->wpa ? IEEE80211_AUTH_WPA : IEEE80211_AUTH_8021X))) {
        wpa_printf(MSG_ERROR, "Error enabling WPA/802.1X!\n");
        return -1;
    }

    return 0;
}

#if defined(CONFIG_IEEE80211R) || defined(CONFIG_IEEE80211W)
/* Description:
 *     Callback API for sending Mgmt frames to client.
 *     Will be called from lib hostap authenticator after necessary
 *     processing of other packets needed before sending mgmt
 *     packets.
 * Arguments:
 *     priv - driver_data allocated structure.
 *     frm - Mgmt frame buffer.
 *     data_len - Mgmt frame length
 *     no_ack - Ack is needed or not.
 *     freq - Freq to repeat the sequence
 */
int send_mgmt(void *priv, const u8 *frm, size_t data_len,
        int noack, unsigned int freq, const u16 *csa_offs,
                         size_t csa_offs_len)
{
    struct driver_data *drv = priv;
    return wifi_sendHostApMgmtFrame(frm, sizeof(struct ieee80211req_mgmtbuf) + data_len, drv->iface);
}

#endif /* CONFIG_IEEE80211R || CONFIG_IEEE80211W */

/*
 * Description:
 *     Callback API to set ap related IE(s)
 * Arguments:
 *     priv - driver_data struct pointer.
 *     params - AP param struct pointer to fetch IE(s)
 *     configs for particular vap.
 */
int set_ap(void *priv, struct wpa_driver_ap_params *params)
{
    /*
     * TODO: Use this to replace set_authmode, set_privacy, set_ieee8021x,
     * set_generic_elem, and hapd_set_ssid.
     */

    wpa_printf(MSG_DEBUG, "set_ap - pairwise_ciphers=0x%x "
            "group_cipher=0x%x key_mgmt_suites=0x%x auth_algs=0x%x "
            "wpa_version=0x%x privacy=%d interworking=%d \n",
            params->pairwise_ciphers, params->group_cipher,
            params->key_mgmt_suites, params->auth_algs,
            params->wpa_version, params->privacy, params->interworking);
    wpa_hexdump_ascii(MSG_DEBUG, "SSID",
            params->ssid, params->ssid_len);
    if (params->hessid)
        wpa_printf(MSG_DEBUG, "HESSID " MACSTR "\n",
                MAC2STR(params->hessid));
    wpa_hexdump_buf(MSG_DEBUG, "beacon_ies",
            params->beacon_ies);
    wpa_hexdump_buf(MSG_DEBUG, "proberesp_ies",
            params->proberesp_ies);
    wpa_hexdump_buf(MSG_DEBUG, "assocresp_ies",
            params->assocresp_ies);

#if defined(CONFIG_HS20) && (defined(IEEE80211_PARAM_OSEN))
    if (params->osen) {
        struct wpa_bss_params bss_params;

        os_memset(&bss_params, 0, sizeof(struct wpa_bss_params));
        bss_params.enabled = 1;
        bss_params.wpa = 2;
        bss_params.wpa_pairwise = WPA_CIPHER_CCMP;
        bss_params.wpa_group = WPA_CIPHER_CCMP;
        bss_params.ieee802_1x = 1;

        if (set_privacy(priv, 1) ||
                wifi_sethostApOsen(priv->iface, 1))
            return -1;

        return set_ieee8021x(priv, &bss_params);
    }
#endif /* CONFIG_HS20 && IEEE80211_PARAM_OSEN */

    return 0;
}

/* Description:
 *     Callback API for sending Auth Resp frame to client
 *     Will be called from lib hostap authenticator after receiving
 *     proper AUTH req from client.
 * Arguments:
 *     priv - driver_data allocated structure.
 *     params -  STA auth param struct pointer to send AUTH resp.
 */
 int
sta_auth(void *priv, struct wpa_driver_sta_auth_params *params)
{
    struct driver_data *drv = priv;
    int ret;
    unsigned int fils_auth = 0;
    unsigned int fils_en = 0;

    wpa_printf(MSG_DEBUG, "%s: addr=%s status_code=%d \n",
            __func__, ether_sprintf(params->addr), params->status);

#ifdef CONFIG_FILS
    /* Copy FILS AAD parameters if the driver supports FILS */
    if (params->fils_auth && drv->fils_en) {
        fils_auth = 1;
        fils_en = 1;
    }
#endif /* CONFIG_FILS */

    ret = wifi_sethostApStaSendAuthResp(drv->iface, (unsigned char *)params->addr, fils_auth, fils_en, params->status, params->seq, params->len, params->ie);
    if (ret < 0) {
        wpa_printf(MSG_ERROR, "%s: Failed to auth STA (addr " MACSTR
                " reason %d) \n",
                __func__, MAC2STR(params->addr), params->status);
    }
    return ret;
}

/*
 * Description:
 *     Callback API to set whether station is authorized or not.
 *     Only when a STA is set to authorized, driver will receive other
 *     action/data frames from client.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     addr - STA address
 *     authorized - Whether station is authorized or not.
 *         1 - authorized, 0 - unauthorized.
 */
 int
set_sta_authorized(void *priv, const u8 *addr, int authorized)
{
    struct driver_data *drv = priv;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s authorized=%d \n",
            __func__ , ether_sprintf(addr), authorized);

    ret = wifi_sethostApStaAuthorized(drv->iface, (unsigned char *)addr, authorized);
    if (ret < 0) {
        wpa_printf(MSG_ERROR, "%s: Failed to %sauthorize STA " MACSTR "\n",
                __func__, authorized ? "" : "un", MAC2STR(addr));
    }

    return ret;
}

/*
 * Description:
 *     Callback API to authorize or unauthorize a client based on flags received.
 *     Only when a STA is set to authorized, driver will receive other
 *     action/data frames from client.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     addr - STA address
 *     total_flags - OR of all the flags determined.
 *     flags_or and flags_and - flags determined in hostapd authenticator
 *     which says client can be authorized or not.
 */
 int
sta_set_flags(void *priv, const u8 *addr,
        unsigned int total_flags, unsigned int flags_or,
        unsigned int flags_and)
{
    /* For now, only support setting Authorized flag */
    if (flags_or & WPA_STA_AUTHORIZED)
        return set_sta_authorized(priv, addr, 1);
    if (!(flags_and & WPA_STA_AUTHORIZED))
        return set_sta_authorized(priv, addr, 0);

    return 0;
}

/* Description:
 *     Callback API for sending Assoc Resp frame to client
 *     Will be called from lib hostap authenticator after receiving
 *     proper Assoc req from client.
 * Arguments:
 *     priv - driver_data allocated structure.
 *     own_addr - Source address [athX interface]
 *     addr - Destination/STA address.
 *     reassoc - Determined whether it is response of reassoc frame or not.
 *     status_code - Status of assoc resp operation
 *     ie - Assoc Resp frame data
 *     len - Assoc resp frame data len.
 */
int
sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
        int reassoc, u16 status_code, const u8 *ie, size_t len)
{
    struct driver_data *drv = priv;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s status_code=%d reassoc %d \n",
            __func__, ether_sprintf(addr), status_code, reassoc);

    ret = wifi_sethostApStaSendAssocResp(drv->iface, (unsigned char *)addr, status_code, reassoc, len, ie);
    if (ret < 0) {
        wpa_printf(MSG_ERROR, "%s: Failed to assoc STA (addr " MACSTR
                " reason %d) \n",
                __func__, MAC2STR(addr), status_code);
    }
    return ret;
}

/* Description:
 *     Callback API for setting up driver to receive frames after all other init is done.
 * Arguments:
 *     priv - driver_data allocated structure.
 */
 int
commit(void *priv)
{
    struct driver_data *drv = priv;
    int count = 0;
    int connected = 0;

    while (!connected){
        if(linux_set_iface_flags(drv->iface, 1)){
            connected = 0;
            count++;
            os_sleep(1, 0);
        } else {
            connected = 1;
        }
    }
    return 0;
}

/* Description:
 *     Callback API for resetting the filter for receiving frames from driver to
 *     upper layer.
 * Arguments:
 *     drv - driver_data allocated structure.
 */
 int reset_appfilter(struct driver_data *drv)
{
    return wifi_setHostApResetAppFilter(drv->iface);
}

/* Description:
 *     Callback API for sending disassoc to specific/all STA in an interface.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     own_addr - Source mac address
 *     addr - Destination mac address.
 *     reason_code - Reason for sending deauth.
 */
 int
sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
        u16 reason_code)
{
    struct driver_data *drv = priv;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d \n",
            __func__, ether_sprintf(addr), reason_code);

    ret = wifi_sethostApStaDisassoc(drv->iface, (unsigned char *)addr, reason_code);
    if (ret < 0) {
        wpa_printf(MSG_ERROR, "%s: Failed to disassoc STA (addr "
                MACSTR " reason %d) \n",
                __func__, MAC2STR(addr), reason_code);
    }

    return ret;
}

#ifdef CONFIG_IEEE80211R
/* Description:
 *     Callback API to add Traffic specification for a particular station.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     addr - Destination mac address.
 *     tspec_ie - Traffic spec IE configs
 *     tspec_ielen - Traffic spec IE configs length.
 */
int
add_tspec(void *priv, const u8 *addr, u8 *tspec_ie,
		size_t tspec_ielen)
{
	struct driver_data *drv = priv;

    wpa_printf(MSG_DEBUG, "%s tspec_ielen = %lu addr=%s", __func__,
                   (unsigned long) tspec_ielen, ether_sprintf(addr));

    return wifi_sethostAddTspec(drv->iface, addr, tspec_ie, tspec_ielen);
}

/* Description:
 *     Callback API to add station node ot driver.
 * Arguments:
 *     priv - driver_data struct pointer.
 *     addr - Destination mac address.
 *     auth_alg - auth algorithm to be used.
 */
int
add_sta_node(void *priv, const u8 *addr, u16 auth_alg)
{
	struct driver_data *drv = priv;

    wpa_printf(MSG_DEBUG, "%s auth_alg = %u addr=%s", __func__,
                   auth_alg, ether_sprintf(addr));
    return wifi_sethostAddStaNode(drv->iface, addr, auth_alg);
}

#endif /* CONFIG_IEEE80211R */

/* Description:
 *     Callback API for setting the filter for receiving frames from driver to
 *     upper layer.
 * Arguments:
 *     drv - driver_data allocated structure.
 */

int hapd_receive_pkt(struct driver_data *drv)
{
    return wifi_setHostApSetAppFilter(drv->iface);
}

/*
 * Description:
 *     Callback API to set WPS related IE(s)
 * Arguments:
 *     priv - driver_data struct pointer.
 *     beacon - WPS beacon IE params
 *     proberesp - WPS Probe Resp IE params
 *     assocresp WPS Assco Resp IE params.
 */
static int set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
                      const struct wpabuf *proberesp,
                      const struct wpabuf *assocresp)
{
    struct driver_data *drv = priv;
    u8 *wpa_ie = NULL;
    size_t wpa_ie_len = 0;

    wpabuf_free(drv->wps_beacon_ie);
    drv->wps_beacon_ie = beacon ? wpabuf_dup(beacon) : NULL;

    wpabuf_free(drv->wps_probe_resp_ie);
    drv->wps_probe_resp_ie = proberesp ? wpabuf_dup(proberesp) : NULL;

    wpa_ie = (u8 *)(drv->wpa_ie ? wpabuf_head(drv->wpa_ie) : NULL);
    wpa_ie_len = drv->wpa_ie ? wpabuf_len(drv->wpa_ie) : 0;
    wifi_sethostApWpsIE(drv->iface, wpa_ie, wpa_ie_len,
                        assocresp ? wpabuf_head(assocresp) : NULL,
                        assocresp ? wpabuf_len(assocresp) : 0,
                        IEEE80211_APPIE_FRAME_ASSOC_RESP);

    if (wifi_sethostApWpsIE(drv->iface, wpa_ie, wpa_ie_len,
                            beacon ? wpabuf_head(beacon) : NULL,
                            beacon ? wpabuf_len(beacon) : 0,
                            IEEE80211_APPIE_FRAME_BEACON))
        return -1;

    return wifi_sethostApWpsIE(drv->iface, wpa_ie, wpa_ie_len,
                               proberesp ? wpabuf_head(proberesp) : NULL,
                               proberesp ? wpabuf_len(proberesp): 0,
                               IEEE80211_APPIE_FRAME_PROBE_RESP);
}

/*
 * Description:
 *     Callback API to set Generic Element related IE(s)
 * Arguments:
 *     priv - driver_data struct pointer.
 *     ie - Generic element IE params
 *     ie_len - Generic element IE params length
 */
static int
set_opt_ie(void *priv, const u8 *ie, size_t ie_len)
{
    struct driver_data *drv = priv;

    wpa_printf(MSG_DEBUG, "%s buflen = %lu", __func__,
               (unsigned long) ie_len);
    wpa_hexdump(MSG_DEBUG, "set_generic_elem", ie, ie_len);

    wpabuf_free(drv->wpa_ie);
    if (ie)
            drv->wpa_ie = wpabuf_alloc_copy(ie, ie_len);
    else
            drv->wpa_ie = NULL;

    wifi_sethostApGenericeElemOptIE(drv->iface,
                                  ie, ie_len,
                                  drv->wps_beacon_ie ? wpabuf_head(drv->wps_beacon_ie) : NULL,
                                  drv->wps_beacon_ie ? wpabuf_len(drv->wps_beacon_ie) : 0,
                                  IEEE80211_APPIE_FRAME_BEACON);

    wifi_sethostApGenericeElemOptIE(drv->iface,
                                  ie, ie_len,
                                  drv->wps_probe_resp_ie ? wpabuf_head(drv->wps_probe_resp_ie) : NULL,
                                  drv->wps_probe_resp_ie ? wpabuf_len(drv->wps_probe_resp_ie) : 0,
                                  IEEE80211_APPIE_FRAME_PROBE_RESP);
    return 0;
}

/*
 * Description:
 *     Callback API to get Sequence number of STA.
 * Arguments:
 *     ifname - Interface name athX interface.
 *     priv - driver_data struct pointer.
 *     addr - STA mac address.
 *     idx - Index number.
 *     seq - buffer in which sequence number from driver has to be filled.
 */
static int sta_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx,
                   u8 *seq)
{
#ifndef WPA_KEY_RSC_LEN
#define WPA_KEY_RSC_LEN 8
#endif

    u8 tmp[WPA_KEY_RSC_LEN];
    if (!wifi_gethostAuthSeqNum((char *)ifname, addr, idx, &tmp[0]))
    {
#ifdef WORDS_BIGENDIAN
        {
            /*
             * wk.ik_keytsc is in host byte order (big endian), need to
             * swap it to match with the byte order used in WPA.
             */
            int i;
            for (i = 0; i < WPA_KEY_RSC_LEN; i++)
            {
                seq[i] = tmp[WPA_KEY_RSC_LEN - i - 1];
            }
        }
#else
        os_memcpy(seq, tmp, WPA_KEY_RSC_LEN);
#endif /* WORDS_BIGENDIAN */
        return 0;
    }
    return -1;
}

#ifdef QCAPATCH_ACLCHECK_HOSTAPD
#if !defined (_XB7_PRODUCT_REQ_)
/*
 * Description:
 *     Callback API to get WPS ACL details
 * Arguments:
 *     priv - driver_data struct pointer.
 *     buf - output buf to be filled
 *     buf_len - Mac output buffer length.
 */
static int wps_acl_get(void *priv, char *buf, size_t *buf_len)
{
    struct driver_data *drv = priv;
    return wifi_hostApGetWpsAcl(drv->iface, (size_t *)buf_len, buf);
}
#endif
#endif /* QCAPATCH_ACLCHECK_HOSTAPD */

#ifdef QCAPATCH_WPSACL
#if !defined (_XB7_PRODUCT_REQ_)
/*
 * Description:
 *     Callback API to set WPS ACL details
 * Arguments:
 *     priv - driver_data struct pointer.
 *     addr - Mac address to be added to ACL
 */
static int wps_acl_set(void *priv, const u8 *addr)
{
    struct driver_data *drv = priv;
    return wifi_hostApSetWpsAcl(drv->iface, addr);
}
#endif
#endif /* QCAPATCH_WPSACL */

static int wifi_hostap_greylist_acl_mac(int apIndex, const u8 *macaddr, BOOL add)
{
    wpa_printf(MSG_DEBUG, "%s:%d Adding greylist cache\n", __func__, __LINE__);
    return wifi_greylist_acl_mac(apIndex, (const unsigned int *)macaddr, add);
}

static void wifi_hostap_kick_mac(char *ifname, unsigned char *addr)
{
    wpa_printf(MSG_DEBUG, "%s:%d greylist kick mac\n", __func__, __LINE__);
    wifi_kick_mac(ifname, addr);
}

/*
 * Description:
 *     API to register all callbacks related to hostapd authenticator during init
 * Arguments:
 *     ap_index - Vap index
 *     hapd - Allocated hostapd_data structure pointer.
 */
void update_hostapd_driver(int ap_index, struct hostapd_data *hapd)
{
    struct wpa_driver_ops *ops = (struct wpa_driver_ops *)hapd->driver;

    ops->name             = "rdkb";
    ops->desc             = "RDKB Hostapd Authenticator";
    ops->hapd_send_eapol  = send_eapol;
    ops->hapd_init        = drv_init;
    ops->set_privacy      = set_privacy;
    //ops->if_add         = if_add;	//handled_through wifi_createAp
    ops->hapd_set_ssid    = set_ssid;
    ops->flush            = flush;
    ops->sta_deauth       = sta_deauth;
    ops->set_key          = set_key;
    ops->set_authmode     = set_authmode;
    ops->set_ieee8021x    = set_ieee8021x;
    ops->set_generic_elem = set_opt_ie;
    ops->set_ap           = set_ap;
#if defined(CONFIG_IEEE80211R) || defined(CONFIG_IEEE80211W)
    ops->sta_auth         = sta_auth;
    ops->send_mlme        = send_mgmt;
    //#endif /* CONFIG_IEEE80211R || CONFIG_IEEE80211W */
#endif /* CONFIG_IEEE80211R || CONFIG_IEEE80211W */
#ifdef CONFIG_IEEE80211R
    ops->add_tspec        = add_tspec;
    ops->add_sta_node     = add_sta_node;
#endif /* CONFIG_IEEE80211R */
    ops->sta_set_flags    = sta_set_flags;
    ops->sta_disassoc     = sta_disassoc;
    ops->sta_assoc        = sta_assoc;
    ops->set_ap_wps_ie    = set_ap_wps_ie;
    ops->get_seqnum       = sta_get_seqnum;
    ops->commit           = commit;
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST) && !defined(_XB7_PRODUCT_REQ_)
    ops->rdk_greylist_get_snr     = wifi_get_snr_value;
    ops->rdk_greylist_add_del_mac = (rdk_greylist_add_del_mac_t )wifi_hostap_greylist_acl_mac;
    ops->rdk_greylist_kick_mac    = wifi_hostap_kick_mac;
#endif
#ifdef QCAPATCH_WPSACL
#if !defined (_XB7_PRODUCT_REQ_)
    ops->wps_acl_set = wps_acl_set;
#endif
#endif
#ifdef QCAPATCH_ACLCHECK_HOSTAPD
#if !defined (_XB7_PRODUCT_REQ_)
    ops->wps_acl_get = (wps_acl_get_t )wps_acl_get;
#endif
#endif /* QCAPATCH_ACLCHECK_HOSTAPD */
#if 0
//We are not currently using it, might be needing it for future purpose
    ops->hapd_deinit        = dummy_deinit,
    ops->read_sta_data      = dummy_read_sta_driver_data,
    ops->hapd_get_ssid      = dummy_get_ssid,
    ops->set_countermeasures    = dummy_set_countermeasures,
    ops->sta_clear_stats    = dummy_sta_clear_stats,
    ops->send_action        = dummy_send_action,
#if defined(CONFIG_WNM) && defined(IEEE80211_APPIE_FRAME_WNM)
    ops->wnm_oper       = dummy_wnm_oper,
#endif /* CONFIG_WNM && IEEE80211_APPIE_FRAME_WNM */
    ops->set_qos_map        = dummy_set_qos_map,
    ops->get_capa               = dummy_get_capa,
#endif
}
#endif
