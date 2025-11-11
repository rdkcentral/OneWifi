/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <math.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"
#include "qca_wifi_hal.h"

#if HAL_IPC
#include "hal_ipc.h"
#include "server_hal_ipc.h"
#endif

#include <asm/byteorder.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/wireless.h>
#include <pthread.h>
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif
#include <ieee80211_external.h>

#define DEFAULT_CMD_SIZE 256
#define MAX_BUF_SIZE 300
#define MAX_NUM_RADIOS 2
#define OUI_QCA "0x001374"
#define RETRY_LIMIT 7
#define DEFAULT_XHS_PASSWORD_KEY "Default XHS Password"

#define MLD_PREFIX "mld"
#define BACKHAUL_STA_SSID  "we.connect.yellowstone"
#define BHAUL_CREDS_PATH   "/mnt/data/pstore/mesh_bhaul_creds"
#define BHAUL_CREDS_LEN     50
#define STATICCPGCFG_LEN    128
#define CONFIG_PATH        "/usr/opensync/scripts"
#define CONFIG_FILE        "getConfigFile.sh"
#define STATICCPGCFG_1     "/tmp/.staticCpgCfg_1"
#define STA_PWD_LEN         STATICCPGCFG_LEN
#define QCA_MAX_CMD_SZ 128

static int nl_fd = -1;
static int dfs_nl_listen_start(void);
static void *dfs_event_thread(void *arg);
static void parse_iwcustom_buffer(const void *buf, unsigned int len);
static pthread_t dfs_thread;
static int dfs_thread_running = 0;

extern INT wifi_setMLDaddr(INT apIndex, CHAR *mldMacAddress);

typedef enum radio_band {
    radio_2g = 0,
    radio_5g,
    radio_6g
} radio_band_t;

struct wifiChannelWidthMap
{
    wifi_channelBandwidth_t halWifiChanWidth;
    char wifiChanWidthName[16];
};

struct wifiVariantBitMap
{
    wifi_ieee80211Variant_t halWifiRadioMode;
    char halWifiRadioModename[5];
};

typedef struct
{
    radio_band_t halWifiBand;
    char wifiBandName[10];
}wifiBandMap;

wifiBandMap wifiRadioBandMap[] = 
{
    {radio_2g, "2GHz"},
    {radio_5g, "5GHz"},
    {radio_6g, "6GHz"},
};
    
struct wifiChannelWidthMap wifiChannelBandWidthMap[] =
{
    {WIFI_CHANNELBANDWIDTH_20MHZ,     "20MHz"},
    {WIFI_CHANNELBANDWIDTH_40MHZ,     "40MHz"},
    {WIFI_CHANNELBANDWIDTH_80MHZ,     "80MHz"},
    {WIFI_CHANNELBANDWIDTH_160MHZ,    "160MHz"},
    {WIFI_CHANNELBANDWIDTH_80_80MHZ,  "80+80MHz"},
};

struct wifiVariantBitMap wifiRadioModeBitMap[] = 
{
    {WIFI_80211_VARIANT_A,     "a"}, 
    {WIFI_80211_VARIANT_B,     "b"},
    {WIFI_80211_VARIANT_G,     "g"},
    {WIFI_80211_VARIANT_N,     "n"},
    {WIFI_80211_VARIANT_H,     "h"},
    {WIFI_80211_VARIANT_AC,   "ac"},
    {WIFI_80211_VARIANT_AD,   "ad"},
    {WIFI_80211_VARIANT_AX,   "ax"},
    {WIFI_80211_VARIANT_BE,   "be"},
};

enum qca_phymode {
    QCA_HAL_IEEE80211_PHYMODE_AUTO             = 0,  /**< autoselect */
    QCA_HAL_IEEE80211_PHYMODE_11A              = 1,  /**< 5GHz, OFDM */
    QCA_HAL_IEEE80211_PHYMODE_11B              = 2,  /**< 2GHz, CCK */
    QCA_HAL_IEEE80211_PHYMODE_11G              = 3,  /**< 2GHz, OFDM */
    QCA_HAL_IEEE80211_PHYMODE_FH               = 4,  /**< 2GHz, GFSK */
    QCA_HAL_IEEE80211_PHYMODE_TURBO_A          = 5,  /**< 5GHz dyn turbo*/
    QCA_HAL_IEEE80211_PHYMODE_TURBO_G          = 6,  /**< 2GHz dyn turbo*/
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT20        = 7,  /**< 5GHz, HT20 */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT20        = 8,  /**< 2GHz, HT20 */
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40PLUS    = 9,  /**< 5GHz, HT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40MINUS   = 10, /**< 5GHz, HT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40PLUS    = 11, /**< 2GHz, HT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40MINUS   = 12, /**< 2GHz, HT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40        = 13, /**< 2GHz, HT40 auto */
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40        = 14, /**< 5GHz, HT40 auto */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20       = 15, /**< 5GHz, VHT20 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40PLUS   = 16, /**< 5GHz, VHT40 (Ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40MINUS  = 17, /**< 5GHz  VHT40 (Ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40       = 18, /**< 5GHz, VHT40 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80       = 19, /**< 5GHz, VHT80 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160      = 20, /**< 5GHz, VHT160 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80_80    = 21, /**< 5GHz, VHT80_80 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20       = 22, /**< 5GHz, HE20 */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20       = 23, /**< 2GHz, HE20 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40PLUS   = 24, /**< 5GHz, HE40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40MINUS  = 25, /**< 5GHz, HE40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40PLUS   = 26, /**< 2GHz, HE40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40MINUS  = 27, /**< 2GHz, HE40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40       = 28, /**< 5GHz, HE40 */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40       = 29, /**< 2GHz, HE40 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80       = 30, /**< 5GHz, HE80 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160      = 31, /**< 5GHz, HE160 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80_80    = 32, /**< 5GHz, HE80_80 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT20      = 33, /**< 5GHz, EHT20 */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20      = 34, /**< 2GHz, EHT20 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40PLUS  = 35, /**< 5GHz, EHT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40MINUS = 36, /**< 5GHz, EHT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40PLUS  = 37, /**< 2GHz, EHT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40MINUS = 38, /**< 2GHz, EHT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40      = 39, /**< 2GHz, EHT40 */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40      = 40, /**< 2GHz, EHT40 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT80      = 41, /**< 5GHz, EHT80 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT160     = 42, /**< 5GHz, EHT160 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT320     = 43, /**< 5GHz, EHT320 */

    /* keep it last */
    QCA_HAL_IEEE80211_PHYMODE_INVALID                /**< Invalid Phymode */
 };

static const uint8_t *phymode_strings[] = {
    [QCA_HAL_IEEE80211_PHYMODE_AUTO]             = (uint8_t *)"AUTO",
    [QCA_HAL_IEEE80211_PHYMODE_11A]              = (uint8_t *)"11A",
    [QCA_HAL_IEEE80211_PHYMODE_11B]              = (uint8_t *)"11B",
    [QCA_HAL_IEEE80211_PHYMODE_11G]              = (uint8_t *)"11G" ,
    [QCA_HAL_IEEE80211_PHYMODE_FH]               = (uint8_t *)"FH" ,
    [QCA_HAL_IEEE80211_PHYMODE_TURBO_A]          = (uint8_t *)"TA" ,
    [QCA_HAL_IEEE80211_PHYMODE_TURBO_G]          = (uint8_t *)"TG" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT20]        = (uint8_t *)"11NAHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT20]        = (uint8_t *)"11NGHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40PLUS]    = (uint8_t *)"11NAHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40MINUS]   = (uint8_t *)"11NAHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40PLUS]    = (uint8_t *)"11NGHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40MINUS]   = (uint8_t *)"11NGHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40]        = (uint8_t *)"11NGHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40]        = (uint8_t *)"11NAHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20]       = (uint8_t *)"11ACVHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40PLUS]   = (uint8_t *)"11ACVHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40MINUS]  = (uint8_t *)"11ACVHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40]       = (uint8_t *)"11ACVHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80]       = (uint8_t *)"11ACVHT80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160]      = (uint8_t *)"11ACVHT160" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80_80]    = (uint8_t *)"11ACVHT80_80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20]       = (uint8_t *) "11AHE20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20]       = (uint8_t *) "11GHE20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40PLUS]   = (uint8_t *) "11AHE40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40MINUS]  = (uint8_t *) "11AHE40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40PLUS]   = (uint8_t *) "11GHE40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40MINUS]  = (uint8_t *) "11GHE40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40]       = (uint8_t *) "11AHE40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40]       = (uint8_t *) "11GHE40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80] = (uint8_t *) "11AHE80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160] = (uint8_t *) "11AHE160" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80_80] = (uint8_t *) "11AHE80_80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT20] = (uint8_t *) "11AEHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20] = (uint8_t *) "11GEHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40PLUS] = (uint8_t *) "11AEHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40MINUS] = (uint8_t *) "11AEHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40PLUS] = (uint8_t *) "11GEHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40MINUS]   = (uint8_t *) "11GEHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40] = (uint8_t *) "11AEHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40] = (uint8_t *) "11GEHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT80] = (uint8_t *) "11AEHT80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT160] = (uint8_t *) "11AEHT160" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT320] = (uint8_t *) "11AEHT320" ,

    [QCA_HAL_IEEE80211_PHYMODE_INVALID]          = NULL ,
 };

/* write event explanations */
static const uint8_t *WPS_enum_to_str[] = {
    [WPS_EV_M2D]                       = (uint8_t*) "WPS_EV_M2D",
    [WPS_EV_FAIL]                      = (uint8_t*) "WPS_EV_FAIL",
    [WPS_EV_SUCCESS]                   = (uint8_t*) "WPS_EV_SUCCESS",
    [WPS_EV_PWD_AUTH_FAIL]             = (uint8_t*) "WPS_EV_PWD_AUTH_FAIL",
    [WPS_EV_PBC_OVERLAP]               = (uint8_t*) "WPS_EV_PBC_OVERLAP",
    [WPS_EV_PBC_TIMEOUT]               = (uint8_t*) "WPS_EV_PBC_TIMEOUT",
    [WPS_EV_PBC_ACTIVE]                = (uint8_t*) "WPS_EV_PBC_ACTIVE",
    [WPS_EV_PBC_DISABLE]               = (uint8_t*) "WPS_EV_PBC_DISABLE",
    [WPS_EV_ER_AP_ADD]                 = (uint8_t*) "WPS_EV_ER_AP_ADD",
    [WPS_EV_ER_AP_REMOVE]              = (uint8_t*) "WPS_EV_ER_AP_REMOVE",
    [WPS_EV_ER_ENROLLEE_ADD]           = (uint8_t*) "WPS_EV_ER_ENROLLEE_ADD",
    [WPS_EV_ER_ENROLLEE_REMOVE]        = (uint8_t*) "WPS_EV_ER_ENROLLEE_REMOVE",
    [WPS_EV_ER_AP_SETTINGS]            = (uint8_t*) "WPS_EV_ER_AP_SETTINGS",
    [WPS_EV_ER_SET_SELECTED_REGISTRAR] = (uint8_t*) "WPS_EV_ER_SET_SELECTED_REGISTRAR",
    [WPS_EV_AP_PIN_SUCCESS]            = (uint8_t*) "WPS_EV_AP_PIN_SUCCESS",
};

static const uint8_t *WPS_ei_to_str[] = {
    [WPS_EI_NO_ERROR]                      = (uint8_t*) "No Error",
    [WPS_EI_SECURITY_TKIP_ONLY_PROHIBITED] = (uint8_t*) "TKIP Only Prohibited",
    [WPS_EI_SECURITY_WEP_PROHIBITED]       = (uint8_t*) "WEP Prohibited",
    [WPS_EI_AUTH_FAILURE]                  = (uint8_t*) "Authentication Failure",
};

static const uint8_t *pbc_status_str[] = {
    [WPS_PBC_STATUS_DISABLE]         = (uint8_t*) "Disabled",
    [WPS_PBC_STATUS_ACTIVE]          = (uint8_t*) "Active",
    [WPS_PBC_STATUS_TIMEOUT]         = (uint8_t*) "Timed-out",
    [WPS_PBC_STATUS_OVERLAP]         = (uint8_t*) "Overlap",
};
enum vap_enum_type {
    vap_private = 0,
    vap_xhs,
    hotspot_open,
    vap_lnf_psk,
    vap_hotspot_secure,
    vap_lnf_radius,
    vap_mesh_backhaul,
    vap_mesh_sta,
    vap_invalid
};
typedef bool (*vap_type) (unsigned int ap_index);

vap_type vap_type_arr[10] = {

    is_wifi_hal_vap_private,
    is_wifi_hal_vap_xhs,
    is_wifi_hal_vap_hotspot_open,
    is_wifi_hal_vap_lnf_psk,
    is_wifi_hal_vap_hotspot_secure,
    is_wifi_hal_vap_lnf_radius,
    is_wifi_hal_vap_mesh_backhaul,
    is_wifi_hal_vap_mesh_sta
};

static char* getInterface(int Index)
{
    unsigned int idx = 0;
    wifi_interface_name_idex_map_t interface_map[(MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)];
    get_wifi_interface_info_map(interface_map);
    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) 
    {
        if (Index == interface_map[idx].index)
        {
	   return interface_map[idx].interface_name;
        }
    }
    return " ";
}

bool isValidAPIndex(int index)
{
	return true;
}


int platform_pre_init()
{
    qca_getRadiosIndex();
    qca_nl_cfg80211_init();
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}


int is_interface_exists(const char *fname)
{
    FILE *file = fopen(fname, "r");
    if (file)
    {
      fclose(file);
      return 1;
    }
    return 0;
}

//check if radio  present in info map
int check_radio_index(uint8_t radio_index)
{
    radio_interface_mapping_t platform_map_t[MAX_NUM_RADIOS];
    uint8_t i = 0;

    get_radio_interface_info_map(platform_map_t);

    for (i = 0; i < MAX_NUM_RADIOS ; i++) {
        if (platform_map_t[i].radio_index == radio_index) {

            return 0;
        }
    }

    wifi_hal_dbg_print("%s: radio not found\n", __FUNCTION__);
    return -1;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

void qca_getRadioMode(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam,
    char *cmd)
{
    wifi_ieee80211Variant_t variant = WIFI_80211_VARIANT_AX;
    wifi_channelBandwidth_t channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;

    variant = operationParam->variant; channelWidth = operationParam->channelWidth;

    switch (operationParam->band) {

        case WIFI_FREQUENCY_2_4_BAND:
            if (variant == WIFI_80211_VARIANT_B) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11B], DEFAULT_CMD_SIZE);

            } else if (variant == WIFI_80211_VARIANT_G) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11G], DEFAULT_CMD_SIZE);

            } else if (variant == (WIFI_80211_VARIANT_B | WIFI_80211_VARIANT_G)) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11G], DEFAULT_CMD_SIZE);

            } else if (!(variant & WIFI_80211_VARIANT_AX) && !(variant & WIFI_80211_VARIANT_BE)) {
                if ( channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NG_HT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NG_HT40], DEFAULT_CMD_SIZE);
                }

            } else if ((variant & WIFI_80211_VARIANT_AX) && !(variant & WIFI_80211_VARIANT_BE)) {
                if ( channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40], DEFAULT_CMD_SIZE);
                }

            } else if (variant & WIFI_80211_VARIANT_BE) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20], DEFAULT_CMD_SIZE);
                if ( channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40], DEFAULT_CMD_SIZE);
                }
            }
            break;

        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
            if ((variant & WIFI_80211_VARIANT_A) && !(variant & ~WIFI_80211_VARIANT_A)) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11A], DEFAULT_CMD_SIZE);
            }
            else if ((variant & WIFI_80211_VARIANT_N) && (~variant & WIFI_80211_VARIANT_AX) && (~variant & WIFI_80211_VARIANT_AC) && (~variant & WIFI_80211_VARIANT_BE)) {

                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NA_HT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NA_HT40], DEFAULT_CMD_SIZE);
                }
            }
            else if ((variant & WIFI_80211_VARIANT_AC) && (~variant & WIFI_80211_VARIANT_AX) && (~variant & WIFI_80211_VARIANT_BE))
            {
                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    // QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_80MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_160MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160], DEFAULT_CMD_SIZE);
                }
            }
            else if ((variant & WIFI_80211_VARIANT_AX) && (~variant & WIFI_80211_VARIANT_BE) ) {

                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    // QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_80MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_160MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160], DEFAULT_CMD_SIZE);
                }
            }
            else if ((variant & WIFI_80211_VARIANT_BE)) {

                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    // QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_80MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT80], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_160MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT160], DEFAULT_CMD_SIZE);
                }
            }
            break;
        default:
            break;
    }
    return;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_vap_info_t *vap;
    int vap_itr;
    char interface_name[32];
    char cmd[DEFAULT_CMD_SIZE];
    char mode[16];
    wifi_radio_info_t *radio;

    for (vap_itr=0; vap_itr < map->num_vaps; vap_itr++) {
        vap = &map->vap_array[vap_itr];
        get_interface_name_from_vap_index(vap->vap_index, interface_name);
        if (vap->vap_mode == wifi_vap_mode_ap) {
            /*Enabling ap_bridge for all ap vaps for intra bss packet transfer*/
            snprintf(cmd, sizeof(cmd), "cfg80211tool %s ap_bridge 1", interface_name);
            wifi_hal_dbg_print("%s:%d Executing %s\n",__func__,__LINE__, cmd);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "cfg80211tool %s athnewind 1", interface_name);
            system(cmd);
        } else {
            radio = get_radio_by_rdk_index(index);
            if (radio) {
                qca_getRadioMode(index, &radio->oper_param, mode);
                snprintf(cmd, sizeof(cmd), "cfg80211tool %s mode %s", interface_name, mode);
                system(cmd);
                wifi_hal_dbg_print("%s:%d Executing %s\n", __func__, __LINE__, cmd);
            }
        }
    }
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int nvram_get_vap_enable_status(bool *vap_enable, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int nvram_get_current_security_mode(wifi_security_modes_t *security_mode,int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int sta_security_keypassphrase_restore(char* password, int vap_index)
{
    int line_number = 1;
    FILE* fptr;
    char credentials_file[BHAUL_CREDS_LEN];
    if (!password)
    {
        return -1;
    }
    sprintf(credentials_file, "%s/%d", BHAUL_CREDS_PATH, vap_index);

    fptr = fopen(credentials_file, "r");
    if (fptr == NULL)
    {
        return -1;
    }

    while (fgets(password, BHAUL_CREDS_LEN, fptr) != NULL) {
        if (line_number == 2)
        {
            size_t len = strlen(password);
            if (len > 0 && password[len - 1] == '\n') /* Remove a newline character */
            {
                password[len - 1] = '\0';
            }
            break;
        }
        line_number++;
    }

    fclose(fptr);

    if (password[0] == '\0')
    {
        return -1;
    }
    return 0;
}

int sta_security_ssid_restore(char* ssid, int vap_index)
{
    FILE* fptr;
    char credentials_file[BHAUL_CREDS_LEN];
    if (!ssid)
    {
        return -1;
    }
    sprintf(credentials_file, "%s/%d", BHAUL_CREDS_PATH, vap_index);

    fptr = fopen(credentials_file, "r");
    if (fptr == NULL)
    {
        return -1;
    }

    if (fgets(ssid, BHAUL_CREDS_LEN, fptr) != NULL)
    {
        size_t len = strlen(ssid);
        if (len > 0 && ssid[len - 1] == '\n') /* Remove a newline character */
        {
            ssid[len - 1] = '\0';
        }
    }
    fclose(fptr);

    if (ssid[0] == '\0')
    {
        return -1;
    }

    return 0;
}
static bool sta_security_config_get(char *config_cmd, int cmd_len)
{
   if (!config_cmd) {
      return false;
   }

   snprintf(config_cmd,cmd_len-1,"%s/%s %s | grep retval",CONFIG_PATH,CONFIG_FILE,STATICCPGCFG_1);
   return true;
}
static bool sta_security_pwd_get(char *cmd, char *pwd)
{

   FILE *fcmd = NULL;
   bool ret = false;
   char buf[STA_PWD_LEN] = {0};

   if (!cmd || !pwd) {
      return false;
   }

    fcmd = popen(cmd, "r");
    if (fcmd ==  NULL)
    {
        goto exit;
    }
    while (fgets(buf, sizeof(buf), fcmd) != NULL) {
        wifi_hal_info_print("%s:%d: Res = [%s] \n", __func__, __LINE__, buf);
    }
    pclose(fcmd);
    fcmd = NULL;
    memset(buf,0,sizeof(buf));

    fcmd = fopen(STATICCPGCFG_1,"r");
    if (fcmd == NULL)
    {
        wifi_hal_error_print("%s, fopen() failed",__func__);
        goto exit;
    }

    if (fgets(buf, STA_PWD_LEN-1,fcmd) != NULL)
    {
        buf[strlen(buf) - 1] = '\0';
        strcpy(pwd, buf);
        ret = true;
    } else {
        wifi_hal_error_print("%s, fgets() failed",__func__);
        goto exit;
    }
exit:
    if (fcmd != NULL) {
        fclose(fcmd);
    }

    return ret;
}

static bool sta_security_pwd_clear()
{
     return remove(STATICCPGCFG_1);
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
   char config_cmd[STATICCPGCFG_LEN] = {0};

   if (!password) {
      wifi_hal_error_print("%s, Invalid input arguments.",__func__);
      return -1;
   }

   if (!is_wifi_hal_vap_mesh_sta(vap_index)) {
      return 0 ;
   }

   if (sta_security_keypassphrase_restore(password, vap_index) == 0){
      return 0;
   }

   if (!sta_security_config_get(config_cmd,STATICCPGCFG_LEN)) {
      return -1;
   }

   if (!sta_security_pwd_get(config_cmd, password))
   {
      return -1;
   }
   sta_security_pwd_clear();
   wifi_hal_info_print("%s, Password fetch successful.",__func__);
   return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
   if (!ssid) {
      return -1;
   }

   if (is_wifi_hal_vap_mesh_sta(vap_index)) {
        sta_security_ssid_restore(ssid, vap_index)  ? strcpy(ssid, BACKHAUL_STA_SSID) : (void)0 ;
    }
    return 0;
}

int platform_get_wps_pin_default(char *pin)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int platform_wps_event(wifi_wps_event_t data)
{
    return 0;
}

int platform_get_country_code_default(char *code)
{
    if (code == NULL) {
        wifi_hal_error_print("%s:%d: code is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
#ifdef TARGET_GEMINI7_2
        strcpy(code, "GR");
#endif
    return 0;
}

int nvram_get_current_password(char *l_password, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

#if defined(CONFIG_MLO)
static int qca_get_vap_mld_addr(wifi_vap_info_t* vap_info, char* mld_mac_buf)
{
    if (vap_info == NULL) {
        wifi_hal_error_print("%s:%d: vap_info is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    mld_mac_buf[0] = 0x00;
    mld_mac_buf[1] = 0x00;
    mld_mac_buf[2] = 0xaa;
    mld_mac_buf[3] = 0xbb;
    mld_mac_buf[4] = 0xcc;
    mld_mac_buf[5] = vap_info->vap_index;
    wifi_hal_info_print("%s:%d: mld address for vap index %d is " MACSTR "\n",
       __func__, __LINE__, vap_info->vap_index, MAC2STR(mld_mac_buf));
    return RETURN_OK;
}
#endif

int platform_create_interface_attributes(struct nl_msg **msg_ptr, wifi_radio_info_t *radio,
    wifi_vap_info_t *vap)
{
    char mld_mac_addr[ETH_ALEN];
    (void)radio;

    if (msg_ptr == NULL || *msg_ptr == NULL || vap == NULL) {
        wifi_hal_dbg_print("%s:%d Invalid arguments\n", __func__, __LINE__);
        return RETURN_ERR;
    }
#if defined(CONFIG_MLO)
    if (qca_get_vap_mld_addr(vap, mld_mac_addr) == RETURN_ERR) {
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d:Adding MLD addr " MACSTR " for vap index:%d\n", __func__, __LINE__,
        MAC2STR(mld_mac_addr), vap->vap_index);
    if (nla_put(*msg_ptr, NL80211_ATTR_MLD_MAC, ETH_ALEN, mld_mac_addr) < 0) {
        return RETURN_ERR;
    }
#endif
    return RETURN_OK;
}

#if defined(CONFIG_MLO)
static int qca_create_mld_interfaces(wifi_vap_info_map_t *map)
{
    char cmd[DEFAULT_CMD_SIZE];
    int i;
    wifi_vap_info_t *vap;
    char mld_mac_addr[ETH_ALEN];

    for (i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        snprintf(cmd, sizeof(cmd), "iw dev | grep -w mld%d", vap->vap_index);
        wifi_hal_info_print("%s:%d: Executing %s\n", __func__, __LINE__, cmd);

        if (system(cmd) == 0) {
            wifi_hal_info_print("%s:%d: mld%d already present\n", __func__, __LINE__, vap->vap_index);
        } else {
            qca_get_vap_mld_addr(vap, mld_mac_addr);
            snprintf(cmd, sizeof(cmd), "iw phy mld-phy0 interface add mld%d type __ap mld_addr " MACSTR,
                                            vap->vap_index, MAC2STR(mld_mac_addr));
            wifi_hal_info_print("%s:%d Executing %s\n", __func__, __LINE__, cmd);
            system(cmd);
        }
    }
    return RETURN_OK;
}
#endif

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    char interface_name[10] = {0};
    char param[128] = {0};
    wifi_vap_info_t *vap = NULL;
    unsigned int vap_itr = 0;

    for (vap_itr=0; vap_itr < map->num_vaps; vap_itr++) {
        memset(interface_name, 0, sizeof(interface_name));
        memset(param, 0, sizeof(param));
        vap = &map->vap_array[vap_itr];
        get_interface_name_from_vap_index(vap->vap_index, interface_name);
        snprintf(param, sizeof(param), "ath%d.vap_enabled", vap->vap_index);
    }
#ifdef CONFIG_MLO
    qca_create_mld_interfaces(map);
#endif
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_flags_init(int *flags)
{  
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    *flags |= PLATFORM_FLAGS_CONTROL_PORT_FRAME;
    return 0;
}

int platform_get_aid(void* priv, u16* aid, const u8* addr)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_free_aid(void* priv, u16* aid)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_sync_done(void* priv)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_get_channel_bandwidth(wifi_radio_index_t index,  wifi_channelBandwidth_t *channelWidth)
{
    char temp_buff [MAX_BUF_SIZE] = {0};
    u_int8_t seqCounter = 0;

    wifi_getRadioOperatingChannelBandwidth(index, temp_buff);
    if (temp_buff[0] == 0) {
        wifi_hal_error_print("%s:%d Channel Bandwidth is NULL\n", __func__, __LINE__);
        return -1;
    }
 
    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiChannelBandWidthMap); seqCounter++) {
        if (strncmp(temp_buff, wifiChannelBandWidthMap[seqCounter].wifiChanWidthName, strlen(wifiChannelBandWidthMap[seqCounter].wifiChanWidthName))) {
            *channelWidth = wifiChannelBandWidthMap[seqCounter].halWifiChanWidth;
        }
    }

    if (*channelWidth == 0) {
        wifi_hal_error_print("%s:%d Channel Bandwidth not supported\n", __func__, __LINE__);
        return -1; 
    }
    
    return 0;
}

int platform_update_radio_presence(void)
{
    unsigned int index = 0;
    char cmd[DEFAULT_CMD_SIZE] = {0};
    wifi_radio_info_t *radio = NULL;

    wifi_hal_info_print("%s:%d: g_wifi_hal.num_radios %d\n", __func__, __LINE__, g_wifi_hal.num_radios);
    for (index = 0; index < g_wifi_hal.num_radios; index++)
    {
        radio = get_radio_by_rdk_index(index);
        snprintf(cmd, sizeof(cmd), "/sys/class/net/wifi%d",index);
        if (!is_interface_exists(cmd)) {
               radio->radio_presence = false;
        }
        wifi_hal_info_print("%s:%d: Index %d presence %d\n", __func__, __LINE__, index, radio->radio_presence);
    }

    return 0;
}

int nvram_get_mgmt_frame_power_control(int vap_index, int* output_dbm)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_set_txpower(void* priv, uint txpower)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int platform_set_offload_mode(void* priv, uint offload_mode)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return RETURN_OK;
}

int platform_get_radius_key_default(char *radius_key)
{   
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int wifi_setQamPlus(void *radioIndex)
{
    return 0;
}

int platform_get_vendor_oui(char *vendor_oui, int vendor_oui_len)
{
    if (NULL == vendor_oui) {
        wifi_hal_error_print("%s:%d  Invalid parameter \n", __func__, __LINE__);
        return -1;
    }
    strncpy(vendor_oui, OUI_QCA, vendor_oui_len - 1);

    return 0;
}

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
     char temp_buff [MAX_BUF_SIZE] = {0};
     FILE *fptr = NULL; char *context = NULL;
     char val[MAX_BUF_SIZE] = {0};

     if (check_radio_index(index) != 0) {
             return -1;
     }

     /* NOTE: rdk_index points to wifi%d index while in vendor hal we would convert to qca_index */

     snprintf(temp_buff,sizeof(temp_buff),"cat /sys/class/net/wifi%d/thermal/temp",index);

     fptr = popen(temp_buff, "r");
     if (fptr == NULL) {
             wifi_hal_dbg_print("%s: popen error\n", __FUNCTION__);
             return -1 ;
     }

     fgets(val,MAX_BUF_SIZE,fptr);
     pclose(fptr);
     strtok_r(val, "\n", &context);

     radioPhyTemperature->radio_Temperature = (val ? atoi(val) : 0);

     return RETURN_OK;
}

int platform_get_acl_num(int vap_index, uint *acl_count)
{
    return 0;
}

int platform_set_neighbor_report(uint index, uint add, mac_address_t mac)
{
    wifi_NeighborReport_t nbr_report;

    wifi_hal_info_print("%s:%d Enter %d\n", __func__, __LINE__,index);

    memcpy(nbr_report.bssid, mac, sizeof(mac_address_t));
    wifi_setNeighborReports(index,add, &nbr_report);

    return 0;
}

int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return 0;
}

int wifi_setApRetrylimit(void *priv)
{
    if (priv == NULL) {
        wifi_hal_error_print("%s:%d:error couldn't find primary interface\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_interface_info_t *interface = (wifi_interface_info_t *) priv;
    wifi_vap_index_t retry_vap_index = interface->vap_info.vap_index;
    int res = -1;

    res = wifi_setApRetryLimit(retry_vap_index, RETRY_LIMIT);

    if (res) {
        wifi_hal_dbg_print("%s:%d: AP_RETRY_LIMIT failed:%d", __func__, __LINE__, res);
    }

    return 0;
}

#ifdef CONFIG_IEEE80211BE
int nl80211_drv_mlo_msg(struct nl_msg *msg, struct nl_msg **msg_mlo, void *priv,
    struct wpa_driver_ap_params *params)
{
#ifdef CONFIG_MLO
    (void)msg_mlo;

    wifi_interface_info_t *interface = (wifi_interface_info_t *) priv;
    int res = 0;
    wifi_hal_dbg_print("%s:%d: params->num_mlo_links: %d\n", __func__, __LINE__, params->num_mlo_links);
    if (params->num_mlo_links) {
        int i;
        struct nlattr *link_ids;
        struct nlattr *mac_addrs;

        link_ids = nla_nest_start(msg, NL80211_ATTR_MLD_LINK_IDS);
        if (link_ids == NULL) {
            wifi_hal_error_print("%s:%d: link_ids is NULL\n", __func__, __LINE__);
            return -1;
        }
        for (i = 0; i < params->num_mlo_links; i++) {
            wifi_hal_dbg_print("nl80211: %s MLO-Link_id %d\n", interface->name,
                                params->mlo_link_ids[i]);
            if ((res = nla_put_u32(msg, i + 1, params->mlo_link_ids[i]))) {
                return res;
            }
        }
        nla_nest_end(msg, link_ids);

        mac_addrs = nla_nest_start(msg, NL80211_ATTR_MLD_LINK_MACS);
        if (mac_addrs == NULL) {
            return -1;
        }
        for (i = 0; i < params->num_mlo_links; i++) {
            wifi_hal_dbg_print("nl80211: %s MLO-Link-Mac " MACSTR "\n",
                                interface->name,
                                MAC2STR(params->mlo_mac_addrs[i]));
            if ((res = nla_put(msg, i + 1, ETH_ALEN, params->mlo_mac_addrs[i]))) {
                return res;
            }
        }
        nla_nest_end(msg, mac_addrs);
    }
    wifi_hal_dbg_print("%s:%d: EXIT\n", __func__, __LINE__);
    return res;
#endif /* CONFIG_MLO */
}

int nl80211_send_mlo_msg(struct nl_msg *msg)
{
    (void)msg;

    return 0;
}

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb) {
    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) {
        size_t len;

        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);

        if (len > sizeof(eht_capab->mac_cap)) {
            len = sizeof(eht_capab->mac_cap);
        }
        os_memcpy(eht_capab->mac_cap,
                nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]), len);
    }
}

int update_hostap_mlo(wifi_interface_info_t *interface) {
#ifdef CONFIG_MLO
    struct hostapd_bss_config *const conf = &interface->u.ap.conf;
    struct hostapd_data *const hapd = &interface->u.ap.hapd;
    char mld_mac_addr[ETH_ALEN];

    wifi_hal_dbg_print("%s:%d: ENTER\n", __func__, __LINE__);
    if(hapd->iface->interfaces->mlds.next == NULL)
    {
        dl_list_init(&hapd->iface->interfaces->mlds);
        wifi_hal_info_print("%s:%d: init dl_list_init(&hapd->iface->interfaces.mld\n", __func__, __LINE__);
    }
    else
    {
        wifi_hal_info_print("%s:%d: Not initializing dl_list_init(&hapd->iface->interfaces.mld Again\n",
                                                                                       __func__, __LINE__);
    }
    if (!conf->disable_11be) {
        wifi_hal_info_print("%s:%d: hostap disable_11be is false\n", __func__, __LINE__);
        //mld_link_mac_list
        os_memcpy(&(conf->mld_link_mac_list.addr[0]), hapd->own_addr, ETH_ALEN);
        conf->mld_link_mac_list.num_links = 1;

        //mld_mac_addr
        qca_get_vap_mld_addr(&interface->vap_info, mld_mac_addr);
        os_memcpy(conf->mld_mac_addr, mld_mac_addr, ETH_ALEN);

        //mld_link_ids
        conf->mld_link_id_list.link_id[0] = interface->vap_info.radio_index;
        conf->mld_link_id_list.num_links = 1;
        wifi_hal_dbg_print("%s:%d: Setting MLD-link-MAC: " MACSTR " link ID: %d MLD_MAC: " MACSTR "\n",
                                          __func__, __LINE__, MAC2STR(conf->mld_link_mac_list.addr[0]),
                                          conf->mld_link_id_list.link_id[0], MAC2STR(conf->mld_mac_addr));
    } else {
        os_memset(&conf->mld_link_mac_list, 0, sizeof(conf->mld_link_mac_list));
        os_memset(conf->mld_mac_addr, 0, sizeof(conf->mld_mac_addr));
        os_memset(&conf->mld_link_id_list, 0, sizeof(conf->mld_link_id_list));
    }
    wifi_hal_dbg_print("%s:%d: EXIT\n", __func__, __LINE__);

    return RETURN_OK;
#endif /* CONFIG_MLO */
}

#endif /* CONFIG_IEEE80211BE */

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return RETURN_OK;
}

int platform_get_reg_domain(wifi_radio_index_t radioIndex, UINT *reg_domain)
{
    char cmd[64] = { 0 };
    char buf[16] = { 0 };
    int ret;

    wifi_hal_dbg_print("%s:%d: radioIndex %d\n", __func__, __LINE__, radioIndex);

    snprintf(cmd, sizeof(cmd), "cfg80211tool wifi%d getRegdomain | cut -d':' -f2", radioIndex);

    ret = _syscmd(cmd, buf, sizeof(buf));
    if ((ret != 0) && (strlen(buf) == 0)) {
        wifi_hal_dbg_print("%s:%d Error", __func__, __LINE__);
        return RETURN_ERR;
    }

    *reg_domain = atoi(buf);

    wifi_hal_dbg_print(" %s:%d Reg domain is %d", __func__, __LINE__, *reg_domain);
    return RETURN_OK;
}

static int qca_add_intf_to_bridge(wifi_interface_info_t *interface, bool is_mld)
{
    char mld_ifname[32];
    wifi_vap_info_t *vap;

    vap = &interface->vap_info;
    if (vap->vap_mode == wifi_vap_mode_ap) {
        wifi_hal_info_print("%s:%d: interface:%s bss enabled:%d bridge:%s\n", __func__,
            __LINE__, interface->name, vap->u.bss_info.enabled, vap->bridge_name);
        if (vap->bridge_name[0] != '\0' && vap->u.bss_info.enabled) {
            wifi_hal_info_print("%s:%d: interface:%s create bridge:%s\n", __func__, __LINE__,
                interface->name, vap->bridge_name);

            snprintf(mld_ifname, sizeof(mld_ifname), "%s%d", MLD_PREFIX, vap->vap_index);
            if (is_mld) {
                if (nl80211_remove_from_bridge(interface->name) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to remove from OVS bridge\n",
                    __func__, __LINE__, interface->name);
                }

                if (nl80211_create_bridge(mld_ifname, vap->bridge_name) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface->name, vap->bridge_name);
                    return RETURN_ERR;
                }
                wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                        mld_ifname, vap->bridge_name);
            } else {
                if (nl80211_remove_from_bridge(mld_ifname) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to remove from OVS bridge\n",
                       __func__, __LINE__, interface->name);
                }
                if (nl80211_create_bridge(interface->name, vap->bridge_name) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface->name, vap->bridge_name);
                    return RETURN_ERR;
                }
            }
            wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                interface->name, vap->bridge_name);
        }
    }
    return RETURN_OK;
}

#if defined(CONFIG_MLO)
static bool is_bonding_slave(const char *mld_name, const char *ifname)
{
    char linebuf[512];
    char slave_list[128];
    char *slave;
    char *rest;
    FILE *fp;
    bool ret = false;

    snprintf(slave_list, sizeof(slave_list), "/sys/class/net/%s/bonding/slaves", mld_name);
    fp = fopen(slave_list, "r");
    if (NULL == fp) {
        wifi_hal_error_print("%s:%d Failed to open file %s\n", __func__, __LINE__, slave_list);
        return ret;
    }

    if (access(slave_list, F_OK) == 0) {
        linebuf[0] = '\0';
        fgets(linebuf, sizeof(linebuf), fp);
        if (strlen(linebuf) && linebuf[strlen(linebuf) - 1] == '\n') {
            linebuf[strlen(linebuf) - 1] = '\0'; // remove trailing newline character (\n)
        }
        wifi_hal_dbg_print("%s:%d  slaves=%s\n", __func__, __LINE__, linebuf);
        rest = linebuf;
        while ((slave = strtok_r(rest, " ", &rest))) {
            printf("%s ", slave);
            if (strcmp(slave, ifname) == 0) {
                wifi_hal_dbg_print("%s:%d %s is bonding slave of %s\n", __func__, __LINE__, ifname,
                    mld_name);
                ret = true;
                break;
            }
        }
    }
    fclose(fp);
    if (!ret) {
        wifi_hal_dbg_print("%s:%d %s is not a bonding slave of %s\n", __func__, __LINE__, ifname,
            mld_name);
    }
    return ret;
}

INT platform_set_intf_mld_bonding(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    char cmd[QCA_MAX_CMD_SZ];
    char mld_ifname[32];
    char ifname[32];
    char mld_mac_addr[ETH_ALEN];
    char mld_mac_str[18];

    if (interface == NULL || radio == NULL) {
        wifi_hal_error_print("%s:%d: Invalid arguments\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if ((int)interface->vap_info.vap_index >= 0) {
        if (get_interface_name_from_vap_index(interface->vap_info.vap_index, ifname) != RETURN_OK) {
            wifi_hal_error_print(
                "%s:%d: vap index:%d failed to get interface name from vap index\n", __func__,
                __LINE__, interface->vap_info.vap_index);
            return RETURN_ERR;
        }
        if (qca_get_vap_mld_addr(&interface->vap_info, mld_mac_addr) == RETURN_ERR) {
            wifi_hal_error_print("%s:%d: vap index:%d failed to get mld address\n", __func__,
                __LINE__, interface->vap_info.vap_index);
            return RETURN_ERR;
        }

        snprintf(mld_mac_str, sizeof(mld_mac_str), MACSTR, MAC2STR(mld_mac_addr));
        snprintf(mld_ifname, sizeof(mld_ifname), "mld%d", interface->vap_info.vap_index);

        if ((!(radio->oper_param.variant & WIFI_80211_VARIANT_BE)) &&
            is_bonding_slave(mld_ifname, ifname)) {
            snprintf(cmd, sizeof(cmd), "cfg80211tool %s mode %s",
                getInterface(interface->vap_info.vap_index),
                (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND) ? "11GHE20" : "11AHE80");
            wifi_hal_info_print("%s:%d Executing: %s\n", __func__, __LINE__, cmd);
            system(cmd);
            wifi_hal_info_print("%s:%d Delete bonding between ifname:%s and mld:%s\n", __func__,
                __LINE__, ifname, mld_ifname);
            // ToDo :- Check and enable if required
            // wifi_setMLDaddr(interface->vap_info.vap_index, "00:00:00:00:00:00");
            wifi_setMLDaddr(interface->vap_info.vap_index, mld_mac_str);
        } else {
            wifi_hal_dbg_print("%s:%d No need to changing bonding state for %s\n", __func__,
                __LINE__, ifname);
        }
    }
    return RETURN_OK;
}
#endif 

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    #define MAX_INTERFACE_IDX 30
    wifi_radio_info_t *radio = NULL;
    wifi_interface_info_t *interface = NULL;
    int existing_vap_indices = 0;
    int i;

    wifi_hal_dbg_print("%s:%d Enter\n",__func__,__LINE__);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if(!radio->configured)
    {
        if (dfs_nl_listen_start()) {
            wifi_hal_error_print("%s:%d DFS socket establishment failed\n", __func__, __LINE__);
        } else {
            wifi_hal_dbg_print("%s:%d DFS socket initialized\n", __func__, __LINE__);
        }
        wifi_hal_info_print("%s:%d: Radio is getting configured for the first time.\n", __func__, __LINE__);
        return RETURN_OK;
    }

    interface = hash_map_get_first(radio->interface_map);
    if (interface == NULL ) {
        wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
        return RETURN_OK;
    }

    while (interface != NULL) {
        if(interface->vap_info.vap_index >= 0) {
            existing_vap_indices |= 1<<interface->vap_info.vap_index;
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }
#if defined(CONFIG_MLO)
    for(i=0; i < MAX_INTERFACE_IDX; i++)
    {
        if(!(existing_vap_indices & 1<<i))
        {
            continue;
        }
        if ((interface = get_interface_by_vap_index(i)) == NULL)
        {
            wifi_hal_error_print("%s:%d: vap index:%d Interface should be created first to get the MLD addr\n",
                                __func__, __LINE__, i);
            continue;
        }
        if (radio->oper_param.variant & WIFI_80211_VARIANT_BE && !(operationParam->variant & WIFI_80211_VARIANT_BE)) {
            // Moving from 11BE to non 11BE mode
            wifi_hal_info_print("%s:%d: 11BE mode is disabled. Remove mld from the bridge. [%d -> %d]\n",
                __func__, __LINE__, radio->oper_param.variant, operationParam->variant);
            if (qca_add_intf_to_bridge(interface, false) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: Failed to add vap idx %d to bridge.\n",
                    __func__, __LINE__, i);
                continue;
            }
        } else if (operationParam->variant & WIFI_80211_VARIANT_BE && !(radio->oper_param.variant & WIFI_80211_VARIANT_BE)) {
            // Moving from non 11BE to 11BE mode
            wifi_hal_info_print("%s:%d: 11BE mode is enabled. Add mld to the bridge. [%d -> %d]\n",
                __func__, __LINE__, radio->oper_param.variant, operationParam->variant);
            if (qca_add_intf_to_bridge(interface, true) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: Failed to add vap idx %d to bridge.\n",
                    __func__, __LINE__, i);
                continue;
            }
        } else {
            wifi_hal_dbg_print("%s:%d: Vap addition to bridge is not required!\n", __func__, __LINE__);
            return 0;
        }
    }
#endif
    if (dfs_nl_listen_start()) {
        wifi_hal_error_print("%s:%d DFS socket establishment failed\n", __func__, __LINE__);
    } else {
        wifi_hal_dbg_print("%s:%d DFS socket initialized\n", __func__, __LINE__);
    }

    wifi_hal_dbg_print("%s:%d Exit\n",__func__,__LINE__);
    return 0;
}

INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    int res = wifi_hal_send_mgmt_frame(apIndex, MacAddr, frame, len, frequency, wait);
    return (res == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_ERROR;
}

INT wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return wifi_sendActionFrameExt(apIndex, MacAddr, frequency, 0, frame, len);
}

static int dfs_nl_listen_start(void)
{
    struct sockaddr_nl addr;
    int fd;

    if (nl_fd != -1) {
        wifi_hal_dbg_print("%s:%d: DFS socket registered already\n", __func__, __LINE__);
        return 0;
    }

    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        wifi_hal_error_print("%s:%d: failed to create socket: %d (%s)\n", __func__, __LINE__, errno,
            strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        wifi_hal_error_print("%s:%d: failed to bind: %d (%s)\n", __func__, __LINE__, errno,
            strerror(errno));
        close(fd);
        return -1;
    }

    nl_fd = fd;

    // Start listener thread
    dfs_thread_running = 1;
    if (pthread_create(&dfs_thread, NULL, dfs_event_thread, NULL) != 0) {
        wifi_hal_error_print("%s:%d: Failed to start DFS thread (%s)\n", __func__, __LINE__,
            strerror(errno));
        close(nl_fd);
        nl_fd = -1;
        dfs_thread_running = 0;
        return -1;
    }
    pthread_detach(dfs_thread);

    wifi_hal_dbg_print("%s:%d: DFS listener initialized\n", __func__, __LINE__);
    return 0;
}

static void *dfs_event_thread(void *arg)
{
    struct pollfd pfd;
    int len = 0;
    int ret;
    size_t buf_size = 3000;

    pfd.fd = nl_fd;
    pfd.events = POLLIN;

    wifi_hal_dbg_print("%s:%d: DFS event thread started\n", __func__, __LINE__);

    while (dfs_thread_running) {
        ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            wifi_hal_error_print("%s:%d: poll failed, err %d (%s)\n", __func__, __LINE__, errno,
                strerror(errno));
            break;
        }
        if (ret == 0) {
            // no event this cycle just continue
            continue;
        }
        if (pfd.revents & POLLIN) {
            char *event_buf = (char *)malloc(buf_size * sizeof(char));
            if (!event_buf) {
                wifi_hal_error_print("%s:%d: Failed to allocate memory for dfs event\n", __func__,
                    __LINE__);
                continue;
            }
            len = recvfrom(nl_fd, event_buf, buf_size, MSG_DONTWAIT, NULL, 0);
            if (len > 0) {
                parse_iwcustom_buffer(event_buf, len);
            } else {
                wifi_hal_error_print("%s:%d: recvfrom returned %d (%s)\n", __func__, __LINE__, len,
                    strerror(errno));
            }
            free(event_buf);
        }
    }

    wifi_hal_dbg_print("%s:%d: DFS event thread exiting\n", __func__, __LINE__);
    return NULL;
}

static void process_event_to_onewifi(const char *ifname,
    wifi_channel_change_event_t radio_channel_param)
{
    radio_interface_mapping_t radio_map_t[MAX_NUM_RADIOS];
    wifi_device_callbacks_t *callbacks;
    wifi_radio_info_t *radio = NULL;
    int radio_index;

    get_radio_interface_info_map(radio_map_t);
    callbacks = get_hal_device_callbacks();

    for (int i = 0; i < MAX_NUM_RADIOS; i++) {
        if (strncmp(ifname, radio_map_t[i].interface_name, sizeof(radio_map_t[i].interface_name)) ==
            0) {
            radio_index = radio_map_t[i].radio_index;
            radio = get_radio_by_rdk_index(radio_index);
            radio_channel_param.radioIndex = radio_index;
            radio_channel_param.channel = radio->oper_param.channel;
            radio_channel_param.channelWidth = radio->oper_param.channelWidth;
            radio_channel_param.op_class = radio->oper_param.operatingClass;
        }
        wifi_hal_dbg_print("%s:%d RadioIndex:%d channel:%d chwid:%d opclass:%d sub-event:%d\n",
            __func__, __LINE__, radio_index, radio_channel_param.channel,
            radio_channel_param.channelWidth, radio_channel_param.op_class,
            radio_channel_param.sub_event);
    }
    radio_channel_param.event = WIFI_EVENT_DFS_RADAR_DETECTED;

    if ((callbacks != NULL) && (callbacks->channel_change_event_callback) &&
        !(radio_channel_param.sub_event == WIFI_EVENT_RADAR_NOP_FINISHED) &&
        (radio->oper_param.channel)) {
        callbacks->channel_change_event_callback(radio_channel_param);
    }
}

static void parse_iwcustom_buffer(const void *buf, unsigned int len)
{
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    struct ifinfomsg *ifi;
    const struct iw_event *iwe;
    int iwelen;
    int attrlen;
    char ifname[32];
    int ifindex;
    wifi_channel_change_event_t radio_channel_param = { 0 };

    memset(ifname, 0, sizeof(ifname));

    for (hdr = buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
        if (hdr->nlmsg_type != RTM_NEWLINK)
            continue;

        ifi = NLMSG_DATA(hdr);
        attr = IFLA_RTA(ifi);
        attrlen = IFLA_PAYLOAD(hdr);

        for (attr = NLMSG_DATA(hdr) + NLMSG_ALIGN(sizeof(struct ifinfomsg)),
            attrlen = NLMSG_PAYLOAD(hdr, sizeof(struct ifinfomsg));
             RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen)) {
            if (attr->rta_type != IFLA_WIRELESS)
                continue;

            ifindex = ifi->ifi_index;
            if (!if_indextoname(ifindex, ifname)) {
                strncpy(ifname, "unknown", sizeof(ifname));
            }
            for (iwe = RTA_DATA(attr), iwelen = RTA_PAYLOAD(attr);
                 ((iwelen) >= (iwe)->len && (iwelen) > 0);
                 iwe = ((iwelen) -= (iwe)->len, (void *)(iwe) + (iwe)->len)) {
                if (iwe->cmd == IWEVCUSTOM) {
                    const struct iw_point *iwp;
                    const void *data;
                    data = ((void *)(iwe) + IW_EV_LCP_LEN);

                    iwp = data - IW_EV_POINT_OFF;
                    data += IW_EV_POINT_LEN - IW_EV_POINT_OFF;
                    switch (iwp->flags) {
                    case IEEE80211_EV_CAC_STARTED:
                        radio_channel_param.sub_event = WIFI_EVENT_RADAR_CAC_STARTED;
                        process_event_to_onewifi(ifname, radio_channel_param);
                        break;
                    case IEEE80211_EV_CAC_COMPLETED:
                        radio_channel_param.sub_event = WIFI_EVENT_RADAR_CAC_FINISHED;
                        process_event_to_onewifi(ifname, radio_channel_param);
                        break;
                    case IEEE80211_EV_NOL_FINISHED:
                        radio_channel_param.sub_event = WIFI_EVENT_RADAR_NOP_FINISHED;
                        process_event_to_onewifi(ifname, radio_channel_param);
                        break;
                    case IEEE80211_EV_RADAR_DETECTED:
                        radio_channel_param.sub_event = WIFI_EVENT_RADAR_DETECTED;
                        process_event_to_onewifi(ifname, radio_channel_param);
                        break;
                    default:
                        wifi_hal_info_print("Unknown event %s:%d\n", __func__, __LINE__);
                        break;
                    }
                }
            }
        }
    }
}
