/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include <assert.h>
#include "hostapd/eap_register.h"
#include "ap/rrm.h"
#include "ap/neighbor_db.h"

#ifdef CONFIG_WIFI_EMULATOR
#include "config_supplicant.h"
#endif
#ifdef BANANA_PI_PORT
#include "wpa_supplicant/config.h"
#endif

#define MAC_ADDRESS_LEN 6

#ifdef CONFIG_WIFI_EMULATOR
#define RADIO_INDEX_ASSERT_RC(radioIndex, retcode) \
    do { \
        int _index = (int)radioIndex; \
        if ((_index >= (MAX_NUM_SIMULATED_CLIENT)) || (_index < 0)) { \
            wifi_hal_error_print("%s: INCORRECT radioIndex = %d numRadios = %d\n", \
                    __FUNCTION__, _index, MAX_NUM_SIMULATED_CLIENT); \
            return retcode; \
        } \
    } while (0)
#else
#define RADIO_INDEX_ASSERT_RC(radioIndex, retcode) \
    do { \
        int _index = (int)radioIndex; \
        if ((_index >= (MAX_NUM_RADIOS)) || (_index < 0)) { \
            wifi_hal_error_print("%s: INCORRECT radioIndex = %d numRadios = %d\n", \
                    __FUNCTION__, _index, MAX_NUM_RADIOS); \
            return retcode; \
        } \
    } while (0)
#endif

#define AP_INDEX_ASSERT_RC(apIndex, retcode) \
    do { \
        int _index = (int)apIndex; \
        if ((_index >= (MAX_VAP)) || (_index < 0)) { \
            wifi_hal_error_print("%s, INCORRECT apIndex = %d MAX_VAP = %d\n", __FUNCTION__, \
                            _index, MAX_VAP); \
            return retcode; \
        } \
    } while (0)

#define NULL_PTR_ASSERT_RC(ptr, retcode) \
    do { \
        if (NULL == ptr) { \
            wifi_hal_error_print("%s:%d NULL pointer!\n", __FUNCTION__, __LINE__); \
            return retcode; \
        } \
    } while (0)

#define RADIO_INDEX_ASSERT(radioIndex)  RADIO_INDEX_ASSERT_RC(radioIndex, WIFI_HAL_INVALID_ARGUMENTS)
#define AP_INDEX_ASSERT(apIndex)        AP_INDEX_ASSERT_RC(apIndex, WIFI_HAL_INVALID_ARGUMENTS)
#define NULL_PTR_ASSERT(ptr)            NULL_PTR_ASSERT_RC(ptr, WIFI_HAL_INVALID_ARGUMENTS)

#ifndef VHT_OPER_CHANWIDTH_20_40MHZ
/* According to IEEE80211-2016 "The subfields of the
 * VHT Operation Information field are defined in Table 9-252.*/
#define VHT_OPER_CHANWIDTH_20_40MHZ         0
#define VHT_OPER_CHANWIDTH_80_160_80P80MHZ  1
#define VHT_OPER_CHANWIDTH_160MHZ           2
#define VHT_OPER_CHANWIDTH_80P80MHZ         3
#endif // VHT_OPER_CHANWIDTH_20_40MHZ

static int g_fd_arr[MAX_VAP] = {0};
static int g_IfIdx_arr[MAX_VAP] = {0};
static unsigned char g_vapSmac[MAX_VAP][MAC_ADDRESS_LEN] = {'\0'};
#ifdef CONFIG_WIFI_EMULATOR
extern const struct wpa_driver_ops g_wpa_supplicant_driver_nl80211_ops;
#endif

#if !defined(CMXB7_PORT)
wifi_hal_priv_t g_wifi_hal;
#endif

INT wifi_hal_getInterfaceMap(wifi_interface_name_idex_map_t *if_map, unsigned int max_entries,
    unsigned int *if_map_size)
{
    *if_map_size = get_sizeof_interfaces_index_map();
    if (max_entries < *if_map_size) {
        wifi_hal_error_print("%s:%d: Invalid buffer size %d, expected %d\n", __func__, __LINE__,
            max_entries, *if_map_size);
        return RETURN_ERR;
    }
    get_wifi_interface_info_map(if_map);
    return RETURN_OK;
}

INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal)
{
    unsigned int i;
    wifi_interface_info_t *interface;
    wifi_radio_info_t *radio;
    wifi_radio_capabilities_t *cap;
    wifi_vap_info_t *vap;
    unsigned int radio_band = 0;
    char output[256] = {0};
    mac_addr_str_t al_ctrl_mac;
    char ifname[100] = {0};
    int ret = 0, colocated_mode;
    bool interface_found = false;
    size_t len;

    NULL_PTR_ASSERT(hal);

    hal->version.major = WIFI_HAL_MAJOR;
    hal->version.minor = WIFI_HAL_MINOR;

    hal->wifi_prop.numRadios = g_wifi_hal.num_radios;

    /*
     * RDKB-32778: Determine max number of stations for given platform
     *
     * This is one time operation upon system bring-up. Hence, consider this routine as
     * SET operation as well because as far as RDKB perspective the driver has already
     * returned HAL capabilities but this routine tweaks HAL caps based on platform and
     * it's requirements.
     */
#if defined(_SKY_HUB_COMMON_PRODUCT_REQ_) && !defined(_SR213_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_SCXF11BFL_PRODUCT_REQ_)
    /* For SKY platforms, set as per _SKY macro defined */
    hal->wifi_prop.BssMaxStaAllow = BSS_MAX_NUM_STA_SKY;
#elif defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined(VNTXER5_PORT) || defined(SCXF10_PORT)
    /* For TCHXB8 platforms, set as per _XB8 macro defined */
    hal->wifi_prop.BssMaxStaAllow = BSS_MAX_NUM_STA_XB8;
#else
    /* For all other platforms, set as per _COMMON macro defined. */
    hal->wifi_prop.BssMaxStaAllow = BSS_MAX_NUM_STA_COMMON;
#endif
#if !defined(_PLATFORM_RASPBERRYPI_)
    /* Copy device manufacturer,model,serial no and software version to here */
    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    _syscmd("cat /etc/machine-id", output, sizeof(output));
    if (strlen(output) == 0) {
        strncpy(output, "bpi-123", sizeof(output));
    }
#else
    _syscmd("grep -a 'Serial' /tmp/factory_nvram.data | cut -d ' ' -f2", output, sizeof(output));
#endif
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    strcpy(hal->wifi_prop.serialNo,output);

    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    _syscmd("cat /proc/device-tree/model | tr -d ' '", output, sizeof(output));
    if (strlen(output) == 0) {
        strncpy(output, "Banana Pi - R4", sizeof(output));
    }
#else
    _syscmd("grep -a 'MODEL' /tmp/factory_nvram.data | cut -d ' ' -f2", output, sizeof(output));
#endif
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    strcpy(hal->wifi_prop.manufacturerModel,output);
    strcpy(hal->wifi_prop.manufacturer,output);

    memset(output, '\0', sizeof(output));
    _syscmd("grep 'imagename:' /version.txt | cut -d ':' -f2 ", output, sizeof(output));
#if defined(_PLATFORM_BANANAPI_R4_)
    if (strlen(output) == 0) {
        strncpy(output, "Banana Pi - R4 V1.0", sizeof(output));
    }
#endif
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    strcpy(hal->wifi_prop.software_version, output);

    // CM mac
    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    if (get_mac_address("erouter0", hal->wifi_prop.cm_mac) != RETURN_OK) {
       if (get_mac_address("eth0", hal->wifi_prop.cm_mac) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Unable to get CM mac address\n", __func__, __LINE__);
            memset(hal->wifi_prop.cm_mac, 0, sizeof(hal->wifi_prop.cm_mac));
       }
    }
#else
    _syscmd("grep -a 'CM' /tmp/factory_nvram.data | cut -d ' ' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    to_mac_bytes(output,hal->wifi_prop.cm_mac);
#endif


    memset(output, '\0', sizeof(output));
#if defined (_PLATFORM_BANANAPI_R4_)
    if (get_mac_address("erouter0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
       if (get_mac_address("eth0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Unable to get AL mac address\n", __func__, __LINE__);
            memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
       }
    }
#else
    if (get_mac_address("eth0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Unable to get AL mac address\n", __func__, __LINE__);
        memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
    }
#endif

#elif (defined (_PLATFORM_RASPBERRYPI_))
   /* Copy device manufacturer,model,serial no and software version to here */
    memset(output, '\0', sizeof(output));
    _syscmd("grep -a 'Serial' /proc/cpuinfo | cut -d ':' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    strcpy(hal->wifi_prop.serialNo,output);

    memset(output, '\0', sizeof(output));
    _syscmd("grep -a 'Model' /proc/cpuinfo | cut -d ':' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    strcpy(hal->wifi_prop.manufacturerModel,output);
    strcpy(hal->wifi_prop.manufacturer,output);

    memset(output, '\0', sizeof(output));
    _syscmd("vcgencmd version | grep 'version' | cut -d ' ' -f2", output, sizeof(output));
    len = strnlen(output, sizeof(output));
    if (len != 0 && output[len - 1] == '\n') {
        output[len - 1] = '\0';
    }
    strcpy(hal->wifi_prop.software_version, output);

    // CM mac
    memset(output, '\0', sizeof(output));
    if (get_mac_address("eth0", hal->wifi_prop.cm_mac) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Unable to get CM mac address\n", __func__, __LINE__);
        memset(hal->wifi_prop.cm_mac, 0, sizeof(hal->wifi_prop.cm_mac));
    }

    memset(output, '\0', sizeof(output));
    if (get_mac_address("eth0", hal->wifi_prop.al_1905_mac) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Unable to get AL mac address\n", __func__, __LINE__);
        memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
    }
#endif

    /* Read the al_mac address from EM_CFG_FILE */
    ret = json_parse_string(EM_CFG_FILE, "Al_MAC_ADDR", al_ctrl_mac, sizeof(al_ctrl_mac));
    if (ret == 0) {
        to_mac_bytes(al_ctrl_mac, hal->wifi_prop.al_1905_mac);
        wifi_hal_dbg_print("%s:%d al_mac %s read from json file:%s.\n", __func__, __LINE__,
            al_ctrl_mac, EM_CFG_FILE);
    } else {
        wifi_hal_error_print("%s:%d: Unable to read al_mac from json file:%s, error:%d\n", __func__,
            __LINE__, EM_CFG_FILE, ret);
        memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
        hal->wifi_prop.colocated_mode = -1;
    }

    /* Read the collocated mode from EM_CFG_FILE*/
    ret = json_parse_integer(EM_CFG_FILE, "Colocated_Mode", &colocated_mode);
    if (ret == 0) {
        hal->wifi_prop.colocated_mode = colocated_mode;
        interface_found = get_ifname_from_mac((mac_address_t *)hal->wifi_prop.al_1905_mac, ifname);
        /* Based on the value of colocated_mode and the interface obtained from almac_address
           Configure the vap_name appropriately */
        if (interface_found == true) {
            if (strncmp(ifname, "eth", strlen("eth")) != 0 &&
                strncmp(ifname, "lo", strlen("lo")) != 0 &&
                strncmp(ifname, "lan", strlen("lan")) != 0 &&
                strncmp(ifname, "brlan", strlen("brlan")) != 0) {
                /* interface is not an ethernet and not an loopback interface */
                if (configure_vap_name_basedon_colocated_mode(ifname,
                        hal->wifi_prop.colocated_mode) != 0) {
                    wifi_hal_error_print(
                        "%s:%d Error configuring vapname for interface:%s, colocated_mode:%d",
                        __func__, __LINE__, ifname, hal->wifi_prop.colocated_mode);
                    hal->wifi_prop.colocated_mode = -1;
                }
            } else {
                /* almac_address is either ethernet or loopback, nothing to be done*/
            }
        } else {
            /* al_mac address configured is incorrect, reset the al_1905_mac to 0*/
            wifi_hal_error_print("%s:%d: No interface found for al_mac address:%s\n", __func__,
                __LINE__, to_mac_str(hal->wifi_prop.al_1905_mac, al_ctrl_mac));
            memset(hal->wifi_prop.al_1905_mac, 0, sizeof(hal->wifi_prop.al_1905_mac));
            hal->wifi_prop.colocated_mode = -1;
        }
    } else {
        wifi_hal_error_print("%s:%d: Unable to read colocated_mode from json file:%s, error:%d\n",
            __func__, __LINE__, EM_CFG_FILE, ret);
        hal->wifi_prop.colocated_mode = -1;
    }

    wifi_hal_info_print("%s:%d: serialNo=%s, ModelName=%s,sw_version=%s, manufacturer=%s "
                        "al_mac_addr=%s colocated_mode:%d\n",
        __func__, __LINE__, hal->wifi_prop.serialNo, hal->wifi_prop.manufacturerModel,
        hal->wifi_prop.software_version, hal->wifi_prop.manufacturer,
        to_mac_str(hal->wifi_prop.al_1905_mac, al_ctrl_mac), hal->wifi_prop.colocated_mode);

    for (i = 0; i < hal->wifi_prop.numRadios; i++) {
        radio_band = 0;
        radio = get_radio_by_rdk_index(i);
        wifi_hal_info_print("%s:%d:Enumerating interfaces on PHY radio index: %d, RDK radio index:%d\n", __func__, __LINE__, radio->index, i);
        hal->wifi_prop.radio_presence[i] = radio->radio_presence;
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            vap = &interface->vap_info;
            strncpy(interface->firmware_version, hal->wifi_prop.software_version, sizeof(interface->firmware_version) - 1);
            interface->firmware_version[sizeof(interface->firmware_version) - 1] = '\0';
            wifi_hal_info_print("%s:%d:interface name: %s, interface->firmware_version: %s, vap index: %d, vap name: %s\n", __func__, __LINE__,
                    interface->name, interface->firmware_version, vap->vap_index, vap->vap_name);
            interface = hash_map_get_next(radio->interface_map, interface);
        }

        radio_band = get_band_info_from_rdk_radio_index(i);
        cap = &hal->wifi_prop.radiocap[i];
        memcpy((unsigned char *)cap, (unsigned char *)&radio->capab, sizeof(wifi_radio_capabilities_t));
        adjust_radio_capability_band(cap, radio_band);
    }

    get_wifi_interface_info_map(hal->wifi_prop.interface_map);
    get_radio_interface_info_map(hal->wifi_prop.radio_interface_map);

    return RETURN_OK;
}

INT wifi_hal_setApWpsButtonPush(INT ap_index)
{
    wifi_hal_info_print("%s:%d: WPS Push Button for radio index %d\n", __func__, __LINE__, ap_index);

    wifi_hal_nl80211_wps_pbc(ap_index);

    return 0;
}

INT wifi_hal_setApWpsCancel(INT ap_index)
{
    wifi_hal_info_print("%s:%d: WPS Cancel session for radio index %d\n", __func__, __LINE__, ap_index);

    wifi_hal_nl80211_wps_cancel(ap_index);

    return 0;
}

INT wifi_hal_setApWpsPin(INT ap_index, char *wps_pin)
{
    if (wps_pin == NULL) {
        wifi_hal_error_print("%s:%d: WPS Pin is NULL for vap_index:%d\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: WPS Pin configuration for vap_index:%d pin:%s\n",
                                __func__, __LINE__, ap_index, wps_pin);

    return (wifi_hal_nl80211_wps_pin(ap_index, wps_pin));
}

INT wifi_hal_init()
{
#ifndef CONFIG_WIFI_EMULATOR
    unsigned int i;
    wifi_radio_info_t *radio;
    platform_get_radio_caps_t get_radio_caps_fn;
    platform_flags_init_t flags_init_fn;
#endif
    pthread_attr_t *attrp = NULL;
#if defined(_PLATFORM_BANANAPI_R4_)
    ssize_t stack_size = 0x800000; /* 8MB */
    pthread_attr_t attr;
    int ret = 0;
#endif
    char *drv_name;

    wifi_hal_info_print("%s:%d: start\n", __func__, __LINE__);
    if ((drv_name = get_wifi_drv_name()) == NULL) {
        wifi_hal_error_print("%s:%d: driver not found, get drv name failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /* check if driver is loaded */
    while (lsmod_by_name(drv_name) == false) {
        usleep(5000);
    }
    #ifdef RDKB_ONE_WIFI_PROD
    /* Remap the interfaces depending on the Wiphy enumeration
    * in the kernel */
    remap_wifi_interface_name_index_map();
    #endif /* RDKB_ONE_WIFI_PROD */
    pthread_mutexattr_init(&g_wifi_hal.hapd_lock_attr);
    pthread_mutexattr_settype(&g_wifi_hal.hapd_lock_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_wifi_hal.hapd_lock, &g_wifi_hal.hapd_lock_attr);

    pthread_mutex_init(&g_wifi_hal.nl_create_socket_lock, NULL);
    pthread_mutex_init(&g_wifi_hal.steering_data_lock, NULL);
    g_wifi_hal.netlink_socket_map = hash_map_create();

    if (init_nl80211() != 0) {
        return RETURN_ERR;
    }
#ifndef CONFIG_WIFI_EMULATOR
    if (create_ecomode_interfaces() != 0) {
        wifi_hal_error_print("%s:%d: Failed to create the ECO mode interfaces\n", __func__, __LINE__);
    }

#ifndef CONFIG_WIFI_EMULATOR_EXT_AGENT
    if (nl80211_init_primary_interfaces() != 0) {
        return RETURN_ERR;
    }
#endif //CONFIG_WIFI_EMULATOR_EXT_AGENT

    if (nl80211_init_radio_info() != 0) {
        return RETURN_ERR;
    }
#endif
    if (eloop_init() < 0) {
        wifi_hal_error_print("%s:%d: Failed to setup eloop\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

#if defined(_PLATFORM_BANANAPI_R4_)
    attrp = &attr;
    pthread_attr_init(&attr);
    ret = pthread_attr_setstacksize(&attr, stack_size);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n",
            __func__, __LINE__, stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif
    if (pthread_create(&g_wifi_hal.nl_tid, attrp, nl_recv_func, &g_wifi_hal) != 0) {
        wifi_hal_error_print("%s:%d:ssp_main create failed\n", __func__, __LINE__);
        if(attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
        return RETURN_ERR;
    }
    if(attrp != NULL) {
        pthread_attr_destroy(attrp);
    }
#ifndef CONFIG_WIFI_EMULATOR
    if (eap_server_register_methods() != 0) {
        wifi_hal_error_print("%s:%d: failing to register eap server default methods\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio->radio_presence == false) {
            wifi_hal_error_print("%s:%d: Skip the Radio %d .This is sleeping in ECO mode \n", __func__, __LINE__, radio->index);
            continue;
        }
        if(update_hostap_interfaces(radio) != RETURN_OK) {
            return RETURN_ERR;
        }
    }

    if (update_channel_flags() != 0) {
        return RETURN_ERR;
    }

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        wifi_interface_info_t *interface;
        radio = get_radio_by_rdk_index(i);
        update_hostap_config_params(radio);
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_info.vap_mode == wifi_vap_mode_ap && update_hostap_data(interface) == RETURN_OK) {
                update_hostap_iface(interface);
                update_hostap_iface_flags(interface);
                init_hostap_hw_features(interface);
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT || TARGET_GEMINI7_2

    if ((get_radio_caps_fn = get_platform_get_radio_caps_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: get platform radio capabilities\n", __func__, __LINE__);
        for (i = 0; i < g_wifi_hal.num_radios; i++) {
            get_radio_caps_fn(i);
        }
    }

    if ((flags_init_fn = get_platform_flags_init_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: set platform specific flags\n", __func__, __LINE__);
        flags_init_fn((int *)&g_wifi_hal.platform_flags);
    }
#endif

    wifi_hal_info_print("%s:%d: HOSTAP_VERSION: %d\n", __func__, __LINE__, HOSTAPD_VERSION);

#ifdef CONFIG_WIFI_EMULATOR
    rearrange_interfaces_map();
#endif
    wifi_hal_info_print("%s:%d: done\n", __func__, __LINE__);

    return RETURN_OK;
}

INT wifi_hal_pre_init()
{
    platform_pre_init_t  pre_init_fn;
    if ((pre_init_fn = get_platform_pre_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platfrom pre init\n", __func__, __LINE__);
        pre_init_fn();
    }

#if defined(BANANA_PI_PORT) && (HOSTAPD_VERSION >= 211)
    void hostapd_wpa_event(void *ctx, enum wpa_event_type event, union wpa_event_data *data);

    wpa_supplicant_event = hostapd_wpa_event;
#endif // BANANA_PI_PORT

    return RETURN_OK;
}

#if HAL_IPC
INT wifi_hal_post_init(wifi_hal_post_init_t *post_init_struct)
{
    platform_post_init_t post_init_fn;
    if ((post_init_fn = get_platform_post_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platform post init\n", __func__, __LINE__);
        post_init_fn(post_init_struct);
    }

    return RETURN_OK;
}
#else
INT wifi_hal_post_init(wifi_vap_info_map_t *vap_map)
{
    platform_post_init_t post_init_fn;
    if ((post_init_fn = get_platform_post_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platform post init\n", __func__, __LINE__);
        post_init_fn(vap_map);
    }

    return RETURN_OK;
}
#endif // HAL_IPC

INT wifi_hal_get_default_ssid(char *ssid, int vap_index)
{
    platform_ssid_default_t platform_ssid_default_fn;
    if ((platform_ssid_default_fn = get_platform_ssid_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform ssid init\n", __func__, __LINE__);
        return (platform_ssid_default_fn(ssid, vap_index));
    }

    return RETURN_ERR;
}

INT wifi_hal_get_default_country_code(char *code)
{
    platform_country_code_default_t platform_country_code_default_fn;
    if ((platform_country_code_default_fn = get_platform_country_code_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform country code init\n", __func__, __LINE__);
        return(platform_country_code_default_fn(code));
    }
    return RETURN_ERR;
}

INT wifi_hal_get_default_keypassphrase(char *password, int vap_index)
{
    platform_keypassphrase_default_t platform_keypassphrase_default_fn;
    if ((platform_keypassphrase_default_fn = get_platform_keypassphrase_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform passphrase init\n", __func__, __LINE__);
        return (platform_keypassphrase_default_fn(password, vap_index));
    }

    return RETURN_ERR;
}
INT wifi_hal_get_default_radius_key(char *radius_key)
{
    platform_radius_key_default_t platform_radius_key_default_fn;
    if ((platform_radius_key_default_fn = get_platform_radius_key_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform  default_radius_key\n", __func__, __LINE__);
        return (platform_radius_key_default_fn(radius_key));
    }

    return RETURN_ERR;
}

INT wifi_hal_get_default_wps_pin(char *pin)
{
    platform_wps_pin_default_t platform_wps_pin_default_fn;
    if ((platform_wps_pin_default_fn = get_platform_wps_pin_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform wps pin init\n", __func__, __LINE__);
        return (platform_wps_pin_default_fn(pin));
    }

    return RETURN_ERR;
}

INT wifi_hal_wps_event(wifi_wps_event_t data)
{
    platform_wps_event_t platform_wps_event_fn;
    if ((platform_wps_event_fn = get_platform_wps_event_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform wps event callback triggered\n", __func__, __LINE__);
        return (platform_wps_event_fn(data));
    }

    return RETURN_ERR;
}

INT wifi_hal_hostApGetErouter0Mac(char *out)
{
    if (out == NULL) {
        return RETURN_ERR;
    }
    strcpy(out, "01:23:12:44:65:ab");
    return RETURN_OK;
}

INT wifi_hal_send_mgmt_frame_response(int ap_index, int type, int status, int status_code, uint8_t *frame, uint8_t *mac, int len, int rssi)
{
    if (status == MGMT_FRAME_RESPONSE_STATUS_OK) {
        wifi_send_wpa_supplicant_event(ap_index, frame, len);
    } else if (status == MGMT_FRAME_RESPONSE_STATUS_DENY) {
        wifi_send_response_failure(ap_index, mac, type, status_code, rssi);
    } else {
        wifi_hal_error_print("%s:%d: Undefined status\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

void wifi_hal_deauth(int vap_index, int status, uint8_t *mac)
{
    u8 own_addr[ETH_ALEN];
    wifi_interface_info_t *interface = get_interface_by_vap_index(vap_index);
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    memcpy(own_addr, hapd->own_addr, ETH_ALEN);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#ifdef HOSTAPD_2_10
    wifi_drv_sta_deauth(interface, own_addr, mac, status);
#endif
    return;
}

#if defined(CONFIG_IEEE80211BE) && defined(SCXER10_PORT) && defined(KERNEL_NO_320MHZ_SUPPORT)
INT _wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);

INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    int status;
    bool b_320mhz = false;
    wifi_radio_info_t *radio;

    radio = get_radio_by_rdk_index(index);
    if ((operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_320MHZ) && operationParam->enable) {
        b_320mhz = true;
        operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_160MHZ;
    }

    status = _wifi_hal_setRadioOperatingParameters(index, operationParam);

    if (b_320mhz) {
        radio->oper_param.channelWidth = WIFI_CHANNELBANDWIDTH_320MHZ;
        if (radio->oper_param.enable) {
            platform_set_csa(index, &radio->oper_param);
        } else {
            platform_set_chanspec(index, &radio->oper_param, true);
        }
        operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_320MHZ;
    }

    return status;
}

INT _wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
#else
INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
#endif
{
    wifi_radio_info_t *radio;
    int op_class;
    platform_set_radio_params_t  set_radio_params_fn;
    wifi_interface_info_t *interface = NULL;
    wifi_interface_info_t *primary_interface = NULL;
    wifi_radio_operationParam_t old_operationParam;
    platform_set_radio_pre_init_t set_radio_pre_init_fn;
    bool is_channel_changed;
    int ret;

#ifdef CMXB7_PORT
    int dfs_start_chan = 52, dfs_end_chan = 144;
#endif

    RADIO_INDEX_ASSERT(index);
    NULL_PTR_ASSERT(operationParam);

#if defined(CONFIG_WIFI_EMULATOR) || defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    radio->configured = true;
    radio->oper_param.enable = true;
    memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam,
        sizeof(wifi_radio_operationParam_t));

    return RETURN_OK;
#endif

    if ((op_class = get_op_class_from_radio_params(operationParam)) == -1) {
        wifi_hal_error_print("%s:%d:Could not find country code for radio index:%d\n", __func__, __LINE__, index);
        return WIFI_HAL_INVALID_ARGUMENTS; // RDKB-47696: Passing invalid channel should return WIFI_HAL_INVALID_ARGUMENTS(-4)
    }

    if (validate_radio_operation_param(operationParam) != RETURN_OK) {
        wifi_hal_error_print("%s:%d:Failed to validate radio operation params for radio index: %d\n", __func__, __LINE__, index);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    operationParam->operatingClass = op_class;

    wifi_hal_info_print("%s:%d:Index:%d Country: %d, Channel: %d, Op Class:%d\n",
        __func__, __LINE__, index, operationParam->countryCode, operationParam->channel, operationParam->operatingClass);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if ((set_radio_pre_init_fn = get_platform_set_radio_pre_init_fn()) != NULL) {
        if (set_radio_pre_init_fn(index, operationParam) < 0){
            wifi_hal_error_print("%s:%d: Error in setting radio pre init\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    } else {
        wifi_hal_error_print("%s:%d: Unable to fetch se_radio_pre_init_fn()\n", __func__, __LINE__);
    }

    if ((false == radio->radio_presence) || (operationParam->EcoPowerDown == true)) {
        wifi_hal_error_print("%s:%d: Skip the Radio %d .This is sleeping in ECO mode \n", __func__, __LINE__, radio->index);
        return RETURN_OK;
    }

    primary_interface = get_primary_interface(radio);
    if (primary_interface == NULL) {
        wifi_hal_error_print("%s:%d: Error updating dev:%d no vprimary interface exist\n", __func__, __LINE__, radio->index);
        return RETURN_ERR;
    }

    memcpy((unsigned char *)&old_operationParam, (unsigned char *)&radio->oper_param, sizeof(wifi_radio_operationParam_t));

    nl80211_interface_enable(wifi_hal_get_interface_name(primary_interface),
        operationParam->enable);
#if defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT)
    if (nl80211_set_amsdu_tid(primary_interface, operationParam->amsduTid) != RETURN_OK)
    {
        wifi_hal_error_print(
            "%s:%d:Failed to update AMSDU TID params ! AMSDU possibly out of sync \n",
            __func__, __LINE__);
        // fall-through, don't return error
    }
#endif

    if (radio->configured && radio->oper_param.enable != operationParam->enable) {
        memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t));

        if (update_hostap_config_params(radio) != RETURN_OK ) {
            wifi_hal_error_print("%s:%d:Failed to update hostap config params\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        interface = hash_map_get_first(radio->interface_map);
        if (interface == NULL ) {
            wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
            goto Exit;
        }

        while (interface != NULL) {
            char *interface_name = wifi_hal_get_interface_name(interface);

            if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
                wifi_hal_info_print(
                    "%s:%d: vap_index: %d interface name: %s vap_initialized: %d "
                    "bss started: %d vap enabled: %d radio configured: %d radio enabled: %d\n",
                    __func__, __LINE__, interface->vap_info.vap_index, interface_name,
                    interface->vap_initialized, interface->bss_started,
                    interface->vap_info.u.bss_info.enabled, radio->configured,
                    radio->oper_param.enable);
                if (radio->oper_param.enable && interface->vap_info.u.bss_info.enabled) {
                    if (nl80211_interface_enable(interface_name, true) != 0) {
                        ret = nl80211_retry_interface_enable(interface, true);
                        if (ret != 0) {
                            wifi_hal_error_print("%s:%d: Retry of interface enable failed:%d\n",
                                __func__, __LINE__, ret);
                        }
                    }
                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        return RETURN_ERR;
                    }
                    interface->beacon_set = 0;
                    start_bss(interface);
                    interface->bss_started = true;
                }

                if (radio->oper_param.enable == false && interface->bss_started) {
                    /* Clear beacon interval in wdev by stoping AP */
                    nl80211_interface_enable(interface_name, false);
                    nl80211_interface_enable(interface_name, true);
                    interface->beacon_set = 0;
                    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                    hostapd_reload_config(interface->u.ap.hapd.iface);
#ifdef CONFIG_SAE
                    if (interface->u.ap.conf.sae_groups) {
                        interface->u.ap.conf.sae_groups = NULL;
                    }
#endif
                    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
                    nl80211_enable_ap(interface, false);
                    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                    deinit_bss(&interface->u.ap.hapd);
                    if (interface->u.ap.hapd.conf->ssid.wpa_psk && !interface->u.ap.hapd.conf->ssid.wpa_psk->next)
                        hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);
                    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        return RETURN_ERR;
                    }
                    interface->bss_started = false;
                    nl80211_interface_enable(interface_name, false);
                }
            }

            if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
                if (radio->oper_param.enable == false) {
                    if (interface->u.sta.state == WPA_COMPLETED) {
                        nl80211_disconnect_sta(interface);
                    }
                    nl80211_interface_enable(interface_name, false);
                }

                if (radio->oper_param.enable) {
                    nl80211_interface_enable(interface_name, true);
                    wifi_drv_set_operstate(interface, 1);
                }
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

        goto Exit;
    }

#ifdef CMXB7_PORT
    if( primary_interface->u.ap.iface.cac_started && ((operationParam->channel >= dfs_start_chan) && (operationParam->channel <= dfs_end_chan)) && (radio->oper_param.channel == operationParam->channel) &&
      ( radio->oper_param.channelWidth == operationParam->channelWidth ) ) {
        wifi_hal_info_print("%s:%d: Setting  primary interface with channel:%u \n", __func__, __LINE__, radio->oper_param.channel);

        if (memcmp((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t)) != 0) {
            wifi_hal_error_print("%s:%d: CAC is running for DFS Channel:%u. Wait for CAC to be over \n", __func__, __LINE__, operationParam->channel);
            return RETURN_ERR;
        }

        if( set_freq_and_interface_enable(primary_interface, radio) ) {
            goto reload_config;
        }
        goto Exit;
    }
#endif

    if (radio->oper_param.DfsEnabled != operationParam->DfsEnabled) {
        platform_set_dfs_t platform_set_dfs_fn = get_platform_dfs_set_fn();

        if (platform_set_dfs_fn != NULL) {
            platform_set_dfs_fn(index, operationParam);
        }
    }

    is_channel_changed = radio->oper_param.channel != operationParam->channel ||
        radio->oper_param.channelWidth != operationParam->channelWidth;
    if (radio->configured && radio->oper_param.enable && is_channel_changed) {
        radio->oper_param.channel = operationParam->channel;
        radio->oper_param.operatingClass = operationParam->operatingClass;
        radio->oper_param.channelWidth = operationParam->channelWidth;
        radio->oper_param.autoChannelEnabled = operationParam->autoChannelEnabled;
		radio->oper_param.DfsEnabledBootup = operationParam->DfsEnabledBootup;
		strncpy(radio->oper_param.radarDetected, operationParam->radarDetected,
				sizeof(radio->oper_param.radarDetected)-1);
		radio->oper_param.DFSTimer = operationParam->DFSTimer;
        memcpy(radio->oper_param.channel_map, operationParam->channel_map,
            sizeof(radio->oper_param.channel_map));

#ifdef CMXB7_PORT
        if( ((radio->oper_param.band == WIFI_FREQUENCY_5_BAND) || (radio->oper_param.band == WIFI_FREQUENCY_5L_BAND) || (radio->oper_param.band == WIFI_FREQUENCY_5H_BAND))) {
            if( !primary_interface->u.ap.iface.cac_started && ((operationParam->channel >= dfs_start_chan && operationParam->channel <= dfs_end_chan) || (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ)) ) {
                wifi_hal_info_print("%s:%d: Starting CAC for DFS Channel:%u \n", __func__, __LINE__, operationParam->channel );
                if(nl80211_start_dfs_cac(radio)) {
                    wifi_hal_error_print("%s:%d: Error starting CAC \n", __func__, __LINE__);
                    goto reload_config;
                }
               goto Exit;
            }

            if( primary_interface->u.ap.iface.cac_started ) {
                int cac_start = 0;
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                primary_interface->u.ap.iface.cac_started = cac_start;
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

                if(primary_interface->u.ap.iface.dfs_cac_ms)
                    reenable_prim_interface(radio);

                if( !(operationParam->channel >= dfs_start_chan && operationParam->channel <= dfs_end_chan) && !(operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) ) {
                    wifi_hal_info_print("%s:%d: Setting channel:%u on 5GHz Radio\n", __func__, __LINE__, radio->oper_param.channel);
                    if( set_freq_and_interface_enable(primary_interface, radio) ) {
                        goto reload_config;
                    }
                    goto Exit;
                }

                wifi_hal_info_print("%s:%d: Starting CAC for DFS Channel:%u \n", __func__, __LINE__, operationParam->channel );
                if(nl80211_start_dfs_cac(radio)) {
                    wifi_hal_error_print("%s:%d: Error starting CAC \n", __func__, __LINE__);
                    goto reload_config;
                }
                goto Exit;
            }
        }
#endif
        if (memcmp((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t)) == 0) {
            if (is_channel_changed) {
                wifi_hal_dbg_print("%s:%d: Switch channel on radio index:%d\n", __func__, __LINE__,
                    index);
                if ((ret = nl80211_switch_channel(radio)) == -1) {
                    wifi_hal_error_print("%s:%d: Error switching channel\n", __func__, __LINE__);
                    goto reload_config;
                } else if (ret != 0) {
                    wifi_hal_error_print("%s:%d: Error switching channel ret:%d\n", __func__,
                        __LINE__, ret);
                    if (ret == -EOPNOTSUPP) {
                        wifi_hal_dbg_print(
                            "%s:%d Try updation of hostap config params for EOPNOTSUPP error\n",
                            __func__, __LINE__);
                        goto try_hostap_config_update;
                    } else {
                        return RETURN_ERR;
                    }
                }
            }
            goto Exit;
        }
    }

try_hostap_config_update:
    if (radio->configured && radio->oper_param.enable) {
        update_hostap_radio_param(radio, operationParam);
    }

    if (radio->oper_param.countryCode != operationParam->countryCode) {
        wifi_hal_dbg_print("%s:%d:Set country code:%d\n", __func__, __LINE__, operationParam->countryCode);
        nl80211_set_regulatory_domain(operationParam->countryCode);
    }

    memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t));
    // update the hostap_config parameters
    if (update_hostap_config_params(radio) != RETURN_OK ) {
        wifi_hal_error_print("%s:%d:Failed to update hostap config params\n", __func__, __LINE__);
        goto reload_config;
    }

    if (nl80211_update_wiphy(radio) != 0) {
        wifi_hal_error_print("%s:%d:Failed to update radio\n", __func__, __LINE__);
        goto reload_config;
    }

#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
    // Call Vendor HAL
    if (wifi_setRadioDfsAtBootUpEnable(index,operationParam->DfsEnabledBootup) != 0) {
        wifi_hal_dbg_print("%s:%d:Failed to Enable DFSAtBootUp on radio %d\n", __func__, __LINE__, index);
    }
#endif // PLATFORM_RASPBERRYPI_ || _PLATFORM_BANANAPI_R4_

Exit:
    if ((set_radio_params_fn = get_platform_set_radio_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: set radio params to nvram for radio : %d\n", __func__, __LINE__, index);
        set_radio_params_fn(index, operationParam);
    }

    if (!radio->configured) {
        radio->configured = true;
    }
    return RETURN_OK;

reload_config:
    if (radio->configured == true) {
        memcpy((unsigned char *)&radio->oper_param, (unsigned char *)&old_operationParam, sizeof(wifi_radio_operationParam_t));
    }
    if (update_hostap_config_params(radio) != RETURN_OK ) {
        wifi_hal_error_print("%s:%d:Failed to update hostap config params, Got into a bad state radioindex : %d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if (nl80211_update_wiphy(radio) != 0) {
        wifi_hal_error_print("%s:%d:Failed to update radio : %d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }
    return RETURN_ERR;

}

INT wifi_hal_connect(INT ap_index, wifi_bss_info_t *bss)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    bssid_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    wifi_bss_info_t *backhaul, *tmp = NULL, *best = NULL;
    int best_rssi = -100;

    NULL_PTR_ASSERT(bss);

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return WIFI_HAL_INVALID_ARGUMENTS;    // RDKB-45724 - Returns -4 when the ap index is not suitable for station mode
    }

    backhaul = &interface->u.sta.backhaul;

    if ((bss != NULL) && (memcmp(null_mac, bss->bssid, sizeof(bssid_t)) != 0)) {
        memcpy(backhaul, bss, sizeof(wifi_bss_info_t));
    } else {
        // find from scan list
        pthread_mutex_lock(&interface->scan_info_mutex);
        tmp = hash_map_get_first(interface->scan_info_map);
        while (tmp != NULL) {
            if ((strcmp(tmp->ssid, vap->u.sta_info.ssid) == 0) &&
                    (tmp->rssi > best_rssi)) {
                best_rssi = tmp->rssi;
                best = tmp;
            }
            tmp = hash_map_get_next(interface->scan_info_map, tmp);
        }

        if (best == NULL) {
            pthread_mutex_unlock(&interface->scan_info_mutex);
            wifi_hal_error_print("%s:%d: Could not find bssid from scan data\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        *backhaul = *best;
        pthread_mutex_unlock(&interface->scan_info_mutex);
    }

    if (nl80211_connect_sta(interface) != 0) {
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_hal_disconnect(INT ap_index)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return WIFI_HAL_INVALID_ARGUMENTS;     // RDKB-45722 - Returns -4 when the ap index is not suitable for station mode
    }

    if (nl80211_disconnect_sta(interface) != 0) {
        return RETURN_ERR;
    }

    return RETURN_OK;
}


INT wifi_hal_findNetworks(INT ap_index, wifi_channel_t *channel, wifi_bss_info_t **bss_array, UINT *num_bss)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_bss_info_t *bss;
    unsigned int num = 0;
    wifi_bss_info_t *bss_info;
    u8 chan;

    if (!channel || !bss_array || !num_bss) {
        wifi_hal_error_print("%s:%d:invalid parameters\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return RETURN_ERR;
    }

    // we may need to lock the hash map so that scan results handlers do not change the map
    pthread_mutex_lock(&interface->scan_info_mutex);
    if (channel->channel == 0) {
        num = hash_map_count(interface->scan_info_map);
    } else {
        bss = hash_map_get_first(interface->scan_info_map);
        while (bss != NULL) {
            ieee80211_freq_to_chan(bss->freq, &chan);
            if (chan == channel->channel) {
                num++;
            }
            bss = hash_map_get_next(interface->scan_info_map, bss);
        }
    }

    bss_info = calloc(num, sizeof(wifi_bss_info_t));
    if (!bss_info) {
        pthread_mutex_unlock(&interface->scan_info_mutex);
        wifi_hal_error_print("%s:%d:memory allocation error\n", __func__, __LINE__);
        *bss_array = NULL;
        *num_bss = 0;
        return RETURN_ERR;
    }
    *bss_array = bss_info;
    *num_bss = num;

    bss = hash_map_get_first(interface->scan_info_map);
    while (bss != NULL) {
        if (channel->channel == 0) {
            memcpy(bss_info, bss, sizeof(wifi_bss_info_t));
        } else {
            ieee80211_freq_to_chan(bss->freq, &chan);
            if (chan == channel->channel) {
                memcpy(bss_info, bss, sizeof(wifi_bss_info_t));
            }
        }
        bss = hash_map_get_next(interface->scan_info_map, bss);
        bss_info++;
    }
    pthread_mutex_unlock(&interface->scan_info_mutex);

    return RETURN_OK;
}

#if defined(CONFIG_WIFI_EMULATOR) || defined(BANANA_PI_PORT)
struct wpa_ssid *get_wifi_wpa_current_ssid(wifi_interface_info_t *interface)
{
    return &interface->current_ssid_info;
}

int deinit_wpa_supplicant(wifi_interface_info_t *interface)
{
    wifi_hal_info_print("%s:%d: deinit wpa supplicant params\n", __func__, __LINE__);
    if (interface->wpa_s.p2pdev != NULL) {
        free(interface->wpa_s.p2pdev);
        interface->wpa_s.p2pdev = NULL;
    }

    if (interface->wpa_s.conf != NULL) {
        free(interface->wpa_s.conf);
        interface->wpa_s.conf = NULL;
    }

    if (interface->wpa_s.current_bss != NULL) {
        free(interface->wpa_s.current_bss);
        interface->wpa_s.current_bss = NULL;
    }

    memset(&interface->wpa_s, 0, sizeof(struct wpa_supplicant));
    return RETURN_OK;
}

int init_wpa_supplicant(wifi_interface_info_t *interface)
{
    interface->wpa_s.drv_flags |= WPA_DRIVER_FLAGS_SAE;
    interface->wpa_s.drv_flags |= WPA_DRIVER_FLAGS_SME;
    if (interface->wpa_s.p2pdev == NULL) {
        interface->wpa_s.p2pdev = (struct wpa_supplicant *)malloc(sizeof(struct wpa_supplicant));
        if (interface->wpa_s.p2pdev == NULL) {
            wifi_hal_error_print("%s:%d: NULL Pointer \n", __func__, __LINE__);
            return RETURN_ERR;
        }
        memset(interface->wpa_s.p2pdev, 0, sizeof(struct wpa_supplicant));
    }

    if (interface->wpa_s.current_ssid == NULL) {
        interface->wpa_s.current_ssid = get_wifi_wpa_current_ssid(interface);
        memset(interface->wpa_s.current_ssid, 0, sizeof(struct wpa_ssid));
    }

    if (interface->wpa_s.conf == NULL) {
        interface->wpa_s.conf = (struct wpa_config*)malloc(sizeof(struct wpa_config));
        if (interface->wpa_s.conf == NULL) {
            wifi_hal_error_print("%s:%d: NULL Pointer \n", __func__, __LINE__);
            return RETURN_ERR;
        }
        memset(interface->wpa_s.conf, 0, sizeof(struct wpa_config));
    }

    if (interface->wpa_s.conf->ssid == NULL) {
        interface->wpa_s.conf->ssid = (struct wpa_ssid *)malloc(sizeof(struct wpa_ssid));
        if (interface->wpa_s.conf->ssid == NULL) {
            wifi_hal_error_print("%s:%d: NULL Pointer \n", __func__, __LINE__);
            return RETURN_ERR;
        }
        memset(interface->wpa_s.conf->ssid, 0, sizeof(struct wpa_ssid));
    }

#ifdef CONFIG_WIFI_EMULATOR
    interface->wpa_s.driver = &g_wpa_supplicant_driver_nl80211_ops;
#else
    interface->wpa_s.driver = &g_wpa_driver_nl80211_ops;
#endif
    dl_list_init(&interface->wpa_s.bss);
    dl_list_init(&interface->wpa_s.bss_tmp_disallowed);
    wifi_hal_info_print("%s:%d: wpa supplicant params init success\n", __func__, __LINE__);

    return RETURN_OK;
}
#endif //CONFIG_WIFI_EMULATOR || BANANA_PI_PORT

int get_sta_4addr_status(bool *sta_4addr)
{
    return json_parse_boolean(EM_CFG_FILE, "sta_4addr_mode_enabled", sta_4addr);
}

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
INT _wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map);

INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    int status;
    bool b_320mhz = false;
    wifi_radio_info_t *radio;

    radio = get_radio_by_rdk_index(index);
    if (radio->oper_param.channelWidth == WIFI_CHANNELBANDWIDTH_320MHZ) {
        b_320mhz = true;
        radio->oper_param.channelWidth = WIFI_CHANNELBANDWIDTH_160MHZ;
    }

    status = _wifi_hal_createVAP(index, map);

    if (b_320mhz) {
        radio->oper_param.channelWidth = WIFI_CHANNELBANDWIDTH_320MHZ;
        platform_set_csa(index, &radio->oper_param);
    }

    return status;
}

INT _wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
#else
INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
#endif
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface, *mbssid_tx_interface;
    wifi_vap_info_t *vap;
    platform_pre_create_vap_t pre_set_vap_params_fn;
    platform_create_vap_t set_vap_params_fn;
    unsigned int i;
    char msg[2048];
    int ret = RETURN_OK;
#ifdef NL80211_ACL
    int set_acl = 0;
#else
    int filtermode;
#endif
    //bssid_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#if defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
#ifdef CONFIG_MLO
    char mld_ifname[32];
#endif 
#endif
    char *interface_name = NULL;

    RADIO_INDEX_ASSERT(index);
    NULL_PTR_ASSERT(map);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio index:%d failed not find radio\n", __func__, __LINE__,
            index);
        return RETURN_ERR;
    }
#ifndef CONFIG_WIFI_EMULATOR
    if (false == radio->radio_presence) {
       wifi_hal_info_print("%s:%d: radio index:%d skip vap create due to ECO mode\n", __func__,
           __LINE__, radio->index);
       return RETURN_OK;
    }
#endif
    if ((pre_set_vap_params_fn = get_platform_pre_create_vap_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: radio index:%d pre-create vap\n", __func__, __LINE__,
            radio->index);
        pre_set_vap_params_fn(index, map);
    }

    // now create vaps on the interfaces
    for (i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];

        wifi_hal_info_print("%s:%d: vap index:%d vap_name = %s create vap\n", __func__, __LINE__,
            vap->vap_index, vap->vap_name);

        if (vap->vap_mode == wifi_vap_mode_ap) {
            if (validate_wifi_interface_vap_info_params(vap, msg, sizeof(msg)) != RETURN_OK) {
                wifi_hal_error_print("%s:%d:Failed to validate interface vap_info params for vap_index: %d on radio index: %d. %s\n", __func__, __LINE__, vap->vap_index, index, msg);
                return WIFI_HAL_INVALID_ARGUMENTS;
            }
        }

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wifi_hal_info_print("%s:%d:vap index:%d vap_name = %s create interface\n", __func__, __LINE__,
                vap->vap_index, vap->vap_name);
            if ((nl80211_create_interface(radio, vap, &interface) != 0) || (interface == NULL)) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to create interface\n", __func__,
                    __LINE__, vap->vap_index);
                continue;
            }
        }

#ifdef NL80211_ACL
        if ((vap->u.bss_info.enabled == 1) &&
            ((vap->u.bss_info.mac_filter_enable == TRUE) ||
             (interface->vap_info.u.bss_info.mac_filter_enable != vap->u.bss_info.mac_filter_enable))) {
            set_acl = 1;
        }
#endif

#if defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
#ifdef CONFIG_MLO
        if (platform_set_intf_mld_bonding(radio, interface) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: vap index:%d failed to create bonding\n", __func__, __LINE__,
                vap->vap_index);
            continue;
        }
#endif
#endif
        wifi_hal_info_print("%s:%d: vap index:%d mode:%d vap_name:%s\n", __func__, __LINE__,
            vap->vap_index, vap->vap_mode, vap->vap_name);
        if (vap->vap_mode == wifi_vap_mode_ap) {
            wifi_hal_info_print("%s:%d: vap_enable_status:%d\n", __func__, __LINE__, vap->u.bss_info.enabled);
            memcpy(vap->u.bss_info.bssid, interface->mac, sizeof(vap->u.bss_info.bssid));
        } else {
            wifi_hal_info_print("%s:%d: vap_enable_status:%d\n", __func__, __LINE__, vap->u.sta_info.enabled);
#if  !defined(CONFIG_WIFI_EMULATOR) && !defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
            memcpy(vap->u.sta_info.mac, interface->mac, sizeof(vap->u.sta_info.mac));
#else
            mac_addr_str_t sta_mac_str;
            char *key = NULL;
            memcpy(interface->mac, vap->u.sta_info.mac, sizeof(mac_address_t));
            memcpy(interface->vap_info.u.sta_info.mac, vap->u.sta_info.mac, sizeof(mac_address_t));
            key = to_mac_str(interface->vap_info.u.sta_info.mac, sta_mac_str);
            wifi_hal_dbg_print("%s:%d: sta mac is : %s\n", __func__, __LINE__, key);
#endif //!defined(CONFIG_WIFI_EMULATOR) || !defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
        }
        memcpy((unsigned char *)&interface->vap_info, (unsigned char *)vap, sizeof(wifi_vap_info_t));
        interface_name = wifi_hal_get_interface_name(interface);

#ifdef CONFIG_GENERIC_MLO
        // VAP down removes MLO links, so restrict down of interface to sta mode only
        if (vap->vap_mode == wifi_vap_mode_sta) {
#endif
            wifi_hal_info_print("%s:%d: interface:%s set down\n", __func__, __LINE__, interface->name);
            nl80211_interface_enable(interface->name, false);
#ifdef CONFIG_GENERIC_MLO
        }
#endif

#if  !defined(CONFIG_WIFI_EMULATOR) && !defined(CONFIG_WIFI_EMULATOR_EXT_AGENT)
        if (vap->vap_mode == wifi_vap_mode_sta) {
            bool sta_4addr = 0;
            wifi_hal_info_print("%s:%d: interface:%s remove from bridge\n", __func__, __LINE__,
                interface_name);
            nl80211_remove_from_bridge(interface_name);
            if (get_sta_4addr_status(&sta_4addr) == RETURN_OK) {
                interface->u.sta.sta_4addr = (int)sta_4addr;
            }
        }
#endif
        wifi_hal_info_print("%s:%d: interface:%s set mode:%d\n", __func__, __LINE__,
            interface_name, vap->vap_mode);
        if (nl80211_update_interface(interface) != 0) {
            wifi_hal_error_print("%s:%d: interface:%s failed to set mode %d\n",__func__, __LINE__,
                interface_name, vap->vap_mode);
            return RETURN_ERR;
        }

        wifi_hal_info_print("%s:%d: interface:%s radio configured:%d radio enabled:%d\n",
            __func__, __LINE__, interface_name, radio->configured, radio->oper_param.enable);
        if (radio->configured && radio->oper_param.enable) {
            wifi_hal_info_print("%s:%d: interface:%s set up\n", __func__, __LINE__,
                interface_name);
            if (nl80211_interface_enable(interface_name, true) != 0) {
                ret = nl80211_retry_interface_enable(interface, true);
                if (ret != 0) {
                    wifi_hal_error_print("%s:%d: Retry of interface enable failed:%d\n", __func__,
                        __LINE__, ret);
                }
            }
        }

        if (vap->vap_mode == wifi_vap_mode_ap) {
            // create the bridge
            wifi_hal_info_print("%s:%d: interface:%s bss enabled:%d bridge:%s\n", __func__,
                __LINE__, interface_name, vap->u.bss_info.enabled, vap->bridge_name);
            if (vap->bridge_name[0] != '\0' && vap->u.bss_info.enabled) {
                wifi_hal_info_print("%s:%d: interface:%s create bridge:%s\n", __func__, __LINE__,
                    interface_name, vap->bridge_name);
#if (defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)) && defined(CONFIG_MLO)
                if (radio->oper_param.variant & WIFI_80211_VARIANT_BE) {
                    snprintf(mld_ifname, sizeof(mld_ifname), "mld%d",  vap->vap_index);
                    if (nl80211_create_bridge(mld_ifname, vap->bridge_name) != 0) {
                        wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                            __func__, __LINE__, interface_name, vap->bridge_name);
                        continue;
                    }
                    wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                         mld_ifname, vap->bridge_name);
                }
                else if (nl80211_create_bridge(interface_name, vap->bridge_name) != 0) {
#else
                if (nl80211_create_bridge(interface_name, vap->bridge_name) != 0) {
#endif
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface_name, vap->bridge_name);
                    continue;
                }
                wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                    interface_name, vap->bridge_name);
                if (nl80211_interface_enable(vap->bridge_name, true) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to set bridge %s up\n",
                        __func__, __LINE__, interface_name, vap->bridge_name);
                    continue;
                }
            }

            wifi_hal_info_print("%s:%d: interface:%s update hostapd params\n", __func__, __LINE__,
                interface_name);
            if (update_hostap_interface_params(interface) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: interface:%s failed to update hostapd params\n",
                    __func__, __LINE__, interface_name);
                return RETURN_ERR;
            }

            wifi_hal_info_print("%s:%d: interface:%s vap_initialized:%d\n", __func__, __LINE__,
                interface_name, interface->vap_initialized);
            if (interface->vap_initialized == true) {
                wifi_hal_info_print("%s:%d: interface:%s bss_started:%d\n", __func__, __LINE__,
                    interface_name, interface->bss_started);
                if (!(interface->bss_started)) {
                    if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                        wifi_hal_info_print("%s:%d: interface:%s enable ap\n", __func__,
                            __LINE__, interface_name);
                        interface->beacon_set = 0;
                        ret = start_bss(interface);
                        interface->bss_started = true;
                    }
                } else {
                    // reload vaps config
                    interface->beacon_set = 0;
                    wifi_hal_info_print("%s:%d: interface:%s reload hostapd config\n", __func__,
                        __LINE__, interface_name);
                    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                    hostapd_reload_config(interface->u.ap.hapd.iface);
#ifdef CONFIG_SAE
                    if (interface->u.ap.conf.sae_groups) {
                        interface->u.ap.conf.sae_groups = NULL;
                    }
#endif
                    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

                    wifi_hal_info_print("%s:%d: interface:%s disable ap\n", __func__, __LINE__,
                        interface_name);
                    nl80211_enable_ap(interface, false);

                    wifi_hal_info_print("%s:%d: interface:%s free hostapd data\n", __func__,
                        __LINE__, interface_name);
                    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                    deinit_bss(&interface->u.ap.hapd);
                    if (interface->u.ap.hapd.conf->ssid.wpa_psk && !interface->u.ap.hapd.conf->ssid.wpa_psk->next)
                        hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);
                    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

                    wifi_hal_info_print("%s:%d: interface:%s update hostapd params\n", __func__,
                        __LINE__, interface_name);
                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        wifi_hal_error_print("%s:%d: interface:%s failed to update hostapd "
                            "params\n", __func__, __LINE__, interface_name);
                        return RETURN_ERR;
                    }

                    if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                        wifi_hal_info_print("%s:%d: interface:%s enable ap\n", __func__,
                            __LINE__, interface_name);
                        interface->beacon_set = 0;
                        ret = start_bss(interface);
                        interface->bss_started = true;
                    }
                    else {
                        interface->bss_started = false;
                    }
                }
            } else {
                interface->vap_initialized = true;
                wifi_hal_info_print("%s:%d: radio index:%d update hostapd interfaces\n", __func__,
                    __LINE__, radio->index);
                if (update_hostap_interfaces(radio)!= RETURN_OK) {
                    wifi_hal_error_print("%s:%d: radio index:%d failed to update hostapd "
                        "interfaces\n", __func__, __LINE__, radio->index);
                    return RETURN_ERR;
                }
                if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                    wifi_hal_info_print("%s:%d: interface:%s enable ap\n", __func__,
                        __LINE__, interface_name);
                    interface->beacon_set = 0;
                    ret = start_bss(interface);
                    interface->bss_started = true;
                }
            }
            if (radio->configured && radio->oper_param.enable) {
                wifi_hal_info_print("%s:%d: interface:%s set %s\n", __func__, __LINE__,
                    interface_name, vap->u.bss_info.enabled ? "up" : "down");
                nl80211_interface_enable(interface_name, vap->u.bss_info.enabled);
#if defined(VNTXER5_PORT) || defined(TARGET_GEMINI7_2)
#ifdef CONFIG_MLO
                if(radio->oper_param.variant & WIFI_80211_VARIANT_BE)
                {
                    snprintf(mld_ifname, sizeof(mld_ifname), "mld%d", vap->vap_index);
                    nl80211_interface_enable(mld_ifname, vap->u.bss_info.enabled);
                }
#endif
#endif
            }

            // set the vap mode on the interface
            interface->vap_info.vap_mode = vap->vap_mode;

            mbssid_tx_interface = wifi_hal_get_mbssid_tx_interface(radio);
            if (mbssid_tx_interface != NULL && mbssid_tx_interface != interface) {
                wifi_hal_configure_mbssid(radio);
            }

        } else if (vap->vap_mode == wifi_vap_mode_sta) {
#if defined(CONFIG_WIFI_EMULATOR)
            if (nl80211_create_bridge(interface_name, vap->bridge_name) != 0) {
                wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface_name, vap->bridge_name);
            }

            nl80211_interface_enable(interface_name, false);
            nl80211_set_mac(interface);
            interface->vap_initialized = true;
            nl80211_interface_enable(interface_name, true);
            wifi_hal_info_print("%s:%d: interface:%s set operstate 1\n", __func__,
                    __LINE__, interface_name);
            wifi_drv_set_operstate(interface, 1);

            nl80211_interface_enable(interface_name, true);
#else
            //XXX set correct status after reconfigure and call conn status callback
            //nl80211_start_scan(interface);
            interface->vap_initialized = true;

            if (vap->u.sta_info.ignite_enabled) {
                if (nl80211_create_bridge(interface->name, vap->bridge_name) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface->name, vap->bridge_name);
                    return RETURN_ERR;
                }
                wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                    interface->name, vap->bridge_name);
                if (nl80211_interface_enable(vap->bridge_name, true) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to set bridge %s up\n",
                        __func__, __LINE__, interface->name, vap->bridge_name);
                    return RETURN_ERR;
                }
            }

#ifdef CONFIG_WIFI_EMULATOR_EXT_AGENT
            nl80211_interface_enable(interface->name, false);
            nl80211_set_mac(interface);
            nl80211_interface_enable(interface->name, true);
#endif
            if (radio->configured && radio->oper_param.enable) {
                wifi_hal_info_print("%s:%d: interface:%s set operstate 1\n", __func__,
                    __LINE__, interface_name);
                wifi_drv_set_operstate(interface, 1);
                if (nl80211_interface_enable(interface->name, true) != 0) {
                    wifi_hal_error_print("%s:%d interface:%s failed to set bridge %s up\n",
                        __func__, __LINE__, interface->name, vap->bridge_name);
                }
            } else {
                wifi_hal_info_print("%s:%d: interface:%s set down\n", __func__, __LINE__,
                    interface_name);
                nl80211_interface_enable(interface_name, false);
            }
#endif //CONFIG_WIFI_EMULATOR
        }

        if (vap->vap_mode == wifi_vap_mode_ap) {
#if (defined(EASY_MESH_NODE) || defined(EASY_MESH_COLOCATED_NODE))
            if (isVapMeshBackhaul(vap->vap_index)) {
                interface->vap_info.u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;
            }
#endif // EASY_MESH_NODE || EASY_MESH_COLOCATED_NODE
#ifdef NL80211_ACL
            if (set_acl == 1) {
                nl80211_set_acl(interface);
            }
#else
            //Call vendor HAL
            if (vap->u.bss_info.mac_filter_enable == TRUE) {
                if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                    //blacklist
                    filtermode = 2;
                } else {
                    //whitelist
                    filtermode = 1;
                }
            } else {
                //disabled
                filtermode  = 0;
            }
            wifi_hal_info_print("%s:%d: vap index:%d set mac filter mode:%d\n", __func__, __LINE__,
                vap->vap_index, filtermode);
            if (wifi_setApMacAddressControlMode(vap->vap_index, filtermode) < 0) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to set mac filter\n", __func__,
                    __LINE__, vap->vap_index);
                return RETURN_ERR;
            }
#endif // NL80211_ACL
            re_configure_steering_mac_list(interface);
        }
        if (vap->vap_mode == wifi_vap_mode_ap) {
            wifi_hal_info_print("%s:%d: vap index:%d set power:%d\n",  __func__, __LINE__,
                vap->vap_index, vap->u.bss_info.mgmtPowerControl);
            if (wifi_setApManagementFramePowerControl(vap->vap_index,
                vap->u.bss_info.mgmtPowerControl) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to set power %d\n", __func__,
                    __LINE__, vap->vap_index, vap->u.bss_info.mgmtPowerControl);
            }
        }
#if defined(CONFIG_WIFI_EMULATOR) || defined(BANANA_PI_PORT)
        //Init wpa-supplicant params.
        if (vap->vap_mode == wifi_vap_mode_sta) {
            deinit_wpa_supplicant(interface);
            if (init_wpa_supplicant(interface) != RETURN_OK) {
                wifi_hal_info_print("%s:%d: Error initializing supplicant params\n", __func__, __LINE__);
            }
        }
#endif
    }

    if ((set_vap_params_fn = get_platform_create_vap_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: radio index:%d post-create vap\n", __func__, __LINE__,
            radio->index);
        set_vap_params_fn(index, map);
    }

    return ret;
}

INT wifi_hal_kickAssociatedDevice(INT ap_index, mac_address_t mac)
{
    wifi_interface_info_t *interface;

    interface  = get_interface_by_vap_index(ap_index);
    if (interface ==  NULL) {
        wifi_hal_error_print("%s:%d: NULL Interface pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }
    u8 own_addr[ETH_ALEN];
    mac_address_t bcastmac= {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    struct hostapd_data *hapd = &interface->u.ap.hapd;
    if(hapd == NULL) {
        wifi_hal_error_print("%s:%d: NULL hapd pointer \n", __func__, __LINE__);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_ERR;
    }
    if(hapd->sta_list == NULL) {
        wifi_hal_error_print("%s:%d: hapd->sta_list is NULL \n", __func__, __LINE__);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_ERR;
    }
    struct sta_info *tmp = NULL;
    memcpy(own_addr, hapd->own_addr, ETH_ALEN);
    if (memcmp(mac, bcastmac, sizeof(mac_address_t)) == 0) {
        tmp = hapd->sta_list;
        while(tmp) {
#if defined(BANANA_PI_PORT) && defined(KERNEL_6_6)
#if HOSTAPD_VERSION >= 211 && defined(CONFIG_GENERIC_MLO)
            int link_id = wifi_hal_get_mld_link_id(interface);
#else
            int link_id = NL80211_DRV_LINK_ID_NA;
#endif // HOSTAPD_VERSION >= 211 && CONFIG_GENERIC_MLO
            wifi_drv_sta_disassoc(interface, own_addr, tmp->addr, WLAN_REASON_UNSPECIFIED, link_id);
#else
            wifi_drv_sta_disassoc(interface, own_addr, tmp->addr, WLAN_REASON_UNSPECIFIED);
#endif // BANANA_PI_PORT && KERNEL_6_6
            tmp=tmp->next;
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    }
    else {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_info_print("%s:%d:mac is not a broadcast mac address\n", __func__, __LINE__);
#if defined(BANANA_PI_PORT) && defined(KERNEL_6_6)
#if HOSTAPD_VERSION >= 211 && defined(CONFIG_GENERIC_MLO)
        int link_id = wifi_hal_get_mld_link_id(interface);
#else
        int link_id = NL80211_DRV_LINK_ID_NA;
#endif // HOSTAPD_VERSION >= 211 && CONFIG_GENERIC_MLO
        wifi_drv_sta_disassoc(interface, own_addr, mac, WLAN_REASON_UNSPECIFIED, link_id);
#else
        wifi_drv_sta_disassoc(interface, own_addr, mac, WLAN_REASON_UNSPECIFIED);
#endif // BANANA_PI_PORT && KERNEL_6_6
    }
    return RETURN_OK;
}

INT wifi_hal_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    unsigned int itr = 0;
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio =  NULL;

    RADIO_INDEX_ASSERT(index);
    NULL_PTR_ASSERT(map);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if (radio->interface_map == NULL) {
        wifi_hal_error_print("%s:%d: No interface map is empty for radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    interface = hash_map_get_first(radio->interface_map);
    if (interface == NULL ) {
        wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    while (interface != NULL) {
        // on CMXB7 platform radio interfaces have vap_index -1
        // therefore check for interface vap_index
        // and don't add radio interfaces to vap map
        if ((int)interface->vap_info.vap_index >= 0){
            memcpy(&map->vap_array[itr], &interface->vap_info, sizeof(wifi_vap_info_t));
            if (strncmp((char *)map->vap_array[itr].vap_name, "sim_sta", strlen("sim_sta")) == 0) {
                memcpy(map->vap_array[itr].u.sta_info.mac, interface->mac, sizeof(map->vap_array[itr].u.sta_info.mac));
            } else if (strncmp((char *)map->vap_array[itr].vap_name, "mesh_sta", strlen("mesh_sta")) != 0) {
                memcpy(map->vap_array[itr].u.bss_info.bssid, interface->mac, sizeof(map->vap_array[itr].u.bss_info.bssid));
            } else {
                memcpy(map->vap_array[itr].u.sta_info.mac, interface->mac, sizeof(map->vap_array[itr].u.sta_info.mac));
            }

            itr++;
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }

    map->num_vaps = itr;

    return RETURN_OK;
}

INT wifi_hal_set_acs_keep_out_chans(wifi_radio_operationParam_t *wifi_radio_oper_param,
    int radioIndex)
{
    char buff[ACS_MAX_VECTOR_LEN + 2];
    char excl_chan_string[20];
    memset(buff, 0, sizeof(buff));
    snprintf(excl_chan_string, sizeof(excl_chan_string), "wl%u_acs_excl_chans", radioIndex);
    if (!wifi_radio_oper_param) {
        wifi_hal_error_print("%s:%d Null radio operation parameter, hence clearing entries\n", __func__, __LINE__);
        return wifi_drv_set_acs_exclusion_list(radioIndex, NULL);
    }
    for (size_t i = 0; i < MAX_NUM_CHANNELBANDWIDTH_SUPPORTED; i++) {
        wifi_channels_list_per_bandwidth_t *chans_per_band = 
            &wifi_radio_oper_param->channels_per_bandwidth[i];
        if (chans_per_band->num_channels_list == 0) {
            continue;
        }
        wifi_channelBandwidth_t bandwidth = chans_per_band->chanwidth;
        for (int j = 0; j < chans_per_band->num_channels_list; j++) {
            wifi_channels_list_t chanlist = chans_per_band->channels_list[j];
            if (wifi_drv_get_chspc_configs(radioIndex, bandwidth, 
                                         chanlist, buff) != 0) {
                wifi_hal_error_print("%s:%d Failed for radio %u bandwidth 0x%x\n",
                                   __func__, __LINE__, radioIndex, bandwidth);
                return RETURN_ERR;
            }
        }
    }
    size_t len = strlen(buff);
    if (len > 0) {
        buff[len - 1] = '\0';
    }
    return wifi_drv_set_acs_exclusion_list(radioIndex, buff);
}

INT wifi_hal_getScanResults(wifi_radio_index_t index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
//    wifi_vap_info_t *vap;
    wifi_radio_operationParam_t *radio_param;
    bool found = false;
    unsigned int freq = 0, total_count = 0;
    char country[8];
    wifi_bss_info_t *scan_info, *tmp_bss;

    if (!channel || !bss || !num_bss) {
        wifi_hal_error_print("%s:%d:invalid parameters\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Could not find radio for index: %d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            found = true;
            break;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    if (found == false) {
        wifi_hal_error_print("%s:%d: Could not find sta interface on radio index: %d, start scan failure\n",
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

//    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    get_coutry_str_from_code(radio_param->countryCode, country);

    if (channel != NULL) {
        if (radio_param->band != channel->band) {
            wifi_hal_error_print("%s:%d: Channel not valid on radio index: %d band : 0x%x\n", __func__, __LINE__, index, channel->band);
            return RETURN_ERR;
        } else if ((freq = ieee80211_chan_to_freq(country, radio_param->operatingClass, channel->channel)) == -1) {
            wifi_hal_error_print("%s:%d: Channel argument error for index : %d channel : %d\n", __func__, __LINE__, index, channel->channel);
            return RETURN_ERR;
        }
    }

    pthread_mutex_lock(&interface->scan_info_mutex);
    if (freq == 0) {
        total_count = hash_map_count(interface->scan_info_map);
    } else {
        scan_info = hash_map_get_first(interface->scan_info_map);
        while (scan_info != NULL) {
            if (freq == scan_info->freq) total_count++;
            scan_info = hash_map_get_next(interface->scan_info_map, scan_info);
        }
    }

    tmp_bss = calloc(total_count, sizeof(wifi_bss_info_t));
    if (!tmp_bss) {
        pthread_mutex_unlock(&interface->scan_info_mutex);
        wifi_hal_error_print("%s:%d:memory allocation error\n", __func__, __LINE__);
        *bss = NULL;
        *num_bss = 0;
        return RETURN_ERR;
    }
    *bss = tmp_bss;
    *num_bss = total_count;

    scan_info = hash_map_get_first(interface->scan_info_map);
    while (scan_info != NULL) {
        if (freq == 0) {
            memcpy(tmp_bss, scan_info, sizeof(wifi_bss_info_t));
        } else {
            if (freq == scan_info->freq) {
                memcpy(tmp_bss, scan_info, sizeof(wifi_bss_info_t));
            }
        }
        tmp_bss++;
        scan_info = hash_map_get_next(interface->scan_info_map, scan_info);
    }
    pthread_mutex_unlock(&interface->scan_info_mutex);

    return RETURN_OK;
}

#ifdef WIFI_HAL_VERSION_3_PHASE2
INT wifi_hal_addApAclDevice(INT apIndex, mac_address_t DeviceMacAddress)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    key = to_mac_str(DeviceMacAddress, sta_mac_str);
    
    wifi_hal_info_print("%s:%d: Interface: %s MAC: %s\n", __func__, __LINE__, interface->name, key);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to add MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_error_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        interface->acl_map = hash_map_create();
        if (interface->acl_map == NULL) {
            wifi_hal_error_print("%s:%d: ACL map create failure for ap index %d\n", __func__, __LINE__, apIndex);
            return RETURN_ERR;
        }
    }

    acl_map = hash_map_get(interface->acl_map, key);

    if (acl_map != NULL) {
        wifi_hal_error_print("%s:%d: MAC %s already present in acl list\n", __func__, __LINE__, key);
        return RETURN_OK;
    }

    acl_map = (acl_map_t *)malloc(sizeof(acl_map_t));

    memcpy(acl_map->mac_addr_str, key, sizeof(mac_addr_str_t));
    memcpy(acl_map->mac_addr, DeviceMacAddress, sizeof(mac_address_t));

    hash_map_put(interface->acl_map, strdup(key), acl_map);

    if (nl80211_set_acl(interface) != 0) {
        wifi_hal_error_print("%s:%d: MAC %s nl80211_set_acl failure for ap_index:%d\n", __func__, __LINE__, key, apIndex);
        return RETURN_ERR;
    }

    if ((vap->u.bss_info.mac_filter_enable == true) &&
        (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list)) {
        if (nl80211_kick_device(interface, DeviceMacAddress) != 0) {
            wifi_hal_error_print("%s:%d: Unable to kick MAC %s on ap_index %d\n", __func__,
                __LINE__, DeviceMacAddress, apIndex);
        }
    }
    return 0;
}
#else
INT wifi_hal_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map = NULL;
    mac_address_t sta_mac;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    wifi_hal_info_print("%s:%d: Interface: %s MAC: %s\n",  __func__, __LINE__, interface->name, DeviceMacAddress);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to add MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_error_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        interface->acl_map = hash_map_create();
        if (interface->acl_map == NULL) {
            wifi_hal_info_print("%s:%d: ACL map create failure for ap index %d\n", __func__, __LINE__, apIndex);
            return RETURN_ERR;
        }
    }

    acl_map = hash_map_get(interface->acl_map, DeviceMacAddress);

    if (acl_map != NULL) {
        wifi_hal_error_print("%s:%d: MAC %s already present in acl list\n", __func__, __LINE__, DeviceMacAddress);
        return RETURN_OK;
    }

    acl_map = (acl_map_t *)malloc(sizeof(acl_map_t));

    memcpy(acl_map->mac_addr_str, DeviceMacAddress, sizeof(mac_addr_str_t));
    to_mac_bytes(acl_map->mac_addr_str, acl_map->mac_addr);

    hash_map_put(interface->acl_map, strdup(DeviceMacAddress), acl_map);

    if (nl80211_set_acl(interface) != 0) {
        wifi_hal_error_print("%s:%d: MAC %s nl80211_set_acl failure for ap_index:%d\n", __func__, __LINE__, DeviceMacAddress, apIndex);
        return RETURN_ERR;
    }

    to_mac_bytes(DeviceMacAddress, sta_mac);
    if ((vap->u.bss_info.mac_filter_enable == true) &&
        (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list)) {
        if (nl80211_kick_device(interface, sta_mac) != 0) {
            wifi_hal_error_print("%s:%d: Unable to kick MAC %s on ap_index %d\n", __func__,
                __LINE__, DeviceMacAddress, apIndex);
        }
    }
    return 0;
}
#endif

#ifdef WIFI_HAL_VERSION_3_PHASE2
INT wifi_hal_delApAclDevice(INT apIndex, mac_address_t DeviceMacAddress)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    key = to_mac_str(sta_mac, sta_mac_str);
    
    wifi_hal_info_print("%s:%d: Interface: %s MAC: %s\n", __func__, __LINE__, interface->name, key);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to del MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_error_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_OK;
    }

    acl_map = hash_map_get(interface->acl_map, key);

    if (acl_map == NULL) {
        wifi_hal_error_print("%s:%d: MAC %s is not present in acl list\n", __func__, __LINE__, key);
        return RETURN_OK;
    }

    hash_map_remove(interface->acl_map, key);
    if (acl_map != NULL) {
        free(acl_map);
    }

    if (nl80211_set_acl(interface) != 0) {
        acl_map = (acl_map_t *)malloc(sizeof(acl_map_t));
        wifi_hal_error_print("%s:%d MAC %s nl80211_set_acl failure for interface:%s\n", __func__, __LINE__, key, interface->name);
        memcpy(acl_map->mac_addr_str, key, sizeof(mac_addr_str_t));
        memcpy(acl_map->mac_addr, DeviceMacAddress, sizeof(mac_addr_str_t));

        hash_map_put(interface->acl_map, strdup(key), acl_map);

        return -1;
    }

    return 0;
}
#else
INT wifi_hal_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;
    
    wifi_hal_info_print("%s:%d: Interface: %s MAC: %s\n", __func__, __LINE__, interface->name, DeviceMacAddress);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to del MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_error_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_OK;
    }

    acl_map = hash_map_get(interface->acl_map, DeviceMacAddress);

    if (acl_map == NULL) {
        wifi_hal_error_print("%s:%d: MAC %s is not present in acl list\n", __func__, __LINE__, DeviceMacAddress);
        return RETURN_OK;
    }

    hash_map_remove(interface->acl_map, DeviceMacAddress);
    if (acl_map != NULL) {
        free(acl_map);
    }

    if (nl80211_set_acl(interface) != 0) {
        acl_map = (acl_map_t *)malloc(sizeof(acl_map_t));
        wifi_hal_error_print("%s:%d MAC %s nl80211_set_acl failure for interface:%s\n", __func__, __LINE__, DeviceMacAddress, interface->name);
        memcpy(acl_map->mac_addr_str, DeviceMacAddress, sizeof(mac_addr_str_t));
        to_mac_bytes(acl_map->mac_addr_str, acl_map->mac_addr);

        hash_map_put(interface->acl_map, strdup(DeviceMacAddress), acl_map);

        return -1;
    }

    return 0;
}
#endif

INT wifi_hal_delApAclDevices(INT apIndex)
{
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map, *temp_acl_map;
    mac_addr_str_t mac_str;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface){
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;
    wifi_hal_dbg_print("%s:%d: Interface: %s \n", __func__, __LINE__, interface->name);
    
    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_dbg_print("%s:%d: Not possible to del MAC ACL for STA device\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: ACL map is NULL for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    acl_map = hash_map_get_first(interface->acl_map);

    if (acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: ACL list is empty for ap index %d\n", __func__, __LINE__, apIndex);
        return RETURN_OK;
    }

    while (acl_map != NULL) {
        memcpy(&mac_str, &acl_map->mac_addr_str, sizeof(mac_addr_str_t));
        acl_map = hash_map_get_next(interface->acl_map, acl_map);
        temp_acl_map = hash_map_remove(interface->acl_map, mac_str);
        if (temp_acl_map != NULL) {
            free(temp_acl_map);
        }
    }

    return nl80211_set_acl(interface);
}

INT wifi_hal_getApAclDeviceNum(INT apIndex, uint *aclCount)
{
    if (aclCount == NULL) {
        wifi_hal_dbg_print("%s:%d: aclCount is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return wifi_drv_getApAclDeviceNum(apIndex, aclCount) ? RETURN_ERR : RETURN_OK;
}

INT wifi_hal_setRadioTransmitPower(wifi_radio_index_t radioIndex, uint txpower)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio for radio index:%d not found\n", __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) {
        interface = get_primary_interface(radio);
    }
    else {
        interface = get_private_vap_interface(radio);
    }

    if (!interface) {
        wifi_hal_error_print("%s:%d: Error updating dev:%d no interfaces exist\n", __func__, __LINE__, radio->index);
        return -1;
    }

    return wifi_drv_set_txpower(interface, txpower) ? RETURN_ERR : RETURN_OK;
}

INT wifi_hal_sendDataFrame( int vap_id, unsigned char *dmac, unsigned char *data_buff, int data_len, BOOL insert_llc, int protocol, int priority)
{
    struct sockaddr_ll addr;
    struct ether_header *ethHdr;
    unsigned int t_data[1600/4];
    int t_len=0;
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("Entering for %s:%d:for : %d\n", __func__, __LINE__, vap_id);

    if ((t_len = (data_len + sizeof(struct ether_header))) > sizeof(t_data))
         return RETURN_ERR;

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);

    if(g_fd_arr[vap_id] <= 0 ) {
        g_fd_arr[vap_id] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (g_fd_arr[vap_id] < 0)
            return RETURN_ERR;

        interface = get_interface_by_vap_index((unsigned int)vap_id);
        if (interface != NULL) {
            g_IfIdx_arr[vap_id] = interface->index;
            memcpy(&g_vapSmac[vap_id][0], interface->mac, sizeof(mac_address_t));
        } else {
            close(g_fd_arr[vap_id]);
            g_fd_arr[vap_id] = -1;
            g_IfIdx_arr[vap_id] = -1;
            return RETURN_ERR;
        }

        addr.sll_ifindex = g_IfIdx_arr[vap_id];
        if (bind(g_fd_arr[vap_id], (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(g_fd_arr[vap_id]);
            g_fd_arr[vap_id] = -1;
            g_IfIdx_arr[vap_id] = -1;
            return RETURN_ERR;
        }
    }

    ethHdr = (struct ether_header *) t_data;
    memcpy(ethHdr->ether_shost, &g_vapSmac[vap_id][0], sizeof(mac_address_t));
    memcpy(ethHdr->ether_dhost, dmac, sizeof(mac_address_t));
    ethHdr->ether_type = htons(protocol);
    ethHdr++;

    memcpy((void *)ethHdr, data_buff, data_len);
    t_len = sizeof(struct ether_header) + data_len;

    addr.sll_ifindex = g_IfIdx_arr[vap_id];
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, dmac, ETH_ALEN);

    if (sendto(g_fd_arr[vap_id], t_data, t_len, 0, (struct sockaddr *)&addr, sizeof(addr)) == t_len) {
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    bool found = false;
    wifi_radio_operationParam_t *radio_param, param;
    char country[8] = {0}, tmp_str[32] = {0}, chan_list_str[512] = {0};
    unsigned int freq_list[MAX_FREQ_LIST_SIZE], i;
    ssid_t  ssid_list[8];
    int op_class, freq_num = 0;

    wifi_hal_stats_dbg_print("%s:%d: index: %d mode: %d dwell time: %d\n", __func__, __LINE__, index,
        scan_mode, dwell_time);

    RADIO_INDEX_ASSERT(index);

    if (dwell_time < 0) {
        wifi_hal_stats_error_print("%s:%d: invalide dwell time: %d\n", __func__, __LINE__, dwell_time);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d:Could not find radio for index: %d\n", __func__, __LINE__, index);
        return RETURN_ERR; 
    }

    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            found = true;
            break;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    if (found == false) {
        wifi_hal_stats_error_print("%s:%d:Could not find sta interface on radio index: %d, start scan failure\n", 
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

#if defined(_PLATFORM_BANANAPI_R4_)
    if (interface->rdk_radio_index != index) {
        wifi_hal_stats_error_print("%s:%d:Not allowing scan on radio_index: %d because not "
            "matching with interface->rdk_radio_index:%d\n",
            __func__, __LINE__, index, interface->rdk_radio_index);
        return RETURN_ERR;
    }
#endif

    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    if (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
        num = 1;
    } else if (scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN) {
        if ((num == 0) || (chan_list == NULL)) {
            wifi_hal_stats_error_print("%s:%d: Channels not speified for offchannel scan mode\n", __func__, __LINE__);
            return RETURN_ERR; 
        }
    } else {
        wifi_hal_stats_error_print("%s:%d: Incorrect scan mode\n", __func__, __LINE__);
        return RETURN_ERR; 
    }

    get_coutry_str_from_code(radio_param->countryCode, country);
    memcpy((unsigned char *)&param, (unsigned char *)radio_param, sizeof(wifi_radio_operationParam_t));

    for (i = 0; i < num && freq_num < MAX_FREQ_LIST_SIZE; i++) {
        param.channel = (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) ?
            radio_param->channel : chan_list[i]; 

        if ((op_class = get_op_class_from_radio_params(&param)) == -1) {
            wifi_hal_stats_error_print("%s:%d: Invalid channel %d\n", __func__, __LINE__, param.channel);
            continue;
        }

        freq_list[freq_num] = ieee80211_chan_to_freq(country, op_class, param.channel);
        if (freq_list[freq_num] == 0) {
            continue;
        }
        sprintf(tmp_str, "%d ", freq_list[freq_num]);
        strcat(chan_list_str, tmp_str);

	freq_num++;
    }

    if (freq_num == 0) {
        wifi_hal_stats_error_print("%s:%d: No valid channels\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    strcpy(ssid_list[0], vap->u.sta_info.ssid);
    wifi_hal_stats_info_print("%s:%d: Scan Frequencies:%s \n", __func__, __LINE__, chan_list_str);

    pthread_mutex_lock(&interface->scan_info_mutex);
    hash_map_cleanup(interface->scan_info_map);
    pthread_mutex_unlock(&interface->scan_info_mutex);

    return (nl80211_start_scan(interface, NL80211_SCAN_FLAG_COLOCATED_6GHZ, freq_num, freq_list, dwell_time, 1, ssid_list) == 0) ? RETURN_OK:RETURN_ERR;
}

/*****************************/

/* Enable (1) or disable(0) active scan in AP mode in wifi_hal_startNeighborScan() */
#define CONFIG_NEIGHBOR_AP_SCAN_ACTIVE 0

/* Verify channels availability and filter out disabled channels (0 or 1)*/
#define OPTION_FILTER_DISABLED_CHANNELS 1

/* Select a method to read channels list: wifi_radio_info_t structure (0) or hostapd interface structure (1).
   The result can be different depending on method; the second method (via hostapd) may returen shorter
   but more correct list of channels */
#define OPTION_GET_CHANNELS_FROM_HOSTAP 1

// - helper macro for input arguments validation
#define _IS_INVALID_ARG(expr) ({ \
    bool __not_valid = (expr); \
    if (__not_valid) { \
        wifi_hal_error_print("%s:%d: Invalid argument; " #expr "\n", __func__, __LINE__); \
    } \
    __not_valid; \
})

static inline int set_freqs_filter(wifi_interface_info_t *interface, uint num_freqs, const uint freqs[])
{
    return uint_array_set(&interface->scan_filter, num_freqs, freqs);
}

static inline void cleanup_freqs_filter(wifi_interface_info_t *interface)
{
    uint_array_set(&interface->scan_filter, 0, NULL);
}

#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
// - get channel list from wifi_radio_info_t*

static int channel_is_valid_from_radio(wifi_radio_info_t *radio, unsigned channel)
{
    enum nl80211_band band = wifi_freq_band_to_nl80211_band(radio->oper_param.band);
    const struct hostapd_hw_modes *mode = NULL;
    int i;

    if (band == NUM_NL80211_BANDS) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] unsupported band (0x%2x)\n", __func__, __LINE__, radio->oper_param.band);
        return -1;
    }

    if (0 == channel) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] invalid channel: %u\n",  __func__, __LINE__, channel);
        return -1;
    }

    mode = &radio->hw_modes[band];
    for (i = 0; i < mode->num_channels; ++i) {
        struct hostapd_channel_data *channel_data = &radio->channel_data[band][i];
        // wifi_hal_dbg_print("%s:%d: [SCAN]: chan:%d, freq:%d, %s, dfs:%s\n", channel_data->chan, channel_data->freq,
        //     channel_data->flag & HOSTAPD_CHAN_DISABLED ? "disabled" : "enabled", get_chan_dfs_state(channel_data));

        if ((int)channel == channel_data->chan) {
            bool enabled = channel_data->flag & HOSTAPD_CHAN_DISABLED ? false : true;
            int freq = channel_data->freq;
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] \tchannel=%u, %s, dfs:%s\n", __func__, __LINE__,
                channel, enabled ? "enabled" : "disabled",
                get_chan_dfs_state(channel_data));
#if OPTION_FILTER_DISABLED_CHANNELS
            return enabled ? freq : -1;
#else
            // - print message, but return OK
            if (!enabled) {
                wifi_hal_stats_info_print("%s:%d: [SCAN] WARNING: channel %u is DISABLED in hostapd structures\n", __func__, __LINE__, channel);
            }
            return freq;
#endif
        }
    }

    return -1;
}

static int get_valid_freqs_list_from_radio(wifi_radio_info_t *radio, uint_array_t* freqs)
{
    enum nl80211_band band = wifi_freq_band_to_nl80211_band(radio->oper_param.band);
    const struct hostapd_hw_modes *mode = NULL;
    int i;
    uint count = 0;
    uint *list;

    if (band == NUM_NL80211_BANDS) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] unsupported band (0x%2x)\n", __func__, __LINE__, radio->oper_param.band);
        return RETURN_ERR;
    }

    mode = &radio->hw_modes[band];
#if OPTION_FILTER_DISABLED_CHANNELS
    // - count available channels
    for (i = 0; i < mode->num_channels; ++i) {
        struct hostapd_channel_data *channel_data = &radio->channel_data[band][i];
        if ( (channel_data->chan != 0) && !(channel_data->flag & HOSTAPD_CHAN_DISABLED) )
            ++count;
    }
#else
    wifi_hal_stats_dbg_print("%s:%d: [SCAN] All channels are used (including disabled DFS channels)\n", __func__, __LINE__);
    count = mode->num_channels;
#endif

    // - allocate array
    if (RETURN_OK != uint_array_set(freqs, count, NULL))
        return RETURN_ERR;

    // - copy enabled freq
    list = freqs->values;
    for (i = 0; i < mode->num_channels; ++i) {
        struct hostapd_channel_data *channel_data = &radio->channel_data[band][i];
        // /* for debugging: */
        // wifi_hal_dbg_print("%s:%d: [SCAN] \tchannel=%u, %s, dfs:%s\n", __func__, __LINE__,
        //     channel_data->chan, (channel_data->flag & HOSTAPD_CHAN_DISABLED) ? "disabled" : "enabled",
        //     get_chan_dfs_state(channel_data));

#if OPTION_FILTER_DISABLED_CHANNELS
        if ( (channel_data->chan != 0) && !(channel_data->flag & HOSTAPD_CHAN_DISABLED) ) {
            *list++ = channel_data->freq;
        }
#else
        // - ignore channel 0
        if (channel_data->chan == 0)
            continue;
        if ( (channel_data->flag & HOSTAPD_CHAN_DISABLED) ) {
            wifi_hal_stats_info_print("%s:%d: [SCAN] WARNING: channel %u is DISABLED in hostapd structures\n", __func__, __LINE__, channel_data->chan);
        }
        *list++ = channel_data->freq;
#endif
    }
    return RETURN_OK;
}

#else
// - get channel list from hostapd_data

/* Returns freq corresponding to the channel or -1 if channel is not valid */
static int channel_is_valid_from_hapd(struct hostapd_data *hapd, unsigned channel)
{
    int i;
    struct hostapd_iface *iface = hapd->iface;
    struct hostapd_hw_modes *feature = iface->current_mode;

    if (feature == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] iface->current_mode is NULL\n", __func__, __LINE__);
        return -1;
    }

    for (i = 0; i < feature->num_channels; ++i) {
        // wifi_hal_dbg_print("%s:%d: [SCAN] chan[%d]=%d, freq=%d, flag=0x%02x\n", __func__, __LINE__,
        //     i, feature->channels[i].chan, feature->channels[i].freq, feature->channels[i].flag);
        if ((int)channel == feature->channels[i].chan) {
            bool enabled = (feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) ? false : true;
            int freq = feature->channels[i].freq;
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] \tchannel=%u, %s, dfs:%s\n", __func__, __LINE__,
                channel, enabled ? "enabled" : "disabled",
                get_chan_dfs_state(&feature->channels[i]));
#if OPTION_FILTER_DISABLED_CHANNELS
            return enabled ? freq : -1;
#else
            // - print message, but return OK
            if (!enabled) {
                wifi_hal_stats_info_print("%s:%d: [SCAN] WARNING: channel %u is DISABLED in hostapd structures\n", __func__, __LINE__, channel);
            }
            return freq;
#endif
        }
    }

    return -1;
}

static int get_valid_freqs_list_from_hapd(struct hostapd_data *hapd, uint_array_t* freqs)
{
    int i;
    struct hostapd_iface *iface = hapd->iface;
    struct hostapd_hw_modes *feature = iface->current_mode;
    uint count = 0;
    uint *list;

    if (feature == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] iface->current_mode is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

#if OPTION_FILTER_DISABLED_CHANNELS
    // - count available channels
    for (i = 0; i < feature->num_channels; ++i) {
        if ( !(feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) )
            ++count;
    }
#else
    wifi_hal_stats_dbg_print("%s:%d: [SCAN] All channels are used (including disabled DFS channels)\n", __func__, __LINE__);
    count = feature->num_channels;
#endif

    // - allocate array
    if (RETURN_OK != uint_array_set(freqs, count, NULL))
        return RETURN_ERR;

    // - copy enabled freq
    list = freqs->values;
    for (i = 0; i < feature->num_channels; ++i) {
        // /* for debugging: */
        // wifi_hal_dbg_print("%s:%d: [SCAN] \tchannel=%u, %s, dfs:%s\n", __func__, __LINE__,
        //     feature->channels[i].chan,
        //     (feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) ? "disabled" : "enabled",
        //     get_chan_dfs_state(&feature->channels[i]));

#if OPTION_FILTER_DISABLED_CHANNELS
        if ( !(feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) )
            *list++ = feature->channels[i].freq;
#else
        if ( (feature->channels[i].flag & HOSTAPD_CHAN_DISABLED) ) {
            wifi_hal_stats_info_print("%s:%d: [SCAN] WARNING: channel %u is DISABLED in hostapd structures\n", __func__, __LINE__,
                feature->channels[i].chan);
        }
        *list++ = feature->channels[i].freq;
#endif
    }
    return RETURN_OK;
}

#endif // OPTION_GET_CHANNELS_FROM_HOSTAP

// - helper macro for copying string
#define _COPY(out,s) ({ \
    int res = wifi_strcpy(out, sizeof(out), s); \
    if (res) wifi_hal_stats_error_print("%s:%d: string copying error!\n", __func__, __LINE__); \
    res; \
})

// - helper macro for adding string to a comma-separated list
#define _APPEND(out,s) ({ \
    int res = str_list_append(out, sizeof(out), s); \
    if (res) wifi_hal_stats_error_print("%s:%d: string adding error!\n", __func__, __LINE__); \
    res; \
})

// - helper macro for string formatting
#define _FORMAT(out, fmt, args...) ({ \
    int res = snprintf(out, sizeof(out), fmt, ##args); \
    res = ((res < 0) || (res >= sizeof(out))); \
    if (res) wifi_hal_stats_error_print("%s:%d: string format error!\n", __func__, __LINE__); \
    res; \
})

static int decode_bss_info_to_neighbor_ap_info(wifi_neighbor_ap2_t *ap, const wifi_bss_info_t *bss)
{
    int ret = RETURN_OK;
    const char *str;

    memset(ap, 0, sizeof(*ap));

    /*  This function check each step, but do not stop filling the output if one step fails.
        This allows to see the rest of the information even if one step fails.
     */

    // - ap_SSID
    if (_COPY(ap->ap_SSID, bss->ssid)) {
        ret = RETURN_ERR;
    }

    // - ap_BSSID
    if (_FORMAT(ap->ap_BSSID, MACSTR, MAC2STR(bss->bssid))) {
        ret = RETURN_ERR;
    }

    // - ap_Mode
    str = "";
    if (bss->caps & WLAN_CAPABILITY_ESS)
        str = "Infrastructure";
    if (bss->caps & WLAN_CAPABILITY_IBSS)
        str = "AdHoc";

    if (_COPY(ap->ap_Mode, str)) {
        ret = RETURN_ERR;
    }

    // - ap_Channel
    if (RETURN_OK != wifi_freq_to_channel(bss->freq, &ap->ap_Channel)) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] Cannot convert freq %u to the channel number!\n",  __func__, __LINE__, bss->freq);
        ret = RETURN_ERR;
    }

    // - ap_SignalStrength
    ap->ap_SignalStrength = bss->rssi;

    // -ap_freq
    ap->ap_freq = bss->freq;

    // - ap_SecurityModeEnabled
    switch (bss->sec_mode) {
        case wifi_security_mode_none:
            str = "None";
            break;
        case wifi_security_mode_wep_64:
        case wifi_security_mode_wep_128:
            str = "WEP";
            break;
        case wifi_security_mode_wpa_personal:
            str = "WPA-Personal";
            break;
        case wifi_security_mode_wpa_enterprise:
            str = "WPA-Enterprise";
            break;
        case wifi_security_mode_wpa2_personal:
            str = "WPA2-Personal";
            break;
        case wifi_security_mode_wpa2_enterprise:
            str = "WPA2-Enterprise";
            break;
        case wifi_security_mode_wpa_wpa2_personal:
            str = "WPA-WPA2-Personal";
            break;
        case wifi_security_mode_wpa_wpa2_enterprise:
            str = "WPA-WPA2-Enterprise";
            break;
        /* For future usage */
        case wifi_security_mode_wpa3_personal:
            str = "WPA3-Personal";
            break;
        case wifi_security_mode_wpa3_transition:
            if (bss->oper_freq_band == WIFI_FREQUENCY_6_BAND || bss->oper_freq_band == WIFI_FREQUENCY_60_BAND) {
                str = "WPA3-Personal";
            } else {
                str = "WPA3-Personal-Transition";
            }
            break;
        case wifi_security_mode_wpa3_enterprise:
            str = "WPA3-Enterprise";
            break;
        case wifi_security_mode_wpa3_compatibility:
            str = "WPA3-Compatibility";
            break;
        default:
            str = "?";
    }
    if (_COPY(ap->ap_SecurityModeEnabled, str)) {
        ret = RETURN_ERR;
    }

    // - ap_EncryptionMode
    switch (bss->enc_method) {
        case wifi_encryption_tkip:
            str = "TKIP";
            break;
        case wifi_encryption_aes:
            str = "AES";
            break;
        case wifi_encryption_aes_tkip:
            str = "AES+TKIP";
            break;
        default:
            str = "None";
            break;
    }
    if (_COPY(ap->ap_EncryptionMode, str)) {
        ret = RETURN_ERR;
    }

    // - ap_OperatingFrequencyBand
    switch (bss->oper_freq_band) {
        case WIFI_FREQUENCY_2_4_BAND:
            str = "2.4GHz";
            break;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
            str = "5GHz";
            break;
        case WIFI_FREQUENCY_6_BAND:
        case WIFI_FREQUENCY_60_BAND:
            str = "6GHz";
            break;
        default:
            str = "";
            break;
    }
    if (_COPY(ap->ap_OperatingFrequencyBand, str)) {
        ret = RETURN_ERR;
    }

    // - ap_SupportedStandards
    // 4th argument - Any prefix to be added before the standard i.e., 802.11
    if (wifi_ieee80211Variant_to_str(ap->ap_SupportedStandards, sizeof(ap->ap_SupportedStandards),
            bss->supp_standards, "")) {
        ret = RETURN_ERR;
    }

    // - ap_OperatingStandards
    if (wifi_ieee80211Variant_to_str(ap->ap_OperatingStandards, sizeof(ap->ap_OperatingStandards),
            bss->oper_standards, "")) {
        ret = RETURN_ERR;
    }

    // - ap_OperatingChannelBandwidth
    if (wifi_channelBandwidth_to_str(ap->ap_OperatingChannelBandwidth, sizeof(ap->ap_OperatingChannelBandwidth), bss->oper_chan_bw)) {
        ret = RETURN_ERR;
    }

    // - ap_BeaconPeriod
    ap->ap_BeaconPeriod = bss->beacon_int;
    // - ap_Noise
    ap->ap_Noise = bss->noise;

    // - ap_BasicDataTransferRates
    if (wifi_bitrate_to_str(ap->ap_BasicDataTransferRates, sizeof(ap->ap_BasicDataTransferRates), bss->basic_rates)) {
        ret = RETURN_ERR;
    }

    // - ap_SupportedDataTransferRates
    if (wifi_bitrate_to_str(ap->ap_SupportedDataTransferRates, sizeof(ap->ap_SupportedDataTransferRates), bss->supp_rates)) {
        ret = RETURN_ERR;
    }

    // - ap_DTIMPeriod
    ap->ap_DTIMPeriod = bss->dtim_period;
    // - ap_ChannelUtilization
    ap->ap_ChannelUtilization = bss->chan_utilization;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] bssid: %s, ssid: %s, channel: %d, noise: %d\n",
        __func__, __LINE__, ap->ap_BSSID, ap->ap_SSID, ap->ap_Channel, ap->ap_Noise);

    return ret;
}

static bool scan_result_passes_filter(wifi_interface_info_t *interface, uint freq)
{
    uint *freqs = interface->scan_filter.values;
    uint num_freqs = interface->scan_filter.num;
    uint i;

    if (freqs == NULL || num_freqs == 0) {
        /* filter is empty, allow this result */
        return true;
    }

    for (i = 0; (i < num_freqs) && (freqs[i] > 0); i++) {
        if (freq == freqs[i]) {
            return true;
        }
    }

    /* not in scan request, filter this result */
    return false;
}

static int copy_scan_results(wifi_interface_info_t *interface, wifi_neighbor_ap2_t **ap_array, uint *array_size)
{
    uint results_copied = 0;
    int ret = RETURN_ERR;

    uint out_size = 0;
    wifi_neighbor_ap2_t* out_array = NULL;
    wifi_bss_info_t *scan_info_ap;

    // mutex_lock ?? (already done by caller)

    *ap_array = NULL;
    *array_size = 0;

    out_size = hash_map_count(interface->scan_info_ap_map[1]);
    if (out_size == 0) {
        ret = RETURN_OK;
        goto exit;
    }

    out_array = (wifi_neighbor_ap2_t *)calloc(out_size, sizeof(wifi_neighbor_ap2_t));
    if (out_array == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] memory allocation error!\n", __func__, __LINE__);
        goto exit;
    }

    scan_info_ap = (wifi_bss_info_t*)hash_map_get_first(interface->scan_info_ap_map[1]);
    while (scan_info_ap != NULL) {
        if (scan_result_passes_filter(interface, scan_info_ap->freq)) {
            if (RETURN_OK != decode_bss_info_to_neighbor_ap_info(&out_array[results_copied], scan_info_ap)) {
                wifi_hal_stats_error_print("%s:%d: [SCAN] bss info decoding error! "
                    "Some fields in AP struct may contain incorrect data\n", __func__, __LINE__);
            }
            results_copied++;
        }
        else {
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan result %s, %u Mhz was dropped\n", __func__, __LINE__,
                scan_info_ap->ssid, scan_info_ap->freq);
        }
        scan_info_ap = (wifi_bss_info_t*)hash_map_get_next(interface->scan_info_ap_map[1], scan_info_ap);
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] out_size:%u, copied:%u\n", __func__, __LINE__, out_size, results_copied);
    if (results_copied == 0) {
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] All results were filtered out\n", __func__, __LINE__);
        free(out_array);
        out_array = NULL;
        out_size = 0;
    }
    else if (results_copied < out_size) {
        wifi_neighbor_ap2_t *new_out_array = (wifi_neighbor_ap2_t *)realloc(out_array, sizeof(wifi_neighbor_ap2_t) * results_copied);
        if (new_out_array == NULL) {
            // - error, but not critical, original array still is valid
            wifi_hal_stats_error_print("%s:%d: [SCAN] memory re-allocation error!\n", __func__, __LINE__);
        }
        else
            out_array = new_out_array;
        out_size = results_copied;
    }

    *ap_array = out_array;
    *array_size = out_size;
    ret = RETURN_OK;

exit:
    // mutex_unlock ??
    return ret;
}

INT wifi_hal_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time,
    UINT chan_num, UINT *chan_list)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    uint freq, op_class;
    uint i;
    char country[8] = { 0 };
    bool is_ap_mode = false;
    int radioIndex, res;
    ssid_t ssid_list[1] = { "" };
    bool is_active_scan = false;
    uint current_channel = 0;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] == ENTER (mode:%u, dwell_time:%d) ==\n", __func__,
        __LINE__, scan_mode, dwell_time);

    if (dwell_time < 0) {
        wifi_hal_stats_error_print("%s:%d: invalid dwell time: %d\n", __func__, __LINE__,
            dwell_time);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    AP_INDEX_ASSERT(apIndex);

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] interface for AP index:%d not found\n", __func__,
            __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    radioIndex = interface->vap_info.radio_index;
    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] radio for radio index:%d not found\n", __func__,
            __LINE__, radioIndex);
        return WIFI_HAL_ERROR;
    }

    is_ap_mode = (interface->vap_info.vap_mode == wifi_vap_mode_ap);

    if (RETURN_OK != get_coutry_str_from_code(radio->oper_param.countryCode, country)) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] Cant find country string (county:%u)\n", __func__,
            __LINE__, radio->oper_param.countryCode);
        return RETURN_ERR;
    }

    op_class = radio->oper_param.operatingClass;
    {
        unsigned global_op_class = country_to_global_op_class(country, op_class);
        wifi_hal_stats_dbg_print(
            "%s:%d: [SCAN] country code: %s, op_class:%d, global_op_class:%d\n", __func__, __LINE__,
            country, op_class, global_op_class);
    }

    /* Scanning is performed for the radio, so the status and results of the scan are stored in the
     * primary/private interface */

#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] primary interface for radio '%s' not found\n",
            __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#else
    interface = get_private_vap_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] private interface for radio '%s' not found\n",
            __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#endif

    pthread_mutex_lock(&interface->scan_state_mutex);
    {
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan_state:%d\n", __func__, __LINE__,
            interface->scan_state);

        if (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_API) {
            wifi_hal_stats_dbg_print(
                "%s:%d: [SCAN] Starting new scan, although results for radio %d "
                "(%s) from previous scan weren't collected\n",
                __func__, __LINE__, radioIndex, interface->name);
        }

        // - Check if scan was already triggered and is in progress
        if (interface->scan_state == WIFI_SCAN_STATE_STARTED) {
            pthread_mutex_unlock(&interface->scan_state_mutex);
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan already triggered for radio %d (%s)\n",
                __func__, __LINE__, radioIndex, interface->name);
            return WIFI_HAL_INTERNAL_ERROR;
        }

        // - Reset state before scanning
        interface->scan_state = WIFI_SCAN_STATE_NONE;

        /* Cleanup scan data (scan_info_ap_map[0]) before the new scan. Result data
         *  (scan_info_ap_map[1]) stays unchanged.
         */
        pthread_mutex_lock(&interface->scan_info_mutex);
        hash_map_cleanup(interface->scan_info_map);
        pthread_mutex_unlock(&interface->scan_info_mutex);
        pthread_mutex_lock(&interface->scan_info_ap_mutex);
        cleanup_freqs_filter(interface);
        hash_map_cleanup(interface->scan_info_ap_map[0]);
        pthread_mutex_unlock(&interface->scan_info_ap_mutex);
    }
    pthread_mutex_unlock(&interface->scan_state_mutex);

    if ((scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) && (dwell_time == 0)) {
        // - special case:
        wifi_hal_stats_dbg_print(
            "%s:%d: [SCAN] On channel scan with dwell time 0 => not triggering "
            "scan, requesting scan results immediately\n",
            __func__, __LINE__);

        // - get the current channel
        if (chan_num == 0 || chan_list == NULL) {
            chan_num = 1;
            current_channel = radio->oper_param.channel;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL))
            return WIFI_HAL_ERROR;

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            if (is_ap_mode) {
                // - verify the channel number (it is possible only in AP mode)
                int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_radio(radio, current_channel);
                } else {
                    i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
                }
#else
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, current_channel);
                } else {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
                }
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
                if (i_freq < 0) {
                    if (current_channel != 0) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, current_channel, radioIndex);
                    } else {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, chan_list[i], radioIndex);
                    }
                    return WIFI_HAL_ERROR;
                }
                freq = i_freq;
            } else {
                if (current_channel != 0) {
                    if (RETURN_OK !=
                        wifi_channel_to_freq(country, op_class, current_channel, &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, current_channel);
                        return WIFI_HAL_ERROR;
                    }
                } else {
                    if (RETURN_OK != wifi_channel_to_freq(country, op_class, chan_list[i], &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, chan_list[i]);
                        return WIFI_HAL_ERROR;
                    }
                }

                interface->scan_filter.values[i] = freq;
                if (current_channel != 0) {
                    wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u (current channel)\n",
                        __func__, __LINE__, current_channel, freq);
                } else {
                    wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__,
                        __LINE__, chan_list[i], freq);
                }
            }

            pthread_mutex_lock(&interface->scan_state_mutex);
            interface->scan_state = WIFI_SCAN_STATE_STARTED;
            pthread_mutex_unlock(&interface->scan_state_mutex);
        }
        // - scan_state is changed by nl80211_get_scan_results()
        if (nl80211_get_scan_results(interface) != RETURN_OK)
            return WIFI_HAL_ERROR;

        return WIFI_HAL_SUCCESS;
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] oper_param.opclass:%d, oper_param.channel:%d\n",
        __func__, __LINE__, radio->oper_param.operatingClass, radio->oper_param.channel);
    switch (scan_mode) {
    case WIFI_RADIO_SCAN_MODE_ONCHAN: {
        if (chan_num == 0 || chan_list == NULL) {
            chan_num = 1;
            current_channel = radio->oper_param.channel;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL))
            return WIFI_HAL_ERROR;

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            if (is_ap_mode) {
                // - verify the channel number (it is possible only in AP mode)
                int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_radio(radio, current_channel);
                } else {
                    i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
                }
#else
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                if (current_channel != 0) {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, current_channel);
                } else {
                    i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
                }
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
                if (i_freq < 0) {
                    if (current_channel != 0) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, current_channel, radioIndex);
                    } else {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                            __LINE__, chan_list[i], radioIndex);
                    }
                    return WIFI_HAL_ERROR;
                }
                freq = i_freq;
            } else {
                if (current_channel != 0) {
                    if (RETURN_OK !=
                        wifi_channel_to_freq(country, op_class, current_channel, &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, current_channel);
                    }
                } else {
                    if (RETURN_OK != wifi_channel_to_freq(country, op_class, chan_list[i], &freq)) {
                        wifi_hal_stats_error_print(
                            "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__,
                            __LINE__, chan_list[i]);
                        return WIFI_HAL_ERROR;
                    }
                }
            }

            interface->scan_filter.values[i] = freq;
            if (current_channel != 0) {
                wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u (current channel)\n",
                    __func__, __LINE__, current_channel, freq);
            } else {
                wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__, __LINE__,
                    chan_list[i], freq);
            }
        }
        break;
    }

    case WIFI_RADIO_SCAN_MODE_OFFCHAN: {
        if (!chan_num || !chan_list) {
            wifi_hal_stats_error_print("%s:%d: [SCAN] OFFCHAN needs chan_num and chan_list param\n",
                __func__, __LINE__);
            return WIFI_HAL_INVALID_ARGUMENTS;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL))
            return WIFI_HAL_ERROR;

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            if (is_ap_mode) {
                // - verify the channel number (it is possible only in AP mode)
                int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
                i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
#else
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
                if (i_freq < 0) {
                    wifi_hal_stats_error_print("%s:%d: [SCAN] channel %u is invalid for radio %d\n",
                        __func__, __LINE__, chan_list[i], radioIndex);
                    return WIFI_HAL_ERROR;
                }
                freq = i_freq;
            } else {
                if (RETURN_OK != wifi_channel_to_freq(country, op_class, chan_list[i], &freq)) {
                    wifi_hal_stats_error_print(
                        "%s:%d: [SCAN] Couldn't get frequency for channel %u\n", __func__, __LINE__,
                        chan_list[i]);
                    return WIFI_HAL_ERROR;
                }
            }

            interface->scan_filter.values[i] = freq;
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__, __LINE__,
                chan_list[i], freq);
        }
        break;
    }

    case WIFI_RADIO_SCAN_MODE_FULL: {
        if (!is_ap_mode) {
            wifi_hal_stats_error_print(
                "%s:%d: [SCAN] Full mode is not supported for STA interface\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }

        // - get list of channels (it is possible only in AP mode)
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
        if (RETURN_OK != get_valid_freqs_list_from_radio(radio, &interface->scan_filter)) {
            wifi_hal_stats_error_print("%s:%d: [SCAN] Couldn't get the freqs list for radio %d\n",
                __func__, __LINE__, radioIndex);
            return WIFI_HAL_ERROR;
        }
#else
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        if (RETURN_OK !=
            get_valid_freqs_list_from_hapd(&interface->u.ap.hapd, &interface->scan_filter)) {
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
            wifi_hal_stats_error_print("%s:%d: [SCAN] Couldn't get the freqs list for radio %d\n",
                __func__, __LINE__, radioIndex);
            return WIFI_HAL_ERROR;
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP

        for (i = 0; i < interface->scan_filter.num; i++) {
            uint chan = 0;
            wifi_freq_to_channel(interface->scan_filter.values[i], &chan);
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] freq[%u]: %u (channel %u)\n", __func__,
                __LINE__, i, interface->scan_filter.values[i], chan);
        }
        break;
    }

    case WIFI_RADIO_SCAN_MODE_SELECT_CHANNELS: {

        if (chan_num != 0 || chan_list != NULL) {
            wifi_hal_error_print("%s:%d: [SCAN] Needs chan_num and chan_list param\n", __func__,
                __LINE__);
            return WIFI_HAL_INVALID_ARGUMENTS;
        }

        // - allocate space for freq list
        if (RETURN_OK != set_freqs_filter(interface, chan_num, NULL)) {
            wifi_hal_error_print("%s:%d: [SCAN] set_freqs_filter failed\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }

        // - convert channels to freqs
        for (i = 0; i < chan_num; i++) {
            // - verify the channel number (it is possible only in AP mode)
            int i_freq;
#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
            i_freq = channel_is_valid_from_radio(radio, chan_list[i]);
#else
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            i_freq = channel_is_valid_from_hapd(&interface->u.ap.hapd, chan_list[i]);
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif // OPTION_GET_CHANNELS_FROM_HOSTAP
            if (i_freq < 0) {
                wifi_hal_error_print("%s:%d: [SCAN] channel %u is invalid for radio %d\n", __func__,
                    __LINE__, chan_list[i], radioIndex);
                return WIFI_HAL_ERROR;
            }
            freq = i_freq;

            interface->scan_filter.values[i] = freq;
            wifi_hal_dbg_print("%s:%d: [SCAN] chan:%u -> freq:%u\n", __func__, __LINE__,
                chan_list[i], freq);
        }
        break;
    }

    default:
        wifi_hal_stats_error_print(
            "%s:%d: [SCAN] scan mode %d is not supported! only supports: "
            "SCAN_MODE_ONCHAN(%d), SCAN_MODE_OFFCHAN(%d) and SCAN_MODE_FULL(%d)\n",
            __func__, __LINE__, scan_mode, WIFI_RADIO_SCAN_MODE_ONCHAN,
            WIFI_RADIO_SCAN_MODE_OFFCHAN, WIFI_RADIO_SCAN_MODE_FULL);
        return WIFI_HAL_ERROR;
    }

    pthread_mutex_lock(&interface->scan_state_mutex);
    interface->scan_state = WIFI_SCAN_STATE_STARTED;
    pthread_mutex_unlock(&interface->scan_state_mutex);

    if (is_ap_mode) {
#if CONFIG_NEIGHBOR_AP_SCAN_ACTIVE
        is_active_scan = true;
        ssid_list[0][0] = '\0'; /* SSID wildcard */
        res = nl80211_start_scan(interface, NL80211_SCAN_FLAG_AP | NL80211_SCAN_FLAG_FLUSH,
            interface->scan_filter.num, interface->scan_filter.values, dwell_time, 1, ssid_list);
#else
        is_active_scan = false;
        res = nl80211_start_scan(interface, NL80211_SCAN_FLAG_AP | NL80211_SCAN_FLAG_FLUSH,
            interface->scan_filter.num, interface->scan_filter.values, dwell_time, 0, NULL);
#endif
    } else {
        is_active_scan = true;
        wifi_strcpy(ssid_list[0], sizeof(ssid_list[0]), interface->vap_info.u.sta_info.ssid);
        res = nl80211_start_scan(interface, 0, interface->scan_filter.num,
            interface->scan_filter.values, dwell_time, 1, ssid_list);
    }

    if (res) {
        pthread_mutex_lock(&interface->scan_state_mutex);
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] scan trigger failed for '%s'\n", __func__,
            __LINE__, interface->name);
        return WIFI_HAL_ERROR;
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan triggered (%s, %s)\n", __func__, __LINE__,
        (is_ap_mode ? "AP" : "STA"), (is_active_scan ? "ACTIVE" : "PASSIVE"));
    return WIFI_HAL_SUCCESS;
}

static INT _wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size, bool test_mode)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    int ret;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] == ENTER ==\n", __func__, __LINE__);

    if (!neighbor_ap_array || !output_array_size) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] Invalid parameters\n", __func__, __LINE__);
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    RADIO_INDEX_ASSERT(radioIndex);

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] radio for radio index:%d not found\n", __func__, __LINE__, radioIndex);
        return WIFI_HAL_ERROR;
    }

#if OPTION_GET_CHANNELS_FROM_HOSTAP == 0
    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] primary interface for radio '%s' not found\n", __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#else
    interface = get_private_vap_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] private interface for radio '%s' not found\n", __func__, __LINE__, radio->name);
        return WIFI_HAL_ERROR;
    }
#endif

    pthread_mutex_lock(&interface->scan_state_mutex);

    if (interface->scan_state == WIFI_SCAN_STATE_ABORTED) {
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] Scan was aborted\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (interface->scan_state == WIFI_SCAN_STATE_ERROR) {
        interface->scan_state = WIFI_SCAN_STATE_NONE;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] Error happened during scan\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    /* If API scan results are available, return them regardless of scan_state */
    if (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_API)
        goto get_results;

    /* In test mode: If TEST scan results are available, return them regardless of scan_state */
    if (test_mode && (interface->scan_has_results & WIFI_SCAN_RES_COLLECTED_TEST))
        goto get_results;

    if (interface->scan_state == WIFI_SCAN_STATE_NONE) {
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan was not triggered\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (interface->scan_state == WIFI_SCAN_STATE_STARTED) {
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan is running, come later\n", __func__, __LINE__);
        errno = EAGAIN;
        return WIFI_HAL_NOT_READY;
    }

get_results:
    if (interface->scan_state == WIFI_SCAN_STATE_STARTED)
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan is running, but previous scan results are available\n", __func__, __LINE__);
    else
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] Scan results are available\n", __func__, __LINE__);

    pthread_mutex_lock(&interface->scan_info_ap_mutex);
    ret = copy_scan_results(interface, neighbor_ap_array, output_array_size);
    pthread_mutex_unlock(&interface->scan_info_ap_mutex);
    if (ret != RETURN_OK) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] copy_scan_results returned with error\n", __func__, __LINE__);
    }

    if (test_mode) {
        // - test mode: reset results only if scan is in progress;
        if (interface->scan_state == WIFI_SCAN_STATE_STARTED)
            interface->scan_has_results &= ~WIFI_SCAN_RES_COLLECTED_TEST;
    }
    else {
        // - reset results for normal API call
        interface->scan_has_results &= ~WIFI_SCAN_RES_COLLECTED_API;
    }

    pthread_mutex_unlock(&interface->scan_state_mutex);

    if (ret != RETURN_OK)
        return WIFI_HAL_ERROR;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] SCAN results are ready | output_array_size:%d\n", __func__, __LINE__, *output_array_size);
    return WIFI_HAL_SUCCESS;
}

INT wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return _wifi_hal_getNeighboringWiFiStatus(radioIndex, neighbor_ap_array, output_array_size, false);
}

/*
  - Special internal version of the wifi_hal_getNeighboringWiFiStatus() function for test purposes.
    This API does not clear the results of a previous scan and returns a filled table until a new scan is started.
    Needed by the wifi_api2 tool to avoid races with the OneWifi process.
*/
INT wifi_hal_getNeighboringWiFiStatus_test(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return _wifi_hal_getNeighboringWiFiStatus(radioIndex, neighbor_ap_array, output_array_size, true);
}

/*****************************/

void wifi_hal_register_frame_hook(wifi_hal_frame_hook_fn_t func)
{
    wifi_device_frame_hooks_t   *hooks;
    hooks = get_device_frame_hooks();
    hooks->frame_hooks_fn[hooks->num_hooks] = func;
    hooks->num_hooks++;
}

/* 802.11v BSS Transition Management APIs */

#define MAX_TOKENS             255

/* length: 13 for basic neighbor report + 3 for preference subelement */
#define NEI_LEN     (ETH_ALEN + 4 + 1 + 1 + 1 + 3)
#define NEIREP_LEN  (MAX_CANDIDATES * (2 + NEI_LEN))

static int build_candidates_list(const wifi_BTMRequest_t *request, u8 *nei_rep, size_t nei_rep_len)
{
    unsigned i;
    const wifi_NeighborReport_t *candidate;
    u8 *nei_pos = nei_rep;

    if (request->numCandidates >= MAX_CANDIDATES) {
        wifi_hal_error_print("%s:%d: [BTM] Wrong number of candidates (%u)\n", __func__, __LINE__, request->numCandidates);
        return -1;
    }

    for (i = 0, candidate = request->candidates; i < request->numCandidates; i++, candidate++)
    {
        u8 cand_pref;

        if (nei_pos + (2 + NEI_LEN) > nei_rep + nei_rep_len) {
            wifi_hal_error_print("%s:%d: [BTM] Not enough room for additional neighbor\n", __func__, __LINE__);
            return -1;
        }

    // - header: 2 bytes
        *nei_pos++ = WLAN_EID_NEIGHBOR_REPORT;
    // - length to be filled in
        *nei_pos++ = NEI_LEN;

    // - BSSID: 6 (ETH_ALEN) bytes
        os_memcpy(nei_pos, candidate->bssid, ETH_ALEN);
        nei_pos += ETH_ALEN;

    // - BSSID Information: 4 bytes
        WPA_PUT_LE32(nei_pos, candidate->info);
        nei_pos += 4;

    // - Operating Class: 1 byte
        *nei_pos++ = candidate->opClass;

    // - Channel Number: 1 byte
        *nei_pos++ = candidate->channel;

    // - PHY Type: 1 byte
        *nei_pos++ = candidate->phyTable;

    // - Priority: 3 bytes
        cand_pref = 255 - i;
        *nei_pos++ = WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE;
        *nei_pos++ = 1;
        *nei_pos++ = cand_pref;
    }

    return nei_pos - nei_rep;
}

/* See 9.6.14.9 BSS Transition Management Request.
   NOTE: peerMac expects MAC address in 6-byte binary format
*/
INT wifi_hal_setBTMRequest(UINT apIndex, mac_address_t peerMac, wifi_BTMRequest_t *request)
{
    wifi_interface_info_t *interface;
    u8 requestMode = request->requestMode;
    struct sta_info *sta = NULL;
    u8 bss_term_dur[12] = {0};
    char *url = NULL;
    int ret_token = -1;
    u8 *nei_rep = NULL;
    int nei_len = 0;

    // - verify input params
    if (_IS_INVALID_ARG(peerMac == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(request == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] BTM request: interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] BTM request: interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    // Get sta
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    sta = ap_get_sta(&interface->u.ap.hapd, peerMac);
    if (sta == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: [BTM] BTM request: station " MACSTR " not found for BSS TM Request message\n", __func__, __LINE__, MAC2STR(peerMac));
        return WIFI_HAL_ERROR;
    }

    /// - flag WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED:
    if (!request->termDuration.duration) {
        // - if no duration, remove flag WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED
        requestMode &= ~WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED;
    }

    if (requestMode & WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED) {
        bss_term_dur[0] = 4; /* Subelement ID */
        bss_term_dur[1] = 10; /* Length */
        WPA_PUT_LE64(&bss_term_dur[2], request->termDuration.tsf);
        WPA_PUT_LE16(&bss_term_dur[10], (short)request->termDuration.duration);
        wifi_hal_dbg_print("%s:%d: [BTM]  - WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED, tsf:0x%0lX, dur:%u\n", __func__, __LINE__,
            request->termDuration.tsf, request->termDuration.duration);
    }

    /// - candidates list:
    if (requestMode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
        nei_rep = (u8*) malloc(NEIREP_LEN);
        if (!nei_rep) {
            wifi_hal_error_print("%s:%d: [BTM] BTM request: Cannot allocate memory\n", __func__, __LINE__);
            goto exit;
        }
        nei_len = build_candidates_list(request, nei_rep, NEIREP_LEN);
        if (nei_len < 0) {
            wifi_hal_error_print("%s:%d: [BTM] BTM request: Cannot build candidates list\n", __func__, __LINE__);
            goto exit;
        }
        if (nei_len == 0) {
            requestMode &= ~WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED;
        }
    }

    // - after all checks:
    if (requestMode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
        wifi_hal_dbg_print("%s:%d: [BTM]  - WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED, nei_len=%d\n", __func__, __LINE__, nei_len);
    }

    /// - flag WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT:
    if (!request->urlLen || !request->url[0]) {
        // - if no URL specified, remove flag WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT
        requestMode &= ~WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT;
    }

    /// - url:
    if (requestMode & WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT) {
        url = (char*) malloc(request->urlLen + 1);
        if (url == NULL) {
            wifi_hal_error_print("%s:%d: [BTM] BTM request: Cannot allocate memory\n", __func__, __LINE__);
            goto exit;
        }
        wifi_strncpy(url, request->urlLen + 1, request->url, request->urlLen);
        wifi_hal_dbg_print("%s:%d: [BTM]  - WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT, url:'%s'\n", __func__, __LINE__, url);
    }

    // - interface->u.ap.hapd has to be locked by mutex g_wifi_hal.hapd_lock
    ret_token = wifi_wnm_send_bss_tm_req(interface, sta,
                request->token,
                requestMode,
                (int)request->timer,
                (int)request->validityInterval,
                bss_term_dur,
                url,
                nei_len ? nei_rep : NULL, nei_len,
                NULL, 0);

    /*
        if dialog_token (request->token) was specifed as 0, wnm_send_bss_tm_req() returns value based on interface->bss_transition_token.
        So, probably, need to update this field with the returned value:
    */
    wifi_hal_dbg_print("%s:%d: [BTM] ret_token: %d\n", __func__, __LINE__, ret_token);
    if ((ret_token > 0) && (request->token == 0)) {
        request->token = ret_token;
    }

exit:
    os_free(nei_rep);
    os_free(url);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return ret_token < 0 ? WIFI_HAL_ERROR : WIFI_HAL_SUCCESS;
}

//static uint8_t g_DialogToken[MAX_AP_INDEX][MAX_TOKENS + 1] = {{0}};
u8_bitmap g_DialogToken[MAX_AP_INDEX] = {{0}};

INT wifi_hal_setRMBeaconRequest(UINT apIndex,
                            mac_address_t peer_mac,
                            wifi_BeaconRequest_t *in_req,
                            UCHAR *out_DialogToken)
{
    wifi_interface_info_t *interface;
    struct wpa_ssid_value ssid = {0}, *ssid_p = NULL;
    u8 measurement_request_mode = 0, last_indication = 0;

    u8 rep_cond, rep_cond_threshold;
    u8* rep_cond_p = NULL, *rep_cond_threshold_p = NULL;
    u8 rep_detail;
    u8* rep_detail_p = NULL;
    u8* ap_ch_rep_p = NULL;
    unsigned int ap_ch_rep_len = 0;
    u8* req_elem_p = NULL;
    unsigned int req_elem_len = 0;
    u8 channel_width, channel_center_ch0, channel_center_ch1;
    u8 *channel_width_p = NULL, *channel_center_ch0_p = NULL, *channel_center_ch1_p = NULL;
    int ret_dialog_token;

    // - verify input params
    if (_IS_INVALID_ARG(peer_mac == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(in_req == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(out_DialogToken == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    // (1) peer_mac -> addr
    // (2) in_req->numRepetitions -> num_of_repetitions

    // (3)
    measurement_request_mode = 0;

    // (4) in_req->opClass -> op_class;
    // (5) in_req->channel -> channel;
    /* Quote from 80211-2016, Chapter 9.4.2.21.7 Beacon request:
    "For operating classes that encompass a primary channel but do not identify the location of the primary
    channel, the Channel Number field value is either 0 or 255; otherwise, the Channel Number field value is 0,
    255, or the channel number for which the measurement request applies and is defined within an operating
    class as shown in Annex E." */
    if (in_req->channel != 0 && in_req->channel != 255) {
        if (ieee80211_chan_to_freq(NULL, in_req->opClass, in_req->channel) < 0) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel/op_class combination invalid\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }
    }

    // (6) in_req->randomizationInterval -> random_interval
    // (7) in_req->duration -> measurement_duration
    // (8) in_req->mode -> mode
    if (in_req->mode > 2) {
        wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - mode is invalid\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    // (9) in_req->bssid -> bssid

    // (10)
    if (in_req->ssidPresent) {
        wifi_strncpy(ssid.ssid, sizeof(ssid.ssid), in_req->ssid, sizeof(in_req->ssid)-1);
        ssid.ssid_len = wifi_strnlen(ssid.ssid, sizeof(ssid.ssid)-1);
        ssid_p = &ssid;
    }

    // (11)
    if (in_req->beaconReportingPresent) {
        rep_cond = in_req->beaconReporting.condition;
        rep_cond_threshold = in_req->beaconReporting.threshold;
        rep_cond_p = &rep_cond;
        rep_cond_threshold_p = &rep_cond_threshold;
    }

    // (12)
    if (in_req->reportingRetailPresent) {
        rep_detail = in_req->reportingDetail;
        rep_detail_p = &rep_detail;
    }

    // (13)
    if (in_req->channelReportPresent) {
        ap_ch_rep_len = MAX_CHANNELS;
        ap_ch_rep_p = in_req->channelReport.channels;
    }

    // (14)
    if (in_req->requestedElementIDSPresent) {
        req_elem_len = MAX_REQUESTED_ELEMS;
        req_elem_p = in_req->requestedElementIDS.ids;
    }

    // (15)
    if (in_req->wideBandWidthChannelPresent) {
        channel_width = in_req->wideBandwidthChannel.bandwidth;
        channel_center_ch0 = in_req->wideBandwidthChannel.centerSeg0;
        channel_center_ch1 = in_req->wideBandwidthChannel.centerSeg1;

        if (/*channel_width < VHT_OPER_CHANWIDTH_20_40MHZ ||*/
            channel_width > VHT_OPER_CHANWIDTH_80P80MHZ) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel width is invalid\n", __func__, __LINE__);
            return WIFI_HAL_ERROR;
        }

        /* According to IEE80211-2016, Chapter 21.3.14 Channelization */
        if (ieee80211_chan_to_freq(NULL, in_req->opClass, channel_center_ch0) < 0) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel center frequency 0 is invalid\n", __func__, __LINE__);
        } else {
            channel_center_ch0_p = &channel_center_ch0;
        }

        if (ieee80211_chan_to_freq(NULL, in_req->opClass, channel_center_ch1) < 0) {
            wifi_hal_error_print("%s:%d: [BTM] REQ_BEACON - channel center frequency 1 is invalid\n", __func__, __LINE__);
        } else {
            channel_center_ch1_p = &channel_center_ch1;
        }

        channel_width_p = &channel_width;
    }

    // (16)
    if (in_req->extdRequestedElementIDSPresent) {
        // - extdRequestedElementIDS: not used by hostapd sources
    }

    // (17)
    if (in_req->vendorSpecificPresent) {
        // - vendorSpecific: not used by hostapd sources
    }

    // (18)
    // last_indication: used by hostapd function, but not specified by API
    last_indication = 0;

    wifi_hal_dbg_print("%s:%d: [BTM] Send beacon request...\n", __func__, __LINE__);
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    // - interface->u.ap.hapd has to be locked by mutex g_wifi_hal.hapd_lock
    ret_dialog_token = wifi_rrm_send_beacon_req(interface, peer_mac, in_req->numRepetitions,
            measurement_request_mode, in_req->opClass, in_req->channel, in_req->randomizationInterval,
            in_req->duration, in_req->mode, in_req->bssid,
            ssid_p, rep_cond_p, rep_cond_threshold_p, rep_detail_p,
            ap_ch_rep_p, ap_ch_rep_len,
            req_elem_p, req_elem_len,
            channel_width_p, channel_center_ch0_p, channel_center_ch1_p,
            last_indication);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    if (ret_dialog_token < 0) {
        wifi_hal_error_print("%s:%d: [BTM] Send beacon request failed!\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    *out_DialogToken = ret_dialog_token;
    //g_DialogToken[apIndex][*out_DialogToken] = 1;
    set_bit_u8(g_DialogToken[apIndex], *out_DialogToken);

    return WIFI_HAL_SUCCESS;
}

INT wifi_hal_cancelRMBeaconRequest(UINT apIndex, UCHAR dialogToken)
{
    // - verify input params
    if (_IS_INVALID_ARG(apIndex >= MAX_AP_INDEX)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    //g_DialogToken[apIndex][dialogToken] = 0;
    reset_bit_u8(g_DialogToken[apIndex], dialogToken);
    return WIFI_HAL_SUCCESS;
}

/* - Helper function for wifi_api2 to enable/configure Neighbor Reports */
INT wifi_hal_configNeighborReports(UINT apIndex, bool enable, bool auto_resp)
{
    struct hostapd_bss_config *conf;
    wifi_interface_info_t *interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] Cannot find interface with index %u\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface->vap_info.u.bss_info.nbrReportActivated = enable;
    interface->vap_info.u.bss_info.bssTransitionActivated = enable;

    // - protect interface->u.ap.conf with mutex
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    conf = &interface->u.ap.conf;
    conf->bss_transition = enable;
    if (enable) {
        conf->radio_measurements[0] |= WLAN_RRM_CAPS_NEIGHBOR_REPORT;
#ifdef CMXB7_PORT
        conf->radio_measurements[0] |= WLAN_RRM_CAPS_LINK_MEASUREMENT;
#endif
    }
    else {
         conf->radio_measurements[0] &= ~(WLAN_RRM_CAPS_NEIGHBOR_REPORT);
    }

#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
    conf->wnm_bss_trans_query_auto_resp = auto_resp;
#else
    interface->wnm_bss_trans_query_auto_resp = auto_resp;
#endif
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return RETURN_OK;
}

#if HOSTAPD_VERSION < 210
static inline void wpabuf_put_le64(struct wpabuf *buf, u64 data)
{
    u8 *pos = (u8 *) wpabuf_put(buf, 8);
    WPA_PUT_LE64(pos, data);
}
#endif // HOSTAPD_VERSION < 210

INT wifi_hal_setNeighborReports(UINT apIndex, UINT numNeighborReports, wifi_NeighborReport_t *neighborReports)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;
    struct wpa_ssid_value ssid;
    uint i;
    int ret = RETURN_ERR;

    // - verify input params
    if (_IS_INVALID_ARG(neighborReports == NULL)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    if (_IS_INVALID_ARG(numNeighborReports < 1)) {
        return WIFI_HAL_INVALID_ARGUMENTS;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: [BTM] interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: [BTM] interface with ap index:%u not in AP mode\n", __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;
    wifi_hal_dbg_print("%s:%d: [BTM] HAPD Interface name:%s\n", __func__, __LINE__, hapd->conf->iface);

    // - Clear the existing neighbor report database
    hostapd_free_neighbor_db(hapd);

    if (!(hapd->conf->radio_measurements[0] & WLAN_RRM_CAPS_NEIGHBOR_REPORT)) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: [BTM] Neighbor report is not enabled\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    for (i = 0; i < numNeighborReports; ++i)
    {
        struct wpabuf *nr = NULL;
        size_t sub_max_size;
        wifi_NeighborReport_t* rep = &neighborReports[i];
        // - 1: BBSID -> neighborReports[i].bssid

        // - 2: SSID -> neighborReports[i].target_ssid,
        wifi_strncpy(ssid.ssid, sizeof(ssid.ssid), rep->target_ssid, SSID_MAX_LEN-1);
        ssid.ssid_len = wifi_strnlen(ssid.ssid, SSID_MAX_LEN-1);

        // - 3: nr ->
        // * Neighbor Report element size nr = BSSID + BSSID info + op_class + chan + phy type + ...
        // * ... + wide bandwidth channel subelement.
        // BSSID    - 6 bytes -> bssid_t
        // info     - 4 bytes -> uint32_t
        // opClass  - 1 byte
        // channel  - 1 byte
        // phyTable - 1 byte ==> 13 bytes
        //
        // (OPTIONAL SUBELEMENTS):
        // - TSF Information:                      6 bytes
        // - Condensed Country String:             4 bytes
        // - wide bandwidth channel subelement:    5 bytes
        // - BSS Transition Candidate Preference:  3 bytes
        // - BSS Termination Duration:            12 bytes
        // - Bearing:                             10 bytes
        // - HT Capabilities subelement:          28 bytes
        // - VHT Capabilities subelement:         14 bytes
        // - HT Operations subelement:            24 bytes
        // - VHT Operations subelement:            7 bytes
        // - Secondary Channel Offset subelement:  3 bytes
        // - RM Enabled Capabilities:              7 bytes
        // - Measurement Pilot Transmission:       2 + (1 + (2 + (5 + MAX_VENDOR_SPECIFIC(32)))) bytes
        // - Vendor Specific:                      2 + (5 + MAX_VENDOR_SPECIFIC(32)) bytes
        sub_max_size = 6 + 4 + 5 + 3 + 12 + 10 + 28 + 14 + 24 + 7 + 3 + 7
               + 2 + (1 + (2 + (5 + MAX_VENDOR_SPECIFIC)))
               + 2 + (5 + MAX_VENDOR_SPECIFIC)
               + 10; // extra bytes for safety;

        nr = wpabuf_alloc(sizeof(bssid_t) + sizeof(uint32_t) + 1 + 1 + 1 + 5 + sub_max_size);
        if (!nr) {
            wifi_hal_error_print("%s:%d: [BTM] Cannot allocate wpa buffer\n", __func__, __LINE__);
            goto failure;
        }

        wpabuf_put_data(nr, rep->bssid, sizeof(bssid_t));
        wpabuf_put_le32(nr, rep->info);
        wpabuf_put_u8(nr, rep->opClass);
        wpabuf_put_u8(nr, rep->channel);
        wpabuf_put_u8(nr, rep->phyTable);

        /*
        * Wide Bandwidth Channel subelement may be needed to allow the
        * receiving STA to send packets to the AP. See IEEE P802.11-REVmc/D5.0
        * Figure 9-301.
        */
        // - wide bandwidth channel: 5 bytes
        if (rep->wideBandWidthChannelPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_WIDE_BW_CHAN);
            wpabuf_put_u8(nr, 3);
            wpabuf_put_u8(nr, rep->wideBandwidthChannel.bandwidth);
            wpabuf_put_u8(nr, rep->wideBandwidthChannel.centerSeg0);
            wpabuf_put_u8(nr, rep->wideBandwidthChannel.centerSeg1);
        }

        // - TSF Information: 6 bytes
        if (rep->tsfPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_TSF);
            wpabuf_put_u8(nr, 4);
            wpabuf_put_le16(nr, rep->tsfInfo.offset);
            wpabuf_put_le16(nr, rep->tsfInfo.interval);
        }

        // - Condensed Country String: 4 bytes
        if (rep->condensedCountrySringPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_CONDENSED_COUNTRY_STRING);
            wpabuf_put_u8(nr, 2);
            wpabuf_put_u8(nr, rep->condensedCountryStr.condensedStr[0]);
            wpabuf_put_u8(nr, rep->condensedCountryStr.condensedStr[1]);
        }

        // - BSS Transition Candidate Preference: 3 bytes
        if (rep->bssTransitionCandidatePreferencePresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE);
            wpabuf_put_u8(nr, 1);
            wpabuf_put_u8(nr, rep->bssTransitionCandidatePreference.preference);
        }

        // - BSS Termination Duration: 12 bytes
        if (rep->btmTerminationDurationPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_BSS_TERMINATION_DURATION);
            wpabuf_put_u8(nr, 10);
            wpabuf_put_le64(nr, rep->btmTerminationDuration.tsf);
            wpabuf_put_le16(nr, rep->btmTerminationDuration.duration);
        }

        // - Bearing: 10 bytes
        if (rep->bearingPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_BEARING);
            wpabuf_put_u8(nr, 8);
            wpabuf_put_le16(nr, rep->bearing.bearing);
            wpabuf_put_le32(nr, rep->bearing.dist);
            wpabuf_put_le16(nr, rep->bearing.height);
        }

        // - HT Capabilities subelement: 2+(2+1+16+2+4+1) => 2+26 => 28 bytes
        if (rep->htCapsPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_HT_CAPAB);
            wpabuf_put_u8(nr, 26);
            wpabuf_put_le16(nr, rep->htCaps.info);
            wpabuf_put_u8(nr, rep->htCaps.ampduParams);
            wpabuf_put_data(nr, rep->htCaps.mcs, sizeof(rep->htCaps.mcs));
            wpabuf_put_le16(nr, rep->htCaps.extended);
            wpabuf_put_le32(nr, rep->htCaps.txBeamCaps);
            wpabuf_put_u8(nr, rep->htCaps.aselCaps);
        }

        // - HT Operations subelement: 24 bytes
        if (rep->htOpPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_HT_OPER);
            wpabuf_put_u8(nr, 22);
            wpabuf_put_u8(nr, rep->htOp.primary);
            wpabuf_put_data(nr, rep->htOp.opInfo, sizeof(rep->htOp.opInfo));
            wpabuf_put_data(nr, rep->htOp.mcs, sizeof(rep->htOp.mcs));
        }

        // - VHT Capabilities subelement: 14 bytes
        if (rep->vhtCapsPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VHT_CAPAB);
            wpabuf_put_u8(nr, 12);
            wpabuf_put_le32(nr, rep->vbhtCaps.info);
            // The Supported VHT-MCS and NSS Set field is 64 bits long, but is broken
            // into 4 16 bit fields for convenience.
            wpabuf_put_le16(nr, rep->vbhtCaps.mcs);
            wpabuf_put_le16(nr, rep->vbhtCaps.rxHighestSupportedRate);
            wpabuf_put_le16(nr, rep->vbhtCaps.txVHTmcs);
            wpabuf_put_le16(nr, rep->vbhtCaps.txHighestSupportedRate);
        }

        // - VHT Operations subelement: 7 bytes
        if (rep->vhtOpPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VHT_OPER);
            wpabuf_put_u8(nr, 5);
            wpabuf_put_u8(nr, rep->vhtOp.opInfo.bandwidth);
            wpabuf_put_u8(nr, rep->vhtOp.opInfo.centerSeg0);
            wpabuf_put_u8(nr, rep->vhtOp.opInfo.centerSeg1);
            wpabuf_put_le16(nr, rep->vhtOp.mcs_nss);
        }

        // - Secondary Channel Offset subelement: 3 bytes
        if (rep->secondaryChannelOffsetPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_SEC_CHAN_OFFSET);
            wpabuf_put_u8(nr, 1);
            wpabuf_put_u8(nr, rep->secondaryChannelOffset.secondaryChOffset);
        }

        // - RM Enabled Capabilities: 7 bytes
        if (rep->rmEnabledCapsPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_RRM_ENABLED_CAPABILITIES);
            wpabuf_put_u8(nr, 5);
            wpabuf_put_data(nr, rep->rmEnabledCaps.capabilities, sizeof(rep->rmEnabledCaps.capabilities));
        }

#define WNM_NEIGHBOR_VENDOR_SPEC 221
        // - See 9.4.2.26
        // - Vendor Specific: 2 + (5 + MAX_VENDOR_SPECIFIC(32)) bytes
        if (rep->vendorSpecificPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VENDOR_SPEC);
            wpabuf_put_u8(nr, 5 + MAX_VENDOR_SPECIFIC);
            wpabuf_put_data(nr, rep->vendorSpecific.oui, sizeof(rep->vendorSpecific.oui));
            wpabuf_put_data(nr, rep->vendorSpecific.buff, sizeof(rep->vendorSpecific.buff));
        }

        // See 9.4.2.42, 9.4.3, 9.4.2.26
        // - Measurement Pilot Transmission:  2 + (1 + (2 + (5 + MAX_VENDOR_SPECIFIC(32)))) bytes
        if (rep->msmtPilotTransmissionPresent) {
            wpabuf_put_u8(nr, WNM_NEIGHBOR_MEASUREMENT_PILOT);
            wpabuf_put_u8(nr, rep->msmtPilotTransmission.pilot);
            // --- Vendor Specific subelement:
            wpabuf_put_u8(nr, WNM_NEIGHBOR_VENDOR_SPEC);
            wpabuf_put_u8(nr, 5 + MAX_VENDOR_SPECIFIC);
            wpabuf_put_data(nr, rep->msmtPilotTransmission.vendorSpecific.oui,
                sizeof(rep->msmtPilotTransmission.vendorSpecific.oui));
            wpabuf_put_data(nr, rep->msmtPilotTransmission.vendorSpecific.buff,
                sizeof(rep->msmtPilotTransmission.vendorSpecific.buff));
        }

#if HOSTAPD_VERSION >= 210 //2.10
        ret = hostapd_neighbor_set(hapd, rep->bssid, &ssid, nr, NULL, NULL, 0, 0);
#else
        ret = hostapd_neighbor_set(hapd, rep->bssid, &ssid, nr, NULL, NULL, 0);
#endif
        wpabuf_free(nr);
        if (ret)
            goto failure;
    }

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return WIFI_HAL_SUCCESS;

failure:
    hostapd_free_neighbor_db(hapd);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return WIFI_HAL_ERROR;
}

/*****************************/

INT wifi_hal_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback func)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }
    callbacks->mgmt_frame_rx_callback = func;

    return 0;
}

void wifi_hal_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_assoc_cbs > MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->assoc_cb[callbacks->num_assoc_cbs] = func;
    callbacks->num_assoc_cbs++;
}

void wifi_hal_apDeAuthEvent_callback_register(wifi_device_deauthenticated_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_apDeAuthEvent_cbs > MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->apDeAuthEvent_cb[callbacks->num_apDeAuthEvent_cbs] = func;
    callbacks->num_apDeAuthEvent_cbs++;
}

INT wifi_vapstatus_callback_register(wifi_vapstatus_callback func) {
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if(callbacks == NULL || callbacks->num_vapstatus_cbs > MAX_REGISTERED_CB_NUM) {
        return RETURN_ERR;
    }
    callbacks->vapstatus_cb[callbacks->num_vapstatus_cbs] = func;
    callbacks->num_vapstatus_cbs++;
    return RETURN_OK;
}

void wifi_hal_ap_max_client_rejection_callback_register(wifi_apMaxClientRejection_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL) {
        return;
    }

    callbacks->max_cli_rejection_cb = func;
}

void wifi_hal_apDisassociatedDevice_callback_register(wifi_device_disassociated_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_disassoc_cbs> MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->disassoc_cb[callbacks->num_disassoc_cbs] = func;
    callbacks->num_disassoc_cbs++;
}

void wifi_hal_stamode_callback_register(wifi_stamode_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_stamode_cbs> MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->stamode_cb[callbacks->num_stamode_cbs] = func;
    callbacks->num_stamode_cbs++;
}

void wifi_hal_apStatusCode_callback_register(wifi_apStatusCode_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_statuscode_cbs> MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->statuscode_cb[callbacks->num_statuscode_cbs] = func;
    callbacks->num_statuscode_cbs++;
}

void wifi_hal_radius_eap_failure_callback_register(wifi_radiusEapFailure_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_radius_eap_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }
    callbacks->radius_eap_cb[callbacks->num_radius_eap_cbs] = func;
    callbacks->num_radius_eap_cbs++;
}

void wifi_hal_radiusFallback_failover_callback_register(wifi_radiusFallback_failover_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_radius_fallback_failover_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->radius_failover_fallback_cbs[callbacks->num_radius_fallback_failover_cbs] = func;
    callbacks->num_radius_fallback_failover_cbs++;
}

void wifi_hal_staConnectionStatus_callback_register(wifi_staConnectionStatus_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->sta_conn_status_callback = func;

    return;
}

void wifi_hal_scanResults_callback_register(wifi_scanResults_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->scan_result_callback = func;

    return;
}

INT wifi_wpsEvent_callback_register(wifi_wpsEvent_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }

    callbacks->wps_event_callback = func;

    return RETURN_OK;
}

INT wifi_hal_analytics_callback_register(wifi_analytics_callback l_callback_cb)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
       return RETURN_ERR;
    }

    callbacks->analytics_callback = l_callback_cb;
    return RETURN_OK;
}

INT wifi_chan_event_register(wifi_chan_event_CB_t event_cb)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
       return RETURN_ERR;
    }

    callbacks->channel_change_event_callback = event_cb;
    return RETURN_OK;
}

#ifdef CMXB7_PORT
void wifi_csi_callback_register(wifi_csi_callback callback_proc)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->csi_callback = callback_proc;
}
#endif

INT wifi_hal_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }
    callbacks->steering_event_callback = event_cb;
#ifndef HAL_IPC
    wifi_steering_eventRegister(nl80211_steering_event);
#endif
    return 0;
}

INT wifi_hal_RMBeaconRequestCallbackUnregister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    if (beaconReportCallback != callbacks->bcnrpt_callback[apIndex])
        return RETURN_ERR;

    callbacks->bcnrpt_callback[apIndex] = NULL;
    return RETURN_OK;
}

INT wifi_hal_BTMQueryRequest_callback_register(UINT apIndex,
                                            wifi_BTMQueryRequest_callback btmQueryCallback,
                                            wifi_BTMResponse_callback btmResponseCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    callbacks->btm_callback[apIndex].query_callback = btmQueryCallback;
    callbacks->btm_callback[apIndex].response_callback = btmResponseCallback;
    return RETURN_OK;
}

INT wifi_hal_RMBeaconRequestCallbackRegister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (apIndex >= MAX_AP_INDEX)
        return RETURN_ERR;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL)
        return RETURN_ERR;

    if (NULL != callbacks->bcnrpt_callback[apIndex])
        return RETURN_ERR;

    callbacks->bcnrpt_callback[apIndex] = beaconReportCallback;
    return RETURN_OK;
}

wifi_device_callbacks_t *get_hal_device_callbacks()
{
    return &g_wifi_hal.device_callbacks;
}

wifi_device_frame_hooks_t *get_device_frame_hooks()
{
    return &g_wifi_hal.hooks;
}


int wifi_hal_send_mgmt_frame(int apIndex,mac_address_t sta, const unsigned char *data,size_t data_len,unsigned int freq, unsigned int wait)
{

    wifi_hal_dbg_print("%s:%d:Enter interface for ap index:%d\n", __func__, __LINE__, apIndex);
    wifi_interface_info_t *interface;
    u8 *buf;
    struct ieee80211_hdr *hdr;
    mac_address_t bssid_buf;
    int res = 0;
#ifdef HOSTAPD_2_11 // 2.11
    int link_id = 0;
#endif
    memset(bssid_buf, 0xff, sizeof(bssid_buf));
    
    buf = os_zalloc(24 + data_len);
    if (buf == NULL)
        return -1;
    os_memcpy(buf + 24, data, data_len);
    hdr = (struct ieee80211_hdr *) buf;
    hdr->frame_control =
        IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);

    if ((interface = get_interface_by_vap_index(apIndex)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
        os_free(buf);
        return -1;
    }
    os_memcpy(hdr->addr1, sta, ETH_ALEN);
    os_memcpy(hdr->addr2, interface->mac, ETH_ALEN);
    os_memcpy(hdr->addr3, bssid_buf, ETH_ALEN);

    
#ifdef HOSTAPD_2_11 // 2.11
    // Action frames will get rejected by kernel if we pass a valid link_id for non-MLO case.
    if(!wifi_hal_is_mld_enabled(interface)) {
        link_id = -1;
    }
    res = wifi_drv_send_mlme(interface, buf, 24 + data_len, 1, freq, NULL, 0, 0, wait, link_id);
#elif HOSTAPD_2_10 // 2.10
    res = wifi_drv_send_mlme(interface, buf, 24 + data_len, 1, freq, NULL, 0, 0, wait);
#else
    res = wifi_drv_send_mlme(interface, buf, 24 + data_len, 1, freq, NULL, 0);
#endif

    os_free(buf);
    wifi_hal_dbg_print("%s:%d:Exit for mgmt frame on AP (%d), IF (%d)\n", __func__, __LINE__, apIndex, interface->index);
    return res;
}

void wifi_hal_disassoc(int vap_index, int status, uint8_t *mac)
{
    u8 own_addr[ETH_ALEN];
    wifi_interface_info_t *interface = get_interface_by_vap_index(vap_index);
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    memcpy(own_addr, hapd->own_addr, ETH_ALEN);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

#if defined(BANANA_PI_PORT) && defined(KERNEL_6_6)
#if HOSTAPD_VERSION >= 211 && defined(CONFIG_GENERIC_MLO)
    int link_id = wifi_hal_get_mld_link_id(interface);
#else
    int link_id = NL80211_DRV_LINK_ID_NA;
#endif // HOSTAPD_VERSION >= 211 && CONFIG_GENERIC_MLO
    wifi_drv_sta_disassoc(interface, own_addr, mac, status, link_id);
#else
    wifi_drv_sta_disassoc(interface, own_addr, mac, status);
#endif // BANANA_PI_PORT && KERNEL_6_6
}

void wifi_hal_set_neighbor_report(uint apIndex,uint add,mac_address_t mac)
{
    platform_set_neighbor_report_t platform_set_neighbor_report_fn;
    if ((platform_set_neighbor_report_fn = get_platform_set_neighbor_report_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platform set_neighbor_repor\n", __func__, __LINE__);
        platform_set_neighbor_report_fn(apIndex,add,mac);
    }
}

INT wifi_hal_getRadioTemperature(wifi_radio_index_t radioIndex,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    platform_get_radio_phytemperature_t get_radio_phytemperature_fn;

    get_radio_phytemperature_fn = get_platform_get_radio_phytemperature_fn();
    if (get_radio_phytemperature_fn == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get phytemperature platfrom cb\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    if (get_radio_phytemperature_fn(radioIndex, radioPhyTemperature) < 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to get radio temperature\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_stats_dbg_print("%s:%d Temperature is %u\n", __func__, __LINE__, radioPhyTemperature->radio_Temperature);
    return RETURN_OK;
}

bool is_db_upgrade_required(char* inactive_firmware)
{
#ifdef TCHCBRV2_PORT
    char *firmware_version = NULL, *saveptr = NULL;
    float sw_version = 0.0;
    FILE *fp2 = NULL, *fp = NULL;
    wifi_hal_info_print("%s Inactive firmware is %s\n",__func__, inactive_firmware);

    if (strstr(inactive_firmware,"sprint") || strstr(inactive_firmware,"stable2")) {
        wifi_hal_info_print("%s Firmware is sprint or stable2\n",__func__);
        return false;
    } else {
        firmware_version = strtok_r(inactive_firmware, "_", &saveptr);
        firmware_version = strtok_r(NULL, "_", &saveptr);
        wifi_hal_info_print("%s Firmware version is %s \n",__func__, firmware_version);

        if (firmware_version != NULL) {
            if ((strncmp(firmware_version, "PROD", strlen("PROD")) == 0) || (strncmp(firmware_version, "DEV", strlen("DEV")) == 0)) {
                firmware_version = strtok_r(NULL, "_", &saveptr);
                wifi_hal_info_print("%s Image is %s\n",__func__,firmware_version);
            } else {
                wifi_hal_info_print("%s Image is %s \n",__func__, firmware_version);
            }
            sw_version = strtof(firmware_version, NULL);
            wifi_hal_info_print("%s Value of sw_version is %f \n",__func__, sw_version);
            if ((sw_version <= 6.7) && (sw_version > 0)) {
                wifi_hal_info_print("%s Software version is 6.7 or less than that\n",__func__);
                fp2 = fopen("/nvram/wifi_db_update_required", "a");
                if (fp2 != NULL) {
                    fclose(fp2);
                }
                fp = fopen("/tmp/db_update_required", "a");
                if (fp != NULL) {
                    fclose(fp);
                }
                return true;
            } else {
                wifi_hal_info_print("%s Software version is %f \n",__func__, sw_version);
                return false;
            }
        }
   }
    return true;
#endif
    return false;
}

int wifi_hal_setApMacAddressControlMode(uint32_t apIndex, uint32_t mac_filter_mode)
{
    wifi_interface_info_t *interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: WiFi interface not found for vap:%d\n", __func__, __LINE__,
            apIndex);
        return RETURN_ERR;
    }

    wifi_vap_info_t *vap;
    vap = &interface->vap_info;
    if (vap == NULL) {
        wifi_hal_error_print("%s:%d: WiFi interface not found for vap:%d\n", __func__, __LINE__,
            apIndex);
        return RETURN_ERR;
    }

    if (vap->u.bss_info.enabled != true || vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print(":%s:%d bss not enabled:%d for vap:%d\n", __func__, __LINE__,
            vap->u.bss_info.enabled, vap->vap_index);
        return RETURN_ERR;
    }

    switch (mac_filter_mode) {
    case 2:
        vap->u.bss_info.mac_filter_enable = true;
        vap->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;
        break;

    case 1:
        vap->u.bss_info.mac_filter_enable = true;
        vap->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
        break;

    case 0:
        vap->u.bss_info.mac_filter_enable = false;
        break;

    default:
        wifi_hal_error_print(":%s:%d Wrong Mac mode %d\n", __func__, __LINE__, mac_filter_mode);
        return RETURN_ERR;
    }

    return (nl80211_set_acl(interface));
}

int wifi_hal_add_station_bridge( char *interface_name,char *bridge_name)
{
    nl80211_remove_from_bridge(interface_name);
    if (nl80211_create_bridge(interface_name, bridge_name) != 0) {
        wifi_hal_error_print("%s:%d: Interface:%s failed to create bridge:%s\n",
            __func__, __LINE__, interface_name, bridge_name);
        return RETURN_ERR;
    }
    return 0;
}

int steering_set_acl_mode(uint32_t apIndex, uint32_t mac_filter_mode)
{
    wifi_vap_info_t *vap;
    wifi_interface_info_t *interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: WiFi interface not found for vap:%d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: sta vap:%d does not support this\n", __func__, __LINE__, vap->vap_index);
        return RETURN_ERR;
    }

    if (vap->u.bss_info.mac_filter_enable == true) {
        if (vap->u.bss_info.mac_filter_mode != wifi_mac_filter_mode_black_list) {
            wifi_hal_error_print("%s:%d: user configured mac filter mode:%d for vap:%d\n", __func__, __LINE__,
                                        vap->u.bss_info.mac_filter_mode, apIndex);
            return RETURN_ERR;
        } else if (vap->u.bss_info.mac_filter_mode == mac_filter_mode) {
            wifi_hal_error_print(":%s:%d mac filtermode is already set for vap:%d\n", __func__, __LINE__, vap->vap_index);
            return RETURN_OK;
        }
    } else {
        wifi_hal_info_print("%s:%d: force enable mac mode for vap:%d\n", __func__, __LINE__, apIndex);
        vap->u.bss_info.mac_filter_enable = true;
    }

    vap->u.bss_info.mac_filter_mode = mac_filter_mode;
    return (nl80211_set_acl(interface));
}

INT wifi_hal_get_RegDomain(wifi_radio_index_t radioIndex, UINT *reg_domain)
{
    platform_get_RegDomain_t platform_get_RegDomain_fn;
    if ((platform_get_RegDomain_fn = get_platform_get_RegDomain_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: Get RegDomain \n", __func__, __LINE__);
        return (platform_get_RegDomain_fn(radioIndex, reg_domain));
    }
    return RETURN_ERR;
}
