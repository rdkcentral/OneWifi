/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
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

#include <stdio.h>
#include <stdbool.h>
#include "ansc_platform.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_hal_sta.h"
    
wifi_hal_capability_t g_hal_cap;

int factory_reset()
{
    return 0;
}

#if defined (FEATURE_SUPPORT_INTERWORKING)
void CosaDmlWiFiPsmDelInterworkingEntry()
{
#if 0
    char recName[256];
    char strValue[1024] = {0};
    int apIns;

    for (apIns = 1; apIns <= 16; apIns++) {

        memset(recName, 0, 256);
        snprintf(recName, sizeof(recName), InterworkingServiceCapability, apIns);
        if (get_record_value(recName, ccsp_string, strValue, sizeof(strValue)) == 0) {
            del_record(recName);

            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), InterworkingServiceEnable, apIns);
            del_record(recName);

            //ASRA
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), InterworkingASRAEnable, apIns);
            del_record(recName);

            //InternetAvailable
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), SetInterworkingInternetAvailable, apIns);
            del_record(recName);

            //VenueOption Present
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), SetInterworkingVenueOptionPresent, apIns);
            del_record(recName);

            //ESR
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), InterworkingESREnable, apIns);
            del_record(recName);

            //UESA
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), InterworkingUESAEnable, apIns);
            del_record(recName);

            //HESSOptionPresent
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), SetInterworkingHESSID, apIns);
            del_record(recName);
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), InterworkingHESSOptionPresentEnable, apIns);
            del_record(recName);

            //AccessNetworkType
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), InterworkingAccessNetworkType, apIns);
            del_record(recName);

           //VenueGroup
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), SetInterworkingVenueGroup, apIns);
            del_record(recName);

            //VenueType
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), SetInterworkingVenueType, apIns);
            del_record(recName);

            //GAS PauseForServerResponse
            memset(recName, 0, 256);
            snprintf(recName, sizeof(recName), "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_GASConfiguration.1.PauseForServerResponse", apIns);
            del_record(recName);
        }
    }
#endif
}

#endif // FEATURE_SUPPORT_INTERWORKING
/* Copyright (c) 2003-2014, Jouni Malinen j@w1.fi
   Licensed under the BSD-3 License */


static int hex2num(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}


int hex2byte(const char *hex)
{
    int a, b;
    a = hex2num(*hex++);

    if (a < 0) {
        return -1;
    }

    b = hex2num(*hex++);

    if (b < 0) {
        return -1;
    }

    return (a << 4) | b;
}


static const char * hwaddr_parse(const char *txt, unsigned char *addr)
{
    size_t i;

    for (i = 0; i < 6; i++) {
        int a;

        a = hex2byte(txt);

        if (a < 0) {
            return NULL;
        }

        txt += 2;
        addr[i] = a;

        if (i < 6 - 1 && *txt++ != ':') {
            return NULL;
        }
    }

    return txt;
}

static int hwaddr_aton(const char *txt, unsigned char *addr)
{
    return hwaddr_parse(txt, addr) ? 0 : -1;
}

int start_wifi_ctrl(wifi_ctrl_t *ctrl, int argc, char *argv[])
{
    bool factoryResetFlag = false;
    wifi_vap_info_map_t map;
    wifi_radio_operationParam_t radio_param;
    int c, i;
    wifi_bss_info_t bss;
    char password[256];
    char ssid[256];
    bssid_t bss_mac;

    for (;;) {
        c = getopt(argc, argv, "b:s:p:f:");

        if (c < 0) {
            break;
        }

        switch (c) {
        case 'b':
            if (hwaddr_aton(optarg, bss_mac) < 0) {
                printf("Failed to parse bssid\n");
                return 0;
            }
            memcpy(bss.bssid, bss_mac, sizeof(mac_address_t));
            break;
        case 's':
            strcpy(bss.ssid, optarg);
            strcpy(ssid, optarg);
            break;
        case 'p':
            strcpy(password, optarg);
            break;
        case 'f':
            bss.freq = atoi(optarg);
            break;
        default:
            printf("Usage: wifi_ctrl -b <BSSID>('01:02:03:04:05:06') -s <SSID>('test_ssid') -p <password>('test_pass') -f <frequency>('2437')");
            break;
        }
    }

    ovsdb_get_factory_reset_data(&factoryResetFlag);
    if (factoryResetFlag) {
        factory_reset();
        ovsdb_set_factory_reset_data(false);
    }

    if (wifi_hal_init() != RETURN_OK) {
        return -1;
    }
    
    if (wifi_hal_getHalCapability(&g_hal_cap) != RETURN_OK) {
        return -1;
    }

    ovsdb_get_radio_params(0, &radio_param); 
    if (wifi_hal_setRadioOperatingParameters(0, &radio_param) != RETURN_OK) {
        return 0;
    }

    memset((unsigned char *)&map, 0, sizeof(wifi_vap_info_map_t));

    ovsdb_get_vap_info_map(0, 0, &map);
    ovsdb_get_vap_info_map(0, 1, &map);
    ovsdb_get_vap_info_map(0, 2, &map);

    strcpy(map.vap_array[0].u.sta_info.security.u.key.key, password);
    strcpy(map.vap_array[0].u.sta_info.ssid, ssid);

    wifi_hal_createVAP(0, &map);

    for (i = 0; i < MAX_NUM_RADIOS; i++) {
	if (wifi_hal_startScan(i, WIFI_RADIO_SCAN_MODE_ONCHAN, 0, 0, NULL) == RETURN_OK) {
    	    printf("%s:%d: start scan success\n", __func__, __LINE__);
	}
    }

    sleep(10);

    printf("\n\n%s:%d:connecting ... %s %s %d\n\n", __func__, __LINE__, bss.ssid, password, bss.freq);

    wifi_hal_connect(14, &bss);

    //wifi_authenticator_run();

    while (1) {
        sleep(10);
    }

    return 0;
}
