 /*****************************************************************************
  If not stated otherwise in this file or this component's LICENSE     
  file the following copyright and licenses apply:                          
                                                                            
  Copyright 2020 RDK Management                                             
                                                                            
  Licensed under the Apache License, Version 2.0 (the "License");           
  you may not use this file except in compliance with the License.          
  You may obtain a copy of the License at                                   
                                                                            
      http://www.apache.org/licenses/LICENSE-2.0                            
                                                                            
  Unless required by applicable law or agreed to in writing, software       
  distributed under the License is distributed on an "AS IS" BASIS,         
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
  See the License for the specific language governing permissions and       
  limitations under the License.                                            
                                                                            
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "collection.h"
#include "log.h"
#include "wifi_hal.h"
#include "wifi_8021x.h"
#include "wifi_util.h"
#if 0
static void to_mac_bytes   (mac_addr_str_t key, mac_address_t bmac) {
   unsigned int mac[6];
    sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
             &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
   bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
   bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}
#endif

void process_eap_data(wifi_8021x_data_t *data, wifi_8021x_t *module, bool new_event)
{
    wifi_eap_frame_t *eap, *prev_eap;
    wifi_8021x_data_t *prev_data;
    mac_addr_str_t mac_str;
    char direction[32], msg[32];
    struct timeval tnow;

    gettimeofday(&tnow, NULL);

    eap = (wifi_eap_frame_t *)data->data;

    to_mac_str(data->mac, mac_str);
    str_tolower(mac_str);

    if (new_event == false) {
        // this is an existing data, call originated from timeout
        if ((tnow.tv_sec - data->packet_time.tv_sec) > 2) {
            if ((eap->code == wifi_eap_code_request) || (eap->code == wifi_eap_code_response)) {
                module->bssid[data->vap].eap_timeout++;
            }

            wifi_util_dbg_print(WIFI_MON, "%s:%d: Removing from hash and deleting\n", __func__, __LINE__);
            hash_map_remove(module->bssid[data->vap].sta_map, mac_str);
            if (data->data != NULL)
                free(data->data);
            if (data != NULL)
                free(data);
        }

        return;
    }
    prev_data = hash_map_get(module->bssid[data->vap].sta_map, mac_str);

    // if this is an eap success or failure
    if (eap->code == wifi_eap_code_success) {
        module->bssid[data->vap].eap_success++;
        if (prev_data != NULL) {
            hash_map_remove(module->bssid[data->vap].sta_map, mac_str);
            free(prev_data->data);
            free(prev_data);
        }
        return;
    } else if (eap->code == wifi_eap_code_success) {
        module->bssid[data->vap].eap_failure++;
        if (prev_data != NULL) {
            hash_map_remove(module->bssid[data->vap].sta_map, mac_str);
            free(prev_data->data);
            free(prev_data);
        }
        return;

    } else if ((eap->code == wifi_eap_code_request) || (eap->code == wifi_eap_code_response)) {
        if (prev_data != NULL) {
            if (prev_data->type == wifi_eapol_type_eap_packet) {
                if (prev_data->dir == data->dir) {

                    prev_eap = (wifi_eap_frame_t *)prev_data->data;
                    if ((prev_eap->code == eap->code) && (prev_eap->id == eap->id)) {
                        module->bssid[data->vap].eap_retries++;
                    }
                }
                hash_map_remove(module->bssid[data->vap].sta_map, mac_str);
                free(prev_data->data);
                free(prev_data);
            }

        }

        gettimeofday(&data->packet_time, NULL);
        hash_map_put(module->bssid[data->vap].sta_map, strdup(mac_str), data);
    }

    if (data->dir == wifi_direction_unknown) {
        strcpy(direction, "unknown");
    } else if (data->dir == wifi_direction_uplink) {
        strcpy(direction, "uplink");
    } else if (data->dir == wifi_direction_downlink) {
        strcpy(direction, "downlink");
    }

    if (eap->code == wifi_eap_code_request) {
        strcpy(msg, "request");
    } else if (eap->code == wifi_eap_code_response) {
       strcpy(msg, "response");
    } else if (eap->code == wifi_eap_code_success) {
       strcpy(msg, "success");
    } else if (eap->code == wifi_eap_code_failure) {
       strcpy(msg, "failure");
    }

    wifi_util_dbg_print(WIFI_MON, "%s:%d: Received eap %s  id:%d diretion:%s\n", __func__, __LINE__, msg, eap->id, direction);
}

void process_assoc_req_packet(wifi_assoc_req_data_t *assoc_data, wifi_8021x_t *module)
{
    UNREFERENCED_PARAMETER(module);
    free(assoc_data->data);
}

void process_assoc_rsp_packet(wifi_assoc_rsp_data_t *assoc_data, wifi_8021x_t *module)
{
    UNREFERENCED_PARAMETER(module);
    free(assoc_data->data);
}

void process_auth_packet(wifi_auth_data_t *auth_data, wifi_8021x_t *module)
{
    UNREFERENCED_PARAMETER(module);
    free(auth_data->data);
}

void process_8021x_packet(wifi_8021x_data_t *data, wifi_8021x_t *module)
{
    switch (data->type) {
        case wifi_eapol_type_eap_packet:
            wifi_util_dbg_print(WIFI_MON, "%s:%d: wifi_eapol_type_eap_packet:\n", __func__, __LINE__);
            process_eap_data(data, module, true);
            break;

        case wifi_eapol_type_eapol_start:
            wifi_util_dbg_print(WIFI_MON, "%s:%d: EAPOL_start:\n", __func__, __LINE__);
            break;

        case wifi_eapol_type_eapol_logoff:
            break;

        case wifi_eapol_type_eapol_key:
            wifi_util_dbg_print(WIFI_MON, "%s:%d  wifi_eapol_type_eapol_key:\n", __func__, __LINE__);
            break;
    }

}

void process_8021x_data_timeout(wifi_8021x_t *module)
{
    wifi_8021x_data_t *data, *tmp;
    unsigned int i;
#ifdef WIFI_HAL_VERSION_3
    for (i = 0; i < (UINT)getTotalNumberVAPs(); i++) {
#else
    for (i = 0; i < MAX_VAP; i++) {
#endif
        data = hash_map_get_first(module->bssid[i].sta_map);

        while (data != NULL) {
            tmp = data;
            data = hash_map_get_next(module->bssid[i].sta_map, data);

    
            switch (tmp->type) {
            case wifi_eapol_type_eap_packet:
                wifi_util_dbg_print(WIFI_MON, "%s:%d:   wifi_eapol_type_eap_packet:\n", __func__, __LINE__);
                process_eap_data(tmp, module, false);
                break;

            case wifi_eapol_type_eapol_start:
                wifi_util_dbg_print(WIFI_MON, "%s:%d:   wifi_eapol_type_eapol_start:\n", __func__, __LINE__);
                break;

            case wifi_eapol_type_eapol_logoff:
                wifi_util_dbg_print(WIFI_MON, "%s:%d:   wifi_eapol_type_eapol_logoff:\n", __func__, __LINE__);
                break;

            case wifi_eapol_type_eapol_key:
                wifi_util_dbg_print(WIFI_MON, "%s:%d:   wifi_eapol_type_eapol_key: \n", __func__, __LINE__);
                break;
            }

        }

        if (i == 0) {
            wifi_util_dbg_print(WIFI_MON, "%s:%d: Objects:%d \n \
                EAP Success:%d EAP Failures:%d EAP Timeouts:%d EAP Retries:%d\n \
                WPA Msg 1 of 4:%d WPA Msg 2 of 4:%d WPA Msg 3 of 4:%d WPA Msg 4 of 4:%d\n \
                WPA Success:%d WPA Failures:%d\n", __func__, __LINE__,
            hash_map_count(module->bssid[i].sta_map), module->bssid[i].eap_success, module->bssid[i].eap_failure,
                module->bssid[i].eap_timeout, module->bssid[i].eap_retries,
                module->bssid[i].wpa_msg_1_of_4, module->bssid[i].wpa_msg_2_of_4, module->bssid[i].wpa_msg_3_of_4, module->bssid[i].wpa_msg_4_of_4,
                module->bssid[i].wpa_success, module->bssid[i].wpa_failure);
        }
    }
}

void deinit_8021x(wifi_8021x_t *module)
{
    unsigned int i;
    wifi_8021x_data_t *sta_data, *temp_sta_data;
    char key[64] = {0};

#ifdef WIFI_HAL_VERSION_3
    for (i = 0; i < (UINT)getTotalNumberVAPs(); i++) {
#else
    for (i = 0; i < MAX_VAP; i++) {
#endif
        if (module->bssid[i].sta_map != NULL) {
            sta_data = hash_map_get_first(module->bssid[i].sta_map);
            while (sta_data != NULL) {
                memset(key, 0, sizeof(key));
                snprintf(key, sizeof(key), "%s", sta_data->mac);
                sta_data = hash_map_get_next(module->bssid[i].sta_map, sta_data);
                temp_sta_data = hash_map_remove(module->bssid[i].sta_map, key);
                if (temp_sta_data != NULL) {
                    free(temp_sta_data);
                }
            }
            hash_map_destroy(module->bssid[i].sta_map);
        }
    }
}

int init_8021x(wifi_8021x_t *module)
{
       unsigned int i;
#ifdef WIFI_HAL_VERSION_3
        for (i = 0; i < (UINT) getTotalNumberVAPs(); i++) {
#else
        for (i = 0; i < MAX_VAP; i++) {
#endif               
            module->bssid[i].sta_map = hash_map_create();
       }

       return 0;
}

