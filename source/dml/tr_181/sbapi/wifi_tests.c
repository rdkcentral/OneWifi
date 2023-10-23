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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_monitor.h"
#include "wifi_tests.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include "ansc_status.h"
#include <sys/prctl.h>

unsigned char           sim_mac_base = 0x55;
wifi_tests_simulator_t   g_simulator = {0};
void *wifi_connections_listener    (void *arg);

void *simulate_connect_disconnect(void *data);

int CosaDmlWiFi_GetGoodRssiThresholdValue(int *rssi)
{
    *rssi = -65;
    return ANSC_STATUS_SUCCESS;
}

int CosaDmlWiFi_GetRapidReconnectThresholdValue(int *rapid_reconnect)
{
    *rapid_reconnect = 300;
    return ANSC_STATUS_SUCCESS;
}

void wifi_apAssociatedDevice_callback_register(device_associated func)
{
    g_simulator.cb[wifi_hal_cb_connect].func = func;
}

void wifi_apAuthEvent_callback_register(device_deauthenticated func)
{
    g_simulator.cb[wifi_hal_cb_deauth].func = func;
}

void wifi_apDisassociatedDevice_callback_register(device_disassociated func)
{
    g_simulator.cb[wifi_hal_cb_disconnect].func = func;
}

int wifi_getApAssociatedDeviceDiagnosticResult(int apIndex, wifi_associated_dev_t **associated_dev_array, unsigned int *output_array_size)
{
    unsigned int i, total = 0;
	wifi_associated_dev_t *assoc;
    simulator_state_t   *sim;

    if (g_simulator.started == false) {
        *output_array_size = 0;
        *associated_dev_array = NULL;
        return RETURN_ERR;
    }
    
    if (apIndex == 1) {
        *output_array_size = 0;
        *associated_dev_array = NULL;
        return RETURN_ERR;
    }

	*associated_dev_array = (wifi_associated_dev_t *)malloc(SIM_NUMBER*sizeof(wifi_associated_dev_t));

	assoc = *associated_dev_array;
    
    pthread_mutex_lock(&g_simulator.lock);
    total = 0;
	for (i = 0; i < SIM_NUMBER; i++) {
        sim = &g_simulator.simulator[i];
        if (sim->connected == true) {
            memcpy(assoc->cli_MACAddress, sim->sta_mac, sizeof(mac_addr_t));
            assoc->cli_RSSI = sim->rssi;
            assoc++;
            total++;
        }
	}
    *output_array_size = total;
    
    pthread_mutex_unlock(&g_simulator.lock);
    
    return RETURN_OK;
}

int start_simulator    ()
{
    unsigned int i;
    simulator_state_t   *sim;
    pthread_condattr_t cond_attr;
    
    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&g_simulator.cond, &cond_attr);
    pthread_condattr_destroy(&cond_attr);
    pthread_mutex_init(&g_simulator.lock, NULL);
    
    for (i = 0; i < SIM_NUMBER; i++) {
        sim = &g_simulator.simulator[i];
        sim->sta_mac[0] = 0x00; sim->sta_mac[1] = 0x11; sim->sta_mac[2] = 0x22;
        sim->sta_mac[3] = 0x33; sim->sta_mac[4] = 0x44; sim->sta_mac[5] = sim_mac_base++;
        sim->rssi = SIM_RSSI_HIGH;
        sim->connected = false;
        
        if (i == 0) {
            sim->update = true;
        } else {
            sim->update = false;
        }
    }
    
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;

    attrp = &attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED ); 
    if (pthread_create(&g_simulator.sim_id, attrp, simulate_connect_disconnect, &g_simulator) != 0) {
        if(attrp != NULL)
            pthread_attr_destroy( attrp );
        wifi_util_dbg_print(WIFI_MON, "Error creating run thread\n");
        return -1;
    }
    
    if (pthread_create(&g_simulator.cb_id, attrp, wifi_connections_listener, &g_simulator) != 0) {
        if(attrp != NULL)
            pthread_attr_destroy( attrp );
        wifi_util_dbg_print(WIFI_MON, "monitor thread create error\n");
        return -1;
    }
    if(attrp != NULL)
        pthread_attr_destroy( attrp );
    g_simulator.started = true;
    return 0;
}

bool get_simulator_buffer   (simulator_state_t   *sim, char *buffer)
{
    bool send = false;
    static bool deauthed = true;
    char tmp[64];
    
    sim->rssi -= 5;
    
    if ((sim->rssi < SIM_RSSI_CONNECTED_THRESH) && (sim->connected == true)) {
        // disconnect or deauth
        if (deauthed) {
            strcpy(tmp, "LEAVE");
            deauthed = false;
        } else {
            strcpy(tmp, "DEAUTH");
            deauthed = true;
        }
        sprintf(buffer, "RDKB_WIFI_NOTIFY: ssid0 %s: 0 %02x:%02x:%02x:%02x:%02x:%02x 0", tmp,
                sim->sta_mac[0], sim->sta_mac[1], sim->sta_mac[2],
                sim->sta_mac[3], sim->sta_mac[4], sim->sta_mac[5]);
        sim->connected = false;
        send = true;
    } else if ((sim->rssi > SIM_RSSI_CONNECTED_THRESH) && (sim->connected == false)) {
        sprintf(buffer, "RDKB_WIFI_NOTIFY: ssid0 JOIN: 0 %02x:%02x:%02x:%02x:%02x:%02x 1",
                sim->sta_mac[0], sim->sta_mac[1], sim->sta_mac[2],
                sim->sta_mac[3], sim->sta_mac[4], sim->sta_mac[5]);
        sim->connected = true;
        send = true;
    }
    
    if (sim->rssi <= SIM_RSSI_LOW) {
        sim->rssi = SIM_RSSI_HIGH;
    }
    
    return send;
}

simulator_state_t *get_simulator_to_update()
{
    unsigned int i;
    simulator_state_t   *sim = NULL;
    
    for (i = 0; i < SIM_NUMBER; i++) {
        sim = &g_simulator.simulator[i];
        if (sim->update == true) {
            break;
        }
    }
    
    if (i == (SIM_NUMBER - 1)) {
        i = 0;
    } else {
        i++;
    }
    
    sim->update = false;
    g_simulator.simulator[i].update = true;
    
    return sim;
}

void *simulate_connect_disconnect(void *data)
{
    int fd;
    bool ret;
    struct sockaddr_un name;
    struct timespec time_to_wait;
    struct timespec tv;
    simulator_state_t   *state;
    wifi_tests_simulator_t *sim = (wifi_tests_simulator_t *)data;
    char buffer[256];

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);
    
    fd = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (fd < 0) {
        return NULL;
    }
    
    /* Bind a name to the socket. */
    name.sun_family = AF_LOCAL;
    strncpy (name.sun_path, KMSG_WRAPPER_FILE_NAME, sizeof(name.sun_path));
    name.sun_path[sizeof (name.sun_path) - 1] = '\0';
    
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &tv);
        time_to_wait.tv_nsec = 0;
        time_to_wait.tv_sec = tv.tv_sec + SIM_LOOP_TIMEOUT;
        pthread_mutex_lock(&sim->lock);
        pthread_cond_timedwait(&sim->cond, &sim->lock, &time_to_wait);
        state = get_simulator_to_update();
        ret = get_simulator_buffer(state, buffer);
        pthread_mutex_unlock(&sim->lock);
        if (ret == true) {
            sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr *)&name, sizeof(struct sockaddr_un));
        }
        
    }
    
    close(fd);
    
    return NULL;
}

void device_associated_states   (char *buff, ssize_t size)
{
    unsigned int ap_index, reason, vap, mac[6];
    mac_addr_t sta_mac;
    wifi_associated_dev_t dev;
    
    if (strstr(buff, "JOIN") != NULL) {
        sscanf(buff, "RDKB_WIFI_NOTIFY: ssid%d JOIN: %d %02x:%02x:%02x:%02x:%02x:%02x %d",
               &ap_index, &vap,
               (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2],
               (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5],
               &reason);
        sta_mac[0] = mac[0]; sta_mac[1] = mac[1]; sta_mac[2] = mac[2];
        sta_mac[3] = mac[3]; sta_mac[4] = mac[4]; sta_mac[5] = mac[5];
        memcpy(dev.cli_MACAddress, sta_mac, sizeof(mac_addr_t));
        ((device_associated)g_simulator.cb[wifi_hal_cb_connect].func)(ap_index, &dev, reason);
        
    } else if (strstr(buff, "LEAVE") != NULL) {
        sscanf(buff, "RDKB_WIFI_NOTIFY: ssid%d LEAVE: %d %02x:%02x:%02x:%02x:%02x:%02x %d",
               &ap_index, &vap,
               (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2],
               (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5],
               &reason);
        sta_mac[0] = mac[0]; sta_mac[1] = mac[1]; sta_mac[2] = mac[2];
        sta_mac[3] = mac[3]; sta_mac[4] = mac[4]; sta_mac[5] = mac[5];
        ((device_disassociated)g_simulator.cb[wifi_hal_cb_disconnect].func)(ap_index, (char *)sta_mac, reason);
    } else if (strstr(buff, "DEAUTH") != NULL) {
        sscanf(buff, "RDKB_WIFI_NOTIFY: ssid%d DEAUTH: %d %02x:%02x:%02x:%02x:%02x:%02x %d",
               &ap_index, &vap,
               (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2],
               (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5],
               &reason);
        sta_mac[0] = mac[0]; sta_mac[1] = mac[1]; sta_mac[2] = mac[2];
        sta_mac[3] = mac[3]; sta_mac[4] = mac[4]; sta_mac[5] = mac[5];
        ((device_deauthenticated)g_simulator.cb[wifi_hal_cb_deauth].func)(ap_index, (char *)sta_mac, reason);
    }
    
}


void *wifi_connections_listener    (void *arg)
{
    fd_set rfds;
    int retval;
    int fd;
    struct sockaddr_un name;
    char data[MAX_IPC_DATA_LEN];
    socklen_t size;
    ssize_t ret;

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);
    
    unlink(KMSG_WRAPPER_FILE_NAME);
    
    fd = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (fd < 0) {
        wifi_util_dbg_print(WIFI_MON, "Error opening local socket err:%d\n", errno);
        return NULL;
    }
    
    /* Bind a name to the socket. */
    name.sun_family = AF_LOCAL;
    strncpy (name.sun_path, KMSG_WRAPPER_FILE_NAME, sizeof(name.sun_path));
    name.sun_path[sizeof (name.sun_path) - 1] = '\0';
    
    if (bind(fd, (struct sockaddr *)&name, sizeof(struct sockaddr_un)) < 0) {
        wifi_util_dbg_print(WIFI_MON, "Error binding to socket:%d\n", errno);
        return NULL;
    }
    
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    
    
    while ((retval = select(fd + 1, &rfds, NULL, NULL, NULL)) >= 0) {
        
        if (retval) {
            // some sta joined or left
            size = sizeof(struct sockaddr_un);
            
            memset(data, 0, MAX_IPC_DATA_LEN);
            if (( ret = recvfrom(fd, data, MAX_IPC_DATA_LEN, 0, (struct sockaddr *)&name, &size)) > 0) {
                device_associated_states(data, ret);
            }
            
        } else if (retval == 0) {
            // time out, should never happen
        }
        
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        
        
    }
    
    close(fd);
    
    return NULL;
}




