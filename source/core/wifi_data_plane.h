 /****************************************************************************
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
                                                                            
 ****************************************************************************/

#ifndef WIFI_DATA_PLANE_H
#define WIFI_DATA_PLANE_H

#if DML_SUPPORT
#include "cosa_apis.h"
#include "cosa_dbus_api.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_internal.h"
#endif // DML_SUPPORT

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
#include "wifi_8021x.h"
#if DML_SUPPORT
#include "wifi_easy_connect.h"
#endif // DML_SUPPORT
#include "wifi_passpoint.h"
#include "wifi_data_plane_types.h"

typedef struct {
       wifi_data_plane_packet_type_t   type;
       union {
               wifi_8021x_data_t *eapol_data;
               wifi_auth_data_t *auth_data;
               wifi_assoc_req_data_t *assoc_req_data;
               wifi_assoc_rsp_data_t *assoc_rsp_data;
       } u;
} wifi_data_plane_packet_t;

typedef struct {
       wifi_data_plane_event_type_t    type;
       union {
               wifi_device_dpp_context_t       *dpp_ctx;
               wifi_anqp_context_t        *anqp_ctx;
       } u;
} wifi_data_plane_event_t;

typedef struct {
       wifi_data_plane_queue_data_type_t type; 
       BOOL  setSignalThread;
       union {
               wifi_data_plane_packet_t         packet;
               wifi_data_plane_event_t         event;
       } u;
} wifi_data_plane_queue_data_t;

typedef struct {
    queue_t             *queue;
    pthread_cond_t      cond;
    pthread_mutex_t     lock;
    pthread_t           id;
    bool                exit_data_plane;
    unsigned int        poll_period;
    struct timespec     last_signalled_time;
    struct timespec     last_polled_time;
    wifi_8021x_t        module_8021x;
#if DML_SUPPORT
    wifi_easy_connect_t module_easy_connect;
#endif // DML_SUPPORT
} wifi_data_plane_t;

wifi_data_plane_queue_data_t *data_plane_queue_create_event(void *ptr, wifi_data_plane_event_type_t type, BOOL setSignalThread);
wifi_data_plane_queue_data_t *data_plane_queue_create_packet(void *ptr, wifi_data_plane_packet_type_t type, BOOL setSignalThread);
void data_plane_queue_push(wifi_data_plane_queue_data_t *data);
void* data_plane_queue_remove_event(wifi_data_plane_event_type_t type, void *ctx);
bool data_plane_queue_check_event(wifi_data_plane_event_type_t type, void *ctx);
int init_wifi_data_plane();
#endif // WIFI_DATA_PLANE_H
