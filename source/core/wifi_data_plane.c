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

#include "wifi_data_plane.h"
#if DML_SUPPORT
#include "wifi_monitor.h"
#else
#include "log.h"
#endif // DML_SUPPORT
#include "wifi_util.h"

wifi_data_plane_t g_data_plane_module;

void *process_data_plane_function  (void *data);
void eapol_frame_received(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len);
void eapol_frame_sent(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len);
void auth_frame_received(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);
void auth_frame_sent(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);
void assoc_req_frame_received(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);
void assoc_rsp_frame_sent(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len);

void wifi_8021x_data_rx_callback_register(wifi_received8021xFrame_callback func);
void wifi_8021x_data_tx_callback_register(wifi_sent8021xFrame_callback func);
void wifi_auth_frame_rx_callback_register(wifi_receivedAuthFrame_callback func);
void wifi_auth_frame_tx_callback_register(wifi_sentAuthFrame_callback func);
void wifi_assoc_req_frame_callback_register(wifi_receivedAssocReqFrame_callback func);
void wifi_assoc_rsp_frame_callback_register(wifi_sentAssocRspFrame_callback func);

void process_timeout()
{
    process_passpoint_timeout();//Call the passpoint timout function to update gas stats rate.
    process_8021x_data_timeout(&g_data_plane_module.module_8021x);
}


void process_packet_timeout(wifi_data_plane_packet_t *packet, wifi_data_plane_t *module)
{
    UNREFERENCED_PARAMETER(packet);
    UNREFERENCED_PARAMETER(module);
}

void process_event_timeout(wifi_data_plane_event_t *event, wifi_data_plane_t *module)
{
       switch (event->type) {

#if !defined(_BWG_PRODUCT_REQ_)
#if defined (DUAL_CORE_XB3) || (defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))
                case wifi_data_plane_event_type_dpp:
                    //process_easy_connect_event_timeout(event->u.dpp_ctx, &module->module_easy_connect);//ONE_WIFI
                    break;

#endif
#endif
                default:
                    UNREFERENCED_PARAMETER(module);
                    break;
       }

}

void process_packet(wifi_data_plane_packet_t *packet, wifi_data_plane_t *module)
{

    switch (packet->type) {
        case wifi_data_plane_packet_type_8021x:
            process_8021x_packet(packet->u.eapol_data, &module->module_8021x);
            break;

        case wifi_data_plane_packet_type_auth:
            process_auth_packet(packet->u.auth_data, &module->module_8021x);
            break;

        case wifi_data_plane_packet_type_assoc_req:
            process_assoc_req_packet(packet->u.assoc_req_data, &module->module_8021x);
            break;

        case wifi_data_plane_packet_type_assoc_rsp:
            process_assoc_rsp_packet(packet->u.assoc_rsp_data, &module->module_8021x);
            break;
    }

}

void process_event(wifi_data_plane_event_t *event, wifi_data_plane_t *module)
{

       switch (event->type) {

#if defined (DUAL_CORE_XB3) || (defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))
#if !defined(_BWG_PRODUCT_REQ_)
               case wifi_data_plane_event_type_dpp:
                       //process_easy_connect_event(event->u.dpp_ctx, &module->module_easy_connect);//ONE_WIFI
                       break;
#endif
#endif
               case wifi_data_plane_event_type_anqp:
                       process_passpoint_event(event->u.anqp_ctx);
                       break;
                default:
                        UNREFERENCED_PARAMETER(module);
                        break;
       }

}

void *process_data_plane_function  (void *data)
{
    wifi_data_plane_t *proc_data;
    struct timespec time_to_wait;
    struct timespec tv_now;
    wifi_data_plane_queue_data_t *queue_data;
    int rc, i, count, queue_offset = 0;
    time_t  time_diff;

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    proc_data = (wifi_data_plane_t *)data;

    while (proc_data->exit_data_plane == false) {
	
        clock_gettime(CLOCK_MONOTONIC, &tv_now);

        time_to_wait.tv_nsec = 0;
        time_to_wait.tv_sec = tv_now.tv_sec + proc_data->poll_period;

        if (proc_data->last_signalled_time.tv_sec > proc_data->last_polled_time.tv_sec) {
            // if were signalled within poll interval if last poll the wait should be shorter
            time_diff = proc_data->last_signalled_time.tv_sec - proc_data->last_polled_time.tv_sec;
            if ((UINT)time_diff < proc_data->poll_period) {
                time_to_wait.tv_sec = tv_now.tv_sec + (proc_data->poll_period - time_diff);
            }
        }

        pthread_mutex_lock(&proc_data->lock);
        rc = pthread_cond_timedwait(&proc_data->cond, &proc_data->lock, &time_to_wait);

        if (rc == ETIMEDOUT) {
            /*wifi_util_dbg_print(WIFI_MON, "%s:%d: Running eloop\n", __func__, __LINE__);
            hapd_wpa_run();
            timeout_count++;
            if (timeout_count < 100) {
                pthread_mutex_unlock(&proc_data->lock);
                continue;
            }
            timeout_count = 0;*/
            //wifi_util_dbg_print(WIFI_MON, "%s:%d: Data plane timed out\n", __func__, __LINE__);
            process_timeout();
            clock_gettime(CLOCK_MONOTONIC, &proc_data->last_polled_time);
        }

        // dequeue data
        count = queue_count(proc_data->queue);
        for (i = 0; i < count; i++) {

            queue_data = queue_peek(proc_data->queue, (queue_count(proc_data->queue) - queue_offset- 1));
            if (queue_data == NULL) {
                continue;
            }

            switch (queue_data->type) {
                case wifi_data_plane_queue_data_type_packet:
                    if (rc == ETIMEDOUT) {
                        process_packet_timeout(&queue_data->u.packet, proc_data);
                    } else if (queue_data->setSignalThread) {
                        process_packet(&queue_data->u.packet, proc_data);
                    }
                    break;

                case wifi_data_plane_queue_data_type_event:
                    if(rc == ETIMEDOUT) {
                        process_event_timeout(&queue_data->u.event, proc_data);
                    } else if (queue_data->setSignalThread) {
                        process_event(&queue_data->u.event, proc_data);
                    } else {
                        queue_offset++;
                        continue;
                    }
                    break;

                default:
                    break;
            }

            queue_remove(proc_data->queue, (queue_count(proc_data->queue) - queue_offset - 1));
            free(queue_data);
            clock_gettime(CLOCK_MONOTONIC, &proc_data->last_signalled_time);

        }

        pthread_mutex_unlock(&proc_data->lock);

    }

    return NULL;
}

void assoc_rsp_frame_sent(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len)
{
    wifi_assoc_rsp_data_t *assoc;

    assoc = malloc(sizeof(wifi_assoc_rsp_data_t));
    memset(assoc, 0, sizeof(wifi_assoc_rsp_data_t));

    assoc->data = malloc(len);
    memcpy(assoc->data, data, len);
    assoc->len = len;

    assoc->vap = ap_index;
    memcpy(assoc->mac, sta, sizeof(mac_address_t));

    data_plane_queue_push(data_plane_queue_create_packet(assoc, wifi_data_plane_packet_type_assoc_rsp, TRUE));

}

void assoc_req_frame_received(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len)
{
    wifi_assoc_req_data_t *assoc;

    assoc = malloc(sizeof(wifi_assoc_req_data_t));
    memset(assoc, 0, sizeof(wifi_assoc_req_data_t));

    assoc->data = malloc(len);
    memcpy(assoc->data, data, len);
    assoc->len = len;

    assoc->vap = ap_index;
    memcpy(assoc->mac, sta, sizeof(mac_address_t));

    data_plane_queue_push(data_plane_queue_create_packet(assoc, wifi_data_plane_packet_type_assoc_req, TRUE));

}

void auth_frame_sent(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len)
{
    wifi_auth_data_t *auth;

    auth = malloc(sizeof(wifi_auth_data_t));
    memset(auth, 0, sizeof(wifi_auth_data_t));

    auth->data = malloc(len);
    memcpy(auth->data, data, len);
    auth->len = len;

    auth->vap = ap_index;
    memcpy(auth->mac, sta, sizeof(mac_address_t));

    auth->dir = wifi_direction_downlink;

    data_plane_queue_push(data_plane_queue_create_packet(auth, wifi_data_plane_packet_type_auth, TRUE));

}

void auth_frame_received(unsigned int ap_index, mac_address_t sta, void *data, unsigned int len)
{
    wifi_auth_data_t *auth;

    auth = malloc(sizeof(wifi_auth_data_t));
    memset(auth, 0, sizeof(wifi_auth_data_t));

    auth->data = malloc(len);
    memcpy(auth->data, data, len);
    auth->len = len;

    auth->vap = ap_index;
    memcpy(auth->mac, sta, sizeof(mac_address_t));

    auth->dir = wifi_direction_uplink;

    data_plane_queue_push(data_plane_queue_create_packet(auth, wifi_data_plane_packet_type_auth, TRUE));

}


void eapol_frame_sent(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len)
{
    // wifi_8021x_data_t *eapol;

    //printf("%s:%d Enter: frame length:%d\n", __func__, __LINE__, len);

    // eapol = malloc(sizeof(wifi_8021x_data_t));
    // memset(eapol, 0, sizeof(wifi_8021x_data_t));

    // eapol->data = malloc(len);
    // memcpy(eapol->data, data, len);
    // eapol->len = len;

    // eapol->vap = ap_index;
    // memcpy(eapol->mac, sta, sizeof(mac_address_t));
    // eapol->type = type;
    // eapol->dir = wifi_direction_downlink;

    //data_plane_queue_push(data_plane_queue_create_packet(eapol, wifi_data_plane_packet_type_8021x, TRUE));

}

void eapol_frame_received(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len)
{
    wifi_8021x_data_t *eapol;

    eapol = malloc(sizeof(wifi_8021x_data_t));
    memset(eapol, 0, sizeof(wifi_8021x_data_t));

    eapol->data = malloc(len);
    memcpy(eapol->data, data, len);
    eapol->len = len;

    eapol->vap = ap_index;
    memcpy(eapol->mac, sta, sizeof(mac_address_t));
    eapol->type = type;
    eapol->dir = wifi_direction_uplink;

    data_plane_queue_push(data_plane_queue_create_packet(eapol, wifi_data_plane_packet_type_8021x, TRUE));

}

void deinit_wifi_data_plane()
{
       deinit_8021x(&g_data_plane_module.module_8021x);
       if (g_data_plane_module.queue != NULL) {
       queue_destroy(g_data_plane_module.queue);
       }

    pthread_mutex_destroy(&g_data_plane_module.lock);
    pthread_cond_destroy(&g_data_plane_module.cond);
}

int init_wifi_data_plane()
{
#if defined (DUAL_CORE_XB3) || \
    (defined(_XB6_PRODUCT_REQ_) && !defined(_XB8_PRODUCT_REQ_)) || \
    (defined(_CBR_PRODUCT_REQ_) && !(defined(_CBR2_PRODUCT_REQ_)) )

    pthread_condattr_t cond_attr;
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;

    init_8021x(&g_data_plane_module.module_8021x);

    g_data_plane_module.poll_period = 3;
    clock_gettime(CLOCK_MONOTONIC, &g_data_plane_module.last_signalled_time);
    clock_gettime(CLOCK_MONOTONIC, &g_data_plane_module.last_polled_time);

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&g_data_plane_module.cond, &cond_attr);
    pthread_condattr_destroy(&cond_attr);
    pthread_mutex_init(&g_data_plane_module.lock, NULL);

    g_data_plane_module.queue = queue_create();
    if (g_data_plane_module.queue == NULL) {
        deinit_wifi_data_plane();
        wifi_util_dbg_print(WIFI_MON, "data_plane queue create error\n");
        return -1;
    }

    g_data_plane_module.exit_data_plane = false;

    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
    if (pthread_create(&g_data_plane_module.id, attrp, process_data_plane_function, &g_data_plane_module) != 0) {
        if(attrp != NULL) {
            pthread_attr_destroy(attrp);
        }

        deinit_wifi_data_plane();
        wifi_util_dbg_print(WIFI_MON, "data_plane thread create error\n");
        return -1;
    }
    
    if(attrp != NULL) {
        pthread_attr_destroy( attrp );
    }
#if 0
    if(RETURN_OK != CosaDmlWiFi_initPasspoint()){
        wifi_util_dbg_print(WIFI_MON,"CosaWifiInitialize Error - WiFi failed to Initialize Passpoint.\n");
    }
#else
    if(RETURN_OK != WiFi_initPasspoint()){
        wifi_util_dbg_print(WIFI_MON,"CosaWifiInitialize Error - WiFi failed to Initialize Passpoint.\n");
    }
#endif//ONE_WIFI
    //wifi_hal_mgmt_frame_callbacks_register(mgmt_frame_received_callback);
    wifi_util_dbg_print(WIFI_MON, "%s:%d: init_wifi_data_plane completed ### \n", __func__, __LINE__);
#endif

    return 0;
}

bool data_plane_queue_check_event(wifi_data_plane_event_type_t type, void *ctx)
{
    bool matched = false;

#if defined (DUAL_CORE_XB3) || (defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))
    unsigned int i, count;
    wifi_data_plane_queue_data_t *queue_data = NULL;
    wifi_data_plane_event_t *event;
    pthread_mutex_lock(&g_data_plane_module.lock);

    count = queue_count(g_data_plane_module.queue);
    for (i = 0; i < count; i++) {
        queue_data = queue_peek(g_data_plane_module.queue, i);
        if ((queue_data != NULL) && (queue_data->type == wifi_data_plane_queue_data_type_event)) {
            event = &queue_data->u.event;

           if (event->type != type) {
               continue;
           }

            switch (event->type) {

                case wifi_data_plane_event_type_dpp:
#if !defined(_BWG_PRODUCT_REQ_)
#if 0
                    if (is_matching_easy_connect_event(event->u.dpp_ctx, ctx) == true) {
                        matched = true;
                    }
#endif//ONE_WIFI
#else
                    UNREFERENCED_PARAMETER(ctx);
#endif
                    break;

                case wifi_data_plane_event_type_anqp:
                    break;
                default:
                    break;
            }

            if (matched == true) {
                break;
            }
        }

    }


    pthread_mutex_unlock(&g_data_plane_module.lock);

#else
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(ctx);
#endif

    return matched;
                            
}
void *
data_plane_queue_remove_event(wifi_data_plane_event_type_t type, void *ctx)
{
       void *ptr = NULL;
#if defined (DUAL_CORE_XB3) || (defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))
    unsigned int i, count;
    wifi_data_plane_event_t *event;
    wifi_data_plane_queue_data_t *queue_data = NULL;
    bool matched = false;
    pthread_mutex_lock(&g_data_plane_module.lock);

       count = queue_count(g_data_plane_module.queue);
       for (i = 0; i < count; i++) {
               queue_data = queue_peek(g_data_plane_module.queue, i);
               if ((queue_data != NULL) && (queue_data->type == wifi_data_plane_queue_data_type_event)) {
                       event = &queue_data->u.event;

                       if (event->type != type) {
                           continue;
                       }

                       switch (event->type) {
                               case wifi_data_plane_event_type_dpp:
#if !defined(_BWG_PRODUCT_REQ_)
#if 0
                                       if (is_matching_easy_connect_event(event->u.dpp_ctx, ctx) == true) {
                                               ptr = event->u.dpp_ctx;
                                               matched = true; 
                                       }
#endif//ONE_WIFI
#else
                                        UNREFERENCED_PARAMETER(ctx);
#endif
                                       break;

                               case wifi_data_plane_event_type_anqp:
                                       break;
                                default:
                                        break;
                       }
                       
                       if (matched == true) {
                               queue_remove(g_data_plane_module.queue, i);
                               free(queue_data);
                               break;
                       }
               }

       }


    pthread_mutex_unlock(&g_data_plane_module.lock);

#else
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(ctx);
#endif

       return ptr;             
}

wifi_data_plane_queue_data_t *
data_plane_queue_create_packet(void *ptr, wifi_data_plane_packet_type_t type, BOOL setSignalThread)
{
    wifi_data_plane_queue_data_t *data;

    data = malloc(sizeof(wifi_data_plane_queue_data_t));
    memset(data, 0, sizeof(wifi_data_plane_queue_data_t));

    data->type = wifi_data_plane_queue_data_type_packet;
    data->u.packet.type = type;
    data->setSignalThread = setSignalThread;

    switch (type) {
            case wifi_data_plane_packet_type_8021x:
                    data->u.packet.u.eapol_data = ptr;
                    break;

     case wifi_data_plane_packet_type_auth:
         data->u.packet.u.auth_data = ptr;
         break;

     case wifi_data_plane_packet_type_assoc_req:
         data->u.packet.u.assoc_req_data = ptr;
         break;

     case wifi_data_plane_packet_type_assoc_rsp:
         data->u.packet.u.assoc_rsp_data = ptr;
         break;

    }       

    return data;            
}


wifi_data_plane_queue_data_t *
data_plane_queue_create_event(void *ptr, wifi_data_plane_event_type_t type, BOOL setSignalThread)
{
       wifi_data_plane_queue_data_t *data;

       data = malloc(sizeof(wifi_data_plane_queue_data_t));
       memset(data, 0, sizeof(wifi_data_plane_queue_data_t));
       
       data->type = wifi_data_plane_queue_data_type_event;
       data->u.event.type = type;
       data->setSignalThread = setSignalThread;

       switch (type) {
               case wifi_data_plane_event_type_dpp:
                       data->u.event.u.dpp_ctx = ptr;
                       break;

               case wifi_data_plane_event_type_anqp:
                       data->u.event.u.anqp_ctx = ptr;
                       break;
       }       

       return data;            
}

void data_plane_queue_push(wifi_data_plane_queue_data_t *data)
{
    if(data && data->setSignalThread) {
        pthread_mutex_lock(&g_data_plane_module.lock);
        queue_push(g_data_plane_module.queue, data);
        pthread_cond_signal(&g_data_plane_module.cond);
        pthread_mutex_unlock(&g_data_plane_module.lock);
    } else {
        queue_push(g_data_plane_module.queue, data);
    }
}
