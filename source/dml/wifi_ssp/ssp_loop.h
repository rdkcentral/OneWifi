/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


#ifndef  _SSP_LOOP_
#define  _SSP_LOOP_

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi_base.h"

typedef enum {
    ssp_event_type_psm_read,
    ssp_event_type_psm_write,
    ssp_event_type_max
} ssp_event_type_t;

typedef enum {
    radio_config,
    radio_feature_config,
    vap_config,
    global_config,
    security_config,
    mac_config_add,
    mac_config_delete
} ssp_event_subtype_t;

typedef int (* ssp_loop_post)(const void *msg, unsigned int len, ssp_event_type_t type, ssp_event_subtype_t sub_type);

typedef struct {
    queue_t             *queue;
    pthread_mutex_t     lock;
    pthread_cond_t      cond;
    bool  exit_loop;
    ssp_loop_post       post;
} ssp_loop_t;

typedef struct {
    ssp_event_type_t     event_type;
    ssp_event_subtype_t  sub_type;
    void *msg;
    unsigned int len;
} __attribute__((__packed__)) ssp_event_t;

wifi_psm_param_t *get_psm_obj(void);
wifi_radio_psm_param_t *get_radio_psm_obj(unsigned char radio_index);
wifi_radio_feat_psm_param_t *get_radio_feat_psm_obj(unsigned char radio_index);
wifi_vap_psm_param_t *get_vap_psm_obj(unsigned char vap_index);
hash_map_t *get_mac_psm_obj(unsigned char vap_index);
hash_map_t **get_mac_psm_map(unsigned char vap_index);
int get_psm_total_mac_list(int instance_number, unsigned int *total_entries, char *mac_list);
int update_data_mac_list_entry(char *str, unsigned int *data_index);
wifi_global_psm_param_t *get_global_psm_obj(void);
void ssp_loop();
int push_data_to_ssp_queue(const void *msg, unsigned int len, ssp_event_type_t type, ssp_event_subtype_t sub_type);
int ssp_loop_init();
#ifdef __cplusplus
}
#endif

#endif
