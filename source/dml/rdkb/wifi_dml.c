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

#include "wifi_dml.h"
#include "wifi_mgr.h"
#include <stdint.h>

void start_dml()
{
    wifi_mgr_t *wifi_mgr = (wifi_mgr_t *) get_wifimgr_obj();

    /* pthread_create for DML functionality */
    start_dml_main(&wifi_mgr->wifidml.ssp);

    wifi_util_info_print(WIFI_MGR,"%s: waiting for DML init\n", __func__);

    pthread_mutex_lock(&wifi_mgr->lock);

    while(!wifi_mgr->wifidml.dml_init_status.condition) {
        pthread_cond_wait(&wifi_mgr->wifidml.dml_init_status.cv, &wifi_mgr->lock);
    }

    pthread_mutex_unlock(&wifi_mgr->lock);
    pthread_cond_destroy(&wifi_mgr->wifidml.dml_init_status.cv);
    wifi_util_info_print(WIFI_MGR,"%s: DML init complete\n", __func__);
}

void set_dml_init_status(bool status)
{
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    if (status == false) {
        wifi_mgr->wifidml.dml_init_status.condition = status;
        pthread_cond_init(&wifi_mgr->wifidml.dml_init_status.cv, NULL);
        pthread_mutex_init(&wifi_mgr->lock, NULL);
    } else {
        pthread_mutex_lock(&wifi_mgr->lock);
        wifi_mgr->wifidml.dml_init_status.condition = status;
        pthread_cond_signal(&wifi_mgr->wifidml.dml_init_status.cv);
        pthread_mutex_unlock(&wifi_mgr->lock);
        wifi_util_info_print(WIFI_MGR, "%s Marking DML Init Complete. Start Wifi Ctrli\n", __FUNCTION__, status);
    }
}

void ssp_init()
{
    if (ssp_loop_init() < 0) {
        wifi_util_error_print(WIFI_MGR,"%s:%d ssp_loop_init failed \n", __func__, __LINE__);
    }
}

void wifi_dml_init(wifi_dml_t *dml)
{
    dml->desc.start_dml_fn = start_dml;
    dml->desc.set_dml_init_status_fn = set_dml_init_status;
    dml->desc.ssp_init_fn = ssp_init;
    dml->desc.push_data_to_ssp_queue_fn = push_data_to_ssp_queue;
}
