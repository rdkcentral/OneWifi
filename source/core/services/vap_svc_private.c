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
#include "stdlib.h"
#include <sys/time.h>
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"

bool vap_svc_is_private(unsigned int vap_index)
{
    if (isVapPrivate(vap_index) || isVapXhs(vap_index) || isVapLnf(vap_index)) {
        return true;
    }

    return false;
}

int vap_svc_private_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    // for private just create vaps and install acl filters
    if (radio_index == WIFI_ALL_RADIO_INDICES) {
        return vap_svc_start(svc);
    }

    return 0;
}

int vap_svc_private_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    if (radio_index == WIFI_ALL_RADIO_INDICES) {
        return vap_svc_stop(svc);
    }
    return 0;
}

int vap_svc_private_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    unsigned int i;
    wifi_vap_info_map_t tgt_vap_map;

    for (i = 0; i < map->num_vaps; i++) {
        memset((unsigned char *)&tgt_vap_map, 0, sizeof(tgt_vap_map));
        memcpy((unsigned char *)&tgt_vap_map.vap_array[0], (unsigned char *)&map->vap_array[i],
                    sizeof(wifi_vap_info_t));
        tgt_vap_map.num_vaps = 1;

        if (wifi_hal_createVAP(radio_index, &tgt_vap_map) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
            continue;
        }
        wifi_util_info_print(WIFI_CTRL,"%s: wifi vap create success: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        wifidb_print("%s: wifi vap create success: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        wifidb_print("%s:%d [Stop] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());
        memcpy((unsigned char *)&map->vap_array[i], (unsigned char *)&tgt_vap_map.vap_array[0],
                    sizeof(wifi_vap_info_t));

        wifidb_update_wifi_vap_info(getVAPName(map->vap_array[i].vap_index), &map->vap_array[i]);
        wifidb_update_wifi_interworking_config(getVAPName(map->vap_array[i].vap_index),
                &map->vap_array[i].u.bss_info.interworking);
        wifidb_update_wifi_security_config(getVAPName(map->vap_array[i].vap_index),
                &map->vap_array[i].u.bss_info.security);
    }

    return 0;
}

int vap_svc_private_event(vap_svc_t *svc, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, vap_svc_event_t event, void *arg)
{
   return 0;
}
