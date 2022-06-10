#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"

bool vap_svc_is_public(unsigned int vap_index)
{
    return isVapHotspot(vap_index) ? true : false;
}

int vap_svc_public_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    // for public just create vaps
    if (radio_index == WIFI_ALL_RADIO_INDICES) {
        return vap_svc_start(svc);
    }

    return 0;
}

int vap_svc_public_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    if (radio_index == WIFI_ALL_RADIO_INDICES) {
        return vap_svc_stop(svc);
    }
    return 0;
}

int vap_svc_public_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    unsigned int i;
    wifi_vap_info_map_t tgt_vap_map, tgt_created_vap_map;
    bool greylist_rfc = false;
    memset((unsigned char *)&tgt_created_vap_map, 0, sizeof(wifi_vap_info_map_t));
    tgt_created_vap_map.num_vaps = 0;

    wifi_util_dbg_print(WIFI_CTRL,"vap_svc_public_update\n");

    wifi_rfc_dml_parameters_t *rfc_info = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    if (rfc_info) {
        greylist_rfc = rfc_info->radiusgreylist_rfc;
    }
    for (i = 0; i < map->num_vaps; i++) {

        // Create xfinity vaps as part of the flow and update db and caches - just the way
        // it happens for other vaps - private, xH, etc,
        // The only expectation is that the first time creation of xfinity vaps will happen
        // through webconfig framework - this is because of the dependency on tunnels

        memset((unsigned char *)&tgt_vap_map, 0, sizeof(tgt_vap_map));
        memcpy((unsigned char *)&tgt_vap_map.vap_array[0], (unsigned char *)&map->vap_array[i],
                    sizeof(wifi_vap_info_t));
        tgt_vap_map.vap_array[0].u.bss_info.network_initiated_greylist = greylist_rfc;
        tgt_vap_map.num_vaps = 1;

        if (wifi_hal_createVAP(radio_index, &tgt_vap_map) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
            continue;
        }
        if (greylist_rfc) {
                    wifi_setApMacAddressControlMode(tgt_vap_map.vap_array[0].vap_index, 2);
          }
        wifi_util_dbg_print(WIFI_CTRL,"%s: wifi vap create success: radio_index:%d vap_index:%d greylist_rfc:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index,greylist_rfc);
        wifidb_print("%s: wifi vap create success: radio_index:%d vap_index:%d \n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        wifidb_print("%s:%d [Stop] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());

        memcpy((unsigned char *)&map->vap_array[i], (unsigned char *)&tgt_vap_map.vap_array[0],
                    sizeof(wifi_vap_info_t));
        memcpy((unsigned char *)&tgt_created_vap_map.vap_array[i], (unsigned char *)&tgt_vap_map.vap_array[0], sizeof(wifi_vap_info_t));
        wifidb_update_wifi_vap_info(map->vap_array[i].vap_name, &map->vap_array[i]);
        wifidb_update_wifi_interworking_config(map->vap_array[i].vap_name,
            &map->vap_array[i].u.bss_info.interworking);
        wifidb_update_wifi_security_config(getVAPName(map->vap_array[i].vap_index),
            &map->vap_array[i].u.bss_info.security);
    }
     update_global_cache(&tgt_created_vap_map);
    //Load all the Acl entries related to the created public vaps
    update_acl_entries(&tgt_created_vap_map);
    return 0;
}
