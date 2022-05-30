#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "vap_svc.h"
#include "wifi_util.h"

bool vap_svc_is_public(unsigned int vap_index)
{
    static unsigned int  allowed_array[] = {4, 8, 5, 9};
    unsigned int i;

    for (i = 0; i < ARRAY_SZ(allowed_array); i++) {
        if (vap_index == allowed_array[i]) {
            return true;
        }
    }
    return false;
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

    for (i = 0; i < map->num_vaps; i++) {

        // No call to wifi_hal_createVAP as part of this flow. Public vaps are created
        // on tunnel up event or as part of web config. But the database and caches
        // should be updated here

        wifidb_update_wifi_vap_info(getVAPName(map->vap_array[i].vap_index), &map->vap_array[i]);
        wifidb_update_wifi_interworking_config(getVAPName(map->vap_array[i].vap_index),
            &map->vap_array[i].u.bss_info.interworking);
        wifidb_update_wifi_security_config(getVAPName(map->vap_array[i].vap_index),
            &map->vap_array[i].u.bss_info.security);
    }

    return 0;
}
