#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"

bool vap_svc_is_mesh_ext(unsigned int vap_index)
{
    return isVapSTAMesh(vap_index) ? true : false;
}

void get_default_supported_scan_channel_list(uint8_t radio_band, unsigned int **channel_list, unsigned char *num_of_channels)
{
    static unsigned int radio_2_4_ghz_channel_list[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    static unsigned int radio_5_ghz_channel_list[] = { 36, 40, 44, 48, 149, 153, 157, 161, 165 };

    if (radio_band == WIFI_FREQUENCY_2_4_BAND) {
        *channel_list = radio_2_4_ghz_channel_list;
        *num_of_channels = ARRAY_SZ(radio_2_4_ghz_channel_list);

    } else if (radio_band == WIFI_FREQUENCY_5_BAND) {
        *channel_list = radio_5_ghz_channel_list;
        *num_of_channels = ARRAY_SZ(radio_5_ghz_channel_list);
    }

//    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi number of scan channels:%d : %d\r\n", __func__, __LINE__, *num_of_channels, *channel_list[0]);
}

int vap_svc_mesh_ext_connect()
{
    wifi_ctrl_t *ctrl;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    unsigned int *channel_list = NULL;
    unsigned char num_of_channels;

    if(ctrl->conn_state == connection_state_disconnected) {
        /* start scan on 2.4Ghz */
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d start Scan on 2.4GHz and 5GHz radios\n",__func__, __LINE__);
        get_default_supported_scan_channel_list(WIFI_FREQUENCY_2_4_BAND, &channel_list, &num_of_channels);
        wifi_hal_startScan(0, WIFI_RADIO_SCAN_MODE_OFFCHAN, 0, num_of_channels, channel_list);

        /* start scan on 5Ghz */
        get_default_supported_scan_channel_list(WIFI_FREQUENCY_5_BAND, &channel_list, &num_of_channels);
        wifi_hal_startScan(1, WIFI_RADIO_SCAN_MODE_OFFCHAN, 0, num_of_channels, channel_list);
    }

    return 0;
}

int vap_svc_mesh_ext_disconnect()
{
    uint8_t num_of_radios;
    unsigned int i, j;
    wifi_vap_info_map_t *vap_map = NULL;
    wifi_vap_info_t *vap;
    wifi_ctrl_t *ctrl;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((num_of_radios = getNumberRadios()) > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_CTRL,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return -1;
    }

    for (i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return -1;
        }

        for (j = 0; j < vap_map->num_vaps; j++) {
            if (vap_svc_is_mesh_ext(vap_map->vap_array[j].vap_index) == true) {
                vap = &vap_map->vap_array[j];
                if ((vap->vap_mode == wifi_vap_mode_sta) &&
                    (vap->u.sta_info.conn_status == wifi_connection_status_connected)) {
                    wifi_util_info_print(WIFI_CTRL, "%s:%d: wifi disconnect :%d\n", __func__, __LINE__, vap->vap_index);
                    wifi_hal_disconnect(vap->vap_index);
		    ctrl->conn_state = connection_state_disconnected;
                }
            }
        }
    }

    return 0;
}

int vap_svc_mesh_ext_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    /* create STA vap's and install acl filters */
    vap_svc_start(svc);

    /* start STA connection procedure */
    vap_svc_mesh_ext_connect();

    return 0;
}

int vap_svc_mesh_ext_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    vap_svc_mesh_ext_disconnect();
    vap_svc_stop(svc);
    return 0;
}

int vap_svc_mesh_ext_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
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
        memcpy((unsigned char *)&map->vap_array[i], (unsigned char *)&tgt_vap_map.vap_array[0],
                    sizeof(wifi_vap_info_t));

        wifidb_update_wifi_vap_info(getVAPName(map->vap_array[i].vap_index), &map->vap_array[i]);
        wifidb_update_wifi_security_config(getVAPName(map->vap_array[i].vap_index),
            &map->vap_array[i].u.sta_info.security);
    }

    vap_svc_mesh_ext_connect();
    return 0;
}
