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
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_csi.h"
#include "wifi_util.h"
#if DML_SUPPORT
#include "wifi_analytics.h"
#endif
#include <rbus.h>

INT process_csi(mac_address_t mac_addr, wifi_csi_data_t  *csi_data)
{
    wifi_event_t *event = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_dbg_print(WIFI_APPS, "%s: CSI data received - MAC  %02x:%02x:%02x:%02x:%02x:%02x\n",__func__, mac_addr[0], mac_addr[1],
                                                        mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    event = create_wifi_event(sizeof(wifi_csi_dev_t), wifi_event_type_csi, wifi_event_type_csi_data); 
    if (event == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: memory allocation for event failed.\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memcpy(event->u.csi->sta_mac, mac_addr, sizeof(mac_addr_t));
    memcpy(&(event->u.csi->csi), csi_data, sizeof(wifi_csi_data_t));
    apps_mgr_event(&ctrl->apps_mgr, event);

    destroy_wifi_event(event);
    return 0;
}

void update_pinger_config(int ap_index, mac_addr_t mac_addr, bool pause_pinger)
{
#if (defined (_XB7_PRODUCT_REQ_) && !defined (_COSA_BCM_ARM_))
    wifi_monitor_data_t *data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data ==  NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));

    memcpy(data->u.csi_mon.mac_addr, mac_addr, sizeof(mac_addr_t));
    data->u.csi_mon.ap_index = ap_index;
    data->u.csi_mon.pause_pinger = pause_pinger;
    push_event_to_monitor_queue(data, wifi_event_monitor_csi_pinger, NULL);
    free(data);
#endif
    return;
}

int csi_start_fn(void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    mac_addr_str_t mac_str = { 0 };
    csi_mac_data_t *to_hash_map = NULL;
    bool enable_sounding = false;

    wifi_app_t *app = (wifi_app_t *)csi_app;
    if (app == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }


    to_mac_str((unsigned char *)mac_addr, mac_str);
    if (app->data.u.csi.csi_sounding_mac_map ==  NULL){
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Hash Map\n", __func__, __LINE__);
        return -1;
    }

    to_hash_map = hash_map_get(app->data.u.csi.csi_sounding_mac_map, mac_str);
    if (to_hash_map != NULL) {
        if (to_hash_map->subscribed_apps & sounding_app) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Request from same APP not sounding\n", __func__, __LINE__);
            return 0;
        } else {
            to_hash_map->subscribed_apps |= sounding_app;
        }
    } else {
        if (app->data.u.csi.num_current_sounding >= MAX_NUM_CSI_SOUNDING) {
            //Check if the requesting app is motion.
            if (sounding_app == wifi_app_inst_motion) {
                //Check if there are any slots available from low priority apps.
                to_hash_map = (csi_mac_data_t *)hash_map_get_first(app->data.u.csi.csi_sounding_mac_map);
                while(to_hash_map != NULL) {
                    if ((to_hash_map->subscribed_apps & ~wifi_app_inst_motion)){
                        wifi_util_info_print(WIFI_APPS, "%s:%d Disabling CSI for mac %02x..%02x\n", __func__, __LINE__, to_hash_map->mac_addr[0], to_hash_map->mac_addr[5]);
                        wifi_enableCSIEngine(to_hash_map->ap_index, to_hash_map->mac_addr, FALSE);
                        update_pinger_config(to_hash_map->ap_index, to_hash_map->mac_addr, true);
                        to_hash_map = (csi_mac_data_t *)hash_map_remove(app->data.u.csi.csi_sounding_mac_map, mac_str);
                        if (to_hash_map != NULL) {
                            free(to_hash_map);
                        }
                        enable_sounding = true;
                        break;
                    }
                    to_hash_map = hash_map_get_next(app->data.u.csi.csi_sounding_mac_map, to_hash_map);
                }
            } else {
                //Ignore request for Low priority apps.
                wifi_util_info_print(WIFI_APPS, "%s:%d Not Enabling for Low priority Apps", __func__, __LINE__);
                return -1;
            }
        } else {
            enable_sounding = true;
        }

        if (enable_sounding) {
            wifi_util_info_print(WIFI_APPS, "%s:%d Enabling CSI\n", __func__, __LINE__);
            to_hash_map = (csi_mac_data_t *)malloc(sizeof(csi_mac_data_t));
            if (to_hash_map == NULL) {
                wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
                return -1;
            }

            memset(to_hash_map, 0, sizeof(csi_mac_data_t));
            to_hash_map->ap_index = ap_index;
            memcpy(to_hash_map->mac_addr, mac_addr, sizeof(mac_addr_t));
            to_hash_map->subscribed_apps |= sounding_app;
            wifi_util_info_print(WIFI_APPS, "%s:%d Enabling CSI for mac %02x..%02x\n", __func__, __LINE__, to_hash_map->mac_addr[0], to_hash_map->mac_addr[5]);
            wifi_enableCSIEngine(ap_index, (unsigned char *)mac_addr, TRUE);
            hash_map_put(app->data.u.csi.csi_sounding_mac_map, strdup(mac_str), to_hash_map);
            app->data.u.csi.num_current_sounding++;
            update_pinger_config(ap_index, mac_addr, false);
            return 0;
        } else {
            wifi_util_info_print(WIFI_APPS, "%s:%d Slots are FULL Not sounding\n", __func__, __LINE__);
        }
    }
    return 0;
}

int csi_stop_fn(void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    mac_addr_str_t mac_str = { 0 };

    wifi_app_t *app = (wifi_app_t *)csi_app;
    if (app == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    to_mac_str((unsigned char *)mac_addr, mac_str);
    //Check if the MAC is there in the hash_map.
    if (app->data.u.csi.csi_sounding_mac_map == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    csi_mac_data_t *mac_data = (csi_mac_data_t *)hash_map_get(app->data.u.csi.csi_sounding_mac_map, mac_str);
    if (mac_data == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Rogue Disable Request from app %d\n", __func__, __LINE__, sounding_app);
        return 0;
    }
    //Check if the mac is currently sounding by more apps.
    if (mac_data->subscribed_apps & ~sounding_app) {
        wifi_util_info_print(WIFI_APPS, "%s:%d MAC is being sounded by more than one apps not disabling sounding\n", __func__, __LINE__);
        mac_data->subscribed_apps &= ~sounding_app;
    } else {
        //Disable Sounding.
        wifi_util_info_print(WIFI_APPS, "%s:%d Disabling CSI for mac %02x..%02x\n", __func__, __LINE__, mac_data->mac_addr[0], mac_data->mac_addr[5]);
        wifi_enableCSIEngine(mac_data->ap_index, mac_data->mac_addr, FALSE);
        mac_data = (csi_mac_data_t *)hash_map_remove(app->data.u.csi.csi_sounding_mac_map, mac_str);
        update_pinger_config(mac_data->ap_index, mac_data->mac_addr, true);
        free(mac_data);
        app->data.u.csi.num_current_sounding--;
    }
    return 0;
}

#ifdef ONEWIFI_CSI_APP_SUPPORT
int csi_init(wifi_app_t *app, unsigned int create_flag)
{
    app->data.u.csi.csi_fns.csi_start_fn = csi_start_fn;
    app->data.u.csi.csi_fns.csi_stop_fn = csi_stop_fn;
    app->data.u.csi.csi_sounding_mac_map = hash_map_create();
    if (app->data.u.csi.csi_sounding_mac_map == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL hash map\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.csi.num_current_sounding = 0;

#if defined (FEATURE_CSI)
    wifi_csi_callback_register(process_csi);
#endif

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Init Csi\n", __func__, __LINE__);
    return RETURN_OK;
}
#endif
