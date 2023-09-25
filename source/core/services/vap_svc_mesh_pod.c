#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include <assert.h>
#include "const.h"
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_monitor.h"
#include "wifi_hal_generic.h"
#include <rbus.h>
#include <errno.h>

#include <opensync/ow_state_barrier.h>
#include <opensync/ow_cbs_register.h>
#include <opensync/ow_webconfig.h>
#include <opensync/osw_drv_target.h>

#define OW_SETTLED_TIMEOUT (60 * 1000)

#define WIFI_HOME_AP_IF_PREFIX     "home-ap-"
#define WIFI_BHAUL_AP_IF_PREFIX    "bhaul-ap-"
#define WIFI_BHAUL_STA_IF_PREFIX   "bhaul-sta-"
#define WIFI_LNF_AP_IF_PREFIX      "svc-d-ap-"
#define WIFI_IOT_AP_IF_PREFIX      "svc-e-ap-"

// Bhaul credentials caching on POD
#define BHAUL_CREDS_DIR      "/mnt/data/pstore/mesh_bhaul_creds/"
#define BHAUL_CREDS_PATH_LEN (sizeof(BHAUL_CREDS_DIR) + 10)
/* max 32 bytes*/
#define SSID_MAX_LEN         (64)
#define KEY_MAX_LEN          (256)

typedef enum {
    ow_state_barrier_vif_conf_type_device,
    ow_state_barrier_vif_conf_type_cloud,
} ow_state_barrier_vif_conf_type_t;

typedef struct {
    char *if_name;
    int vif_index;
    int phy_index;
    char *vap_name;
    ow_state_barrier_vif_conf_type_t conf_type;
} ow_state_barrier_vif_info_t;

typedef struct {
    char *phy_name;
    int phy_index;
} ow_state_barrier_phy_info_t;

typedef struct {
    wifi_radio_operationParam_t *phy;
    char if_name[MAXIFACENAMESIZE];
} ow_phy_oper_param_t;

typedef struct 
{
    wifi_vap_info_t *vap;
    char phy_name[MAXIFACENAMESIZE];
    char vif_name[MAXIFACENAMESIZE];
} ow_vif_config_param_t;

ow_state_barrier_vif_info_t vif_list[] = {
    {"bhaul-ap-24",   0,  0, "mesh_backhaul_2g",  ow_state_barrier_vif_conf_type_device},
    {"bhaul-ap-l50",  1,  1, "mesh_backhaul_5gl", ow_state_barrier_vif_conf_type_device},
    {"bhaul-ap-u50",  2,  2, "mesh_backhaul_5gh", ow_state_barrier_vif_conf_type_device},
    {"home-ap-24",    3,  0, "private_ssid_2g",   ow_state_barrier_vif_conf_type_device},
    {"home-ap-l50",   4,  1, "private_ssid_5gl",  ow_state_barrier_vif_conf_type_device},
    {"home-ap-u50",   5,  2, "private_ssid_5gh",  ow_state_barrier_vif_conf_type_device},
    {"bhaul-sta-24",  6,  0, "mesh_sta_2g",       ow_state_barrier_vif_conf_type_device},
    {"bhaul-sta-l50", 7,  1, "mesh_sta_5gl",      ow_state_barrier_vif_conf_type_device},
    {"bhaul-sta-u50", 8,  2, "mesh_sta_5gh",      ow_state_barrier_vif_conf_type_device},
    {"svc-d-ap-24",   9,  0, "lnf_psk_2g",        ow_state_barrier_vif_conf_type_device},
    {"svc-d-ap-l50",  10, 1, "lnf_psk_5gl",       ow_state_barrier_vif_conf_type_device},
    {"svc-d-ap-u50",  11, 2, "lnf_psk_5gh",       ow_state_barrier_vif_conf_type_device},
    {"svc-e-ap-24",   12, 0, "iot_ssid_2g",       ow_state_barrier_vif_conf_type_device},
    {"svc-e-ap-l50",  13, 1, "iot_ssid_5gl",      ow_state_barrier_vif_conf_type_device},
    {"svc-e-ap-u50",  14, 2, "iot_ssid_5gh",      ow_state_barrier_vif_conf_type_device},
};

ow_state_barrier_phy_info_t phy_list[] = {
    {"wifi0", 0},
    {"wifi1", 1},
    {"wifi2", 2},
};
static unsigned int prev_sta_connected_idx = 0;
static bool sta_reconnect = false;

static int if_name_to_phy_index(const char *if_name)
{
    for(unsigned int i = 0; i < ARRAY_SIZE(vif_list) ; i++) {
        if (strcmp(vif_list[i].if_name, if_name) == 0) {
            return vif_list[i].phy_index;
        }
    }

    return -1;
}

static char *phy_index_to_phy_name(const int phy_index)
{
    for (unsigned int i = 0; i < ARRAY_SIZE(phy_list); i++) {
        ow_state_barrier_phy_info_t *phy = &phy_list[i];

        if (phy->phy_index == phy_index) {
            return phy->phy_name;
        }
    }

    return NULL;
}

bool vap_svc_is_mesh_ext(unsigned int vap_index)
{
    return isVapSTAMesh(vap_index) ? true : false;
}

BOOL vap_svc_is_mesh_sta(char *vap_name)
{
    if (!vap_name)
        return FALSE;
    
    return (strncmp(vap_name, "mesh_sta", strlen("mesh_sta"))) ? FALSE :TRUE;
}

int vap_svc_mesh_ext_disconnect(vap_svc_t *svc)
{
   return 0;
}

void vap_svc_mesh_pod_ap_connection_handler(struct ow_barrier_sta_conn_info *sta_conn_info, wifi_bss_info_t *bss_info, wifi_station_stats_t *sta, int index)
{
    wifi_monitor_data_t *data;
    wifi_monitor_t *monitor;
    wifi_event_subtype_t type;
    wifi_event_t *event;
    assoc_dev_data_t assoc_data = { 0 };
    char mac_str[32] = { 0 };
    wifi_event_subtype_t sub_type;

    if (!bss_info || !sta) {
        return;
    }

    switch (sta->connect_status) {
        case wifi_connection_status_connected:
            assoc_data.dev_stats.cli_Active = TRUE;
            type = wifi_event_hal_assoc_device;
            break;

        case wifi_connection_status_disconnected:
            assoc_data.dev_stats.cli_Active = FALSE;
            type = wifi_event_hal_disassoc_device;
            break;

        default:
            return;
    }

    memcpy(assoc_data.dev_stats.cli_MACAddress, sta_conn_info->mac, sizeof(mac_address_t));
    assoc_data.ap_index = index;
    push_event_to_ctrl_queue(&assoc_data, sizeof(assoc_data), wifi_event_type_hal_ind, type, NULL);

    if (!(monitor = get_wifi_monitor())) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Monitor is not available!\n", __func__, __LINE__);
        return;
    }


    sub_type = (sta->connect_status == wifi_connection_status_connected) ? wifi_event_monitor_connect : wifi_event_monitor_disconnect;
    event = (wifi_event_t *)create_wifi_event(sizeof(wifi_monitor_data_t), wifi_event_type_monitor, sub_type);
    if (event == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Unable to allocate memory!\n", __func__, __LINE__);
        return;
    }

    data = event->u.mon_data;
    data->ap_index = index;
    memcpy(data->u.dev.sta_mac, sta_conn_info->mac, sizeof(mac_address_t));

    pthread_mutex_lock(&monitor->queue_lock);
    queue_push(monitor->queue, event);
    pthread_cond_signal(&monitor->cond);
    pthread_mutex_unlock(&monitor->queue_lock);

    uint8_mac_to_string_mac(sta_conn_info->mac, mac_str);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d: STA [%s] %s\n", __func__, __LINE__, mac_str, (sta->connect_status == wifi_connection_status_connected) ? "connected" : "disconnected");
}

void ow_mesh_ext_sta_conn_connection_callback(struct ow_barrier_sta_conn_info *sta_conn_info, 
                                          wifi_bss_info_t *bss_info, wifi_station_stats_t *sta)
{
    int vap_index = 0;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    wifi_vap_name_t vap_name;
    
    if (convert_ifname_to_vapname(&g_wifi_mgr->hal_cap.wifi_prop, (char *)sta_conn_info->if_name, vap_name, sizeof(vap_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: cannot convert vif_name=%s to vap_name\n", __func__, __LINE__, sta_conn_info->if_name);
        return;
    }
    vap_index = convert_vap_name_to_index(&g_wifi_mgr->hal_cap.wifi_prop, vap_name); 

    if (isVapSTAMesh(vap_index)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: STA connection status changed [%s]\n", __func__, __LINE__,sta_conn_info->if_name);
        sta->vap_index = vap_index;
        sta_connection_handler(sta_conn_info->if_name, bss_info, sta);
    }
    else {
        vap_svc_mesh_pod_ap_connection_handler(sta_conn_info, bss_info, sta, vap_index);
    }
}


void
ow_mesh_ext_sta_conn_status_cb_register(ow_cbs_register_staConnected_fn_t *conn_fn)
{
    struct ow_cbs_register_observer g_ow_cbs;

    memset(&g_ow_cbs,0,sizeof(g_ow_cbs));
    g_ow_cbs.staConnectedfn = conn_fn;
    g_ow_cbs.staDisconnectedfn = conn_fn;
    ow_register_observer(&g_ow_cbs);
}

void
ow_mesh_ext_chan_event_cb_register(ow_state_barrier_channel_event_fn_t *cb)
{
    ow_state_barrier_channel_event_register(cb);
}

void vap_mesh_svc_pod_phy_config_cb(ow_phy_oper_param_t  *phy_param)
{
    ow_webconfig_set_phy(phy_param->if_name, phy_param->phy);
}

int ow_mesh_ext_set_phy_config(int phy_index,wifi_radio_operationParam_t *phy)
{
    ow_phy_oper_param_t phy_param;
    wifi_platform_property_t *prop = NULL;

    memset(&phy_param,0,sizeof(phy_param));
    phy_param.phy = phy;

    prop = (wifi_platform_property_t *) get_wifi_hal_cap_prop();
    strncpy(phy_param.if_name,prop->radio_interface_map[phy_index].interface_name,sizeof(phy_param.if_name));

    wifi_util_dbg_print(WIFI_CTRL,"WIFI %s : Setting Phy %s with channel:[%d], enable:[%d], band[%d],width[%d] \n",__FUNCTION__,phy_param.if_name,phy->channel,phy->enable,phy->band,phy->channelWidth);
    
    ow_core_thread_call(vap_mesh_svc_pod_phy_config_cb, &phy_param);
    ow_state_barrier_wait(OW_SETTLED_TIMEOUT, phy_param.if_name);
    return RETURN_OK;
}

void ow_core_update_vap_mac(char *if_name, wifi_vap_info_t *vap_info)
{
    int phy_index;
    mac_address_t mac_addr;
    char mac_str[32] = { 0 };

    if (vap_info->vap_mode == wifi_vap_mode_ap) {
        if (ow_state_barrier_get_vif_mac(if_name, mac_addr) != 0) {

            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Not able to get MAC address for %s\n", __FUNCTION__, __LINE__, if_name);
            return;
        }
        if(!is_bssid_valid(mac_addr)) {
            wifi_util_dbg_print(WIFI_CTRL,"Vap mac is empty or invalid \n");
            return;
        }
        memcpy(vap_info->u.bss_info.bssid, mac_addr, sizeof(mac_address_t));
        uint8_mac_to_string_mac(vap_info->u.bss_info.bssid, mac_str);
    }
    else {
        if ((phy_index = if_name_to_phy_index(if_name)) < 0 ||
            ow_state_barrier_get_phy_mac(phy_index, mac_addr) != 0) {

            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Not able to get MAC address for %s\n", __FUNCTION__, __LINE__, if_name);
            return;
        }

        if(!is_bssid_valid(mac_addr)) {
            wifi_util_dbg_print(WIFI_CTRL,"Vap mac is empty or invalid \n");
            return;
        }

        memcpy(vap_info->u.sta_info.mac, mac_addr, sizeof(mac_address_t));
        uint8_mac_to_string_mac(vap_info->u.sta_info.mac, mac_str);
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s : Updated MAC [%s] for %s\n", __FUNCTION__, mac_str, if_name);
}

void vap_mesh_svc_pod_vif_config_cb(ow_vif_config_param_t *vif_param)
{
    ow_webconfig_set_vif(vif_param->phy_name, vif_param->vif_name, vif_param->vap);    
}

void vap_mesh_svc_pod_vif_config(ow_vif_config_param_t *vif_param)
{
    wifi_vap_info_map_t *vap_map;
    uint8_t num_radios = getNumberRadios();

    ow_core_thread_call(vap_mesh_svc_pod_vif_config_cb, vif_param);
    ow_state_barrier_wait(OW_SETTLED_TIMEOUT, vif_param->vif_name);

    for (uint8_t i = 0; i < num_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);

        for (uint8_t j = 0; j < vap_map->num_vaps; j++) {
            wifi_vap_info_t *vap = &vap_map->vap_array[j];

            if (strcmp(vap->vap_name, vif_param->vap->vap_name) == 0) {

                ow_core_update_vap_mac(vif_param->vif_name, vap);
                return;
            }
        }
    }
}

int vap_svc_mesh_ext_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    uint8_t num_of_radios;
    uint8_t j;
    int i;
    int ret;
    wifi_vap_info_map_t *vap_map = NULL, tgt_vap_map;
    ow_vif_config_param_t vif_config;
    rdk_wifi_vap_info_t *rdk_vap_info;
    char mac_str[32] = { 0 };

    if ((num_of_radios = getNumberRadios()) > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_CTRL,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return RETURN_ERR;
    }

    vap_svc_ext_t *ext;
    ext = &svc->u.ext;
    ext->conn_state = connection_state_connection_in_progress;
    for (i = num_of_radios-1; i >= 0; i--) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return RETURN_ERR;
        }

        memset(&tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
        for (j = 0; j < vap_map->num_vaps; j++) {
            if (svc->is_my_fn(vap_map->vap_array[j].vap_index) == false) {
                continue;
            }

            rdk_vap_info = get_wifidb_rdk_vap_info(vap_map->vap_array[j].vap_index);
            if (rdk_vap_info == NULL) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get rdk vap info for index %d\n",__func__, __LINE__, vap_map->vap_array[j].vap_index);
                continue;
            }

            if (rdk_vap_info->exists == false) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:VAP [%s] doesnt exist, Skip enabling\n",__FUNCTION__,vap_map->vap_array[j].vap_name );
                continue;
            } else {
                wifi_util_dbg_print(WIFI_CTRL,"%s:VAP [%s] exist, enabling..\n",__FUNCTION__,vap_map->vap_array[j].vap_name );
            }

            memcpy((unsigned char *)&tgt_vap_map.vap_array[tgt_vap_map.num_vaps], (unsigned char *)&vap_map->vap_array[j], sizeof(wifi_vap_info_t));

            wifi_util_dbg_print(WIFI_CTRL,"%s:Configuting backhaul vap with ssid : %s\n",__FUNCTION__,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].u.sta_info.ssid );
            memset(&vif_config,0,sizeof(vif_config));
            vif_config.vap = &tgt_vap_map.vap_array[tgt_vap_map.num_vaps];
            ret = convert_radio_index_to_ifname(svc->prop,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].radio_index,vif_config.phy_name,sizeof(vif_config.phy_name));
            if (ret != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:Failed to get phy name.",__FUNCTION__);
                return RETURN_ERR;
            }
            ret = convert_apindex_to_ifname(svc->prop,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].vap_index,vif_config.vif_name ,sizeof(vif_config.vif_name));
            if (ret != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:Failed to get interface name.",__FUNCTION__);
                return RETURN_ERR;
            }
            // If interface is already enbaled restart network
            if ((vap_map->vap_array[j].u.sta_info.enabled == true && 
                  prev_sta_connected_idx == vap_map->vap_array[j].vap_index) || sta_reconnect) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:Interface already enabled & connected- Restarting network..\n",__FUNCTION__);
                tgt_vap_map.vap_array[tgt_vap_map.num_vaps].u.sta_info.enabled = false;
                vap_mesh_svc_pod_vif_config(&vif_config);
                sta_reconnect = false;
            }

            memset(mac_str,0,sizeof(mac_str));
            uint8_mac_to_string_mac(tgt_vap_map.vap_array[tgt_vap_map.num_vaps].u.sta_info.bssid, mac_str); 
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Start Connecting to bssid [%s]\n", __func__, __LINE__,mac_str);
 
            tgt_vap_map.vap_array[tgt_vap_map.num_vaps].u.sta_info.enabled = true; 
            vap_mesh_svc_pod_vif_config(&vif_config);
            vap_map->vap_array[j].u.sta_info.enabled = true;
            tgt_vap_map.num_vaps++;
        }
   }
   return RETURN_OK;
}

int vap_svc_mesh_ext_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    uint8_t j;
    int ret;
    wifi_vap_info_map_t *vap_map = NULL, tgt_vap_map;
    ow_vif_config_param_t vif_config;
    wifi_vap_name_t  vap_name;
    rdk_wifi_vap_info_t *rdk_vap_info;

    wifi_util_dbg_print(WIFI_CTRL,"%s:Disabling STA vap for radio [%d]\n",__FUNCTION__,radio_index);

    vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_index);
    if (vap_map == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__,radio_index);
        return RETURN_ERR;
    }

    memset(&tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
    memset(&vif_config,0,sizeof(vif_config));

    for (j = 0; j < vap_map->num_vaps; j++) {

        if (svc->is_my_fn(vap_map->vap_array[j].vap_index) == false) {
            continue;
        }

        if (vap_map->vap_array[j].u.sta_info.enabled != true) {
            continue;
        }
       
        rdk_vap_info = get_wifidb_rdk_vap_info(vap_map->vap_array[j].vap_index);
        if (rdk_vap_info == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get rdk vap info for index %d\n",__func__, __LINE__, vap_map->vap_array[j].vap_index);
            continue;
        }

        if (rdk_vap_info->exists == false) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:VAP [%s] doesnt exist, Skip disabling\n",__FUNCTION__,vap_map->vap_array[j].vap_name );
            continue;
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"%s:VAP [%s] Exists disabling..\n",__FUNCTION__,vap_map->vap_array[j].vap_name );
        }

        memcpy((unsigned char *)&tgt_vap_map.vap_array[tgt_vap_map.num_vaps], (unsigned char *)&vap_map->vap_array[j], sizeof(wifi_vap_info_t));
        tgt_vap_map.vap_array[tgt_vap_map.num_vaps].u.sta_info.enabled = false;

        wifi_util_dbg_print(WIFI_CTRL,"%s:Stopping vap [%s]\n",__FUNCTION__,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].vap_name );
        vif_config.vap = &tgt_vap_map.vap_array[tgt_vap_map.num_vaps];
        ret = convert_radio_index_to_ifname(svc->prop,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].radio_index,vif_config.phy_name,sizeof(vif_config.phy_name));
        if (ret != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:Failed to get phy name.\n",__FUNCTION__);
            return RETURN_ERR;
        }
        ret = convert_apindex_to_ifname(svc->prop,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].vap_index,vif_config.vif_name ,sizeof(vif_config.vif_name));
        if (ret != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:Failed to get interface name.\n",__FUNCTION__);
            return RETURN_ERR;
        }

        // Convert VAP name to vif_name
        memset(vap_name,0,sizeof(vap_name)); 
        strncpy(vap_name,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].vap_name,sizeof(vap_name));
        strncpy(tgt_vap_map.vap_array[tgt_vap_map.num_vaps].vap_name,vif_config.vif_name,sizeof(wifi_vap_name_t));
        wifi_util_dbg_print(WIFI_CTRL,"%s:Calling vap_mesh_svc_pod_vif_config vap name [%s]\n",__FUNCTION__,tgt_vap_map.vap_array[tgt_vap_map.num_vaps].vap_name);
        vap_mesh_svc_pod_vif_config(&vif_config);
        strncpy(tgt_vap_map.vap_array[tgt_vap_map.num_vaps].vap_name,vap_name,sizeof(wifi_vap_name_t));
        vap_map->vap_array[j].u.sta_info.enabled = false;
        tgt_vap_map.num_vaps++;
    }

    return RETURN_OK;
}

static char* get_bhaul_creds_path_by_vap_idx(unsigned int vap_index, char* buf, size_t buf_len)
{
    if (!buf) {
        return NULL;
    }

    snprintf(buf, buf_len, "%s%u", BHAUL_CREDS_DIR, vap_index);

    return buf;
}

static bool save_bhaul_creds(unsigned int vap_index, ssid_t ssid, wifi_security_key_t *security_key)
{
    /* consider directory exists */
    char fpath[BHAUL_CREDS_PATH_LEN + 1] = {0};
    if (!get_bhaul_creds_path_by_vap_idx(vap_index, fpath, BHAUL_CREDS_PATH_LEN)) {
        wifi_util_dbg_print(WIFI_CTRL, "Error getting bhaul creds by vap index !!!\n");
        return false;
    }

    int rc = mkdir(BHAUL_CREDS_DIR, 0700);
    if (rc != 0 && errno != EEXIST) {
        wifi_util_dbg_print(WIFI_CTRL, "Creating directory [%s] failed !!!\n", BHAUL_CREDS_DIR);
        return false;
    }

    FILE *fp = fopen(fpath, "w");
    if (!fp) {
        wifi_util_dbg_print(WIFI_CTRL, "Error opening file [%s] !!!\n", fpath);
        return false;
    }

    fprintf(fp, "%.*s\n", sizeof(ssid_t) - 1,            ssid);
    fprintf(fp, "%.*s\n", sizeof(security_key->key) - 1, security_key->key);

    fclose(fp);
    return true;
}

static bool is_bhaul_creds_changed(unsigned int vap_index, ssid_t new_ssid, wifi_security_key_t *new_security_key)
{
    bool is_changed = false;
    FILE* fp = NULL;
    char fpath[BHAUL_CREDS_PATH_LEN + 1] = {0};
    char old_ssid[SSID_MAX_LEN + 1] = {0};
    char old_key[KEY_MAX_LEN + 1] = {0};

    if (!get_bhaul_creds_path_by_vap_idx(vap_index, fpath, BHAUL_CREDS_PATH_LEN)) {
        return false;
    }

    fp = fopen(fpath, "r");
    if (!fp)
    {
        return true;
    }

    if (fgets(old_ssid, SSID_MAX_LEN, fp) == 0) {
        is_changed = true;
        goto exit;
    }
    old_ssid[strcspn(old_ssid, "\n")] = 0;

    if (fgets(old_key, KEY_MAX_LEN, fp) == 0) {
        is_changed = true;
        goto exit;
    }
    old_key[strcspn(old_key, "\n")] = 0;

    is_changed |= !!strncmp(old_ssid, new_ssid,              SSID_MAX_LEN);
    is_changed |= !!strncmp(old_key,  new_security_key->key, KEY_MAX_LEN);
    if (is_changed) {
        wifi_util_dbg_print(WIFI_CTRL,"%s: Changed vap[%d]\n", __func__, vap_index);
        wifi_util_dbg_print(WIFI_CTRL,"%s: old_ssid[%s] new_ssid[%s]\n", __func__, old_ssid, new_ssid);
    }

exit:
    fclose(fp);
    return is_changed;
}

static bool backup_bhaul_creds()
{
    bool success = true;
    /* TODO: enhance the partial backup approach */
    wifi_back_haul_sta_t *sta_cfg_active = NULL;
    int vap_index = 0;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS] = {0};
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();
    unsigned int num_vaps = get_list_of_mesh_sta(&wifi_hal_cap_obj->wifi_prop, MAX_NUM_RADIOS, &vap_names[0]);

    for (size_t i = 0; i < num_vaps; i++) {
        vap_index = convert_vap_name_to_index(&wifi_hal_cap_obj->wifi_prop, vap_names[i]);
        if (vap_index == RETURN_ERR) {
            continue;
        }

        sta_cfg_active = (wifi_back_haul_sta_t *) get_wifi_object_sta_parameter(vap_index);
        if (sta_cfg_active->enabled) {
            wifi_util_dbg_print(WIFI_CTRL,"%s: active if[%s]\n", __func__, vap_names[i]);
            break;
        }
    }

    if (!sta_cfg_active) {
        return false;
    }

    for (size_t i = 0; i < num_vaps; i++) {
        vap_index = convert_vap_name_to_index(&wifi_hal_cap_obj->wifi_prop, vap_names[i]);
        if (vap_index != RETURN_ERR
            && is_bhaul_creds_changed(vap_index, sta_cfg_active->ssid, &sta_cfg_active->security.u.key))
        {
            success &= save_bhaul_creds(vap_index, sta_cfg_active->ssid, &sta_cfg_active->security.u.key);
            wifi_util_dbg_print(WIFI_CTRL,"%s: save_bhaul_creds vap[%d]\n", __func__, vap_index);
        }
    }

    return success;
}

int vap_svc_mesh_ext_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    unsigned int i;

    for (i = 0; i < map->num_vaps; i++) {
        wifidb_update_wifi_vap_info(getVAPName(map->vap_array[i].vap_index), &map->vap_array[i],
            &rdk_vap_info[i]);
        wifidb_update_wifi_security_config(getVAPName(map->vap_array[i].vap_index),
            &map->vap_array[i].u.sta_info.security);
    }

    bool backup_success = backup_bhaul_creds();
    wifi_util_dbg_print(WIFI_CTRL,"Partial backup is %s\n", backup_success ? "succeeded" : "failed");

    return 0;
}

int process_ext_scan_results(vap_svc_t *svc, void *arg)
{
    return 0;
}

int publish_ext_sta_connection_status(wifi_ctrl_t *ctrl,int index, wifi_connection_status_t connect_status)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    char name[64];

    memset (name,0,sizeof(name));

    sprintf(name, "Device.WiFi.STA.%d.Connection.Status", index + 1);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus name:%s:connection status:%d\r\n", __func__, __LINE__,
                    name, connect_status);

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, name, value);
    rbusValue_SetBytes(value, (uint8_t *)&connect_status, sizeof(wifi_connection_status_t));
    event.name = name;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    if (rbusEvent_Publish(ctrl->rbus_handle, &event) != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);

        rbusValue_Release(value);
        rbusObject_Release(rdata);

        return RETURN_ERR;
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

int process_ext_sta_conn_status(vap_svc_t *svc, void *arg)
{
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *temp_vap_info = NULL;
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)arg;
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;
    bool  send_event = false;
    unsigned int i, index;
    wifi_radio_operationParam_t *radio_params = NULL;
    wifi_radio_feature_param_t *radio_feat = NULL;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->ext_conn_status_ind_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_conn_status_ind_timeout_handler_id);
        ext->ext_conn_status_ind_timeout_handler_id = 0;
    }

    /* first update the internal cache */
    index = get_radio_index_for_vap_index(svc->prop, sta_data->stats.vap_index);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d - radio index %d, VAP index %d.\n", __func__, __LINE__, index, sta_data->stats.vap_index);
    vap_map = &mgr->radio_config[index].vaps.vap_map;

    for (i = 0; i < vap_map->num_vaps; i++) {
        if (vap_map->vap_array[i].vap_index == sta_data->stats.vap_index) {
            temp_vap_info = &vap_map->vap_array[i];
            if (temp_vap_info->u.sta_info.conn_status == sta_data->stats.connect_status &&
                is_bssid_valid(sta_data->bss_info.bssid) &&
                memcmp(temp_vap_info->u.sta_info.bssid, sta_data->bss_info.bssid, sizeof(bssid_t)) == 0) {
                wifi_util_info_print(WIFI_CTRL, "%s:%d: received duplicated wifi_event_hal_sta_conn_status event.\n", __func__, __LINE__);
                return 0;
            }
            temp_vap_info->u.sta_info.conn_status = sta_data->stats.connect_status;
            break;
        }
    }

    if (temp_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: temp_vap_info is NULL \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (sta_data->stats.connect_status == wifi_connection_status_connected) {

        if (ext->conn_state == connection_state_connection_in_progress) { 
             memset(&ext->last_connected_bss, 0, sizeof(bss_candidate_t));
             memcpy(&ext->last_connected_bss.external_ap, &sta_data->bss_info, sizeof(wifi_bss_info_t));
             ext->connected_vap_index = sta_data->stats.vap_index;

             convert_radio_index_to_freq_band(svc->prop, index, (int*)&ext->last_connected_bss.radio_freq_band);
             wifi_util_dbg_print(WIFI_CTRL,"%s:%d - Connected radio_band:%d\r\n", __func__, __LINE__, ext->last_connected_bss.radio_freq_band);

            memcpy (temp_vap_info->u.sta_info.bssid, sta_data->bss_info.bssid, sizeof(temp_vap_info->u.sta_info.bssid));
            //send_event = true;
            radio_feat = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map(index);
            
            radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index);
            if (radio_params != NULL) {
                if ((sta_data->stats.channel != 0 && radio_params->channel != sta_data->stats.channel) ||
                    (sta_data->stats.channelWidth != 0 && radio_params->channelWidth != sta_data->stats.channelWidth)) {
                    pthread_mutex_lock(&mgr->data_cache_lock);
                    radio_params->channel = sta_data->stats.channel;
                    radio_params->channelWidth = sta_data->stats.channelWidth;
                    radio_params->op_class = sta_data->stats.op_class;
                    pthread_mutex_unlock(&mgr->data_cache_lock);

                    mgr->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
                    start_wifi_sched_timer(index, ctrl, wifi_radio_sched);
                    update_wifi_radio_config(index, radio_params, radio_feat);
                }
            }

            // Stop other STA vaps
           for (i = 0; i < getNumberRadios(); i++) {
                if (i != temp_vap_info->radio_index) {
                     wifi_util_dbg_print(WIFI_CTRL,"%s:%d - Stopping STA vap on Radio [%d]\r\n", __func__, __LINE__,i);
                     vap_svc_mesh_ext_stop(svc, i, NULL);
                }
            }

           // Set State to connected only after all operations.
           ext->conn_state = connection_state_connected;
        }
        else {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d - Connect event from [%d]\r\n", __func__, __LINE__,sta_data->stats.vap_index);
            if (sta_data->stats.vap_index != prev_sta_connected_idx) {
                prev_sta_connected_idx = sta_data->stats.vap_index;
            }
        }
    } else if (sta_data->stats.connect_status == wifi_connection_status_disconnected) { 

        wifi_util_dbg_print(WIFI_CTRL,"%s:%d STA DISCONNECT. last_index = %d, new index = %d\n", __func__, __LINE__,ext->connected_vap_index,sta_data->stats.vap_index);

        if (ext->conn_state == connection_state_connected && ext->connected_vap_index == sta_data->stats.vap_index) {

            wifi_util_dbg_print(WIFI_CTRL,"%s:%d - STA disconnected vap index: %d.\n", __func__, __LINE__,sta_data->stats.vap_index);

            // Set conn_state to in progress immediately after disconnect
            ext->conn_state = connection_state_connection_in_progress;
            ext->connected_vap_index = 0;

            // Check if we received a disconnect from previous bssid -  parent switch. 
            if (is_bssid_valid(sta_data->bss_info.bssid) && is_bssid_valid(temp_vap_info->u.sta_info.bssid) &&
                    memcmp(&temp_vap_info->u.sta_info.bssid,sta_data->bss_info.bssid, sizeof(bssid_t)) ) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d - Disconnect event from previous bssid, try reconnct.\n", __func__, __LINE__);
                sta_reconnect = true;
            }

            wifi_util_dbg_print(WIFI_CTRL,"%s:%d - Restart enabled VAPs for STA connection.\n", __func__, __LINE__);
            vap_svc_mesh_ext_start(svc, WIFI_ALL_RADIO_INDICES, NULL);
            //send_event = true;
        }
        else if (ext->conn_state == connection_state_connected) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d - Received disconnect from a secondary interface. %d.\n", __func__, __LINE__,sta_data->stats.vap_index);
            if (sta_data->stats.vap_index == prev_sta_connected_idx) {
                prev_sta_connected_idx = 0;
            }
        }
        memset(&temp_vap_info->u.sta_info.bssid, 0, sizeof(temp_vap_info->u.sta_info.bssid));
    }
 
    if (send_event == true) {
        if (publish_ext_sta_connection_status(ctrl,index,sta_data->stats.connect_status) != RETURN_OK) {
             wifi_util_dbg_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);
             return RETURN_ERR;
         }
    }
    return RETURN_OK;
}

int process_ext_hal_ind(vap_svc_t *svc, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case wifi_event_scan_results:
            process_ext_scan_results(svc, arg);
            break;
            
        case wifi_event_hal_sta_conn_status:
            process_ext_sta_conn_status(svc, arg);
            break;

        case wifi_event_hal_channel_change:
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= wifi_event_hal_max);
        break;
    }

    return 0;
}

int process_ext_connect_algorithm(vap_svc_t *svc)
{
    return 0;
}

int vap_svc_mesh_ext_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg)
{
    switch (type) {
        case wifi_event_type_exec:
            break;

        case wifi_event_type_command:
            break;

        case wifi_event_type_hal_ind:
            process_ext_hal_ind(svc, sub_type, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: default - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            break;
    }

    return 0;
}

static wifi_freq_bands_t freq_band_from_radio_idx(int idx)
{
    switch(idx) {
        case 0:
            return WIFI_FREQUENCY_2_4_BAND;
        case 1:
            return WIFI_FREQUENCY_5L_BAND;
        case 2:
            return WIFI_FREQUENCY_5H_BAND;
    }
    return WIFI_FREQUENCY_2_4_BAND;
}

int get_vif_radio_index(const char *if_name)
{
    int vif_radio_index = -1;

    if(! strncmp(if_name, WIFI_BHAUL_STA_IF_PREFIX, strlen(WIFI_BHAUL_STA_IF_PREFIX))) 
    {
        vif_radio_index = 0;
    }
    else if(! strncmp(if_name, WIFI_BHAUL_AP_IF_PREFIX, strlen(WIFI_BHAUL_AP_IF_PREFIX)))
    {
        vif_radio_index = 1;
    }
    else if(! strncmp(if_name, WIFI_HOME_AP_IF_PREFIX, strlen(WIFI_HOME_AP_IF_PREFIX)))
    {
        vif_radio_index = 2;
    }
    else if(! strncmp(if_name, WIFI_LNF_AP_IF_PREFIX, strlen(WIFI_LNF_AP_IF_PREFIX)))
    {
        vif_radio_index = 4;
    }
    else if(! strncmp(if_name, WIFI_IOT_AP_IF_PREFIX, strlen(WIFI_IOT_AP_IF_PREFIX)))
    {
        vif_radio_index = 5;
    }

    return vif_radio_index;
}

void vap_svc_mesh_pod_set_capab_priv()
{
    struct osw_drv_target *target = osw_drv_target_get_ref();
    char phy_name[20];
    int vif_radio_idx = -1;

    for(unsigned int i = 0 ; i < ARRAY_SIZE(vif_list) ; i++)
    {
        ow_state_barrier_vif_info_t *vif = &vif_list[i];
        snprintf(phy_name, sizeof(phy_name), "wifi%d", vif->phy_index);
        osw_drv_target_vif_set_phy(target, vif->if_name, phy_name);
	    vif_radio_idx = get_vif_radio_index(vif->if_name);
        
        if(vif_radio_idx == -1)
        {
            wifi_util_dbg_print(WIFI_CTRL, "VIF not found = %s\n", vif->if_name);
            return;
        }
        osw_drv_target_vif_set_idx(target, vif->if_name, vif_radio_idx);
        osw_drv_target_phy_set_hw_type(target, phy_name, "qca4019");

        osw_drv_target_vif_set_mode(target, vif->if_name, vap_svc_is_mesh_sta(vif->vap_name) ? "sta" : "ap");
        osw_drv_target_vif_set_exists(target, vif->if_name, true);
        //osw_drv_target_phy_set_hw_config(target, phy_name, hw_config);
    }
}


void ow_mesh_ext_set_capab()
{
    ow_state_barrier_wait(OW_SETTLED_TIMEOUT, NULL);
    ow_core_thread_call(vap_svc_mesh_pod_set_capab_priv, NULL);
}

int ow_mesh_ext_get_hal_capab(wifi_hal_capability_t *halCapab)
{
    unsigned int num_radios;
    unsigned int num_vaps;
    unsigned int i,j;

    wifi_radio_capabilities_t *radio_capab = NULL;
    wifi_interface_name_idex_map_t *interface_map = NULL;
    ow_state_barrier_vif_info_t *vif = NULL;

    // Get HAL capability from HW
    if (ow_state_barrier_wait(OW_SETTLED_TIMEOUT, NULL) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d : Failed in ow_state_barrier_wait.\n",__func__, __LINE__);
        return RETURN_ERR;
    }

    if (ow_state_barrier_get_hal_capab(halCapab) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d : Failed to get hal capabilities.\n",__func__, __LINE__);
        return RETURN_ERR;
    }

    num_radios = halCapab->wifi_prop.numRadios;
    num_vaps = ARRAY_SIZE(vif_list);
    radio_capab = halCapab->wifi_prop.radiocap;
    interface_map = halCapab->wifi_prop.interface_map;

    // Fill rest of the parameters
    for(i = 0; i < num_radios; i++)
    {
        radio_capab[i].numSupportedFreqBand = 1;
        radio_capab[i].maxNumberVAPs = num_vaps/num_radios;
        radio_capab[i].band[0] = freq_band_from_radio_idx(i);
    }

    for(j = 0; j < num_vaps; j++)
    {
        vif = &vif_list[j];
        strncpy(interface_map[j].interface_name, vif->if_name,sizeof(wifi_interface_name_t));
        strncpy(interface_map[j].vap_name, vif->vap_name,sizeof(wifi_vap_name_t));
        interface_map[j].phy_index = vif->phy_index;
        interface_map[j].index = vif->vif_index;
        interface_map[j].rdk_radio_index = vif->phy_index ;
    }
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d ow: Hal caps initialized for %d radios. \r\n",__func__, __LINE__,num_radios);
    return RETURN_OK;
}

int ow_mesh_ext_get_radio_stats(int phy_index, wifi_radioTrafficStats2_t *stats)
{
    char *phy_name;

    if ((phy_name = phy_index_to_phy_name(phy_index)) == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Can't get phy_name for %d\n", __func__, __LINE__, phy_index);
        return RETURN_ERR;
    }

    return osw_drv_target_request_survey_stats(phy_name, stats);
}

int ow_mesh_ext_get_device_stats(int ap_index, char *radio_type, int nf,
    unsigned char *mac, wifi_associated_dev3_t *stats, int *sleep_mode)
{
    int phy_index = -1;
    char *phy_name = NULL;
    char *if_name = NULL;

    for(unsigned int i = 0 ; i < ARRAY_SIZE(vif_list) ; i++) {
        ow_state_barrier_vif_info_t *vif = &vif_list[i];

        if (vif->vif_index == ap_index) {
            phy_index = vif->phy_index;
            if_name = vif->if_name;
            break;
        }
    }

    if (phy_index == -1 || if_name == NULL || (phy_name = phy_index_to_phy_name(phy_index)) == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Invalid parameter! phy_index=%d, if_name=%s\n", __func__, __LINE__, phy_index, if_name);
        return RETURN_ERR;
    }

    return osw_drv_target_get_device_stats(radio_type, phy_name, if_name, mac, nf, stats, sleep_mode);
}

bool ow_mesh_ext_is_radio_enabled(int phy_index)
{
    char *phy_name;

    if (!(phy_name = phy_index_to_phy_name(phy_index))) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get phy_name for %d\n", __func__, __LINE__, phy_index);
        return false;
    }

    return ow_state_barrier_get_radio_presence(phy_name);
}

void ow_core_set_vif_cloud_conf_type(char *if_name)
{
    ow_state_barrier_vif_info_t *vif = NULL;

    for (unsigned int i = 0; i < ARRAY_SIZE(vif_list); i++) {
        vif = &vif_list[i];

        if (strcmp(vif->if_name, if_name) == 0) {
            break;
        }
    }

    if (vif == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to find VIF for [%s]\n", __func__, __LINE__, if_name);
        return;
    }

    if (vif->conf_type != ow_state_barrier_vif_conf_type_cloud) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d VIF [%s] conf type set to cloud\n", __func__, __LINE__, if_name);
        vif->conf_type = ow_state_barrier_vif_conf_type_cloud;
    }
}

bool ow_core_vif_conf_type_is_cloud(char *vap_name)
{
    for (unsigned int i = 0; i < ARRAY_SIZE(vif_list); i++) {
        if (strcmp(vif_list[i].vap_name, vap_name) == 0 &&
            vif_list[i].conf_type == ow_state_barrier_vif_conf_type_cloud) {
            return true;
        }
    }

    return false;
}

INT ow_core_get_default_country_code(int radio_index, char *code, int len)
{
    char *phy_name;

    if (!(phy_name = phy_index_to_phy_name(radio_index))) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get phy_name for %d\n", __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    if (!osw_drv_target_get_country_code(phy_name, code, len)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get country code for %s\n", __func__, __LINE__, phy_name);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT ow_core_get_reg_domain(int radio_index, int *reg_domain)
{
    char *phy_name;

    if (!(phy_name = phy_index_to_phy_name(radio_index))) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get phy_name for %d\n", __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    if (!osw_drv_target_get_reg_domain(phy_name, reg_domain)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get reg domain for %s\n", __func__, __LINE__, phy_name);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
