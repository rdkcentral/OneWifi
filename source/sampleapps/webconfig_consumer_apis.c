#include <stdio.h>
#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "scheduler.h"
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>
#include <libgen.h>
#include "errno.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"
#include "schema.h"
#include "webconfig_external_proto_ovsdb.h"
#include "wifi_webconfig_consumer.h"

#define MAX_NUM_CLIENTS 64

webconfig_consumer_t    webconfig_consumer;
webconfig_external_ovsdb_t    ext_proto;
BOOL is_ovs_init = false;
BOOL dml_init_sync = false;
BOOL enable_ovsdb = false;
BOOL debug_enable = false;
void free_ovs_schema_structs();
void dump_subdoc(const char *str, webconfig_subdoc_type_t type);
wifi_vap_info_t *get_wifi_radio_vap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix);
rdk_wifi_vap_info_t *get_wifi_radio_rdkvap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix);

static unsigned long long int cmd_start_time = 0;
static unsigned int cmd_delta_time = 0;
unsigned long long int get_current_time_ms(void)
{
    struct timeval tv_now = { 0 };
    unsigned long long int milliseconds = 0;
    gettimeofday(&tv_now, NULL);
    milliseconds = (tv_now.tv_sec*1000LL + tv_now.tv_usec/1000);
    return milliseconds;
}

webconfig_consumer_t *get_consumer_object()
{
    return &webconfig_consumer;
}

const char* testapp_security_config_find_by_key(
        const struct schema_Wifi_VIF_Config *vconf,
        char *key)
{
    int  i;
    for (i = 0; i < vconf->security_len; i++) {
        if (!strcmp(vconf->security_keys[i], key)) {
            return vconf->security[i];
        }
    }
    return NULL;
}


const char* testapp_security_state_find_by_key(
        const struct  schema_Wifi_VIF_State *vstate,
        char *key)
{
    int  i;
    for (i = 0; i < vstate->security_len; i++) {
        if (!strcmp(vstate->security_keys[i], key)) {
            return vstate->security[i];
        }
    }
    return NULL;
}

void print_radio_state_ovs_schema(FILE  *fp, const struct schema_Wifi_Radio_State *radio)
{
    int  i;
    fprintf(fp, "if_name                   : %s\n",   radio->if_name);
    fprintf(fp, "freq_band                 : %s\n",   radio->freq_band);
    fprintf(fp, "enabled                   : %d\n",   radio->enabled);
    fprintf(fp, "dfs_demo                  : %d\n",   radio->dfs_demo);
    fprintf(fp, "hw_type                   : %s\n", radio->hw_type);
    //fprintf(fp, "hw_config               : %s\n", radio->hw_config);
    fprintf(fp, "country                   : %s\n",   radio->country);
    fprintf(fp, "channel                   : %d\n",   radio->channel);
    fprintf(fp, "channel_sync              : %d\n",   radio->channel_sync);
    fprintf(fp, "channel_mode              : %s\n",   radio->channel_mode);
    fprintf(fp, "hw_mode                   : %s\n",   radio->hw_mode);
    fprintf(fp, "ht_mode                   : %s\n",   radio->ht_mode);
    fprintf(fp, "thermal_shutdown          : %d\n",   radio->thermal_shutdown);
    fprintf(fp, "thermal_downgrade_temp    : %d\n",   radio->thermal_downgrade_temp);
    fprintf(fp, "thermal_upgrade_temp      : %d\n",   radio->thermal_upgrade_temp);
    fprintf(fp, "thermal_integration       : %d\n",   radio->thermal_integration);
    //fprintf(fp, "temperature_control       : %s\n",   radio->temperature_control);
    fprintf(fp, "tx_power                  : %d\n",   radio->tx_power);
    fprintf(fp, "bcn_int                   : %d\n",   radio->bcn_int);
    fprintf(fp, "tx_chainmask              : %d\n",   radio->tx_chainmask);
    fprintf(fp, "thermal_tx_chainmask      : %d\n",   radio->thermal_tx_chainmask);
    fprintf(fp, "zero_wait_dfs             : %s\n",   radio->zero_wait_dfs);
    fprintf(fp, "allowedchannels           : ");
    for (i = 0; i< radio->allowed_channels_len; i++) {
            fprintf(fp, "%d,", radio->allowed_channels[i]);
    }
    fprintf(fp, "\n");
    //mac
    //allowed_channels
    //channels

    return;
}

void print_radio_config_ovs_schema(FILE  *fp, const struct schema_Wifi_Radio_Config *radio)
{
    fprintf(fp, "if_name                   : %s\n",   radio->if_name);
    fprintf(fp, "freq_band                 : %s\n",   radio->freq_band);
    fprintf(fp, "enabled                   : %d\n",   radio->enabled);
    fprintf(fp, "dfs_demo                  : %d\n",   radio->dfs_demo);
    fprintf(fp, "hw_type                   : %s\n", radio->hw_type);
    //fprintf(fp, "hw_config               : %s\n", radio->hw_config);
    fprintf(fp, "country                   : %s\n",   radio->country);
    fprintf(fp, "channel                   : %d\n",   radio->channel);
    fprintf(fp, "channel_sync              : %d\n",   radio->channel_sync);
    fprintf(fp, "channel_mode              : %s\n",   radio->channel_mode);
    fprintf(fp, "hw_mode                   : %s\n",   radio->hw_mode);
    fprintf(fp, "ht_mode                   : %s\n",   radio->ht_mode);
    fprintf(fp, "thermal_shutdown          : %d\n",   radio->thermal_shutdown);
    fprintf(fp, "thermal_downgrade_temp    : %d\n",   radio->thermal_downgrade_temp);
    fprintf(fp, "thermal_upgrade_temp      : %d\n",   radio->thermal_upgrade_temp);
    fprintf(fp, "thermal_integration       : %d\n",   radio->thermal_integration);
    //fprintf(fp, "temperature_control       : %s\n",   radio->temperature_control);
    fprintf(fp, "tx_power                  : %d\n",   radio->tx_power);
    fprintf(fp, "bcn_int                   : %d\n",   radio->bcn_int);
    fprintf(fp, "tx_chainmask              : %d\n",   radio->tx_chainmask);
    fprintf(fp, "thermal_tx_chainmask      : %d\n",   radio->thermal_tx_chainmask);
    fprintf(fp, "zero_wait_dfs             : %s\n",   radio->zero_wait_dfs);

    return;
}

void print_vif_state_ovs_schema(FILE  *fp, const struct schema_Wifi_VIF_State *vif)
{
    int i = 0;
    fprintf(fp, " if_name                   : %s\n",   vif->if_name);
    fprintf(fp, " enabled                   : %d\n",   vif->enabled);
    fprintf(fp, " mode                      : %s\n",   vif->mode);
    fprintf(fp, " vif_radio_idx             : %d\n",   vif->vif_radio_idx);
    fprintf(fp, " mac                       : %s\n",   vif->mac);
    fprintf(fp, " wds                       : %d\n",   vif->wds);
    fprintf(fp, " ssid                      : %s\n",   vif->ssid);
    fprintf(fp, " ssid_broadcast            : %s\n",   vif->ssid_broadcast);
    fprintf(fp, " bridge                    : %s\n",   vif->bridge);
    fprintf(fp, " mac_list_type             : %s\n",   vif->mac_list_type);
    fprintf(fp, " vlan_id                   : %d\n",   vif->vlan_id);
    fprintf(fp, " min_hw_mode               : %s\n",   vif->min_hw_mode);
    fprintf(fp, " uapsd_enable              : %d\n",   vif->uapsd_enable);
    fprintf(fp, " group_rekey               : %d\n",   vif->group_rekey);
    fprintf(fp, " ap_bridge                 : %d\n",   vif->ap_bridge);
    fprintf(fp, " ft_psk                    : %d\n",   vif->ft_psk);
    fprintf(fp, " ft_mobility_domain        : %d\n",   vif->ft_mobility_domain);
    fprintf(fp, " rrm                       : %d\n",   vif->rrm);
    fprintf(fp, " btm                       : %d\n",   vif->btm);
    fprintf(fp, " dynamic_beacon            : %d\n",   vif->dynamic_beacon);
    fprintf(fp, " mcast2ucast               : %d\n",   vif->mcast2ucast);
    fprintf(fp, " multi_ap                  : %s\n",   vif->multi_ap);
    fprintf(fp, " wps                       : %d\n",   vif->wps);
    fprintf(fp, " wps_pbc                   : %d\n",   vif->wps_pbc);
    fprintf(fp, " wps_pbc_key_id            : %s\n",   vif->wps_pbc_key_id);
    fprintf(fp, " wpa                       : %d\n",   vif->wpa);
    fprintf(fp, " parent                    : %s\n",   vif->parent);
    //#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    const char *str;

    str = testapp_security_state_find_by_key(vif, "encryption");
    if (str != NULL) {
        fprintf(fp, " encryption                : %s\n",   str);
    }

    str = testapp_security_state_find_by_key(vif, "mode");
    if (str != NULL) {
        fprintf(fp, " sec mode                  : %s\n",   str);
    }

    str = testapp_security_state_find_by_key(vif, "key");
    if (str != NULL) {
        fprintf(fp, " key                       : %s\n",   str);
    }
    /*
#else
    for (i=0; i<vif->wpa_key_mgmt_len; i++) {
        if (vif->wpa_key_mgmt[i] != NULL) {
            fprintf(fp, " wpa_key_mgmt                : %s\n",   vif->wpa_key_mgmt[i]);
        }
    }
    for (i=0; i<vif->wpa_psks_len; i++) {
        if (vif->wpa_psks[i] != NULL) {
            fprintf(fp, " wpa_psk                : %s\n",   vif->wpa_psks[i]);
        }
    }
#endif
*/
    for (i=0; i<vif->mac_list_len; i++) {
        if (vif->mac_list[i] != NULL) {
            fprintf(fp, " mac_list                : %s\n",   vif->mac_list[i]);
        }
    }
    //  fprintf(fp, " wpa_psks                  : %s\n",   vif->wpa_psks);
    //  fprintf(fp, " wpa_oftags                : %s\n",   vif->wpa_oftags);
    fprintf(fp, " radius_srv_addr           : %s\n",   vif->radius_srv_addr);
    fprintf(fp, " radius_srv_port           : %d\n",   vif->radius_srv_port);
    fprintf(fp, " radius_srv_secret         : %s\n",   vif->radius_srv_secret);

    return;
}

void print_vif_config_ovs_schema(FILE  *fp, const struct schema_Wifi_VIF_Config *vif)
{
    int i = 0;
    fprintf(fp, " if_name                   : %s\n",   vif->if_name);
    fprintf(fp, " enabled                   : %d\n",   vif->enabled);
    fprintf(fp, " mode                      : %s\n",   vif->mode);
    fprintf(fp, " vif_radio_idx             : %d\n",   vif->vif_radio_idx);
    fprintf(fp, " vif_dbg_lvl               : %d\n",   vif->vif_dbg_lvl);
    fprintf(fp, " wds                       : %d\n",   vif->wds);
    fprintf(fp, " ssid                      : %s\n",   vif->ssid);
    fprintf(fp, " ssid_broadcast            : %s\n",   vif->ssid_broadcast);
    fprintf(fp, " bridge                    : %s\n",   vif->bridge);
    fprintf(fp, " mac_list_type             : %s\n",   vif->mac_list_type);
    fprintf(fp, " vlan_id                   : %d\n",   vif->vlan_id);
    fprintf(fp, " min_hw_mode               : %s\n",   vif->min_hw_mode);
    fprintf(fp, " uapsd_enable              : %d\n",   vif->uapsd_enable);
    fprintf(fp, " group_rekey               : %d\n",   vif->group_rekey);
    fprintf(fp, " ap_bridge                 : %d\n",   vif->ap_bridge);
    fprintf(fp, " ft_psk                    : %d\n",   vif->ft_psk);
    fprintf(fp, " ft_mobility_domain        : %d\n",   vif->ft_mobility_domain);
    fprintf(fp, " rrm                       : %d\n",   vif->rrm);
    fprintf(fp, " btm                       : %d\n",   vif->btm);
    fprintf(fp, " dynamic_beacon            : %d\n",   vif->dynamic_beacon);
    fprintf(fp, " mcast2ucast               : %d\n",   vif->mcast2ucast);
    fprintf(fp, " multi_ap                  : %s\n",   vif->multi_ap);
    fprintf(fp, " wps                       : %d\n",   vif->wps);
    fprintf(fp, " wps_pbc                   : %d\n",   vif->wps_pbc);
    fprintf(fp, " wps_pbc_key_id            : %s\n",   vif->wps_pbc_key_id);
    fprintf(fp, " wpa                       : %d\n",   vif->wpa);
    fprintf(fp, " parent                    : %s\n",   vif->parent);
    //fprintf(fp, " wpa_key_mgmt                : %s\n",   vif->wpa_key_mgmt);
    //  fprintf(fp, " wpa_psks                  : %s\n",   vif->wpa_psks);
    //  fprintf(fp, " wpa_oftags                : %s\n",   vif->wpa_oftags);
    //#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    const char *str;

    str = testapp_security_config_find_by_key(vif, "encryption");
    if (str != NULL) {
        fprintf(fp, " encryption                : %s\n",   str);
    }

    str = testapp_security_config_find_by_key(vif, "mode");
    if (str != NULL) {
        fprintf(fp, " wpa_key_mgmt              : %s\n",   str);
    }

    str = testapp_security_config_find_by_key(vif, "key");
    if (str != NULL) {
        fprintf(fp, " wpa_psk                   : %s\n",   str);
    }
    /*
#else
    for (i=0; i<vif->wpa_key_mgmt_len; i++) {
        if (vif->wpa_key_mgmt[i] != NULL) {
            fprintf(fp, " wpa_key_mgmt                : %s\n",   vif->wpa_key_mgmt[i]);
        }
    }
    for (i=0; i<vif->wpa_psks_len; i++) {
        if (vif->wpa_psks[i] != NULL) {
            fprintf(fp, " wpa_psk                : %s\n",   vif->wpa_psks[i]);
        }
    }
#endif
*/
    for (i=0; i<vif->mac_list_len; i++) {
        if (vif->mac_list[i] != NULL) {
            fprintf(fp, " mac_list                : %s\n",   vif->mac_list[i]);
        }
    }
    fprintf(fp, " radius_srv_addr           : %s\n",   vif->radius_srv_addr);
    fprintf(fp, " radius_srv_port           : %d\n",   vif->radius_srv_port);
    fprintf(fp, " radius_srv_secret         : %s\n",   vif->radius_srv_secret);
    fprintf(fp, " default_oftag             : %s\n",   vif->default_oftag);

    return;
}

void print_associated_clients_ovs_schema(FILE  *fp, const struct schema_Wifi_Associated_Clients *assoc_clients, unsigned int count)
{
    if ((assoc_clients->mac != NULL) && (strlen(assoc_clients->mac)) != 0) {
        fprintf(fp, " Client Number             : %d\n",   count);
        fprintf(fp, " Client mac                : %s\n",   assoc_clients->mac);
        fprintf(fp, " Client state              : %s\n",   assoc_clients->state);
        fprintf(fp, " Client capabilities       : %s\n",   assoc_clients->capabilities[0]);
        fprintf(fp, " Client ifname             : %s\n",   assoc_clients->_uuid.uuid);
    }
    return;
}

void dump_ovs_schema(webconfig_subdoc_type_t type)
{
    if ((debug_enable == false) || (enable_ovsdb == false)) {
        return;
    }
    FILE *fp = NULL;
    char file_name[128];

    char *mesh_vap_names[] = {"mesh_backhaul_2g", "mesh_backhaul_5g", "mesh_sta_2g", "mesh_sta_5g"};
    char *total_vap_names[] = {"private_ssid_2g", "private_ssid_5g",
        "iot_ssid_2g", "iot_ssid_5g",
        "hotspot_open_2g", "hotspot_open_5g",
        "lnf_psk_2g", "lnf_psk_5g",
        "hotspot_secure_2g", "hotspot_secure_5g",
        "lnf_radius_2g", "lnf_radius_5g",
        "mesh_backhaul_2g", "mesh_backhaul_5g",
        "mesh_sta_2g", "mesh_sta_5g"};
    char *mesh_sta_vap_names[] = {"mesh_sta_2g", "mesh_sta_5g"};
    char **vap_names = NULL;
    int i = 0;
    int array_size = 0;
    const struct schema_Wifi_Radio_Config *radio_row;
    const struct schema_Wifi_VIF_Config *vif_row;
    const struct schema_Wifi_Radio_State *radio_state;
    const struct schema_Wifi_VIF_State   *vif_state;
    const struct schema_Wifi_Associated_Clients *assoc_clients;
    unsigned int vap_array_index = 0;
    webconfig_consumer_t *consumer = get_consumer_object();

    //    getcwd(file_name, 128);
    strcpy(file_name, "/tmp");

    switch (type) {
        case webconfig_subdoc_type_radio:
            strcat(file_name, "/log_radio_schema");
        break;

        case webconfig_subdoc_type_mesh:
            strcat(file_name, "/log_mesh_schema");
            vap_names = (char **)&mesh_vap_names;
            array_size = ARRAY_SZ(mesh_vap_names);
        break;
        case webconfig_subdoc_type_mesh_sta:
            strcat(file_name, "/log_mesh_sta_schema");
            vap_names = (char **)&mesh_sta_vap_names;
            array_size = ARRAY_SZ(mesh_sta_vap_names);
        break;
        case webconfig_subdoc_type_dml:
            strcat(file_name, "/log_init_schema");
            vap_names = (char **)&total_vap_names;
            array_size = ARRAY_SZ(total_vap_names);
        break;
        case webconfig_subdoc_type_mac_filter:
            strcat(file_name, "/log_macfilter_schema");
            vap_names = (char **)&total_vap_names;
            array_size = ARRAY_SZ(total_vap_names);
        break;
        case webconfig_subdoc_type_associated_clients:
            strcat(file_name, "/log_assoc_client_schema");
        break;
        case webconfig_subdoc_type_null:
            strcat(file_name, "/log_null_schema");
            vap_names = (char **)&total_vap_names;
            array_size = ARRAY_SZ(total_vap_names);
        break;

        default:
            return;
    }

    if ((fp = fopen(file_name, "w")) == NULL) {
        printf("%s:%d: error opening file:%s\n", __func__, __LINE__, file_name);
        return;
    }

    if ((type == webconfig_subdoc_type_radio) || (type == webconfig_subdoc_type_dml) || (type == webconfig_subdoc_type_null)) {
        fprintf(fp, "Radio Config Schema Configuration\n");
        for (i = 0; i < (int)ext_proto.radio_config_row_count; i++) {
            radio_row = ext_proto.radio_config[i];
            if (radio_row == NULL) {
                printf("%s:%d: radio row is empty for : %d\n", __func__, __LINE__, i);
                return;
            }
            print_radio_config_ovs_schema(fp, radio_row);
            fprintf(fp, "\n");
        }
    }

    if (((type == webconfig_subdoc_type_mesh) || (type == webconfig_subdoc_type_dml) || (type == webconfig_subdoc_type_mac_filter) || (type == webconfig_subdoc_type_null) || (type == webconfig_subdoc_type_mesh_sta)) && (type != webconfig_subdoc_type_radio)) {
        fprintf(fp, "VIF Config Schema Configuration\n");
        for (i = 0; i < array_size; i++) {

            vap_array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);

            vif_row = ext_proto.vif_config[vap_array_index];
            if (vif_row == NULL) {
                printf("%s:%d: vif_row is empty for : %d\n", __func__, __LINE__, i);
                return;
            }
            print_vif_config_ovs_schema(fp, vif_row);
            fprintf(fp, "\n");
        }
    }

    if ((type == webconfig_subdoc_type_dml) || (type == webconfig_subdoc_type_null)) {
        fprintf(fp, "Radio State Schema Configuration\n");
        for (i = 0; i < (int)ext_proto.radio_config_row_count; i++) {
            radio_state = ext_proto.radio_state[i];
            if (radio_state == NULL) {
                printf("%s:%d: radio row is empty for : %d\n", __func__, __LINE__, i);
                return;
            }
            print_radio_state_ovs_schema(fp, radio_state);
            fprintf(fp, "\n");
        }
    }

    if ((type == webconfig_subdoc_type_dml) || (type == webconfig_subdoc_type_null)) {
        fprintf(fp, "VIF State Schema Configuration\n");
        for (i = 0; i < array_size; i++) {

            vap_array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);

            vif_state = ext_proto.vif_state[vap_array_index];
            if (vif_state == NULL) {
                printf("%s:%d: vif_row is empty for : %d\n", __func__, __LINE__, i);
                return;
            }
            print_vif_state_ovs_schema(fp, vif_state);
            fprintf(fp, "\n");
        }
    }

    if (type == webconfig_subdoc_type_associated_clients) {
        fprintf(fp, "Associated clients Configuration\n");
        for (i = 0; i < MAX_NUM_CLIENTS; i++) {
            assoc_clients = ext_proto.assoc_clients[i];
            if (assoc_clients == NULL) {
                printf("%s:%d: vif_row is empty for : %d\n", __func__, __LINE__, i);
                return;
            }
            print_associated_clients_ovs_schema(fp, assoc_clients, i);
        }
        fprintf(fp, "\n");
    }



    fclose(fp);

    return;
}

webconfig_error_t   app_free_macfilter_entries(webconfig_subdoc_data_t *data)
{
    unsigned int i, j;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    rdk_wifi_vap_info_t *rdk_vap;
    acl_entry_t *temp_acl_entry, *acl_entry;
    mac_addr_str_t mac_str;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];

        for (j = 0; j < radio->vaps.num_vaps; j++) {
            rdk_vap = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap == NULL){
                continue;
            }
            if(rdk_vap->acl_map != NULL) {
                acl_entry = hash_map_get_first(rdk_vap->acl_map);
                while(acl_entry != NULL) {
                    to_mac_str(acl_entry->mac,mac_str);
                    acl_entry = hash_map_get_next(rdk_vap->acl_map,acl_entry);
                    temp_acl_entry = hash_map_remove(rdk_vap->acl_map, mac_str);
                    if (temp_acl_entry != NULL) {
                        free(temp_acl_entry);
                    }
                }
                hash_map_destroy(rdk_vap->acl_map);
                rdk_vap->acl_map = NULL;
            }
        }
    }
    return webconfig_error_none;
}

int push_data_to_consumer_queue(const void *msg, unsigned int len, ctrl_event_type_t type, ctrl_event_subtype_t sub_type)
{
    consumer_event_t *data;
    webconfig_consumer_t *consumer = &webconfig_consumer;

    printf("%s:%d start send data to consumer queue[%d] type:%d sub_type:%d\r\n",__func__, __LINE__, len, type, sub_type);
    data = (consumer_event_t *)malloc(sizeof(consumer_event_t));
    if(data == NULL) {
        printf("RDK_LOG_WARN, WIFI %s: data malloc null\n",__FUNCTION__);
        return RETURN_ERR;
    }

    data->event_type = type;
    data->sub_type = sub_type;

    data->msg = malloc(len + 1);
    if(data->msg == NULL) {
        printf("RDK_LOG_WARN,,,WIFI %s: data message malloc null\n",__FUNCTION__);
        return RETURN_ERR;
    }
    /* copy msg to data */
    memcpy(data->msg, msg, len);
    data->len = len;

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    pthread_mutex_lock(&consumer->lock);
    queue_push(consumer->queue, data);
    pthread_cond_signal(&consumer->cond);
    pthread_mutex_unlock(&consumer->lock);

    return RETURN_OK;
}

webconfig_error_t webconfig_consumer_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

int init_queue(webconfig_consumer_t *consumer)
{
    gettimeofday(&consumer->last_signalled_time, NULL);
    gettimeofday(&consumer->last_polled_time, NULL);
    pthread_cond_init(&consumer->cond, NULL);
    pthread_mutex_init(&consumer->lock, NULL);
    consumer->poll_period = QUEUE_WIFI_CTRL_TASK_TIMEOUT;

    /*Intialize the scheduler*/
    consumer->sched = scheduler_init();
    if (consumer->sched == NULL) {
        printf( "RDK_LOG_WARN, WIFI %s: control monitor scheduler init failed\n", __FUNCTION__);
        return -1;
    }

    consumer->queue = queue_create();
    if (consumer->queue == NULL) {
        printf("RDK_LOG_WARN, WIFI %s: control monitor queue create failed\n",__FUNCTION__);
        return -1;
    }

    return 0;
}

int init_tests(webconfig_consumer_t *consumer)
{
    init_queue(consumer);

    //Initialize Webconfig Framework
    consumer->webconfig.initializer = webconfig_initializer_ovsdb;
    consumer->webconfig.apply_data = (webconfig_apply_data_t)webconfig_consumer_apply;

    if (webconfig_init(&consumer->webconfig) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_MGR, "[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        return -1;
    }

    consumer->rbus_events_subscribed = false;

#ifndef WEBCONFIG_TESTS_OVER_QUEUE
    if (webconfig_consumer_register(consumer) != webconfig_error_none) {
        printf("[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        // unregister and deinit everything
        return RETURN_ERR;
    }

#endif

    return 0;
}

void handle_webconfig_consumer_event(webconfig_consumer_t *consumer, const char *str, unsigned int len, consumer_event_subtype_t subtype)
{
    webconfig_t *config;
    webconfig_subdoc_data_t data;
    webconfig_subdoc_type_t subdoc_type;
    webconfig_error_t ret = webconfig_error_none;

    config = &consumer->webconfig;

    printf( "%s:%d:webconfig initializ:%d\n", __func__, __LINE__, config->initializer);
    switch (subtype) {
        case consumer_event_webconfig_set_data:

            //            printf("%s:%d: Received webconfig subdoc:\n%s\n ... decoding and translating\n", __func__, __LINE__, str);
            // tell webconfig to decode
            if (enable_ovsdb == true) {
                unsigned int *num;
                num = (unsigned int *)&ext_proto.radio_config_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios;
                num = (unsigned int *)&ext_proto.vif_config_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios * MAX_NUM_VAP_PER_RADIO;
                num = (unsigned int *)&ext_proto.radio_state_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios;
                num = (unsigned int *)&ext_proto.vif_state_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios * MAX_NUM_VAP_PER_RADIO;
                num = (unsigned int *)&ext_proto.assoc_clients_row_count;
                *num = MAX_NUM_CLIENTS;

                ret = webconfig_ovsdb_decode(&consumer->webconfig, str, &ext_proto, &subdoc_type);
                printf( "%s:%d:webconfig_ovsdb_decode : %d\n", __func__, __LINE__, subdoc_type);
            } else {
                printf( "%s:%d:webconfig_decode\n", __func__, __LINE__);

                memset(&data, 0, sizeof(webconfig_subdoc_data_t));
                memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));
                ret = webconfig_decode(&consumer->webconfig, &data, str);
                if (ret == webconfig_error_none)
                    subdoc_type = data.type;

            }

            if (ret == webconfig_error_none ) {
                printf( "%s:%d:webconfig initializ:%d subdoc_type : %d\n", __func__, __LINE__, config->initializer, subdoc_type);

                switch (subdoc_type) {
                    case webconfig_subdoc_type_dml:
                        dump_subdoc(str, webconfig_subdoc_type_dml);
                        //free the data in hash_map
                        if (enable_ovsdb == false) {
                            app_free_macfilter_entries(&data);
                        }
                        consumer->hal_cap.wifi_prop.numRadios = data.u.decoded.num_radios;
                        memcpy((unsigned char *)&consumer->config, (unsigned char *)&data.u.decoded.config, sizeof(wifi_global_config_t));
                        memcpy((unsigned char *)consumer->radios, (unsigned char *)data.u.decoded.radios, consumer->hal_cap.wifi_prop.numRadios * sizeof(rdk_wifi_radio_t));
                        memcpy((unsigned char *)&consumer->hal_cap, (unsigned char *)&data.u.decoded.hal_cap, sizeof(wifi_hal_capability_t));

                        if (consumer->test_state == consumer_test_state_radio_subdoc_test_pending) {
                            consumer->radio_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_radio_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: Radio set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                            dump_ovs_schema(webconfig_subdoc_type_radio); //This is to print only radio subdoc
                            dump_ovs_schema(subdoc_type);
                        } else if (consumer->test_state == consumer_test_state_private_subdoc_test_pending) {
                            consumer->private_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_private_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: consumer vap private set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                        } else if (consumer->test_state == consumer_test_state_mesh_subdoc_test_pending) {
                            consumer->mesh_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_mesh_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: consumer vap mesh set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                            dump_ovs_schema(webconfig_subdoc_type_mesh); //This is to print only mesh subdoc
                            dump_ovs_schema(subdoc_type);
                        } else if (consumer->test_state == consumer_test_state_xfinity_subdoc_test_pending) {
                            consumer->xfinity_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: consumer vap xfinity set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                        } else if (consumer->test_state == consumer_test_state_home_subdoc_test_pending) {
                            consumer->home_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_home_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: consumer Vap home set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                        } else if (consumer->test_state == consumer_test_state_macfilter_subdoc_test_pending) {
                            consumer->macfilter_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_macfilter_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: macfilter set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                        } else {
                            consumer->test_state = consumer_test_state_cache_init_complete;

                            if (enable_ovsdb == true) {
                                dump_ovs_schema(webconfig_subdoc_type_dml);
                            }
                            printf("%s:%d: Cache init successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                        }
                    break;

                    case webconfig_subdoc_type_mesh_sta:
                        printf("%s:%d: Cache init successful, mesh_sta subdoc Test State:%d\n", __func__, __LINE__,
                                consumer->test_state);
                        if (enable_ovsdb == true) {
                            dump_ovs_schema(webconfig_subdoc_type_mesh_sta);
                        }
                        dump_subdoc(str, webconfig_subdoc_type_mesh_sta);
                    break;

                    default:
                        printf("%s:%d: Unknown webconfig subdoc type:%d\n", __func__, __LINE__, data.type);
                    break;
                }

            } else {
                printf("%s:%d: webconfig error\n", __func__, __LINE__);
            }
        break;
        case consumer_event_webconfig_get_data:
            //printf("%s:%d: Received webconfig subdoc:\n%s\n ... decoding and translating\n", __func__, __LINE__, str);
            // tell webconfig to decode
            if (enable_ovsdb == true) {
                unsigned int *num;
                num = (unsigned int *)&ext_proto.radio_config_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios;
                num = (unsigned int *)&ext_proto.vif_config_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios * MAX_NUM_VAP_PER_RADIO;
                num = (unsigned int *)&ext_proto.radio_state_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios;
                num = (unsigned int *)&ext_proto.vif_state_row_count;
                *num = consumer->hal_cap.wifi_prop.numRadios * MAX_NUM_VAP_PER_RADIO;
                num = (unsigned int *)&ext_proto.assoc_clients_row_count;
                *num = MAX_NUM_CLIENTS;

                ret = webconfig_ovsdb_decode(&consumer->webconfig, str, &ext_proto, &subdoc_type);
                printf( "%s:%d:webconfig_ovsdb_decode\n", __func__, __LINE__);
            } else {
                printf( "%s:%d:webconfig_decode\n", __func__, __LINE__);

                memset(&data, 0, sizeof(webconfig_subdoc_data_t));
                memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));
                ret = webconfig_decode(&consumer->webconfig, &data, str);
                if (ret == webconfig_error_none)
                    subdoc_type = data.type;

            }

            if (ret == webconfig_error_none ) {
                printf( "%s:%d:webconfig initializ:%d subdoc_type : %d\n", __func__, __LINE__, config->initializer, subdoc_type);
                switch (subdoc_type) {
                    case webconfig_subdoc_type_associated_clients:
                        printf("%s:%d: Received Associated client status, Use -d 1 option to see the log file\n", __func__, __LINE__);
                        dump_ovs_schema(webconfig_subdoc_type_associated_clients);
                        dump_subdoc(str, webconfig_subdoc_type_associated_clients);
                    break;
                    case webconfig_subdoc_type_null:
                        printf("%s:%d: webconfig_subdoc_type_null subdoc\n", __func__, __LINE__);
                        if (consumer->test_state == consumer_test_state_null_subdoc_test_pending) {
                            consumer->null_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_null_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: null set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                            if (enable_ovsdb == true) {
                                dump_ovs_schema(webconfig_subdoc_type_null);
                            }
                            dump_subdoc(str, webconfig_subdoc_type_null);
                        }
                    break;

                    default:
                        printf("%s:%d: Unknown webconfig subdoc type:%d\n", __func__, __LINE__, data.type);
                    break;
                }
            } else {
                printf("%s:%d: webconfig error\n", __func__, __LINE__);
            }
        break;
    }
}

webconfig_error_t webconfig_parse_json_to_struct(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    webconfig_error_t err = RETURN_OK;

    if (validate_subdoc_data(config, data) == false) {
        printf("%s:%d: Invalid data .. not parsable\r\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    printf("%s %d subdoc data type:%d\n", __func__, __LINE__, data->type);
    doc = &config->subdocs[data->type];
    if (doc->access_check_subdoc(config, data) != webconfig_error_none) {
        printf("%s:%d: invalid access for subdocument type:%d in entity:%d\n",
                __func__, __LINE__, doc->type, config->initializer);
        return webconfig_error_not_permitted;
    }

    if ((err = doc->decode_subdoc(config, data)) != webconfig_error_none) {
        printf("%s:%d: Subdocument translation failed\n", __func__, __LINE__);
    }

    return err;

}

int parse_subdoc_input_param(webconfig_consumer_t *consumer, webconfig_subdoc_data_t *data)
{
    int ret = RETURN_OK;

    ret = read_subdoc_input_param_from_file(consumer->user_input_file_name, data->u.encoded.raw);
    if (ret == RETURN_OK) {
        // parse JSON blob
        data->signature = WEBCONFIG_MAGIC_SIGNATUTRE;
        data->type = webconfig_subdoc_type_unknown;
        data->descriptor = webconfig_data_descriptor_encoded;
        ret = webconfig_parse_json_to_struct(&consumer->webconfig, data);
    } else {
        printf("%s:%d: Using default config\r\n", __func__, __LINE__);
    }

    return ret;
}

void test_radio_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    char *str;
    webconfig_error_t ret=webconfig_error_none;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_radio;
        unsigned int i = 0;
        unsigned int *num = (unsigned int *)&ext_proto_radio.radio_config_row_count;
        const struct schema_Wifi_Radio_Config *radio_table[MAX_NUM_RADIOS];
        *num = consumer->hal_cap.wifi_prop.numRadios;
        unsigned int *param;

        for ( i = 0; i < *num; i++) {
            radio_table[i] = ext_proto.radio_config[i];
            param = (unsigned int *)&radio_table[i]->channel;
            if (i == 0) {
                *param = 9;
            } else if (i == 1){
                *param = 36;
            }
        }

        ext_proto_radio.radio_config = radio_table;

        printf("%s:%d: start webconfig_ovsdb_encode \n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_radio,
                webconfig_subdoc_type_radio, &str);
    } else {
        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            data.u.decoded.radios[0].oper.channel = 3;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        //clearing the descriptor
        data.descriptor =  0;

        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_radio);
        if (ret == webconfig_error_none)
            str = data.u.encoded.raw;
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer radio start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_radio);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        str = NULL;
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

}

void test_null_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret=webconfig_error_none;
    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    //The below information is not required for the null subdoc, Filled the structures for testing purpose.
    if (enable_ovsdb == true) {
        ret = webconfig_ovsdb_encode(&consumer->webconfig, NULL,
                webconfig_subdoc_type_null, &str);
    } else {
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_null);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer null vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_null);
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}

void test_mesh_sta_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret=webconfig_error_none;
    time_t t;

    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    srand((unsigned) time(&t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_mesh;
        unsigned int *num = (unsigned int *)&ext_proto_mesh.vif_config_row_count;
        char *vap_names[2] = {"mesh_sta_2g", "mesh_sta_5g"};
        const struct schema_Wifi_VIF_Config *vif_table[2];
        unsigned int i = 0;
        unsigned int array_index = 0;
        bool *param;
        //unsigned int *param_int;

        *num = ARRAY_SZ(vap_names);

        for ( i = 0; i < *num; i++) {
            array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
            vif_table[i] = ext_proto.vif_config[array_index];
            param = (bool *)&vif_table[i]->enabled;
            *param = true;
        }
        ext_proto_mesh.vif_config = vif_table;

        printf("%s:%d: start webconfig_ovsdb_encode \n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_mesh,
                webconfig_subdoc_type_mesh_sta, &str);
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            wifi_vap_info_t *vap_info;

            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "mesh_sta");
            if (vap_info == NULL) {
                printf("%s:%d: vap_info is NULL \n", __func__, __LINE__);
                return;
            }
            vap_info->u.sta_info.scan_params.period = rand() % 10;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "mesh_sta");
            if (vap_info == NULL) {
                printf("%s:%d: vap_info is NULL \n", __func__, __LINE__);
                return;
            }
            vap_info->u.sta_info.scan_params.period = rand() % 10;
        }

        //clearing the descriptor
        data.descriptor =  0;
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_mesh_sta);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer mesh sta vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_mesh_sta);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}

void test_mesh_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret=webconfig_error_none;
    char test_mac[18];
    time_t t;
    rdk_wifi_vap_info_t *rdk_vap;
    mac_address_t mac;
    acl_entry_t *acl_entry;

    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    srand((unsigned) time(&t));
    snprintf(test_mac, sizeof(test_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 0xaa, 0xbb,0xcc,0xaa, rand() % 25, rand() % 50);

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_mesh;
        unsigned int *num = (unsigned int *)&ext_proto_mesh.vif_config_row_count;
        char *vap_names[4] = {"mesh_backhaul_2g", "mesh_backhaul_5g", "mesh_sta_2g", "mesh_sta_5g"};
        const struct schema_Wifi_VIF_Config *vif_table[4];
        unsigned int i = 0;
        unsigned int array_index = 0;
        bool *param;
        unsigned int *param_int;

        *num = ARRAY_SZ(vap_names);

        for ( i = 0; i < *num; i++) {
            array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
            vif_table[i] = ext_proto.vif_config[array_index];
            snprintf((char *)vif_table[i]->ssid, sizeof(vif_table[i]->ssid), "mesh_test_%d", array_index);
            param = (bool *)&vif_table[i]->enabled;
            *param = true;
            param_int = (unsigned int *)&vif_table[i]->mac_list_len;
            *param_int = 1;
            snprintf((char *)vif_table[i]->mac_list[0], sizeof(vif_table[i]->mac_list[0]),"%s", test_mac);
        }
        ext_proto_mesh.vif_config = vif_table;

        printf("%s:%d: start webconfig_ovsdb_encode \n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_mesh,
                webconfig_subdoc_type_mesh, &str);
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int radio_0_bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 4;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "mesh_backhaul");
            /* set to different value from current to force a change */
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = radio_0_bssMaxSta = 6;
            } else {
                vap_info->u.bss_info.bssMaxSta = radio_0_bssMaxSta = 5;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "mesh_backhaul");
            vap_info->u.bss_info.bssMaxSta = (radio_0_bssMaxSta == 6) ? 5 : 6;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "mesh_sta");
            vap_info->u.sta_info.scan_params.period = 2;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "mesh_sta");
            vap_info->u.sta_info.scan_params.period = 2;

            rdk_vap = get_wifi_radio_rdkvap_info(&data.u.decoded.radios[0], "mesh_backhaul");
            if ((rdk_vap == NULL)) {
                printf("%s:%d: rdk_vap is null\n", __func__, __LINE__);
                return;
            }

            rdk_vap->acl_map = hash_map_create();
            str_to_mac_bytes(test_mac, mac);
            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            if (acl_entry == NULL) {
                printf("%s:%d NULL Pointer \n", __func__, __LINE__);
                return;
            }
            memset(acl_entry, 0, (sizeof(acl_entry_t)));

            memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
            hash_map_put(rdk_vap->acl_map, strdup(test_mac), acl_entry);
        
        }

        //clearing the descriptor
        data.descriptor =  0;
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_mesh);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer mesh vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_mesh);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}


void test_macfilter_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    uint8_t vap_array_index = 0;
    webconfig_error_t ret=webconfig_error_none;
    char test_mac[18];
    rdk_wifi_vap_info_t *rdk_vap;
    mac_address_t mac;
    acl_entry_t *acl_entry;
    time_t t;

    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    srand((unsigned) time(&t));

    snprintf(test_mac, sizeof(test_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 0xaa, 0xbb,0xcc,0xdd, rand() % 25, rand() % 50);

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_macfilter;
        unsigned int *num = (unsigned int *)&ext_proto_macfilter.vif_config_row_count;
        char *vap_names[16] = {"private_ssid_2g", "private_ssid_5g",
            "iot_ssid_2g", "iot_ssid_5g",
            "hotspot_open_2g", "hotspot_open_5g",
            "lnf_psk_2g", "lnf_psk_5g",
            "hotspot_secure_2g", "hotspot_secure_5g",
            "lnf_radius_2g", "lnf_radius_5g",
            "mesh_backhaul_2g", "mesh_backhaul_5g",
            "mesh_sta_2g", "mesh_sta_5g"};
        const struct schema_Wifi_VIF_Config *vif_table[16];
        unsigned int i = 0;
        unsigned int array_index = 0;
        bool *param;
        unsigned int *param_int;

        *num = ARRAY_SZ(vap_names);
        for ( i = 0; i < *num; i++) {
            array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
            vif_table[i] = ext_proto.vif_config[array_index];
            if (is_vap_mesh_backhaul(&consumer->hal_cap.wifi_prop, array_index) == TRUE) {
                snprintf((char *)vif_table[i]->ssid, sizeof(vif_table[i]->ssid), "macfilter_test_%d", array_index);
                param = (bool *)&vif_table[i]->enabled;
                *param = true;
                param_int = (unsigned int *)&vif_table[i]->mac_list_len;
                *param_int = 1;
                snprintf((char *)vif_table[i]->mac_list[0], sizeof(vif_table[i]->mac_list[0]),"%s", test_mac);
            }
        }
        ext_proto_macfilter.vif_config = vif_table;

        printf("%s:%d: start webconfig_ovsdb_encode \n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_macfilter,
                webconfig_subdoc_type_mac_filter, &str);
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            rdk_vap = NULL;
            for (vap_array_index = 0; vap_array_index < data.u.decoded.radios[0].vaps.num_vaps; ++vap_array_index) {
                if (!strncmp(data.u.decoded.radios[0].vaps.rdk_vap_array[vap_array_index].vap_name, "mesh_backhaul", strlen("mesh_backhaul"))) {
                    rdk_vap = &data.u.decoded.radios[0].vaps.rdk_vap_array[vap_array_index];
                    break;
                }
            }

            if ((rdk_vap == NULL)) {
                printf("%s:%d: rdk_vap is null\n", __func__, __LINE__);
                return;
            }

            rdk_vap->acl_map = hash_map_create();
            str_to_mac_bytes(test_mac, mac);
            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            if (acl_entry == NULL) {
                printf("%s:%d NULL Pointer \n", __func__, __LINE__);
                return;
            }
            memset(acl_entry, 0, (sizeof(acl_entry_t)));

            memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
            hash_map_put(rdk_vap->acl_map, strdup(test_mac), acl_entry);
        }

        //clearing the descriptor
        data.descriptor =  0;
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_mac_filter);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer macfilter start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_mac_filter);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}



void test_private_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;

    char *str;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_private;
        unsigned int *num = (unsigned int *)&ext_proto_private.vif_config_row_count;
        char *vap_names[2] = {"private_ssid_2g", "private_ssid_5g"};
        const struct schema_Wifi_VIF_Config *vif_table[2];
        unsigned int i = 0;
        unsigned int array_index = 0;

        *num = ARRAY_SZ(vap_names);

        for ( i = 0; i < *num; i++) {
            array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
            vif_table[i] = ext_proto.vif_config[array_index];
            snprintf((char *)vif_table[i]->ssid, sizeof(vif_table[i]->ssid), "ovsdb_private_test_%d", array_index);
        }
        ext_proto_private.vif_config = vif_table;

        printf("%s:%d: start webconfig_ovsdb_encode changing the ssid to ovsdb_test\n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_private,
                webconfig_subdoc_type_private, &str);
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 5;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "private_ssid");
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 6;
            } else {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 5;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "private_ssid");
            vap_info->u.bss_info.bssMaxSta = bssMaxSta;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        //clearing the descriptor
        data.descriptor =  0;
        printf("%s:%d: start webconfig_encode num_of_radio:%d\n", __func__, __LINE__, data.u.decoded.num_radios);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_private);
        if (ret == webconfig_error_none)
            str = data.u.encoded.raw;
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer private vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_private);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}

void test_home_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    char *str;
    webconfig_error_t ret = webconfig_error_none;
    bool *param;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    int num_vaps;

    str = NULL;
    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
                                     1, VAP_PREFIX_IOT);
    if (num_vaps == 0) {
        printf("%s:%d: Home VAP is not supported\n", __func__, __LINE__);
        consumer->home_test_pending_count = 0;
        consumer->test_state = consumer_test_state_home_subdoc_test_complete;
        return;
    }

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_home;
        unsigned int *num = (unsigned int *)&ext_proto_home.vif_config_row_count;
        char *vap_names[2] = {"iot_ssid_2g", "iot_ssid_5g"};
        const struct schema_Wifi_VIF_Config *vif_table[2];
        unsigned int i = 0;
        unsigned int array_index = 0;

        *num = ARRAY_SZ(vap_names);

        for ( i = 0; i < *num; i++) {
            array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
            vif_table[i] = ext_proto.vif_config[array_index];
            param = (bool *)&vif_table[i]->enabled;
            *param = true;
            snprintf((char *)vif_table[i]->ssid, sizeof(vif_table[i]->ssid), "ovsdb_home_test_%d", array_index);
        }
        ext_proto_home.vif_config = vif_table;

        printf("%s:%d: start webconfig_ovsdb_encode \n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_home,
                webconfig_subdoc_type_home, &str);

    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 5;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "iot_ssid");
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 6;
            } else {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 5;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "iot_ssid");
            vap_info->u.bss_info.bssMaxSta = bssMaxSta;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        //clearing the descriptor
        data.descriptor =  0;
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_home);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer home vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_home);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}


void test_getsubdoctype(webconfig_consumer_t *consumer)
{
    int num_vaps;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    wifi_interface_name_t *ifname;
    int vapindex = 0;
    webconfig_subdoc_type_t type;

    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
            8, VAP_PREFIX_PRIVATE, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
            VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS, VAP_PREFIX_MESH_BACKHAUL, \
            VAP_PREFIX_MESH_STA, VAP_PREFIX_IOT);

    for (vapindex = 0; vapindex < num_vaps; vapindex++) {
        ifname = get_interface_name_for_vap_index(vapindex, &consumer->hal_cap.wifi_prop);
        if (ifname == NULL) {
            printf("%s:%d: ifname get failed\n", __func__, __LINE__);
            return;
        }
        webconfig_convert_ifname_to_subdoc_type(ifname[0], &type);
        printf("%s:%d: ifname %s type : %d\n", __func__, __LINE__, ifname[0], type);

    }
    return;
}

void test_lnf_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;
    char *str;
    int num_vaps;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    int i = 0;
    unsigned int array_index = 0;
    unsigned int radio_index = 0;
    bool *param;

    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
                                     2, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);
    if (num_vaps == 0) {
        printf("%s:%d: lnf VAP is not supported\n", __func__, __LINE__);
        consumer->lnf_test_pending_count = 0;
        consumer->test_state = consumer_test_state_lnf_subdoc_test_complete;
        return;
    }

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_lnf;
        const struct schema_Wifi_VIF_Config *vif_table[4];
        unsigned int *num = (unsigned int *)&ext_proto_lnf.vif_config_row_count;
        *num = num_vaps;

        for ( i = 0; i < num_vaps; i++) {
            array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
            vif_table[i] = ext_proto.vif_config[array_index];
            param = (bool *)&vif_table[i]->enabled;
            *param = true;
            snprintf((char *)vif_table[i]->ssid, sizeof(vif_table[i]->ssid), "ovsdb_lnf_test_%d", array_index);
        }
        ext_proto_lnf.vif_config = vif_table;

        printf("%s:%d: start webconfig_ovsdb_encode \n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_lnf,
                webconfig_subdoc_type_lnf, &str);
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            wifi_vap_info_t *vap_info;

            for ( i = 0; i < num_vaps; i++) {
                array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
                radio_index = convert_vap_name_to_radio_array_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
                vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[radio_index], vap_names[i]);
                snprintf((char *)vap_info->u.bss_info.ssid, sizeof(vap_info->u.bss_info.ssid), "app_lnf_test_%d", array_index);
                printf("%s:%d: radio_index : %d vap_names[i] : %s\n", __func__, __LINE__, radio_index, vap_names[i]);
            }
        }
        //clearing the descriptor
        data.descriptor =  0;
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        printf("%s:%d: start webconfig_encode \n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_lnf);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer lnf vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_lnf);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}


void test_xfinity_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;
    char *str;
    int num_vaps;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    bool *param;

    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
            2, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE);
    if (num_vaps == 0) {
        printf("%s:%d: Xfinity VAP is not supported\n", __func__, __LINE__);
        consumer->xfinity_test_pending_count = 0;
        consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
        return;
    }

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
        webconfig_external_ovsdb_t ext_proto_xfinity;
        unsigned int *num = (unsigned int *)&ext_proto_xfinity.vif_config_row_count;
        char *vap_names[] = { "hotspot_open_2g", "hotspot_open_5g", "hotspot_secure_2g", "hotspot_secure_5g" };
        const struct schema_Wifi_VIF_Config *vif_table[4];
        unsigned int i = 0;
        unsigned int array_index = 0;

        *num = ARRAY_SZ(vap_names);

        for ( i = 0; i < *num; i++) {
            array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
            vif_table[i] = ext_proto.vif_config[array_index];
            param = (bool *)&vif_table[i]->enabled;
            *param = true;
            snprintf((char *)vif_table[i]->ssid, sizeof(vif_table[i]->ssid), "ovsdb_xfinity_test_%d", array_index);
        }
        ext_proto_xfinity.vif_config = vif_table;

        printf("%s:%d: start webconfig_ovsdb_encode \n", __func__, __LINE__);
        ret = webconfig_ovsdb_encode(&consumer->webconfig, &ext_proto_xfinity,
                webconfig_subdoc_type_xfinity, &str);
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int radio_1_open_bssMaxSta, radio_2_open_bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 6;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "hotspot_open");
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = radio_1_open_bssMaxSta = 6;
                radio_2_open_bssMaxSta = 5;
            } else {
                vap_info->u.bss_info.bssMaxSta = radio_1_open_bssMaxSta = 5;
                radio_2_open_bssMaxSta = 6;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "hotspot_open");
            vap_info->u.bss_info.bssMaxSta = radio_2_open_bssMaxSta;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "hotspot_secure");
            vap_info->u.bss_info.bssMaxSta = radio_2_open_bssMaxSta;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "hotspot_secure");
            vap_info->u.bss_info.bssMaxSta = radio_1_open_bssMaxSta;
        }
        //clearing the descriptor
        data.descriptor =  0;
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        printf("%s:%d: start webconfig_encode \n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_xfinity);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer xfinity vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_xfinity);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
}

void test_initial_sync()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    push_data_to_ctrl_queue(NULL, 0, ctrl_event_type_webconfig, ctrl_event_webconfig_get_data);
#else
    initial_sync(&webconfig_consumer);
#endif
}

void exit_consumer_queue_loop(void)
{
    webconfig_consumer_t *consumer = get_consumer_object();
    printf("%s:%d: Exit consumer queue loop\n", __func__, __LINE__);
    consumer->exit_consumer = true;
    free_ovs_schema_structs();
}

void de_init_rbus_object(void)
{
    rbusDataElement_t rbusEvents[] = {
        { WIFI_ACTIVE_GATEWAY_CHECK, RBUS_ELEMENT_TYPE_METHOD,
            { NULL, webconfig_consumer_set_subdoc, NULL, NULL, NULL, NULL }},
        { WIFI_WAN_FAILOVER_TEST, RBUS_ELEMENT_TYPE_METHOD,
            { NULL, webconfig_consumer_set_subdoc, NULL, NULL, NULL, NULL }},
    };
    webconfig_consumer_t *consumer = get_consumer_object();

    if (consumer->rbus_handle != NULL) {
        printf("%s:%d: un-register rbus data element\n", __func__, __LINE__);
        rbus_unregDataElements(consumer->rbus_handle, ARRAY_SZ(rbusEvents), rbusEvents);
        rbus_close(consumer->rbus_handle);
    }
}

void consumer_app_all_test_sequence(webconfig_consumer_t *consumer)
{
    switch (consumer->test_state) {
        case consumer_test_state_none:
            consumer->test_state = consumer_test_state_cache_init_pending;
            test_initial_sync();
            break;

        case consumer_test_state_cache_init_complete:
            consumer->test_state = consumer_test_state_radio_subdoc_test_pending;
            // do radio subdoc change test
            test_radio_subdoc_change(consumer);
            break;

        case consumer_test_state_radio_subdoc_test_pending:
            consumer->radio_test_pending_count++;
            if (consumer->radio_test_pending_count > MAX_WAIT) {
                printf("%s:%d: Radio test failed, timed out, proceeding with private subdoc test\n", __func__, __LINE__);
                consumer->radio_test_pending_count = 0;
                consumer->test_state = consumer_test_state_radio_subdoc_test_complete;
            }
            break;

        case consumer_test_state_radio_subdoc_test_complete:
            consumer->test_state = consumer_test_state_private_subdoc_test_pending;
            test_private_subdoc_change(consumer);
            break;

        case consumer_test_state_private_subdoc_test_pending:
            consumer->private_test_pending_count++;
            if (consumer->private_test_pending_count > MAX_WAIT) {
                printf("%s:%d: Private test failed, timed out, proceeding with mesh subdoc test\n", __func__, __LINE__);
                consumer->private_test_pending_count = 0;
                consumer->test_state = consumer_test_state_private_subdoc_test_complete;
            }
            break;

        case consumer_test_state_private_subdoc_test_complete:
            consumer->test_state = consumer_test_state_mesh_subdoc_test_pending;
            test_mesh_subdoc_change(consumer);
            break;

        case consumer_test_state_mesh_subdoc_test_pending:
            consumer->mesh_test_pending_count++;
            if (consumer->mesh_test_pending_count > MAX_WAIT) {
                printf("%s:%d: vap mesh test failed, timed out, proceeding with xfinity test\n", __func__, __LINE__);
                consumer->mesh_test_pending_count = 0;
                consumer->test_state = consumer_test_state_mesh_subdoc_test_complete;
            }
            break;

        case consumer_test_state_mesh_subdoc_test_complete:
            consumer->test_state = consumer_test_state_xfinity_subdoc_test_pending;
            test_xfinity_subdoc_change(consumer);
            break;

        case consumer_test_state_xfinity_subdoc_test_pending:
            consumer->xfinity_test_pending_count++;
            if (consumer->xfinity_test_pending_count > MAX_WAIT) {
                printf("%s:%d: vap xfinity test failed, timed out, proceeding with home test\n", __func__, __LINE__);
                consumer->mesh_test_pending_count = 0;
                consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
            }
            break;

        case consumer_test_state_xfinity_subdoc_test_complete:
            consumer->test_state = consumer_test_state_home_subdoc_test_pending;
            test_home_subdoc_change(consumer);
            break;

        case consumer_test_state_home_subdoc_test_pending:
            consumer->home_test_pending_count++;
            if (consumer->home_test_pending_count > MAX_WAIT) {
                printf("%s:%d: vap home test failed, timed out, all test completed\n", __func__, __LINE__);
                consumer->home_test_pending_count = 0;
                consumer->test_state = consumer_test_state_home_subdoc_test_complete;
            }
            break;

        default:
            //printf("%s:%d: Noop test state:%d\n", __func__, __LINE__, consumer->test_state);
        break;
    }
}

void reset_all_test_pending_count(void)
{
    webconfig_consumer_t *consumer = get_consumer_object();

    consumer->radio_test_pending_count = 0;
    consumer->private_test_pending_count = 0;
    consumer->mesh_test_pending_count = 0;
    consumer->xfinity_test_pending_count = 0;
    consumer->home_test_pending_count = 0;
}

void consumer_app_trigger_subdoc_test( webconfig_consumer_t *consumer, consumer_test_sequence_t test_state)
{
    printf("%s:%d: consumer app trigger test:%d\n", __func__, __LINE__, test_state);
    consumer->test_input = test_state;
    switch (test_state) {
        case consumer_test_start_radio_subdoc:
            consumer->radio_test_pending_count = 0;
            consumer->test_state = consumer_test_state_radio_subdoc_test_pending;
            test_radio_subdoc_change(consumer);
            break;

        case consumer_test_start_private_subdoc:
            consumer->private_test_pending_count = 0;
            consumer->test_state = consumer_test_state_private_subdoc_test_pending;
            test_private_subdoc_change(consumer);
            break;

        case consumer_test_start_mesh_subdoc:
            consumer->mesh_test_pending_count = 0;
            consumer->test_state = consumer_test_state_mesh_subdoc_test_pending;
            test_mesh_subdoc_change(consumer);
            break;

        case consumer_test_start_xfinity_subdoc:
            consumer->xfinity_test_pending_count = 0;
            consumer->test_state = consumer_test_state_xfinity_subdoc_test_pending;
            test_xfinity_subdoc_change(consumer);
            break;

        case consumer_test_start_home_subdoc:
            consumer->home_test_pending_count = 0;
            consumer->test_state = consumer_test_state_home_subdoc_test_pending;
            test_home_subdoc_change(consumer);
            break;

        case consumer_test_start_macfilter_subdoc:
            consumer->macfilter_test_pending_count= 0;
            consumer->test_state = consumer_test_state_macfilter_subdoc_test_pending;
            test_macfilter_subdoc_change(consumer);
            break;

        case consumer_test_start_null_subdoc:
            consumer->null_test_pending_count= 0;
            consumer->test_state = consumer_test_state_null_subdoc_test_pending;
            test_null_subdoc_change(consumer);
        break;

        case consumer_test_start_mesh_sta_subdoc:
            consumer->mesh_test_pending_count = 0;
            consumer->test_state = consumer_test_state_mesh_sta_subdoc_test_pending;
            test_mesh_sta_subdoc_change(consumer);
        break;

        case consumer_test_start_lnf_subdoc:
            consumer->xfinity_test_pending_count = 0;
            consumer->test_state = consumer_test_state_lnf_subdoc_test_pending;
            test_lnf_subdoc_change(consumer);
            break;

        case consumer_test_start_all_subdoc:
            reset_all_test_pending_count();
            consumer->test_state = consumer_test_state_cache_init_complete;
            consumer_app_all_test_sequence(consumer);
            break;

        default:
            printf("%s:%d: [%d] This Test index not supported\r\n", __func__, __LINE__, test_state);
            break;
    }
}

void consumer_app_trigger_wan_test( webconfig_consumer_t *consumer, consumer_test_sequence_t test_state, bool status)
{
    printf("%s:%d: consumer app trigger test:%d\n", __func__, __LINE__, test_state);
    consumer->test_input = test_state;
    switch (test_state) {
        case consumer_test_start_wan_manager:
            webconfig_rbus_other_gateway_state_publish(consumer, status);
        break;

        default:
            printf("%s:%d: [%d] This Test index not supported\r\n", __func__, __LINE__, test_state);
        break;
    }
}

void generate_tunnel_event(bool status, rbusHandle_t handle)
{
    const char *evt_name = "TunnelStatus";
    const char *evt_val = status ? "TUNNEL_UP" : "TUNNEL_DOWN";

    rbusValue_t value;
    rbusObject_t rd;

    rbusValue_Init(&value);
    rbusValue_SetString(value, evt_val);

    rbusObject_Init(&rd, NULL);
    rbusObject_SetValue(rd, evt_name, value);

    rbusEvent_t event;
    event.name = evt_name;
    event.data = rd;
    event.type = RBUS_EVENT_GENERAL;

    int rc = rbusEvent_Publish(handle, &event);
    if(rc != RBUS_ERROR_SUCCESS){
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d rbusEvent_Publish %s failed\n", __func__, __LINE__, event.name );
    }

    rbusValue_Release(value);
    rbusObject_Release(rd);
}

void copy_data(char *dest, char *src, unsigned char dest_len)
{
    if (src != NULL) {
        strcpy(dest, src);
    } else {
        memset(dest, 0 , dest_len);
    }
}

void initialize_ovs_schema_structs()
{
    unsigned int i = 0;

    ext_proto.radio_config = (const struct schema_Wifi_Radio_Config **) malloc(sizeof(struct schema_Wifi_Radio_Config *) * MAX_NUM_RADIOS);
    if (ext_proto.radio_config == NULL) {
        printf("[%s]:%d Memory allocation fail for radio config table\n",__FUNCTION__,__LINE__);
        return;
    }
    memset((struct schema_Wifi_Radio_Config **)ext_proto.radio_config, 0, (sizeof(struct schema_Wifi_Radio_Config *)*MAX_NUM_RADIOS));

    ext_proto.radio_state = (const struct schema_Wifi_Radio_State **) malloc(sizeof(struct schema_Wifi_Radio_State *) * MAX_NUM_RADIOS);
    if (ext_proto.radio_state == NULL) {
        printf("[%s]:%d Memory allocation fail for radio state table\n",__FUNCTION__,__LINE__);
        return;
    }

    memset((struct schema_Wifi_Radio_State **)ext_proto.radio_state, 0, (sizeof(struct schema_Wifi_Radio_State *)*MAX_NUM_RADIOS));

    for (i = 0; i < MAX_NUM_RADIOS; i++) {
        ext_proto.radio_config[i] = (struct schema_Wifi_Radio_Config *)malloc(sizeof(struct schema_Wifi_Radio_Config));
        if (ext_proto.radio_config[i] == NULL) {
            printf("[%s]:%d Memory allocation fail for %d\n",__FUNCTION__,__LINE__, i);
            free_ovs_schema_structs();
            return;
        }
        memset((struct schema_Wifi_Radio_Config *)ext_proto.radio_config[i], 0, sizeof(struct schema_Wifi_Radio_Config));

        ext_proto.radio_state[i] = (struct schema_Wifi_Radio_State *)malloc(sizeof(struct schema_Wifi_Radio_State));
        if (ext_proto.radio_state[i] == NULL) {
            printf("[%s]:%d Memory allocation fail for %d\n",__FUNCTION__,__LINE__, i);
            free_ovs_schema_structs();
            return;
        }
        memset((struct schema_Wifi_Radio_State *)ext_proto.radio_state[i], 0, sizeof(struct schema_Wifi_Radio_State));
    }

    ext_proto.vif_config = (const struct schema_Wifi_VIF_Config **) malloc(sizeof(struct schema_Wifi_VIF_Config *) * MAX_VAP);
    if (ext_proto.vif_config == NULL) {
        printf("[%s]:%d Memory allocation fail for vif config table\n",__FUNCTION__,__LINE__);
        free_ovs_schema_structs();
        return;
    }
    memset((struct schema_Wifi_VIF_Config **)ext_proto.vif_config, 0, (sizeof(struct schema_Wifi_VIF_Config *) * MAX_VAP));

    ext_proto.vif_state = (const struct schema_Wifi_VIF_State **) malloc(sizeof(struct schema_Wifi_VIF_State *) * MAX_VAP);
    if (ext_proto.vif_state == NULL) {
        printf("[%s]:%d Memory allocation fail for vif state table\n",__FUNCTION__,__LINE__);
        free_ovs_schema_structs();
        return;
    }
    memset((struct schema_Wifi_VIF_State **)ext_proto.vif_state, 0, (sizeof(struct schema_Wifi_VIF_State *) * MAX_VAP));

    for (i = 0; i < MAX_VAP; i++) {
        //Allocate the memory
        ext_proto.vif_config[i] = (struct schema_Wifi_VIF_Config *)malloc(sizeof(struct schema_Wifi_VIF_Config));
        if (ext_proto.vif_config[i] == NULL) {
            printf("[%s]:%d Memory allocation fail for %d\n",__FUNCTION__,__LINE__, i);
            free_ovs_schema_structs();
            return;
        }
        memset((struct schema_Wifi_VIF_Config *)ext_proto.vif_config[i], 0, sizeof(struct schema_Wifi_VIF_Config));

        //Allocate the memory
        ext_proto.vif_state[i] = (struct schema_Wifi_VIF_State *)malloc(sizeof(struct schema_Wifi_VIF_State));
        if (ext_proto.vif_state[i] == NULL) {
            printf("[%s]:%d Memory allocation fail for %d\n",__FUNCTION__,__LINE__, i);
            free_ovs_schema_structs();
            return;
        }
        memset((struct schema_Wifi_VIF_State *)ext_proto.vif_state[i], 0, sizeof(struct schema_Wifi_VIF_State));
    }

    ext_proto.assoc_clients = (const struct schema_Wifi_Associated_Clients **) malloc(sizeof(struct schema_Wifi_Associated_Clients *) * MAX_NUM_CLIENTS);
    if (ext_proto.assoc_clients== NULL) {
        printf("[%s]:%d Memory allocation fail for assoc clients table\n",__FUNCTION__,__LINE__);
        free_ovs_schema_structs();
        return;
    }
    memset((struct schema_Wifi_Associated_Clients **)ext_proto.assoc_clients, 0, (sizeof(struct schema_Wifi_Associated_Clients *) * MAX_NUM_CLIENTS));

    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        ext_proto.assoc_clients[i] = (struct schema_Wifi_Associated_Clients *)malloc(sizeof(struct schema_Wifi_Associated_Clients));
        if (ext_proto.assoc_clients[i] == NULL) {
            printf("[%s]:%d Memory allocation fail for %d\n",__FUNCTION__,__LINE__, i);
            free_ovs_schema_structs();
            return;
        }
        memset((struct schema_Wifi_Associated_Clients *)ext_proto.assoc_clients[i], 0, sizeof(struct schema_Wifi_Associated_Clients));
    }

    return;
}

void free_ovs_schema_structs()
{
    if (enable_ovsdb == true) {
        unsigned int i = 0;
        if (is_ovs_init == true) {
            for (i = 0; i < MAX_NUM_RADIOS; i++) {
                if (ext_proto.radio_config[i] != NULL) {
                    free((struct schema_Wifi_Radio_Config *)ext_proto.radio_config[i]);
                    ext_proto.radio_config[i] = NULL;
                }

                if (ext_proto.radio_state[i] != NULL) {
                    free((struct schema_Wifi_Radio_State *)ext_proto.radio_state[i]);
                    ext_proto.radio_state[i] = NULL;
                }

            }

            if (ext_proto.radio_config != NULL) {
                free(ext_proto.radio_config);
                ext_proto.radio_config = NULL;
            }

            if (ext_proto.radio_state != NULL) {
                free(ext_proto.radio_state);
                ext_proto.radio_state = NULL;
            }

            for (i = 0; i < MAX_VAP; i++) {
                if (ext_proto.vif_config[i] != NULL) {
                    free((struct schema_Wifi_VIF_Config *)ext_proto.vif_config[i]);
                    ext_proto.vif_config[i] = NULL;
                }
                if (ext_proto.vif_state[i] != NULL) {
                    free((struct schema_Wifi_VIF_State *)ext_proto.vif_state[i]);
                    ext_proto.vif_state[i] = NULL;
                }
            }
            if (ext_proto.vif_config != NULL) {
                free(ext_proto.vif_config);
                ext_proto.vif_config = NULL;
            }
            if (ext_proto.vif_state != NULL) {
                free(ext_proto.vif_state);
                ext_proto.vif_state = NULL;
            }

            for (i = 0; i < MAX_NUM_CLIENTS; i++) {
                if (ext_proto.assoc_clients[i] != NULL) {
                    free((struct schema_Wifi_Associated_Clients *)ext_proto.assoc_clients[i]);
                    ext_proto.assoc_clients[i] = NULL;
                }
            }
            if (ext_proto.assoc_clients!= NULL) {
                free(ext_proto.assoc_clients);
                ext_proto.assoc_clients = NULL;
            }

            is_ovs_init = false;
        }
        enable_ovsdb = false;
    }
}

int webconfig_rbus_event_publish(webconfig_consumer_t *consumer, char *event_name, unsigned char event_type, unsigned char *data)
{
    bool l_bool_data;
    unsigned int l_uint_data;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, event_name, value);
    if (event_type == rbus_bool_data) {
        memcpy(&l_bool_data, data, sizeof(l_bool_data));
        rbusValue_SetBoolean(value, l_bool_data);
    } else if (event_type == rbus_int_data) {
        memcpy(&l_uint_data, data, sizeof(l_uint_data));
        rbusValue_SetUInt32(value, l_uint_data);
    }
    event.name = event_name;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    if (rbusEvent_Publish(consumer->rbus_handle, &event) != RBUS_ERROR_SUCCESS) {
        printf( "%s:%d: rbusEvent_Publish Event failed for %s\n", __func__, __LINE__, event_name);
        return RETURN_ERR;
    } else {
        printf( "%s:%d: rbusEvent_Publish success for %s\n", __func__, __LINE__, event_name);
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

int recv_data_decode(webconfig_consumer_t *consumer, webconfig_subdoc_data_t *data, const char *recv_data)
{
    webconfig_error_t ret = webconfig_error_none;

    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data->u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));
    ret = webconfig_decode(&consumer->webconfig, data, recv_data);

    if (ret == webconfig_error_none) {
        return 0;
    } else {
        return -1;
    }
}

int get_device_network_mode_from_ctrl_thread(webconfig_consumer_t *consumer, unsigned int *device_network_mode)
{
    rbusValue_t value;
    const char *str;
    int len = 0;
    int rc = RBUS_ERROR_SUCCESS;
    webconfig_consumer_t l_consumer;
    webconfig_subdoc_data_t data;
    const char *paramNames[] = {WIFI_WEBCONFIG_INIT_DML_DATA};
    memset(&l_consumer, 0, sizeof(l_consumer));

    rc = rbus_get(consumer->rbus_handle, paramNames[0], &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf ("rbus_get failed for [%s] with error [%d]\n", paramNames[0], rc);
        return -1;
    }

    str = rbusValue_GetString(value, &len);
    if (str == NULL) {
        printf("%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return -1;
    }

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    rc = recv_data_decode(consumer, &data, str);
    if (rc == 0) {
        memcpy((unsigned char *)&l_consumer.config, (unsigned char *)&data.u.decoded.config, sizeof(wifi_global_config_t));
        *device_network_mode = l_consumer.config.global_parameters.device_network_mode;
        printf("%s:%d: get device network mode:%d\n", __func__, __LINE__, *device_network_mode);
    } else {
        printf("%s:%d: use default value\r\n", __func__, __LINE__);
        *device_network_mode = consumer->config.global_parameters.device_network_mode;
    }

    return 0;
}

int rbus_multi_get(webconfig_consumer_t *consumer, char *first_arg, char *next_arg)
{
    int rc = RBUS_ERROR_SUCCESS;
    int numOfInputParams = 0, numOfOutVals = 0;
    const char *pInputParam[RBUS_CLI_MAX_PARAM] = {0, 0};
    rbusProperty_t outputVals = NULL;
    int i = 0;

    if (first_arg != NULL) {
        pInputParam[numOfInputParams] = first_arg;
        numOfInputParams++;
    }

    if (next_arg != NULL) {
        pInputParam[numOfInputParams] = next_arg;
        numOfInputParams++;
    }

    if (numOfInputParams == 0) {
        printf("%s:%d: numOfInputParams = %d\r\n", __func__, __LINE__, numOfInputParams);
        return -1;
    }

    rc = rbus_getExt(consumer->rbus_handle, numOfInputParams, pInputParam, &numOfOutVals, &outputVals);
    if(RBUS_ERROR_SUCCESS == rc) {
        rbusProperty_t next = outputVals;
        for (i = 0; i < numOfOutVals; i++) {
            rbusValue_t val = rbusProperty_GetValue(next);
            rbusValueType_t type = rbusValue_GetType(val);
            char *pStrVal = rbusValue_ToString(val,NULL,0);

            printf ("Parameter %2d:\n\r", i+1);
            printf ("              Name  : %s\n\r", rbusProperty_GetName(next));
            printf ("              Type  : %d\n\r", type);
            printf ("              Value : %s\n\r", pStrVal);

            if(pStrVal) {
                free(pStrVal);
            }

            next = rbusProperty_GetNext(next);
        }
        /* Free the memory */
        rbusProperty_Release(outputVals);
    } else {
        printf ("Failed to get the data. Error : %d\n\r",rc);
        return -1;
    }

    return 0;
}

int parse_input_parameters(char *first_input, char *second_input, char *input_file_name)
{
    webconfig_consumer_t *consumer = get_consumer_object();
    unsigned int device_network_mode = 0;
    unsigned int vap_index = 0;

    if (!strncmp(first_input, "-w", strlen("-w"))) {
        if (consumer->rbus_events_subscribed == true) {

            if (dml_init_sync == false) {
                printf("%s %d Test for DML subdoc testing\n", __func__, __LINE__);
                dml_init_sync = true;
                enable_ovsdb = false;
                is_ovs_init = false;
                test_initial_sync();
            }


            if (!strncmp(second_input, "radio", strlen("radio"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_radio_subdoc);
            } else if (!strncmp(second_input, "private", strlen("private"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_private_subdoc);
            } else if (!strncmp(second_input, "meshsta", strlen("meshsta"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_sta_subdoc);
            } else if (!strncmp(second_input, "mesh", strlen("mesh"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_subdoc);
            } else if (!strncmp(second_input, "xfinity", strlen("xfinity"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_xfinity_subdoc);
            } else if (!strncmp(second_input, "lnf", strlen("lnf"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_lnf_subdoc);
            } else if (!strncmp(second_input, "home", strlen("home"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_home_subdoc);
            } else if (!strncmp(second_input, "all", strlen("all"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_all_subdoc);
            } else if (!strncmp(second_input, "macfilter", strlen("macfilter"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_macfilter_subdoc);
            } else if (!strncmp(second_input, "sync", strlen("sync"))) {
                test_initial_sync();
            } else {
                printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
                return RETURN_ERR;
            }
        } else {
            printf("%s:%d: rbus event not subsctibed:\r\n", __func__, __LINE__);
        }
    } else if (!strncmp(first_input, "-c", strlen("-c"))) {
        if (!strncmp(second_input, "0", strlen("0"))) {
            get_device_network_mode_from_ctrl_thread(consumer, &device_network_mode);
            if (device_network_mode == rdk_dev_mode_type_ext) {
                consumer_app_trigger_wan_test(consumer, consumer_test_start_wan_manager, false);
            } else {
                printf("%s:%d: current mode is %d, wan manager test-case run only in extender(station) mode\r\n", __func__, __LINE__, device_network_mode);
            }
        } else if (!strncmp(second_input, "1", strlen("1"))) {
            get_device_network_mode_from_ctrl_thread(consumer, &device_network_mode);
            if (device_network_mode == rdk_dev_mode_type_ext) {
                consumer_app_trigger_wan_test(consumer, consumer_test_start_wan_manager, true);
            } else {
                printf("%s:%d: current mode is %d, wan manager test-case run only in extender(station) mode\r\n", __func__, __LINE__, device_network_mode);
            }
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }
    } else if (!strncmp(first_input, "-t", strlen("-t"))) {
        if (!strncmp(second_input, "0", strlen("0"))) {
            generate_tunnel_event(false, consumer->rbus_handle);
        } else if (!strncmp(second_input, "1", strlen("1"))) {
            generate_tunnel_event(true, consumer->rbus_handle);
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }
    } else if (!strncmp(first_input, "-o", strlen("-o"))) {
        if (consumer->rbus_events_subscribed == true) {

            enable_ovsdb = true;
            if (is_ovs_init == false) {
                printf("%s %d Test for subdoc testing for ovs\n", __func__, __LINE__);
                initialize_ovs_schema_structs();
                is_ovs_init = true;
                test_initial_sync();
                dml_init_sync = false;
            }

            if (!strncmp(second_input, "radio", strlen("radio"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_radio_subdoc);
            } else if (!strncmp(second_input, "meshsta", strlen("meshsta"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_sta_subdoc);
            } else if (!strncmp(second_input, "mesh", strlen("mesh"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_subdoc);
            } else if (!strncmp(second_input, "macfilter", strlen("macfilter"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_macfilter_subdoc);
            } else if (!strncmp(second_input, "sync", strlen("sync"))) {
                test_initial_sync();
            } else if (!strncmp(second_input, "null", strlen("null"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_null_subdoc);
            } else if (!strncmp(second_input, "private", strlen("private"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_private_subdoc);
            } else if (!strncmp(second_input, "lnf", strlen("lnf"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_lnf_subdoc);
            } else if (!strncmp(second_input, "home", strlen("home"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_home_subdoc);
            } else if (!strncmp(second_input, "xfinity", strlen("xfinity"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_xfinity_subdoc);
            } else if (!strncmp(second_input, "getsubdoc", strlen("getsubdoc"))) {
                test_getsubdoctype(consumer);
            } else if (!strncmp(second_input, "disable", strlen("disable"))) {
                free_ovs_schema_structs();
                is_ovs_init = false;
                enable_ovsdb = false;
            } else {
                printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
                return RETURN_ERR;
            }
        } else {
            printf("%s:%d: rbus event not subsctibed:\r\n", __func__, __LINE__);
        }
    } else if (!strncmp(first_input, "-d", strlen("-d"))) {
        if (!strncmp(second_input, "1", strlen("1"))) {
            debug_enable = true;
        } else if (!strncmp(second_input, "0", strlen("0"))) {
            debug_enable = false;
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }

    } else if (!strncmp(first_input, "-a", strlen("-a"))) {
        if (!strncmp(second_input, "DeviceNetworkMode", strlen("DeviceNetworkMode"))) {
            if ((!strncmp(input_file_name, "1", strlen("1"))) ||
                    (!strncmp(input_file_name, "0", strlen("0")))) {
                unsigned int device_mode = atoi(input_file_name);
                webconfig_rbus_event_publish(consumer, TEST_WIFI_DEVICE_MODE, rbus_int_data, (unsigned char *)&device_mode);
            } else {
                printf("%s:%d: wrong third argument:%s\r\n", __func__, __LINE__, input_file_name);
                return RETURN_ERR;
            }
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }

    } else if (!strncmp(first_input, "-kickmac", strlen("-kickmac"))) {
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_KICK_MAC, second_input);

    } else if (!strncmp(first_input, "wps", strlen("wps"))) {
        vap_index = atoi(second_input);
        if (vap_index < MAX_VAP) {
            webconfig_rbus_event_publish(consumer, RBUS_WIFI_WPS_PIN_START, rbus_int_data, (unsigned char *)&vap_index);
        } else {
            printf("%s:%d: wrong second argument:%s:vap_index:%d:%d\r\n", __func__, __LINE__, second_input, vap_index, MAX_VAP);
            return RETURN_ERR;
        }

    } else if (!strncmp(first_input, "rbusGet", strlen("rbusGet"))) {
        rbus_multi_get(consumer, second_input, input_file_name);

    } else {
        printf("%s:%d: wrong first argument:%s\r\n", __func__, __LINE__, first_input);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_rbus_sta_interface_name(const char *paramNames)
{
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    webconfig_consumer_t *consumer = get_consumer_object();

    rc = rbus_get(consumer->rbus_handle, paramNames, &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf ("rbus_get failed for [%s] with error [%d]\n", paramNames, rc);
        return -1;
    }

    printf(":%s:%d Sta interface name = [%s]\n", __func__, __LINE__, rbusValue_GetString(value, NULL));

    return 0;
}

void webconfig_consumer_sta_conn_status(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    bool conn_status;
    unsigned int index = 0;
    int len = 0;
    wifi_sta_conn_info_t sta_conn_info;
    memset(&sta_conn_info, 0, sizeof(wifi_sta_conn_info_t));
    mac_addr_str_t mac_str;
    const unsigned char *temp_buff;
    rbusValue_t value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        printf("%s:%d FAIL: value is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    printf("%s:%d Rbus event name=%s\n",__FUNCTION__, __LINE__, event->name);

    sscanf(event->name, "Device.WiFi.STA.%d.Connection.Status", &index);
    temp_buff = rbusValue_GetBytes(value, &len);
    if (temp_buff == NULL) {
        printf("%s:%d Rbus get string failure len=%d\n", __FUNCTION__, __LINE__, len);
        return;
    }

    memcpy(&sta_conn_info, temp_buff, len);
    conn_status = (sta_conn_info.connect_status == wifi_connection_status_connected) ? true:false;
    if (conn_status == true) {
        printf("%s:%d: Station successfully connected with external AP radio:%d\r\n",
                    __func__, __LINE__, index - 1);
        if (index == 1) {
            get_rbus_sta_interface_name(WIFI_STA_2G_INTERFACE_NAME);
        } else if (index == 2) {
            get_rbus_sta_interface_name(WIFI_STA_5G_INTERFACE_NAME);
        }
    } else {
        printf("%s:%d: Station disconnected with external AP:%d radio:%d\r\n",
                __func__, __LINE__, conn_status, index - 1);
    }
    printf("%s:%d: MAC address info:%s\r\n", __func__, __LINE__, to_mac_str(sta_conn_info.bssid, mac_str));

    return;
}

void webconfig_consumer_sta_interface_name(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    unsigned int index = 0;
    int len = 0;
    const char *temp_buff;
    rbusValue_t value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        printf("%s:%d FAIL: value is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    printf("%s:%d Rbus event name=%s\n",__FUNCTION__, __LINE__, event->name);

    sscanf(event->name, "Device.WiFi.STA.%d.InterfaceName", &index);

    temp_buff = rbusValue_GetString(value, &len);
    if (temp_buff == NULL) {
        printf("%s:%d Rbus get string failure len=%d\n", __FUNCTION__, __LINE__, len);
        return;
    }

    printf("%s:%d radio index:%d Rbus get string:%s len=%d\n",__FUNCTION__, __LINE__, index, temp_buff, len);
    return;
}

void consumer_queue_loop(webconfig_consumer_t *consumer)
{
    struct timespec time_to_wait;
    struct timeval tv_now;
    time_t  time_diff;
    int rc;
    consumer_event_t *queue_data = NULL;

    while (consumer->exit_consumer == false) {
        gettimeofday(&tv_now, NULL);
        time_to_wait.tv_nsec = 0;
        time_to_wait.tv_sec = tv_now.tv_sec + consumer->poll_period;

        if (consumer->last_signalled_time.tv_sec > consumer->last_polled_time.tv_sec) {
            time_diff = consumer->last_signalled_time.tv_sec - consumer->last_polled_time.tv_sec;
            if ((UINT)time_diff < consumer->poll_period) {
                time_to_wait.tv_sec = tv_now.tv_sec + (consumer->poll_period - time_diff);
            }
        }

        pthread_mutex_lock(&consumer->lock);
        rc = pthread_cond_timedwait(&consumer->cond, &consumer->lock, &time_to_wait);
        if (rc == 0) {
            while (queue_count(consumer->queue)) {
                queue_data = queue_pop(consumer->queue);
                if (queue_data == NULL) {
                    pthread_mutex_unlock(&consumer->lock);
                    continue;
                }
                switch (queue_data->event_type) {
                    case consumer_event_type_webconfig:
                        printf("%s:%d consumer webconfig event subtype:%d\r\n",__func__, __LINE__, queue_data->sub_type);
                        handle_webconfig_consumer_event(consumer, queue_data->msg, queue_data->len, queue_data->sub_type);
                    break;

                    default:
                        //printf("[%s]:WIFI consumer thread not supported this event %d\r\n",__FUNCTION__, queue_data->event_type);
                    break;
                }

                if(queue_data->msg) {
                    free(queue_data->msg);
                }

                free(queue_data);
                gettimeofday(&consumer->last_signalled_time, NULL);
            }
        } else if (rc == ETIMEDOUT) {
            gettimeofday(&consumer->last_polled_time, NULL);
            scheduler_execute(consumer->sched, consumer->last_polled_time, (consumer->poll_period*1000));

#ifndef WEBCONFIG_TESTS_OVER_QUEUE
            if (consumer->rbus_events_subscribed == false) {
                consumer_events_subscribe(consumer);
                if (consumer->rbus_events_subscribed == true) {
                    dml_init_sync = true;
                    enable_ovsdb = false;
                    is_ovs_init = false;
                    printf("%s %d Trigger initial sync message\r\n", __func__, __LINE__);
                    test_initial_sync();
                }
            }
#endif
            if (consumer->rbus_events_subscribed == true) {
                if ((consumer->test_input == consumer_test_start_all_subdoc) &&
                        (consumer->test_state != consumer_test_state_home_subdoc_test_complete)) {
                    consumer_app_all_test_sequence(consumer);
                }
            }

            if ((consumer->test_state == consumer_test_state_radio_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_radio_subdoc)) {
                consumer->radio_test_pending_count++;
                if (consumer->radio_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: Radio test failed, timed out\n", __func__, __LINE__);
                    consumer->radio_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_radio_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_private_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_private_subdoc)) {
                consumer->private_test_pending_count++;
                if (consumer->private_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: Private vap test failed, timed out\n", __func__, __LINE__);
                    consumer->private_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_private_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_mesh_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_mesh_subdoc)) {
                consumer->mesh_test_pending_count++;
                if (consumer->mesh_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: Mesh vap test failed, timed out\n", __func__, __LINE__);
                    consumer->mesh_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_mesh_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_xfinity_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_xfinity_subdoc)) {
                consumer->xfinity_test_pending_count++;
                if (consumer->xfinity_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: xfinity vap test failed, timed out\n", __func__, __LINE__);
                    consumer->xfinity_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_home_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_home_subdoc)) {
                consumer->home_test_pending_count++;
                if (consumer->home_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: home vap test failed, timed out\n", __func__, __LINE__);
                    consumer->home_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_home_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_macfilter_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_macfilter_subdoc)) {
                consumer->macfilter_test_pending_count++;
                if (consumer->macfilter_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: macfilter test failed, timed out\n", __func__, __LINE__);
                    consumer->macfilter_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_macfilter_subdoc_test_complete;
                }
            }  else if ((consumer->test_state == consumer_test_state_null_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_null_subdoc)) {
                consumer->null_test_pending_count++;
                if (consumer->null_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: null test failed, timed out\n", __func__, __LINE__);
                    consumer->null_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_null_subdoc_test_complete;
                }
            }

        } else {
            pthread_mutex_unlock(&consumer->lock);
            printf("RDK_LOG_WARN, WIFI %s: Invalid Return Status %d\n",__FUNCTION__,rc);
            continue;
        }
        pthread_mutex_unlock(&consumer->lock);
    }

    return;
}



int start_tests(webconfig_consumer_t *consumer)
{
    consumer->exit_consumer = false;
    consumer->radio_test_pending_count = 0;
    consumer->private_test_pending_count = 0;
    consumer->mesh_test_pending_count = 0;

    consumer->test_state = consumer_test_state_none;
    consumer_queue_loop(consumer);

    printf("%s:%d Exited queue_wifi_consumer_task.\n",__FUNCTION__,__LINE__);
    return 0;
}

void run_tests()
{
    if (init_tests(&webconfig_consumer) != 0) {
        printf("%s:%d: Failed to init\n", __func__, __LINE__);
        return;
    }

    create_cli_task();
    start_tests(&webconfig_consumer);

}

#ifdef WEBCONFIG_TESTS_OVER_QUEUE
void *webconfig_consumer_tests(void *arg)
{
    wifi_mgr_t *mgr = (wifi_mgr_t *)arg;

    pthread_cond_signal(&mgr->dml_init_status);
    printf("%s:%d:test program started\n", __func__, __LINE__);

    webconfig_consumer.test_over_rbus = false;

    run_tests();

    return NULL;

}
#endif

void set_test_data_radio()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    wifi_mgr_t *mgr = get_wifimgr_obj();
    rdk_wifi_radio_t    *radio = mgr->radio_config;
    wifi_radio_operationParam_t *oper;

    // Radio 1
    radio = &mgr->radio_config[0];

    strcpy(radio->name, "radio1");

    radio->vaps.radio_index = 0;
    radio->vaps.num_vaps = 8;
    radio->vaps.rdk_vap_array[0].vap_index = 0;
    strcpy((char *)radio->vaps.rdk_vap_array[0].vap_name, "private_ssid_2g");
    radio->vaps.rdk_vap_array[1].vap_index = 2;
    strcpy((char *)radio->vaps.rdk_vap_array[1].vap_name, "iot_ssid_2g");
    radio->vaps.rdk_vap_array[2].vap_index = 4;
    strcpy((char *)radio->vaps.rdk_vap_array[2].vap_name, "hotspot_open_2g");
    radio->vaps.rdk_vap_array[3].vap_index = 6;
    strcpy((char *)radio->vaps.rdk_vap_array[3].vap_name, "lnf_psk_2g");
    radio->vaps.rdk_vap_array[4].vap_index = 8;
    strcpy((char *)radio->vaps.rdk_vap_array[4].vap_name, "hotspot_secure_2g");
    radio->vaps.rdk_vap_array[5].vap_index = 10;
    strcpy((char *)radio->vaps.rdk_vap_array[5].vap_name, "lnf_radius_2g");
    radio->vaps.rdk_vap_array[6].vap_index = 12;
    strcpy((char *)radio->vaps.rdk_vap_array[6].vap_name, "mesh_backhaul_2g");
    radio->vaps.rdk_vap_array[7].vap_index = 14;
    strcpy((char *)radio->vaps.rdk_vap_array[7].vap_name, "mesh_sta_2g");

    oper = &radio->oper;
    oper->enable = true;
    oper->band = WIFI_FREQUENCY_2_4_BAND;
    oper->autoChannelEnabled = true;
    oper->channel = 6;
    oper->channelWidth = 1;

    // Radio 2
    radio = &mgr->radio_config[1];

    strcpy(radio->name, "radio2");

    radio->vaps.radio_index = 1;
    radio->vaps.num_vaps = 8;
    radio->vaps.rdk_vap_array[0].vap_index = 1;
    strcpy((char *)radio->vaps.rdk_vap_array[0].vap_name, "private_ssid_5g");
    radio->vaps.rdk_vap_array[1].vap_index = 3;
    strcpy((char *)radio->vaps.rdk_vap_array[1].vap_name, "iot_ssid_5g");
    radio->vaps.rdk_vap_array[2].vap_index = 5;
    strcpy((char *)radio->vaps.rdk_vap_array[2].vap_name, "hotspot_open_5g");
    radio->vaps.rdk_vap_array[3].vap_index = 7;
    strcpy((char *)radio->vaps.rdk_vap_array[3].vap_name, "lnf_psk_5g");
    radio->vaps.rdk_vap_array[4].vap_index = 9;
    strcpy((char *)radio->vaps.rdk_vap_array[4].vap_name, "hotspot_secure_5g");
    radio->vaps.rdk_vap_array[5].vap_index = 11;
    strcpy((char *)radio->vaps.rdk_vap_array[5].vap_name, "lnf_radius_5g");
    radio->vaps.rdk_vap_array[6].vap_index = 13;
    strcpy((char *)radio->vaps.rdk_vap_array[6].vap_name, "mesh_backhaul_5g");
    radio->vaps.rdk_vap_array[7].vap_index = 15;
    strcpy((char *)radio->vaps.rdk_vap_array[7].vap_name, "mesh_sta_5g");

    oper = &radio->oper;
    oper->enable = true;
    oper->band = WIFI_FREQUENCY_5_BAND;
    oper->autoChannelEnabled = true;
    oper->channel = 36;
    oper->channelWidth = 1;
#endif//WEBCONFIG_TESTS_OVER_QUEUE
}


void set_config_data()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    mac_address_t client_mac = {0x01, 0x21, 0x33, 0x45, 0x42, 0xdd};
    wifi_mgr_t *mgr = get_wifimgr_obj();
    wifi_global_config_t *config = &mgr->global_config;
    wifi_GASConfiguration_t *gas_config = &config->gas_config;;
    wifi_global_param_t *global_param = &config->global_parameters;

    // fill config
    gas_config->AdvertisementID = 0;
    gas_config->PauseForServerResponse = true;
    gas_config->ResponseTimeout = 1000;
    gas_config->ComeBackDelay = 40;
    gas_config->ResponseBufferingTime = 10;
    gas_config->QueryResponseLengthLimit = 100;

    global_param->notify_wifi_changes = true;
    global_param->prefer_private = true;
    global_param->prefer_private_configure = true;
    global_param->factory_reset = false;
    global_param->tx_overflow_selfheal = false;
    global_param->inst_wifi_client_enabled = false;
    global_param->inst_wifi_client_reporting_period = 10;
    memcpy(global_param->inst_wifi_client_mac, client_mac, sizeof(mac_address_t));
    strcpy(global_param->wps_pin, "1234");
    strcpy(global_param->wifi_region_code, "US");
    global_param->validate_ssid = true;
#endif//WEBCONFIG_TESTS_OVER_QUEUE
}

void set_test_data_vaps()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    wifi_mgr_t *mgr = get_wifimgr_obj();
    rdk_wifi_radio_t    *radio = (rdk_wifi_radio_t *)&mgr->radio_config;
    wifi_vap_info_map_t *map;
    wifi_vap_info_t *vap;

    // Radio 1
    radio = &mgr->radio_config[0];
    map = &radio->vaps.vap_map;
    map->num_vaps = 8;

    // private
    vap = &radio->vaps.vap_map.vap_array[0];
    vap->vap_index = 0;
    strcpy(vap->vap_name, "private_ssid_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_private_ssid_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // iot
    vap = &radio->vaps.vap_map.vap_array[1];
    vap->vap_index = 2;
    strcpy(vap->vap_name, "iot_ssid_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_iot_ssid_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot open
    vap = &radio->vaps.vap_map.vap_array[2];
    vap->vap_index = 4;
    strcpy(vap->vap_name, "hotspot_open_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_open_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_none;

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf psk
    vap = &radio->vaps.vap_map.vap_array[3];
    vap->vap_index = 6;
    strcpy(vap->vap_name, "lnf_psk_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_psk_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot secure
    vap = &radio->vaps.vap_map.vap_array[4];
    vap->vap_index = 8;
    strcpy(vap->vap_name, "hotspot_secure_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_secure_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "hotspot 2.4 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "hotspot 2.4 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf radius
    vap = &radio->vaps.vap_map.vap_array[5];
    vap->vap_index = 10;
    strcpy(vap->vap_name, "lnf_radius_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_radius_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "lnf 2.4 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "lnf 2.4 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");


    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh backhaul
    vap = &radio->vaps.vap_map.vap_array[6];
    vap->vap_index = 12;
    strcpy(vap->vap_name, "mesh_backhaul_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_mesh_backhaul_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh sta
    vap = &radio->vaps.vap_map.vap_array[7];
    vap->vap_index = 14;
    strcpy(vap->vap_name, "mesh_sta_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_sta;

    strcpy(vap->u.sta_info.ssid, "test_mesh_sta_2g");
    memset(vap->u.sta_info.bssid, 0, sizeof(bssid_t));
    vap->u.sta_info.enabled = true;

    vap->u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.sta_info.security.encr = wifi_encryption_aes;
    vap->u.sta_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.sta_info.security.u.key.key, "test1webconf");

    vap->u.sta_info.scan_params.period = 2;
    vap->u.sta_info.scan_params.channel.channel = 0;


    // Radio 2
    radio = &mgr->radio_config[1];
    map = &radio->vaps.vap_map;
    map->num_vaps = 8;

    // private
    vap = &radio->vaps.vap_map.vap_array[0];
    vap->vap_index = 1;
    strcpy(vap->vap_name, "private_ssid_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_private_ssid_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test2webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // iot
    vap = &radio->vaps.vap_map.vap_array[1];
    vap->vap_index = 3;
    strcpy(vap->vap_name, "iot_ssid_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_iot_ssid_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot open
    vap = &radio->vaps.vap_map.vap_array[2];
    vap->vap_index = 5;
    strcpy(vap->vap_name, "hotspot_open_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_open_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_none;

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf psk
    vap = &radio->vaps.vap_map.vap_array[3];
    vap->vap_index = 7;
    strcpy(vap->vap_name, "lnf_psk_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_psk_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot secure
    vap = &radio->vaps.vap_map.vap_array[4];
    vap->vap_index = 9;
    strcpy(vap->vap_name, "hotspot_secure_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_secure_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "hotspot 5 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "hotspot 5 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf radius
    vap = &radio->vaps.vap_map.vap_array[5];
    vap->vap_index = 11;
    strcpy(vap->vap_name, "lnf_radius_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_radius_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "lnf 5 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "lnf 5 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh backhaul
    vap = &radio->vaps.vap_map.vap_array[6];
    vap->vap_index = 13;
    strcpy(vap->vap_name, "mesh_backhaul_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_mesh_backhaul_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh sta
    vap = &radio->vaps.vap_map.vap_array[7];
    vap->vap_index = 15;
    strcpy(vap->vap_name, "mesh_sta_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_sta;

    strcpy(vap->u.sta_info.ssid, "test_mesh_sta_5g");
    memset(vap->u.sta_info.bssid, 0, sizeof(bssid_t));
    vap->u.sta_info.enabled = true;

    vap->u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.sta_info.security.encr = wifi_encryption_aes;
    vap->u.sta_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.sta_info.security.u.key.key, "test1webconf");

    vap->u.sta_info.scan_params.period = 2;
    vap->u.sta_info.scan_params.channel.channel = 0;

#endif//WEBCONFIG_TESTS_OVER_QUEUE
}

void webconfig_consumer_set_test_data()
{
    set_config_data();
    set_test_data_radio();
    set_test_data_vaps();
}

void dump_subdoc(const char *str, webconfig_subdoc_type_t type)
{
    if (debug_enable == false) {
        return ;
    }
    FILE *fp = NULL;
    char file_name[128];

    //    getcwd(file_name, 128);
    strcpy(file_name, "/tmp");
    switch (type) {
        case webconfig_subdoc_type_private:
            strcat(file_name, "/log_private_subdoc");
        break;

        case webconfig_subdoc_type_radio:
            strcat(file_name, "/log_radio_subdoc");
        break;

        case webconfig_subdoc_type_mesh:
            strcat(file_name, "/log_mesh_subdoc");
        break;
        case webconfig_subdoc_type_xfinity:
            strcat(file_name, "/log_xfinity_subdoc");
        break;
        case webconfig_subdoc_type_lnf:
            strcat(file_name, "/log_lnf_subdoc");
        break;
        case webconfig_subdoc_type_home:
            strcat(file_name, "/log_home_subdoc");
        break;
        case webconfig_subdoc_type_mac_filter:
            strcat(file_name, "/log_mac_filter_subdoc");
        break;
        case webconfig_subdoc_type_dml:
            strcat(file_name, "/log_dml_subdoc");
        break;

        case webconfig_subdoc_type_associated_clients:
            strcat(file_name, "/log_assoc_clients_subdoc");
        break;

        case webconfig_subdoc_type_null:
            strcat(file_name, "/log_null_subdoc");
            break;

        case webconfig_subdoc_type_mesh_sta:
            strcat(file_name, "/log_mesh_sta_subdoc");
        break;

        default:
            return;
    }

    if ((fp = fopen(file_name, "w")) == NULL) {
        printf("%s:%d: error opening file:%s\n", __func__, __LINE__, file_name);
        return;
    }

    fputs(str, fp);
    fclose(fp);

    return;
}

wifi_vap_info_t *get_wifi_radio_vap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix)
{
    unsigned int vap_array_index;
    wifi_vap_info_t *vap_info = NULL;

    for (vap_array_index = 0; vap_array_index < wifi_radio->vaps.vap_map.num_vaps; ++vap_array_index) {
        if (!strncmp(wifi_radio->vaps.vap_map.vap_array[vap_array_index].vap_name, vap_name_prefix, strlen(vap_name_prefix))) {
            vap_info = &wifi_radio->vaps.vap_map.vap_array[vap_array_index];
        }
    }
    return vap_info;
}

rdk_wifi_vap_info_t *get_wifi_radio_rdkvap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix)
{
    unsigned int vap_array_index;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;

    for (vap_array_index = 0; vap_array_index < wifi_radio->vaps.num_vaps; ++vap_array_index) {
        if (!strncmp(wifi_radio->vaps.rdk_vap_array[vap_array_index].vap_name, vap_name_prefix, strlen(vap_name_prefix))) {
            rdk_vap_info = &wifi_radio->vaps.rdk_vap_array[vap_array_index];
        }
    }
    return rdk_vap_info;
}
