/* ************************************************************************************
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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>  // Include the header file for struct ifaddrs
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <math.h>
#include "cJSON.h"
#include "wifi_webconfig.h"
#include "ctype.h"
#include "const.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"
#include "schema.h"
#include "schema_gen.h"
#include "webconfig_external_proto.h"

// static member to store the subdoc
static webconfig_subdoc_data_t  webconfig_easymesh_data;
/* global pointer to webconfig subdoc encoded data to avoid memory loss when passing data to  */
static char *webconfig_easymesh_raw_data_ptr = NULL;

// This routine will take mac adderess from the user and returns interfacename
int interfacename_from_mac(const mac_address_t *mac, char *ifname)
{
    struct ifaddrs *ifaddr = NULL, *tmp = NULL;
    struct sockaddr *addr;
    struct sockaddr_ll *ll_addr;
    bool found = false;

    if (getifaddrs(&ifaddr) != 0) {
        wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Failed to get interfae information\n", __func__, __LINE__);
        return -1;
    }

    tmp = ifaddr;
    while (tmp != NULL) {
        addr = tmp->ifa_addr;
        ll_addr = (struct sockaddr_ll*)tmp->ifa_addr;
        if ((addr != NULL) && (addr->sa_family == AF_PACKET) && (memcmp(ll_addr->sll_addr, mac, sizeof(mac_address_t)) == 0)) {
            strncpy(ifname, tmp->ifa_name, strlen(tmp->ifa_name));
            found = true;
            break;
        }

        tmp = tmp->ifa_next;
    }

    freeifaddrs(ifaddr);

    return (found == true) ? 0:-1;
}

// This routine will take mac adderess from the user and returns interfacename
int mac_address_from_name(const char *ifname, mac_address_t mac)
{
    int sock;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Failed to create socket\n", __func__, __LINE__);
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
        close(sock);
        wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: ioctl failed to get hardware address for interface:%s\n", __func__, __LINE__, ifname);
        return -1;
    }

    memcpy(mac, (unsigned char *)ifr.ifr_hwaddr.sa_data, sizeof(mac_address_t));

    close(sock);

    return 0;
}
// webconfig_easymesh_decode() will convert the onewifi structures to easymesh structures
webconfig_error_t webconfig_easymesh_decode(webconfig_t *config, const char *str,
        webconfig_external_easymesh_t *data,
        webconfig_subdoc_type_t *type)
{
    webconfig_easymesh_data.u.decoded.external_protos = (webconfig_external_easymesh_t *)data;
    webconfig_easymesh_data.descriptor = webconfig_data_descriptor_translate_to_easymesh;

    if (webconfig_decode(config, &webconfig_easymesh_data, str) != webconfig_error_none) {
        //        *data = NULL;
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Easymesh decode failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Easymesh decode subdoc type %d sucessfully\n", __func__, __LINE__, webconfig_easymesh_data.type);
    *type = webconfig_easymesh_data.type;
    //debug_external_protos(&webconfig_easymesh_data, __func__, __LINE__);
    webconfig_data_free(&webconfig_easymesh_data);
    return webconfig_error_none;
}

// webconfig_easymesh_encode() will convert the easymesh structures to onewifi structures
webconfig_error_t webconfig_easymesh_encode(webconfig_t *config,
        const webconfig_external_easymesh_t *data,
        webconfig_subdoc_type_t type,
        char **str)
{
    wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Easymesh encode subdoc type %d\n", __func__, __LINE__, type);

    webconfig_easymesh_data.u.decoded.external_protos = (webconfig_external_easymesh_t *)data;
    webconfig_easymesh_data.descriptor = webconfig_data_descriptor_translate_from_easymesh;
   // debug_external_protos(&webconfig_ovsdb_data, __func__, __LINE__);

    if (webconfig_encode(config, &webconfig_easymesh_data, type) != webconfig_error_none) {
        *str = NULL;
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Easymesh encode failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (webconfig_easymesh_raw_data_ptr != NULL) {
        free(webconfig_easymesh_raw_data_ptr);
        webconfig_easymesh_raw_data_ptr = NULL;
    }
    webconfig_easymesh_raw_data_ptr = webconfig_easymesh_data.u.encoded.raw;

    *str = webconfig_easymesh_raw_data_ptr;
    return webconfig_error_none;
}
// sets the default values in em_bss_info_t Easymesh structure
void default_em_bss_info(em_bss_info_t  *vap_row)
{
    memset(vap_row->est_svc_params_be,'\0',sizeof(vap_row->est_svc_params_be));
    memset(vap_row->est_svc_params_bk,'\0',sizeof(vap_row->est_svc_params_bk));
    memset(vap_row->est_svc_params_vi,'\0',sizeof(vap_row->est_svc_params_vi));
    memset(vap_row->est_svc_params_vo,'\0',sizeof(vap_row->est_svc_params_vo));

    vap_row->profile_1b_sta_allowed = false;
    vap_row->profile_1b_sta_allowed = false;
    vap_row->r1_disallowed = false;
    vap_row->r1_disallowed = false;
    vap_row->backhaul_use = false;
    vap_row->fronthaul_use = false;
    vap_row->xhs_use = false;
    vap_row->lnfpsk_use = false;
    vap_row->lnfradius_use = false;
    vap_row->meshsta_use = false;
    vap_row->multi_bssid = false;
    vap_row->transmitted_bssid = false;
    vap_row->assoc_allowed_status = 5;

    vap_row->unicast_bytes_sent = 0;
    vap_row->unicast_bytes_rcvd = 0;
    vap_row->numberofsta = 0;
    vap_row->byte_counter_units = 0;

    vap_row->num_fronthaul_akms = 0;
    memset(vap_row->fronthaul_passphrase,'\0',sizeof(vap_row->fronthaul_passphrase));

    vap_row->num_backhaul_akms = 0;
    memset(vap_row->backhaul_passphrase,'\0',sizeof(vap_row->backhaul_passphrase));

    vap_row->num_xhs_akms = 0;
    memset(vap_row->xhs_passphrase,'\0',sizeof(vap_row->xhs_passphrase));

    vap_row->num_lnf_psk_akms = 0;
    memset(vap_row->lnf_psk_passphrase,'\0',sizeof(vap_row->lnf_psk_passphrase));

    vap_row->num_lnf_radius_akms = 0;
    memset(vap_row->lnf_radius_passphrase,'\0',sizeof(vap_row->lnf_radius_passphrase));

    vap_row->num_mesh_sta_akms = 0;
    memset(vap_row->mesh_sta_passphrase,'\0',sizeof(vap_row->mesh_sta_passphrase));

}

// sets the default values in em_device_info_t Easymesh structure
void default_em_device_info(em_device_info_t  *device_info, em_ieee_1905_security_info_t *security_info)
{
    strncpy(device_info->net_id,"02:01:02:01:00:01",strlen("02:01:02:01:00:01"));
    strncpy(device_info->multi_ap_cap,"4A==",strlen("4A=="));
    strncpy(device_info->exec_env,"testEnv",strlen("testEnv"));
    memset(device_info->primary_device_type,'\0',sizeof(device_info->primary_device_type));
    memset(device_info->secondary_device_type,'\0',sizeof(device_info->secondary_device_type));
    device_info->traffic_sep_cap = false;
    device_info->report_unsuccess_assocs = false;
    device_info->traffic_sep_allowed = false;
    device_info->svc_prio_allowed = false;
    device_info->sta_steer_state = false;
    device_info->coord_cac_allowed = false;
    device_info->easy_conn_cap = false;

    device_info->coll_interval = 20000;
    device_info->max_reporting_rate = 1000;
    device_info->ap_metrics_reporting_interval = 200;
    device_info->max_unsuccessful_assoc_report_rate = 100;
    device_info->test_cap = 3;
    device_info->sec_1905.auth_flags = 0;
    device_info->sec_1905.encr_flags = 0;
    device_info->sec_1905.conn_flags = 0;
    device_info->sec_1905.cfg_methods = 0;
    memcpy(security_info->id,device_info->id.mac,sizeof(mac_address_t));
    security_info->sec_cap.onboarding_proto = 0;
    security_info->sec_cap.integrity_algo = 0;
    security_info->sec_cap.encryption_algo = 0;

}

// This routine converts DML webconfig subdoc values to em_device_info_t,em_network_info_t easymesh structures
webconfig_error_t   translate_device_object_to_easymesh_for_dml(webconfig_subdoc_data_t *data)
{
    em_device_info_t  *device_info;
    em_network_info_t *network_info;
    em_ieee_1905_security_info_t *security_info;

    webconfig_external_easymesh_t *proto;
    rdk_wifi_radio_t *radio;
    bool dfs_enable = false;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    webconfig_subdoc_decoded_data_t *decoded_params;
    decoded_params = &data->u.decoded;
    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    device_info = proto->em_device_cap_data;
    if (device_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: device_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    network_info = proto->em_network_data;
    if (network_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:network_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    security_info = proto->ieee_1905_security_data;
    if (security_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:network_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    strncpy(device_info->software_ver, wifi_prop->software_version, strlen(wifi_prop->software_version));
    strncpy(device_info->manufacturer_model, wifi_prop->manufacturerModel, strlen(wifi_prop->manufacturerModel));
    strncpy(device_info->manufacturer, wifi_prop->manufacturer, strlen(wifi_prop->manufacturer));
    strncpy(device_info->serial_number, wifi_prop->serialNo, strlen(wifi_prop->serialNo));
    memcpy(device_info->id.mac, wifi_prop->al_1905_mac, sizeof(mac_address_t));
    memcpy(device_info->backhaul_alid.mac, wifi_prop->al_1905_mac, sizeof(mac_address_t));
    interfacename_from_mac((const mac_address_t *)device_info->backhaul_alid.mac,device_info->backhaul_alid.name);
    device_info->num_radios = wifi_prop->numRadios;
    strncpy(device_info->country_code, "US", strlen("US"));
    for (unsigned int i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        dfs_enable  = radio->oper.DfsEnabled;
        if (dfs_enable)
            break;
    }
    device_info->dfs_enable = dfs_enable;
    default_em_device_info(device_info,security_info);

    // Fill the network_info structure
    memcpy(network_info->colocated_agent_id.mac, wifi_prop->al_1905_mac, sizeof(mac_address_t));
    interfacename_from_mac((const mac_address_t *)network_info->colocated_agent_id.mac,network_info->colocated_agent_id.name);
    memcpy(network_info->ctrl_id.mac, wifi_prop->cm_mac, sizeof(mac_address_t));
    interfacename_from_mac((const mac_address_t *)network_info->ctrl_id.mac,network_info->ctrl_id.name);
    uint8_mac_to_string_mac(network_info->colocated_agent_id.mac,network_info->id);

    return webconfig_error_none;
}

// This routine converts DML webconfig subdoc values to em_radio_list_t,em_radio_info_t easymesh structures
webconfig_error_t   translate_radio_object_to_easymesh_for_dml(webconfig_subdoc_data_t *data)
{
    em_radio_list_t   *em_radio_info;
    em_radio_info_t   *radio_info_row;
    em_op_class_info_t *op_class_info;
    unsigned int radio_index = 0, bss_count = 0;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t	*vap;
    wifi_vap_info_map_t *vap_map;
    radio_interface_mapping_t *radio_iface_map;
    webconfig_external_easymesh_t *proto;
    //wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
   wifi_radio_operationParam_t  *oper_param;
    webconfig_subdoc_decoded_data_t *decoded_params;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    em_radio_info = proto->em_radio_data;
    if (em_radio_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_translate_to_easymesh;
    }
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    for (unsigned int index = 0; index < decoded_params->num_radios; index++) {
        radio = &decoded_params->radios[index];
        bss_count = 0;
        vap_map = &radio->vaps.vap_map;
        for (unsigned int j = 0; j < radio->vaps.num_vaps; j++) {
            vap = &vap_map->vap_array[j];
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }
            bss_count++;
        }
        radio_info_row = &(em_radio_info[index].radio);
        if (radio_info_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio_info_row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_to_easymesh;
        }

        op_class_info = &(em_radio_info[index].radio_op);
        if (op_class_info == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: op_class_info is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_to_easymesh;
        }
        oper_param = &decoded_params->radios[index].oper;
		radio_info_row->number_of_bss = bss_count;
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[index].name);
        radio_info_row->enabled = oper_param->enable;
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for \n", __func__, __LINE__);
            return webconfig_error_translate_to_easymesh;
        }
        strncpy(radio_info_row->id.name,radio_iface_map->radio_name,sizeof(radio_info_row->id.name));
        mac_address_from_name(radio_iface_map->interface_name,radio_info_row->id.mac);

        strncpy(op_class_info->id.ruid.name,radio_iface_map->radio_name,sizeof(radio_info_row->id.name));
        mac_address_from_name(radio_iface_map->interface_name,op_class_info->id.ruid.mac);

        op_class_info->id.type = 2;
        op_class_info->op_class = oper_param->op_class;
        op_class_info->channel = oper_param->channel;
        op_class_info->tx_power = oper_param->transmitPower;
        op_class_info->max_tx_power = oper_param->transmitPower;
        op_class_info->num_non_op_channels = 0;
        //Add default params of radio_info
        radio_info_row->number_of_unassoc_sta = 0;
        radio_info_row->noise = 90;
        radio_info_row->utilization = 50;
        radio_info_row->number_of_curr_op_classes  = 1;
        radio_info_row->traffic_sep_combined_fronthaul = 0;
        radio_info_row->traffic_sep_combined_backhaul = 0;
        radio_info_row->steering_policy = 0;
        radio_info_row->channel_util_threshold = 0;
        radio_info_row->rcpi_steering_threshold = 0;
        radio_info_row->sta_reporting_rcpi_threshold = 0;
        radio_info_row->sta_reporting_hysteresis_margin_override = 0;
        radio_info_row->channel_utilization_reporting_threshold = 0;
        radio_info_row->associated_sta_traffic_stats_inclusion_policy = 0;
        radio_info_row->associated_sta_link_mterics_inclusion_policy = 0;
        strncpy (radio_info_row->chip_vendor, wifi_prop->manufacturer, strlen(radio_info_row->chip_vendor));

    }

    return webconfig_error_none;
}

// translate_vap_info_to_em_common() converts common data elements of wwifi_vap_info_ifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_vap_info_to_em_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map, wifi_platform_property_t *wifi_prop)
{
    unsigned k = 0;
    char mac_str[128] = "";
    radio_interface_mapping_t *radio_iface_map;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->enabled = vap->u.bss_info.enabled;
    strncpy(vap_row->ssid, vap->u.bss_info.ssid, sizeof(vap_row->ssid));

    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", vap->u.bss_info.bssid[0], vap->u.bss_info.bssid[1],
                                                    vap->u.bss_info.bssid[2], vap->u.bss_info.bssid[3],
                                                    vap->u.bss_info.bssid[4], vap->u.bss_info.bssid[5]);
    str_to_mac_bytes(mac_str,vap_row->bssid.mac);
    strncpy(vap_row->bssid.name,iface_map->interface_name,sizeof(vap_row->bssid.name));
    strncpy(ssid_vid_map->ssid, vap->u.bss_info.ssid, sizeof(ssid_vid_map->ssid));
    strncpy(ssid_vid_map->id, mac_str, sizeof(ssid_vid_map->id));
    ssid_vid_map->vid =  iface_map->vlan_id;

    default_em_bss_info(vap_row);
    radio_iface_map = NULL;
    for (k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
        if (wifi_prop->radio_interface_map[k].radio_index == vap->radio_index) {
            radio_iface_map = &(wifi_prop->radio_interface_map[k]);
            break;
        }
    }
    if (radio_iface_map == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_easymesh;
    }
    strncpy(vap_row->ruid.name,radio_iface_map->radio_name,sizeof(vap_row->ruid.name));
    mac_address_from_name(radio_iface_map->interface_name,vap_row->ruid.mac);	
    return webconfig_error_none;
}

// translate_sta_info_to_em_common() converts common data elements of wifi_vap_info_t related to sta to em_bss_info_t of  easymesh

webconfig_error_t translate_sta_info_to_em_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map, wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;
    char mac_str[128] = "";
    unsigned k = 0;
    radio_interface_mapping_t *radio_iface_map;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->enabled = vap->u.sta_info.enabled;
    strncpy(vap_row->ssid, vap->u.sta_info.ssid, sizeof(vap_row->ssid));

    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
                                                    vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
                                                    vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);
    str_to_mac_bytes(mac_str,vap_row->bssid.mac);
    strncpy(vap_row->bssid.name,iface_map->interface_name,sizeof(vap_row->bssid.name));	

    strncpy(ssid_vid_map->ssid, vap->u.sta_info.ssid, sizeof(ssid_vid_map->ssid));
    strncpy(ssid_vid_map->id, mac_str, sizeof(ssid_vid_map->id));
    ssid_vid_map->vid =  iface_map->vlan_id; 

    radio_iface_map = NULL;
    for (k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
        if (wifi_prop->radio_interface_map[k].radio_index == vap->radio_index) {
            radio_iface_map = &(wifi_prop->radio_interface_map[k]);
            break;
        }
    }
    if (radio_iface_map == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_easymesh;
    }
    strncpy(vap_row->ruid.name,radio_iface_map->radio_name,sizeof(vap_row->ruid.name));
    mac_address_from_name(radio_iface_map->interface_name,vap_row->ruid.mac);

    default_em_bss_info(vap_row);

    vap_row->num_fronthaul_akms = 1;
    enum_sec = vap->u.sta_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->fronthaul_akm[0],
        vap_row->fronthaul_akm[1], sizeof(vap_row->fronthaul_akm[0]),
        sizeof(vap_row->fronthaul_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
          "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
    }
    vap_row->num_backhaul_akms = 0;
    for (int i=0;i<EM_MAX_AKMS ; i++){
        vap_row->backhaul_akm[i][0] = '\0';
    }

    return webconfig_error_none;
}

// translate_private_vap_info_to_em_bss_config() converts private data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_private_vap_info_to_em_bss_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t      *vap_row,em_ssid_2_vid_map_info_t  *ssid_vid_map,  wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;

    if (translate_vap_info_to_em_common(vap, iface_map, vap_row, ssid_vid_map, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    vap_row->fronthaul_use = true;

    vap_row->num_fronthaul_akms = 1;
    // convert akm to its equivalent string
    enum_sec = vap->u.bss_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->fronthaul_akm[0],
         vap_row->fronthaul_akm[1], sizeof(vap_row->fronthaul_akm[0]),
         sizeof(vap_row->fronthaul_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
    }

    return webconfig_error_none;
}

// translate_xhs_vap_info_to_em_bss_config() converts xhs data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_xhs_vap_info_to_em_bss_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t      *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map,  wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;

    if (translate_vap_info_to_em_common(vap, iface_map, vap_row, ssid_vid_map, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    vap_row->xhs_use = true;

    vap_row->num_xhs_akms = 1;
    // convert akm to its equivalent string
    enum_sec = vap->u.bss_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->xhs_akm[0],
         vap_row->xhs_akm[1], sizeof(vap_row->xhs_akm[0]),
         sizeof(vap_row->xhs_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
    }
    strncpy(vap_row->xhs_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key));

    return webconfig_error_none;

}

// translate_lnf_psk_vap_info_to_em_bss_config() converts lnf_psk data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_lnf_psk_vap_info_to_em_bss_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t      *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map, wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;

    if (translate_vap_info_to_em_common(vap, iface_map, vap_row,ssid_vid_map, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->lnfpsk_use = true;

    vap_row->num_lnf_psk_akms = 1;
    // convert akm to its equivalent string
    enum_sec = vap->u.bss_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->lnf_psk_akm[0],
         vap_row->lnf_psk_akm[1], sizeof(vap_row->lnf_psk_akm[0]),
         sizeof(vap_row->lnf_psk_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
    }
    strncpy(vap_row->lnf_psk_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key));

    return webconfig_error_none;
}

// translate_lnf_radius_vap_info_to_em_bss_config() converts lnf_radio data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_lnf_radius_vap_info_to_em_bss_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t      *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map, wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;

    if (translate_vap_info_to_em_common(vap, iface_map, vap_row, ssid_vid_map,wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->lnfradius_use = true;

    vap_row->num_lnf_radius_akms = 1;
    enum_sec = vap->u.bss_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->lnf_radius_akm[0],
         vap_row->lnf_radius_akm[1], sizeof(vap_row->lnf_radius_akm[0]),
         sizeof(vap_row->lnf_radius_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
    }
    strncpy(vap_row->lnf_radius_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key));

    return webconfig_error_none;
}

// translate_mesh_backhaul_vap_info_to_em_bss_config() converts mesh_backhaul data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_mesh_backhaul_vap_info_to_em_bss_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t      *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map,wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;

    if (translate_vap_info_to_em_common(vap, iface_map, vap_row,ssid_vid_map, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->backhaul_use = true;

    vap_row->num_backhaul_akms = 1;
    enum_sec = vap->u.bss_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->backhaul_akm[0],
         vap_row->backhaul_akm[1], sizeof(vap_row->backhaul_akm[0]),
         sizeof(vap_row->backhaul_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
    }
    strncpy(vap_row->backhaul_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key));

    return webconfig_error_none;
}

// translate_mesh_sta_info_to_em_bss_config() converts mesh_sta data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_mesh_sta_info_to_em_bss_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t      *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map,wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;

    if (translate_sta_info_to_em_common(vap, iface_map, vap_row, ssid_vid_map, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->meshsta_use = true;

    vap_row->num_mesh_sta_akms = 1;
    enum_sec = vap->u.sta_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->mesh_sta_akm[0],
        vap_row->mesh_sta_akm[1], sizeof(vap_row->mesh_sta_akm[0]),
        sizeof(vap_row->mesh_sta_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
          "security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
    }

    enum_sec = vap->u.sta_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->fronthaul_akm[0],
         vap_row->fronthaul_akm[1], sizeof(vap_row->fronthaul_akm[0]),
         sizeof(vap_row->fronthaul_akm[1]), ENUM_TO_STRING, &len) != RETURN_OK) {

        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
    }
    strncpy(vap_row->mesh_sta_passphrase, vap->u.sta_info.security.u.key.key,strlen(vap->u.sta_info.security.u.key.key));

    return webconfig_error_none;
}

// translate_vap_object_to_easymesh_for_dml() converts DML data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t   translate_vap_object_to_easymesh_for_dml(webconfig_subdoc_data_t *data)
{
    em_radio_list_t   *em_radio_data;
    em_bss_info_t     *em_vap_info;
    em_bss_info_t     *vap_info_row;
    wifi_vap_info_map_t *vap_map;
    em_ssid_2_vid_map_info_t *ssid_vid_info;
    em_ssid_2_vid_map_info_t *ssid_vid_row;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    unsigned int count = 0;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0, k = 0;
    rdk_wifi_radio_t *radio;
    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    em_radio_data = proto->em_radio_data;
    if (em_radio_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_radio_list is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_translate_to_easymesh;
    }

    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
 
        em_vap_info = em_radio_data[i].bss_info;
        if (em_vap_info == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_vap_info is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_to_easymesh;
        }
        ssid_vid_info = em_radio_data[i].ssid_vid_map;
        if (ssid_vid_info == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:ssid_vid_info is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_to_easymesh;
        }
        vap_map = &radio->vaps.vap_map;
        count = 0;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }

            // please move this code to specific vap function like ovsdb_translator
            vap_info_row =  (em_bss_info_t *)(em_vap_info + count);
            ssid_vid_row = (em_ssid_2_vid_map_info_t *)(ssid_vid_info + count);
            count++;
            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }

            // please move this code to specific vap function like ovsdb_translator
            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_xhs_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_psk_vap_info_to_em_bss_config(vap, iface_map, vap_info_row,ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of backhaul vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh_stavap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            }
        }
    }
    return webconfig_error_none;
}

//translate_vap_object_to_easymesh_bss_info() converts data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_vap_object_to_easymesh_bss_info(webconfig_subdoc_data_t *data,char *vap_name)
{
    em_radio_list_t   *em_radio_data;
    em_bss_info_t     *em_vap_info;
    em_bss_info_t     *vap_info_row;
    em_ssid_2_vid_map_info_t *ssid_vid_info;
    em_ssid_2_vid_map_info_t *ssid_vid_row;
 
    wifi_vap_info_map_t *vap_map;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    unsigned int count = 0;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0, k = 0;
    rdk_wifi_radio_t *radio;
    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    em_radio_data = proto->em_radio_data;
    if (em_radio_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];

        em_vap_info = em_radio_data[i].bss_info;//Please add NULL check TBD-P
        ssid_vid_info = em_radio_data[i].ssid_vid_map;//Please add NULL check TBD-P
        vap_map = &radio->vaps.vap_map;
        count = 0;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }

            vap_info_row =  (em_bss_info_t *)(em_vap_info + count);
            ssid_vid_row = (em_ssid_2_vid_map_info_t *)(ssid_vid_info + count);
            count++;
            if (strstr(vap->vap_name,vap_name) == false) {
                continue;
            }
            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }

            // please move this code to specific vap function like ovsdb_translator
            vap_info_row =  (em_bss_info_t *)(em_vap_info + count); //Assumed on easy mesh side you will pass vap_info[16/24] structure, You will pass it.
            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_xhs_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row,  wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_psk_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row,  wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of backhaul vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row,  wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh_stavap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            }
        }
    }
    return webconfig_error_none;
}
// translate_em_common_to_vap_info_common() converts common data elements of em_bss_info_t to wifi_vap_info_t  of Onewifi
webconfig_error_t translate_em_common_to_vap_info_common( wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    vap->u.bss_info.enabled = vap_row->enabled ;
    strncpy(vap->u.bss_info.ssid,vap_row->ssid, sizeof(vap->u.bss_info.ssid));

    return webconfig_error_none;
}

// translate_em_common_to_sta_info_common() converts common data elements of em_bss_info_t to wifi_vap_info_t  of Onewifi
webconfig_error_t translate_em_common_to_sta_info_common(wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    vap->u.sta_info.enabled =  vap_row->enabled;
    strncpy( vap->u.sta_info.ssid,vap_row->ssid, sizeof(vap->u.sta_info.ssid));

    return webconfig_error_none;
}
// translate_em_bss_to_private_vap_info() em_bss_info_t data elements of wifi_vap_info_t of Onewifi for private vaps
webconfig_error_t translate_em_bss_to_private_vap_info(wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    wifi_security_modes_t enum_sec;
    int len = 0;
    if (translate_em_common_to_vap_info_common(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    if ((key_mgmt_conversion(&enum_sec, (char *)vap_row->fronthaul_akm[0], (char *)vap_row->fronthaul_akm[1], sizeof(vap_row->fronthaul_akm[0]), sizeof(vap_row->fronthaul_akm[1]), STRING_TO_ENUM, &len)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
            (vap_row->fronthaul_akm[0]) ? vap_row->fronthaul_akm[0]: "NULL");
        return webconfig_error_translate_from_easymesh;
    }

    strncpy(vap->u.bss_info.security.u.key.key,vap_row->fronthaul_passphrase,strlen(vap->u.bss_info.security.u.key.key));
    vap->u.bss_info.security.mode = enum_sec;

    return webconfig_error_none;
}

// translate_em_bss_to_xhs_vap_info() em_bss_info_t data elements of wifi_vap_info_t of Onewifi for xhs vaps
webconfig_error_t translate_em_bss_to_xhs_vap_info(wifi_vap_info_t *vap,  const em_bss_info_t *vap_row)
{

    wifi_security_modes_t enum_sec;
    int len = 0;
    if (translate_em_common_to_vap_info_common(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    if ((key_mgmt_conversion(&enum_sec, (char *)vap_row->xhs_akm[0], (char *)vap_row->xhs_akm[1], sizeof(vap_row->xhs_akm[0]), sizeof(vap_row->xhs_akm[1]), STRING_TO_ENUM, &len)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
            (vap_row->xhs_akm[0]) ? vap_row->xhs_akm[0]: "NULL");
        return webconfig_error_translate_from_easymesh;
    }

    strncpy(vap->u.bss_info.security.u.key.key,vap_row->xhs_passphrase,strlen(vap->u.bss_info.security.u.key.key));
    vap->u.bss_info.security.mode = enum_sec;

    return webconfig_error_none;
}

// translate_em_bss_to_lnf_psk_vap_info() em_bss_info_t data elements of wifi_vap_info_t of Onewifi for lnf_psk vaps
webconfig_error_t translate_em_bss_to_lnf_psk_vap_info(wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    wifi_security_modes_t enum_sec;
    int len = 0;
    if (translate_em_common_to_vap_info_common(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    if ((key_mgmt_conversion(&enum_sec, (char *)vap_row->lnf_psk_akm[0], (char *)vap_row->lnf_psk_akm[1], sizeof(vap_row->lnf_psk_akm[0]), sizeof(vap_row->lnf_psk_akm[1]), STRING_TO_ENUM, &len)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
            (vap_row->lnf_psk_akm[0]) ? vap_row->lnf_psk_akm[0]: "NULL");
        return webconfig_error_translate_from_easymesh;
    }

    strncpy(vap->u.bss_info.security.u.key.key,vap_row->lnf_psk_passphrase,strlen(vap->u.bss_info.security.u.key.key));
    vap->u.bss_info.security.mode = enum_sec;

    return webconfig_error_none;
}

// translate_em_bss_to_lnf_radius_vap_info() em_bss_info_t data elements of wifi_vap_info_t of Onewifi for lnf_radius vaps
webconfig_error_t translate_em_bss_to_lnf_radius_vap_info(wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    wifi_security_modes_t enum_sec;
    int len = 0;

    if (translate_em_common_to_vap_info_common(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    if ((key_mgmt_conversion(&enum_sec, (char *)vap_row->lnf_radius_akm[0], (char *)vap_row->lnf_radius_akm[1], sizeof(vap_row->lnf_radius_akm[0]), sizeof(vap_row->lnf_radius_akm[1]), STRING_TO_ENUM, &len)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
            (vap_row->lnf_radius_akm[0]) ? vap_row->lnf_radius_akm[0]: "NULL");
        return webconfig_error_translate_from_easymesh;
    }

    strncpy(vap->u.bss_info.security.u.key.key,vap_row->lnf_radius_passphrase,strlen(vap->u.bss_info.security.u.key.key));
    vap->u.bss_info.security.mode = enum_sec;

    return webconfig_error_none;
}
// translate_em_bss_to_mesh_backhaul_vap_info() em_bss_info_t data elements of wifi_vap_info_t of Onewifi for mesh_backhaul vaps
webconfig_error_t translate_em_bss_to_mesh_backhaul_vap_info(wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    wifi_security_modes_t enum_sec;
    int len = 0;
    
    if (translate_em_common_to_vap_info_common(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
   
    if ((key_mgmt_conversion(&enum_sec, (char *)vap_row->backhaul_akm[0], (char *)vap_row->backhaul_akm[1], sizeof(vap_row->backhaul_akm[0]), sizeof(vap_row->backhaul_akm[1]), STRING_TO_ENUM, &len)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
            (vap_row->backhaul_akm[0]) ? vap_row->backhaul_akm[0]: "NULL");
        return webconfig_error_translate_from_easymesh;
    }

    vap->u.bss_info.security.mode = enum_sec;
    strncpy(vap->u.bss_info.security.u.key.key,vap_row->backhaul_passphrase,strlen(vap->u.bss_info.security.u.key.key));

    return webconfig_error_none;
}

// translate_em_bss_to_mesh_sta_info() em_bss_info_t data elements of wifi_vap_info_t of Onewifi for mesh_sta vaps
webconfig_error_t translate_em_bss_to_mesh_sta_info(wifi_vap_info_t *vap,   const em_bss_info_t *vap_row)
{
    wifi_security_modes_t enum_sec;
    int len = 0;
    

    if (translate_em_common_to_sta_info_common(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    
    if ((key_mgmt_conversion(&enum_sec, (char *)vap_row->mesh_sta_akm[0], (char *)vap_row->mesh_sta_akm[1], sizeof(vap_row->mesh_sta_akm[0]), sizeof(vap_row->mesh_sta_akm[1]), STRING_TO_ENUM, &len)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
            (vap_row->mesh_sta_akm[0]) ? vap_row->mesh_sta_akm[0]: "NULL");
        return webconfig_error_translate_from_easymesh;
    }

    vap->u.sta_info.security.mode = enum_sec;
    strncpy(vap->u.sta_info.security.u.key.key,vap_row->mesh_sta_passphrase,strlen(vap->u.bss_info.security.u.key.key));

    return webconfig_error_none;
}


// translate_from_easymesh_bssinfo_to_vap_object() converts data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_from_easymesh_bssinfo_to_vap_object(webconfig_subdoc_data_t *data,char *vap_name)
{
    em_radio_list_t   *em_radio_data;
    em_bss_info_t     *em_vap_info;
    em_bss_info_t     *vap_info_row;
    wifi_vap_info_map_t *vap_map;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    unsigned int count = 0;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0, k = 0;
    rdk_wifi_radio_t *radio;
    wifi_hal_capability_t *hal_cap;
    decoded_params = &data->u.decoded;
    wifi_interface_name_idex_map_t *iface_map;

    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    em_radio_data = proto->em_radio_data;
    if (em_radio_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    hal_cap =&data->u.decoded.hal_cap;
    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];

        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            em_vap_info = em_radio_data[i].bss_info;//Please add NULL check TBD-P
            if (em_vap_info == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_vap_info is NULL\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            count = 0;
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }
            // please move this code to specific vap function like ovsdb_translator
            vap_info_row =  (em_bss_info_t *)(em_vap_info + count);
            count++;
            if (strstr(vap->vap_name,vap_name) == false) {
                continue;
            }

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_private_vap_info(vap,  vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  private vap failed %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
                count++;
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_xhs_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  iot vap  failed  %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
                count++;
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_lnf_psk_vap_info(vap,  vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to lnf psk vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
                count++;
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_lnf_radius_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  lnf radius vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
                count++;
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_mesh_backhaul_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  backhaul vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
                count++;
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_mesh_sta_info(vap,  vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  mesh_stavap failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            }
        }
    }
    return webconfig_error_none;
}

//translate_device_object_from_easymesh_to_dml() converts data elements of em_device_info_t of  easymesh to Onewifi
webconfig_error_t   translate_device_object_from_easymesh_to_dml(webconfig_subdoc_data_t *data)
{
    em_device_info_t  *device_info;
    em_network_info_t *network_info;

    webconfig_external_easymesh_t *proto;
    rdk_wifi_radio_t *radio;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    webconfig_subdoc_decoded_data_t *decoded_params;
    decoded_params = &data->u.decoded;
    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    device_info = proto->em_device_cap_data;
    if (device_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: device_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    network_info = proto->em_network_data;
    if (network_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:network_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    strncpy(wifi_prop->software_version, device_info->software_ver, strlen(device_info->software_ver));
    strncpy(wifi_prop->manufacturerModel,device_info->manufacturer_model, strlen(device_info->manufacturer_model));
    strncpy (wifi_prop->manufacturer, device_info->manufacturer, strlen(device_info->manufacturer));
    strncpy(wifi_prop->serialNo, device_info->serial_number,strlen(device_info->serial_number));
    memcpy( wifi_prop->al_1905_mac, device_info->id.mac, sizeof(mac_address_t));
    for (unsigned int i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        radio->oper.DfsEnabled =  device_info->dfs_enable;
    }

    // Fill the CMMac from network_info structure
    memcpy(wifi_prop->cm_mac, network_info->ctrl_id.mac,sizeof(mac_address_t));

    return webconfig_error_none;
}

//translate_radio_object_from_easymesh_to_dml() converts data elements of em_radio_list_t of  easymesh to Onewifi
webconfig_error_t   translate_radio_object_from_easymesh_to_dml(webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

//translate_vap_object_from_easymesh_to_dml() converts data elements of em_bss_info_t of  easymesh to Onewifi
webconfig_error_t   translate_vap_object_from_easymesh_to_dml(webconfig_subdoc_data_t *data)
{
    em_radio_list_t   *em_radio_data;
    em_bss_info_t     *em_vap_info;
    em_bss_info_t     *vap_info_row;
    wifi_vap_info_map_t *vap_map;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    unsigned int count = 0;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0;
    rdk_wifi_radio_t *radio;
    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    em_radio_data = proto->em_radio_data;
    if (em_radio_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];

        vap_map = &radio->vaps.vap_map;
        em_vap_info = em_radio_data[i].bss_info;//Please add NULL check TBD-P
        if (em_vap_info == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_vap_info is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_easymesh;
        }
        count = 0;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }

            // please move this code to specific vap function like ovsdb_translator
            vap_info_row =  (em_bss_info_t *)(em_vap_info + count);
            count++;
            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_private_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_xhs_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_lnf_psk_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_lnf_radius_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_mesh_backhaul_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of backhaul vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_mesh_sta_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh_stavap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            }
        }
    }
    return webconfig_error_none;
}
// translate_to_easymesh_tables() is translations of OneWifi structures to Easymesh structures based on type
webconfig_error_t  translate_to_easymesh_tables(webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: subdoc_type:%d\n", __func__, __LINE__, type);
    switch (type) {
        case webconfig_subdoc_type_private:
            if (translate_vap_object_to_easymesh_bss_info(data, "private_ssid") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_private vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

        case webconfig_subdoc_type_home:
            if (translate_vap_object_to_easymesh_bss_info(data, "iot_ssid") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_home vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

        case webconfig_subdoc_type_lnf:
            if (translate_vap_object_to_easymesh_bss_info(data, "lnf_") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_lnf vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

        case webconfig_subdoc_type_mesh_backhaul:
            if (translate_vap_object_to_easymesh_bss_info(data, "mesh_backhaul") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

        case webconfig_subdoc_type_mesh_sta:
            if (translate_vap_object_to_easymesh_bss_info(data, "mesh_sta") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_sta vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

        case webconfig_subdoc_type_dml:
            if (translate_device_object_to_easymesh_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml radio state translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            if (translate_radio_object_to_easymesh_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml radio_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }

            if (translate_vap_object_to_easymesh_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;
        default:
            break;
    }
    return webconfig_error_none;
}

// translate_from_easymesh_tables() is translations of Easymesh structures to Onewifi structures based on type
webconfig_error_t   translate_from_easymesh_tables(webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: subdoc_type:%d\n", __func__, __LINE__, type);
    switch (type) {
        case webconfig_subdoc_type_private:
            if (translate_from_easymesh_bssinfo_to_vap_object(data, "private_ssid") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_private vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;

        case webconfig_subdoc_type_home:
            if (translate_from_easymesh_bssinfo_to_vap_object(data, "iot_ssid") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_home vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;

        case webconfig_subdoc_type_lnf:
            if (translate_from_easymesh_bssinfo_to_vap_object(data, "lnf_") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_lnf vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;

        case webconfig_subdoc_type_mesh_backhaul:
            if (translate_from_easymesh_bssinfo_to_vap_object(data, "mesh_backhaul") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;

        case webconfig_subdoc_type_mesh_sta:
            if (translate_from_easymesh_bssinfo_to_vap_object(data, "mesh_sta") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_sta vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;

        case webconfig_subdoc_type_dml:
            if (translate_device_object_from_easymesh_to_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml translation from easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            if (translate_radio_object_from_easymesh_to_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml translation from easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }

            if (translate_vap_object_from_easymesh_to_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml translation from easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;
        default:
            break;
    }
    return webconfig_error_none;
}

