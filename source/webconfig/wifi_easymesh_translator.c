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
#include <cjson/cJSON.h>
#include "wifi_webconfig.h"
#include "ctype.h"
#include "const.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"
#include "schema.h"
#include "schema_gen.h"
#include "webconfig_external_proto.h"
#include "common/ieee802_11_defs.h"

// static member to store the subdoc
static webconfig_subdoc_data_t  webconfig_easymesh_data;
/* global pointer to webconfig subdoc encoded data to avoid memory loss when passing data to  */
static char *webconfig_easymesh_raw_data_ptr = NULL;

void convert_vap_name_to_hault_type(em_haul_type_t *haultype, char *vapname)
{
        if (strncmp("private_ssid", vapname, strlen("private_ssid")) == 0) {
                *haultype = em_haul_type_fronthaul;
        } else if (strncmp("hotspot", vapname, strlen("hotspot")) == 0) {
                *haultype = em_haul_type_hotspot;
        } else if (strncmp("iot_ssid", vapname, strlen("iot_ssid")) == 0) {
                *haultype = em_haul_type_iot;
        } else if (strncmp("lnf_psk", vapname, strlen("lnf_psk")) == 0) {
                *haultype = em_haul_type_configurator;
        } else if (strncmp("mesh_backhaul", vapname, strlen("mesh_backhaul")) == 0) {
                *haultype = em_haul_type_backhaul;
        } else if (strncmp("mesh_sta", vapname, strlen("mesh_sta")) == 0) {
                *haultype = em_haul_type_backhaul;
        }
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
    vap_row->vap_mode = em_vap_mode_ap;
    vap_row->connect_status = false;
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
    vap_row->multi_bssid = false;
    vap_row->transmitted_bssid = false;
    vap_row->assoc_allowed_status = 5;

    vap_row->unicast_bytes_sent = 0;
    vap_row->unicast_bytes_rcvd = 0;
    vap_row->numberofsta = 0;
    vap_row->byte_counter_units = 0;

    vap_row->num_fronthaul_akms = 0;

    vap_row->num_backhaul_akms = 0;
}

// sets the default values in em_device_info_t Easymesh structure
void default_em_device_info(em_device_info_t  *device_info, em_ieee_1905_security_info_t *security_info)
{
    strncpy(device_info->id.net_id,"OneWifiMesh",strlen("OneWifiMesh"));
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
    memcpy(security_info->id, device_info->intf.mac,sizeof(mac_address_t));
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

    if (proto->get_device_info(proto->data_model) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_device_info is NULL\n",__func__, __LINE__);
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_device_info is not NULL\n",__func__, __LINE__);
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Value of get_device_info: %p\n",__func__, __LINE__, (void *)proto->get_device_info(proto->data_model));
    }

    device_info = proto->get_device_info(proto->data_model);
    if (device_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: device_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    network_info = proto->get_network_info(proto->data_model);
    if (network_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:network_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    security_info = proto->get_ieee_1905_security_info(proto->data_model);
    if (security_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:security_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    strncpy(device_info->software_ver, wifi_prop->software_version, strlen(wifi_prop->software_version));
    strncpy(device_info->manufacturer_model, wifi_prop->manufacturerModel, strlen(wifi_prop->manufacturerModel));
    strncpy(device_info->manufacturer, wifi_prop->manufacturer, strlen(wifi_prop->manufacturer));
    strncpy(device_info->serial_number, wifi_prop->serialNo, strlen(wifi_prop->serialNo));
    memcpy(device_info->intf.mac, wifi_prop->al_1905_mac, sizeof(mac_address_t));
    memcpy(device_info->backhaul_alid.mac, wifi_prop->al_1905_mac, sizeof(mac_address_t));
    interfacename_from_mac((const mac_address_t *)device_info->backhaul_alid.mac,device_info->backhaul_alid.name);
    //proto->set_num_radio(proto->data_model, wifi_prop->numRadios);
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
// This routine converts Radio webconfig subdoc values to em_radio_list_t,em_radio_info_t easymesh structures
webconfig_error_t translate_radio_object_to_easymesh_for_radio(webconfig_subdoc_data_t *data)
{
    em_radio_info_t *em_radio_info;
    em_op_class_info_t *em_op_class_info;
    unsigned int radio_index = 0, bss_count = 0, per_radio_subdoc = 0, freq_band = 0, radio_count = 0;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t *vap;
    wifi_vap_info_map_t *vap_map;
    radio_interface_mapping_t *radio_iface_map;
    webconfig_external_easymesh_t *proto;
    wifi_radio_operationParam_t *oper_param;
    webconfig_subdoc_decoded_data_t *decoded_params;
    unsigned int no_of_opclass = 0, i = 0, j = 0, index = 0;

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

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", 
            __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_translate_to_easymesh;
    }
    
    if (data->type == webconfig_subdoc_type_radio_24G) {
        freq_band = WIFI_FREQUENCY_2_4_BAND;
        per_radio_subdoc++;
    } else if (data->type == webconfig_subdoc_type_radio_5G) {
        freq_band = WIFI_FREQUENCY_5_BAND;
        per_radio_subdoc++;
    } else if (data->type == webconfig_subdoc_type_radio_6G) {
        freq_band = WIFI_FREQUENCY_6_BAND;
        per_radio_subdoc++;
    }

    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    for (unsigned int index = 0; index < decoded_params->num_radios; index++) {
        em_radio_info = proto->get_radio_info(proto->data_model, radio_count);
        radio = &decoded_params->radios[index];
        oper_param = &decoded_params->radios[index].oper;
        if ((per_radio_subdoc > 0) && (oper_param->band != freq_band)) {
                continue;
        }
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[index].name);
        em_radio_info->enabled = oper_param->enable;

        if (oper_param->band == WIFI_FREQUENCY_2_4_BAND) {
            em_radio_info->band = 0;
        } else if (oper_param->band == WIFI_FREQUENCY_5_BAND) {
            em_radio_info->band = 1;
        } else if (oper_param->band == WIFI_FREQUENCY_6_BAND) {
            em_radio_info->band = 2;
        }
        
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_easymesh;
        }
        strncpy(em_radio_info->intf.name, radio->name, sizeof(em_interface_name_t));
        mac_address_from_name(radio_iface_map->interface_name, em_radio_info->intf.mac);
        no_of_opclass = proto->get_num_op_class(proto->data_model);
        radio_count ++;
        for (i = 0; i < oper_param->numOperatingClasses; i++) {
            em_op_class_info = proto->get_op_class_info(proto->data_model, no_of_opclass);
            mac_address_from_name(radio_iface_map->interface_name,em_op_class_info->id.ruid);
            em_op_class_info->id.type = em_op_class_type_capability;
            em_op_class_info->id.op_class = oper_param->operatingClasses[i].opClass;
            em_op_class_info->op_class = oper_param->operatingClasses[i].opClass;
            em_op_class_info->max_tx_power = oper_param->operatingClasses[i].maxTxPower;
            em_op_class_info->num_channels = oper_param->operatingClasses[i].numberOfNonOperChan;
            for(int k = 0; k < oper_param->operatingClasses[i].numberOfNonOperChan; k++) {
                em_op_class_info->channels[k] = oper_param->operatingClasses[i].nonOperable[k];
            }
            no_of_opclass++;
            proto->set_num_op_class(proto->data_model, no_of_opclass);
        }

        //Update current operating class
        em_op_class_info = proto->get_op_class_info(proto->data_model, no_of_opclass);
        mac_address_from_name(radio_iface_map->interface_name,em_op_class_info->id.ruid);
        em_op_class_info->id.type = em_op_class_type_current;
        em_op_class_info->id.op_class = oper_param->operatingClass;
        em_op_class_info->op_class = oper_param->operatingClass;
        em_op_class_info->channel = oper_param->channel;
        no_of_opclass++;
        proto->set_num_op_class(proto->data_model,no_of_opclass);
    }
	proto->set_num_radio(proto->data_model, radio_count);

    return webconfig_error_none;
}

// This routine converts DML webconfig subdoc values to em_radio_list_t,em_radio_info_t easymesh structures
webconfig_error_t translate_radio_object_to_easymesh_for_dml(webconfig_subdoc_data_t *data)
{
    em_radio_info_t *em_radio_info;
    em_op_class_info_t *em_op_class_info;
    unsigned int radio_index = 0, bss_count = 0, op_class_count = 0;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t	*vap;
    wifi_vap_info_map_t *vap_map;
    radio_interface_mapping_t *radio_iface_map;
    webconfig_external_easymesh_t *proto;
    wifi_radio_operationParam_t *oper_param;
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

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", 
            __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_translate_to_easymesh;
    }
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    for (unsigned int index = 0; index < decoded_params->num_radios; index++) {
        em_radio_info = proto->get_radio_info(proto->data_model, index);
        radio = &decoded_params->radios[index];
        em_op_class_info = proto->get_op_class_info(proto->data_model, index);
        bss_count = 0;
        vap_map = &radio->vaps.vap_map;
        for (unsigned int j = 0; j < radio->vaps.num_vaps; j++) {
            vap = &vap_map->vap_array[j];
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }
            bss_count++;
        }

        oper_param = &decoded_params->radios[index].oper;
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[index].name);
        em_radio_info->enabled = oper_param->enable;
        //translate frequency band of wifi_freq_bands_t to em_freq_band_t specified in IEEE-1905-1-2013 table 6-23 
        if (oper_param->band == WIFI_FREQUENCY_2_4_BAND) {
            em_radio_info->band = 0;
        } else if (oper_param->band == WIFI_FREQUENCY_5_BAND) {
            em_radio_info->band = 1;
        } else if (oper_param->band == WIFI_FREQUENCY_6_BAND) {
            em_radio_info->band = 2;
        }
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_easymesh;
        }
        strncpy(em_radio_info->intf.name,radio_iface_map->radio_name, sizeof(em_interface_name_t));
        mac_address_from_name(radio_iface_map->interface_name, em_radio_info->intf.mac);
        op_class_count = proto->get_num_op_class(proto->data_model);
        for (unsigned int j = 0; j < oper_param->numOperatingClasses; j++) {
            em_op_class_info = (em_op_class_info_t *)(proto->get_op_class_info(proto->data_model, op_class_count));
            mac_address_from_name(radio_iface_map->interface_name, em_op_class_info->id.ruid);
            em_op_class_info->id.type = 2;
            em_op_class_info->id.op_class = oper_param->operatingClasses[j].opClass;
            em_op_class_info->op_class = oper_param->operatingClasses[j].opClass;
            em_op_class_info->max_tx_power = oper_param->operatingClasses[j].maxTxPower;
            em_op_class_info->num_channels = oper_param->operatingClasses[j].numberOfNonOperChan;
            for(int i = 0; i < oper_param->operatingClasses[j].numberOfNonOperChan; i++) {
                em_op_class_info->channels[i] = oper_param->operatingClasses[j].nonOperable[i];
            }
			op_class_count++;
        }
        //Update current operating class
        em_op_class_info = proto->get_op_class_info(proto->data_model, op_class_count);
        mac_address_from_name(radio_iface_map->interface_name,em_op_class_info->id.ruid);
        em_op_class_info->id.type = 1;
        em_op_class_info->op_class = oper_param->operatingClass;
        em_op_class_info->id.op_class = oper_param->operatingClass;
        em_op_class_info->channel = oper_param->channel;

        //Incrementing the number of operating classes by one, as the dml lacks an operating class for current.
        proto->set_num_op_class(proto->data_model, (op_class_count+1));
        mac_address_from_name(radio_iface_map->interface_name, em_radio_info->intf.mac);

        //Add default params of radio_info
        em_radio_info->number_of_unassoc_sta = 0;
        em_radio_info->noise = 90;
        em_radio_info->utilization = 50;
        em_radio_info->traffic_sep_combined_fronthaul = 0;
        em_radio_info->traffic_sep_combined_backhaul = 0;
        em_radio_info->steering_policy = 0;
        em_radio_info->channel_util_threshold = 0;
        em_radio_info->rcpi_steering_threshold = 0;
        em_radio_info->sta_reporting_rcpi_threshold = 0;
        em_radio_info->sta_reporting_hysteresis_margin_override = 0;
        em_radio_info->channel_utilization_reporting_threshold = 0;
        em_radio_info->associated_sta_traffic_stats_inclusion_policy = 0;
        em_radio_info->associated_sta_link_mterics_inclusion_policy = 0;
        strncpy (em_radio_info->chip_vendor, wifi_prop->manufacturer, strlen(em_radio_info->chip_vendor));

    }

    return webconfig_error_none;
}

// translate_vap_info_to_em_common() converts common data elements of wifi_vap_info_t to em_bss_info_t of easymesh
webconfig_error_t translate_vap_info_to_em_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map, wifi_platform_property_t *wifi_prop)
{
    unsigned k = 0;
    char mac_str[128] = "";
    radio_interface_mapping_t *radio_iface_map;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: input argument is NULL\n", __func__,
            __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap_mode:%d is not wifi_vap_mode_ap.\n",
            __func__, __LINE__, vap->vap_mode);
        return webconfig_error_translate_to_easymesh;
    }

    vap_row->vap_mode = em_vap_mode_ap;

    vap_row->enabled = vap->u.bss_info.enabled;
    strncpy(vap_row->ssid, vap->u.bss_info.ssid, sizeof(vap_row->ssid));
    vap_row->vap_index = vap->vap_index;

    // Set the em_bss_info_t vendor_elements to the same as wifi_vap_info_t vendor_elements
    memset(vap_row->vendor_elements, 0, sizeof(vap_row->vendor_elements));
    memcpy(vap_row->vendor_elements, vap->u.bss_info.vendor_elements, vap->u.bss_info.vendor_elements_len);
    vap_row->vendor_elements_len = vap->u.bss_info.vendor_elements_len;


    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", vap->u.bss_info.bssid[0], vap->u.bss_info.bssid[1],
            vap->u.bss_info.bssid[2], vap->u.bss_info.bssid[3],
            vap->u.bss_info.bssid[4], vap->u.bss_info.bssid[5]);
    str_to_mac_bytes(mac_str,vap_row->bssid.mac);
    strncpy(vap_row->bssid.name, vap->vap_name, sizeof(vap_row->bssid.name));
	convert_vap_name_to_hault_type(&vap_row->id.haul_type, (char *)vap->vap_name);

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
    strncpy(vap_row->ruid.name, radio_iface_map->radio_name,sizeof(vap_row->ruid.name));
    mac_address_from_name(radio_iface_map->interface_name,vap_row->ruid.mac);	
    return webconfig_error_none;
}

//Converting data elements of assoc client stats to em_sta_info_t of easymesh
webconfig_error_t translate_associated_clients_to_easymesh_sta_info(webconfig_subdoc_data_t *data)
{
    em_sta_info_t *em_sta_dev_info = NULL;
    unsigned int associated_client_count = 0;
    unsigned int i = 0, j = 0, tag_len = 0;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;
    rdk_wifi_radio_t *radio = NULL;
    wifi_vap_info_map_t *vap_map = NULL;
    wifi_vap_info_t *vap = NULL;
    assoc_dev_data_t *assoc_dev_data = NULL;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    webconfig_external_easymesh_t *proto = NULL;
    mac_addr_str_t sta_str, bss_str, radio_str;
    struct ieee80211_mgmt *mgmt = NULL;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            if (vap == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap entry\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }

            rdk_vap_info = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap_info == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: rdk_vap_info NULL\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }

            if (rdk_vap_info->associated_devices_diff_map != NULL) {
                assoc_dev_data = hash_map_get_first(rdk_vap_info->associated_devices_diff_map);
                while (assoc_dev_data != NULL) {
                    if (associated_client_count >= WEBCONFIG_MAX_ASSOCIATED_CLIENTS) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Exceeded max number of associated clients %d, vap_name '%s'\n", __func__, __LINE__, WEBCONFIG_MAX_ASSOCIATED_CLIENTS, rdk_vap_info->vap_name);
                        break;
                    }

                    em_sta_dev_info = (em_sta_info_t *)malloc(sizeof(em_sta_info_t));
                    if (em_sta_dev_info == NULL) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: sta_info malloc failed\n", __func__, __LINE__);
                        return webconfig_error_translate_to_easymesh;
                    }

                    memset(em_sta_dev_info, 0, sizeof(em_sta_dev_info));

                    em_radio_info_t *radio_info = proto->get_radio_info(proto->data_model, vap->radio_index);
                    em_bss_info_t *bss_info = proto->get_bss_info(proto->data_model, rdk_vap_info->vap_index);
                    proto->set_num_radio(proto->data_model, decoded_params->num_radios);
                    proto->set_num_bss(proto->data_model, radio->vaps.num_vaps);
                    printf("%s:%d: client_state: %d\n", __func__, __LINE__, assoc_dev_data->client_state);

                    memcpy(em_sta_dev_info->id, assoc_dev_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
                    if (vap->vap_mode == wifi_vap_mode_ap) {
                        memcpy(em_sta_dev_info->bssid, vap->u.bss_info.bssid,
                            sizeof(mac_address_t));
                    } else if (vap->vap_mode == wifi_vap_mode_sta) {
                        memcpy(em_sta_dev_info->bssid, vap->u.sta_info.bssid,
                            sizeof(mac_address_t));
                    }
                    memcpy(em_sta_dev_info->radiomac, radio_info->intf.mac, sizeof(mac_address_t));
                    em_sta_dev_info->last_ul_rate = assoc_dev_data->dev_stats.cli_LastDataUplinkRate;
                    em_sta_dev_info->last_dl_rate = assoc_dev_data->dev_stats.cli_LastDataDownlinkRate;
                    em_sta_dev_info->retrans_count = assoc_dev_data->dev_stats.cli_RetransCount;
                    em_sta_dev_info->signal_strength=assoc_dev_data->dev_stats.cli_SignalStrength;
                    em_sta_dev_info->pkts_tx=assoc_dev_data->dev_stats.cli_PacketsSent;
                    em_sta_dev_info->pkts_rx=assoc_dev_data->dev_stats.cli_PacketsReceived;
                    em_sta_dev_info->bytes_tx=assoc_dev_data->dev_stats.cli_BytesSent;
                    em_sta_dev_info->bytes_rx=assoc_dev_data->dev_stats.cli_BytesReceived;
                    em_sta_dev_info->errors_tx=assoc_dev_data->dev_stats.cli_ErrorsSent;

                    if (assoc_dev_data->sta_data.msg_data.data == NULL) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Association frame data not present\n", __func__, __LINE__);
                        return webconfig_error_translate_to_easymesh;
                    }
                    mgmt = (struct ieee80211_mgmt *) assoc_dev_data->sta_data.msg_data.data;
                    tag_len = assoc_dev_data->sta_data.msg_data.frame.len - IEEE80211_HDRLEN - sizeof(mgmt->u.assoc_req);
                    if (tag_len > EM_MAX_FRAME_BODY_LEN) {
                        tag_len = EM_MAX_FRAME_BODY_LEN-1;
                    }
                    memcpy(em_sta_dev_info->frame_body, mgmt->u.assoc_req.variable, tag_len);
                    em_sta_dev_info->frame_body_len = tag_len;

                    if (assoc_dev_data->client_state == 0) {
                        em_sta_dev_info->associated = true;
                        proto->put_sta_info(proto->data_model, em_sta_dev_info, em_target_sta_map_assoc);
                    } else {
                        em_sta_dev_info->associated = false;
                        proto->put_sta_info(proto->data_model, em_sta_dev_info, em_target_sta_map_disassoc);
                    }
                    free(em_sta_dev_info);
                    associated_client_count++;
                    assoc_dev_data = hash_map_get_next(rdk_vap_info->associated_devices_diff_map, assoc_dev_data);
                }
            }
        }
    }

    return webconfig_error_none ;
}

//Converting data elements of assoc dev stats to em_sta_info_t of easymesh
webconfig_error_t translate_sta_object_to_easymesh_for_assocdev_stats(webconfig_subdoc_data_t *data)
{
    time_t response_time;
    struct tm *local_time;
    char time_str[32] = {0};
    int sta_size = 0;
    em_sta_info_t *em_sta_dev_info;
    webconfig_external_easymesh_t *proto;
    em_radio_info_t *radio_info;
    em_bss_info_t *bss_info;
    wifi_provider_response_t **assoc_device_stats;
    wifi_associated_dev3_t *client_stats;
    int vap_index = 0, radio_index = 0;
    wifi_platform_property_t *wifi_prop;

    webconfig_subdoc_decoded_data_t *params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    assoc_device_stats = (wifi_provider_response_t **)&params->collect_stats.stats;
    sta_size = (*assoc_device_stats)->stat_array_size;

    client_stats = (wifi_associated_dev3_t*)(*assoc_device_stats)->stat_pointer;
    if (client_stats == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Dev Stats is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    vap_index = (*assoc_device_stats)->args.vap_index;
    wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    radio_index = get_radio_index_for_vap_index(wifi_prop, vap_index);

    response_time = (*assoc_device_stats)->response_time;
    local_time = localtime(&response_time);
    if (local_time != NULL) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local_time);
        //add to timestamp of em_sta_info
    }

    proto = (webconfig_external_easymesh_t *)params->external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_sta_info_t is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    for (unsigned int count = 0; count < sta_size; count++) {
        radio_info = proto->get_radio_info(proto->data_model, radio_index);
        bss_info = proto->get_bss_info(proto->data_model, vap_index);
        em_sta_dev_info = proto->get_sta_info(proto->data_model, client_stats[count].cli_MACAddress, \
             bss_info->bssid.mac, radio_info->intf.mac, em_target_sta_map_consolidated);
        if (em_sta_dev_info != NULL) {     
            memcpy(em_sta_dev_info->id, client_stats[count].cli_MACAddress, sizeof(mac_address_t));
            memcpy(em_sta_dev_info->timestamp, time_str, sizeof(time_str));
            em_sta_dev_info->last_ul_rate             = client_stats[count].cli_LastDataUplinkRate;
            em_sta_dev_info->last_dl_rate             = client_stats[count].cli_LastDataDownlinkRate;
            //TODO: formulae derivation pending
            em_sta_dev_info->est_ul_rate              = client_stats[count].cli_LastDataUplinkRate;
            em_sta_dev_info->est_dl_rate              = client_stats[count].cli_LastDataDownlinkRate;
            em_sta_dev_info->retrans_count            = client_stats[count].cli_RetransCount;
            //TODO: formulae derivation pending
            em_sta_dev_info->rcpi                     = 0;
            em_sta_dev_info->signal_strength          = client_stats[count].cli_SignalStrength;
            //TODO: formulae derivation pending
            em_sta_dev_info->util_tx                  = client_stats[count].cli_BytesSent;
            //TODO: formulae derivation pending
            em_sta_dev_info->util_rx                  = client_stats[count].cli_BytesReceived;
            em_sta_dev_info->pkts_tx                  = client_stats[count].cli_PacketsSent;
            em_sta_dev_info->pkts_rx                  = client_stats[count].cli_PacketsReceived;
            em_sta_dev_info->bytes_tx                 = client_stats[count].cli_BytesSent;
            em_sta_dev_info->bytes_rx                 = client_stats[count].cli_BytesReceived;
            em_sta_dev_info->errors_tx                = client_stats[count].cli_ErrorsSent;
        }
    }
    return webconfig_error_none;
}

#ifdef EM_APP
webconfig_error_t translate_sta_link_metrics_object_to_easy_mesh_sta_info(webconfig_subdoc_data_t *data)
{
    time_t response_time;
    struct tm *local_time;
    char time_str[32] = {0};
    int sta_size = 0;
    em_sta_info_t *em_sta_dev_info;
    webconfig_external_easymesh_t *proto;
    em_radio_info_t *radio_info;
    em_bss_info_t *bss_info;
    per_sta_metrics_t sta_stats;
    int vap_index = 0, radio_index = 0;
    wifi_platform_property_t *wifi_prop;

    webconfig_subdoc_decoded_data_t *params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    sta_size = params->em_sta_link_metrics_rsp.sta_count;

    if (sta_size == 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Dev Stats is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    vap_index = params->em_sta_link_metrics_rsp.vap_index;
    wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    radio_index = get_radio_index_for_vap_index(wifi_prop, vap_index);

    proto = (webconfig_external_easymesh_t *)params->external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_sta_info_t is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    for (unsigned int count = 0; count < sta_size; count++) {
        sta_stats = params->em_sta_link_metrics_rsp.per_sta_metrics[count];
        radio_info = proto->get_radio_info(proto->data_model, radio_index);
        bss_info = proto->get_bss_info(proto->data_model, vap_index);
        em_sta_dev_info = proto->get_sta_info(proto->data_model, sta_stats.sta_mac, \
            bss_info->bssid.mac, radio_info->intf.mac, em_target_sta_map_consolidated);

        em_radio_info_t *radio_info = proto->get_radio_info(proto->data_model, radio_index);
        em_bss_info_t *bss_info = proto->get_bss_info(proto->data_model, vap_index);

        if (em_sta_dev_info != NULL) {
            memcpy(em_sta_dev_info->id, sta_stats.sta_mac, sizeof(mac_address_t));
            memcpy(em_sta_dev_info->bssid, bss_info->bssid.mac, sizeof(mac_address_t));
            memcpy(em_sta_dev_info->radiomac, radio_info->intf.mac, sizeof(mac_address_t));

            strncpy(em_sta_dev_info->sta_client_type, sta_stats.client_type, sizeof(em_sta_dev_info->sta_client_type));
            em_sta_dev_info->sta_client_type[strlen(sta_stats.client_type)] = '\0';

            em_sta_dev_info->last_ul_rate             = sta_stats.assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_uplink_rate;
            em_sta_dev_info->last_dl_rate             = sta_stats.assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_downlink_rate;

            em_sta_dev_info->est_ul_rate              = sta_stats.assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_up;
            em_sta_dev_info->est_dl_rate              = sta_stats.assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_down;

            em_sta_dev_info->rcpi                     = sta_stats.assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].rcpi;

            em_sta_dev_info->util_tx                  = sta_stats.assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_transmit;
            em_sta_dev_info->util_rx                  = sta_stats.assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_receive;   

            // Update the consolidated map and also put into assoc map to identify which entries are new
            proto->put_sta_info(proto->data_model, em_sta_dev_info, em_target_sta_map_assoc);
        }
    }
    return webconfig_error_none;
}

webconfig_error_t translate_ap_metrics_report_to_easy_mesh_bss_info(webconfig_subdoc_data_t *data)
{
    em_bss_info_t *em_bss_info;
    wifi_vap_info_map_t *vap_map;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    unsigned int j = 0, radio_index = 0;
    rdk_wifi_radio_t *radio;
    webconfig_external_easymesh_t *proto;
    em_ap_metrics_report_t *em_ap_report = NULL;
    em_vap_metrics_t *ap_metrics = NULL;
    em_radio_info_t *radio_info = NULL;
    em_sta_info_t *em_sta_dev_info = NULL;
    mac_addr_str_t bss_str;

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

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_translate_to_easymesh;
    }

    em_ap_report = &decoded_params->em_ap_metrics_report;
    radio_index = decoded_params->em_ap_metrics_report.radio_index;
    radio = &decoded_params->radios[radio_index];
    vap_map = &radio->vaps.vap_map;

    for (j = 0; j < radio->vaps.num_vaps; j++) {
        //Get the corresponding vap
        vap = &vap_map->vap_array[j];
        ap_metrics = &em_ap_report->vap_reports[j];
        if ((vap->vap_mode != wifi_vap_mode_ap) || (strncmp(ap_metrics->vap_metrics.bssid, vap->u.bss_info.bssid, sizeof(bssid_t)) != 0)) {
            continue;
        }

        em_bss_info =  (em_bss_info_t *)(proto->get_bss_info_with_mac(proto->data_model, vap->u.bss_info.bssid));
        if (em_bss_info == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Cannot find bss info for index %d\n", __func__, __LINE__, vap->vap_index);
            continue;
        }
        em_bss_info->numberofsta = ap_metrics->sta_cnt;

        per_sta_metrics_t *sta_stats = NULL;
        for (unsigned int count = 0; count < em_bss_info->numberofsta; count++) {
            radio_info = proto->get_radio_info(proto->data_model, radio_index);
            if (radio_info == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Cannot find radio info for index %d\n", __func__, __LINE__, vap->vap_index);
                continue;
            }
            //wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Assoc Sta count %d\n", __func__, __LINE__, em_bss_info->numberofsta);
            sta_stats = &ap_metrics->sta_link_metrics[count];
            if (sta_stats == NULL) {
                continue;
            }
            em_sta_dev_info = proto->get_sta_info(proto->data_model, sta_stats->sta_mac, \
                em_bss_info->bssid.mac, radio_info->intf.mac, em_target_sta_map_consolidated);
            // Update the consolidated map
            // Link metrics and Extended Link metrics
            if (em_sta_dev_info != NULL) {
                if (ap_metrics->is_sta_link_metrics_enabled == true) {
                    strncpy(em_sta_dev_info->sta_client_type, sta_stats->client_type, sizeof(em_sta_dev_info->sta_client_type));
                    em_sta_dev_info->sta_client_type[strlen(sta_stats->client_type)] = '\0';
                    em_sta_dev_info->last_ul_rate             = sta_stats->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_uplink_rate;
                    em_sta_dev_info->last_dl_rate             = sta_stats->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_downlink_rate;
                    em_sta_dev_info->est_ul_rate              = sta_stats->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_up;
                    em_sta_dev_info->est_dl_rate              = sta_stats->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_down;
                    em_sta_dev_info->rcpi                     = sta_stats->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].rcpi;
                    em_sta_dev_info->util_tx                  = sta_stats->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_transmit;
                    em_sta_dev_info->util_rx                  = sta_stats->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_receive;
                }

                if (ap_metrics->is_sta_traffic_stats_enabled == true) {
                    //Traffic stats
                    em_sta_dev_info->pkts_tx                  = ap_metrics->sta_traffic_stats[count].packets_sent;
                    em_sta_dev_info->pkts_rx                  = ap_metrics->sta_traffic_stats[count].packets_rcvd;
                    em_sta_dev_info->bytes_tx                 = ap_metrics->sta_traffic_stats[count].bytes_sent;
                    em_sta_dev_info->bytes_rx                 = ap_metrics->sta_traffic_stats[count].bytes_rcvd;
                    em_sta_dev_info->errors_tx                = ap_metrics->sta_traffic_stats[count].tx_packtes_errs;
                    em_sta_dev_info->errors_rx                = ap_metrics->sta_traffic_stats[count].rx_packtes_errs;
                    em_sta_dev_info->retrans_count            = ap_metrics->sta_traffic_stats[count].rx_packtes_errs;
                }
            }
        }
    }

    return webconfig_error_none;
}
#endif

// translate_sta_info_to_em_common() converts common data elements of wifi_vap_info_t related to sta to em_bss_info_t of  easymesh
webconfig_error_t translate_sta_info_to_em_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, em_bss_info_t *vap_row, em_ssid_2_vid_map_info_t  *ssid_vid_map, wifi_platform_property_t *wifi_prop)
{
    wifi_security_modes_t enum_sec;
    int len = 0;
    unsigned k = 0;
    radio_interface_mapping_t *radio_iface_map = NULL;
    mac_addr_str_t mac_str;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }
    default_em_bss_info(vap_row);

    vap_row->vap_mode = em_vap_mode_sta;

    vap_row->enabled = vap->u.sta_info.enabled;
    vap_row->vap_index = vap->vap_index;
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: vap_index %d vap_name %s\n", __func__, __LINE__, vap->vap_index, vap->vap_name);

    // Copy basic info
    strncpy(vap_row->ssid, vap->u.sta_info.ssid, sizeof(vap->u.sta_info.ssid));
    memcpy(vap_row->bssid.mac, vap->u.sta_info.bssid, sizeof(mac_address_t));
    strncpy(vap_row->bssid.name, vap->vap_name, sizeof(vap_row->bssid.name));
    memcpy(vap_row->sta_mac, vap->u.sta_info.mac, sizeof(mac_address_t));
    uint8_mac_to_string_mac( vap_row->sta_mac, mac_str);
    wifi_util_info_print(WIFI_WEBCONFIG, "Backhaul sta mac: %s\n", mac_str);
    convert_vap_name_to_hault_type(&vap_row->id.haul_type, (char *)vap->vap_name);

    // Copy security info (mode/AKMs)
    enum_sec = vap->u.sta_info.security.mode;
    

    if ((key_mgmt_conversion(&enum_sec, &len, ENUM_TO_STRING, 0, (char(*)[])vap_row->fronthaul_akm)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: "
                "security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->num_fronthaul_akms = len;
    // Set backhaul AKMs to empty
    vap_row->num_backhaul_akms = 0;
    for (int i=0;i<EM_MAX_AKMS ; i++){
        vap_row->backhaul_akm[i][0] = '\0';
    }

    
    //Copy Passphrase
    strncpy(vap_row->mesh_sta_passphrase, vap->u.sta_info.security.u.key.key, sizeof(vap_row->mesh_sta_passphrase));
    
    // Find the radio interface map
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

    // Copy radio information
    strncpy(vap_row->ruid.name, radio_iface_map->radio_name,sizeof(vap_row->ruid.name));
    mac_address_from_name(radio_iface_map->interface_name, vap_row->ruid.mac);

    if (vap->u.sta_info.conn_status == wifi_connection_status_connected) {
        vap_row->connect_status = true;
    } else {
        vap_row->connect_status = false;
    }
    vap_row->vap_mode = vap->vap_mode;

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

    // convert akm to its equivalent string
    enum_sec = vap->u.bss_info.security.mode;
    if ((key_mgmt_conversion(&enum_sec, &len, ENUM_TO_STRING, 0, (char(*)[])vap_row->fronthaul_akm)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: "
                "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->num_fronthaul_akms = len;

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

    /* vap_row->xhs_use = true;

    // convert akm to its equivalent string
    enum_sec = vap->u.bss_info.security.mode;
    if ((key_mgmt_conversion(&enum_sec, &len, ENUM_TO_STRING, 0, (char(*)[])vap_row->xhs_akm)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: "
                "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->num_xhs_akms = len;
    strncpy(vap_row->xhs_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key));
     */
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
    /* vap_row->lnfpsk_use = true;

    // convert akm to its equivalent string
    enum_sec = vap->u.bss_info.security.mode;
    if ((key_mgmt_conversion(&enum_sec, &len, ENUM_TO_STRING, 0, (char(*)[])vap_row->lnf_psk_akm)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: "
                "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->num_lnf_psk_akms = len;
    strncpy(vap_row->lnf_psk_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key));
     */
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
    /* vap_row->lnfradius_use = true;

       enum_sec = vap->u.bss_info.security.mode;
       if ((key_mgmt_conversion(&enum_sec, &len, ENUM_TO_STRING, 0, (char(*)[])vap_row->lnf_radius_akm)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
                    "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
            return webconfig_error_translate_to_easymesh;
       }
       vap_row->num_lnf_radius_akms = len;
       strncpy(vap_row->lnf_radius_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key));
     */
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

    enum_sec = vap->u.bss_info.security.mode;
    if ((key_mgmt_conversion(&enum_sec, &len, ENUM_TO_STRING, 0, (char(*)[])vap_row->backhaul_akm)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: "
                "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_easymesh;
    }
    vap_row->num_backhaul_akms = len;
    /* strncpy(vap_row->backhaul_passphrase, vap->u.bss_info.security.u.key.key,strlen(vap->u.bss_info.security.u.key.key)); */

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

    return webconfig_error_none;
}

void fill_ap_mld_info_from_vap(em_ap_mld_info_t *ap_info, wifi_vap_info_t *vap,
    radio_interface_mapping_t *radio_iface_map)
{

    if (ap_info == NULL || vap == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return false;
    }

    memset(ap_info, 0, sizeof(em_ap_mld_info_t));

    ap_info->mac_addr_valid = true;
    memcpy(&ap_info->mac_addr, vap->u.bss_info.mld_info.common_info.mld_addr,
        sizeof(mac_address_t));
    strncpy(ap_info->ssid, vap->u.bss_info.ssid, sizeof(ssid_t));

    // Todo: VAP structure currently does not have below details, so set it to default for testing.
    ap_info->str = true;
    ap_info->nstr = false;
    ap_info->emlsr = true;
    ap_info->emlmr = false;

    ap_info->num_affiliated_ap++;
    em_affiliated_ap_info_t *aff = &ap_info->affiliated_ap[0];
    memset(aff, 0, sizeof(*aff));

    aff->mac_addr_valid = true;
    aff->link_id_valid = true;
    strncpy((char *)aff->ruid.name, radio_iface_map->radio_name, sizeof(aff->ruid.name));
    mac_address_from_name(radio_iface_map->interface_name, aff->ruid.mac);
    memcpy(&aff->mac_addr, &vap->u.bss_info.bssid, sizeof(mac_address_t));
    aff->link_id = vap->u.bss_info.mld_info.common_info.mld_link_id;
}

// translate_vap_object_to_easymesh_for_dml() converts DML data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_vap_object_to_easymesh_for_dml(webconfig_subdoc_data_t *data)
{
    em_radio_info_t *em_radio_info;
    em_bss_info_t *em_bss_info;
    wifi_vap_info_map_t *vap_map;
    em_ssid_2_vid_map_info_t *ssid_vid_map = NULL;
    em_ssid_2_vid_map_info_t *ssid_vid_row;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    radio_interface_mapping_t *radio_iface_map;
    unsigned int count = 0;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0, k = 0, num_bss = 0, radio_index = 0;
    rdk_wifi_radio_t *radio;
    mac_address_t rmac;

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

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_translate_to_easymesh;
    }

    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    proto->set_num_radio(proto->data_model, decoded_params->num_radios);
    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_easymesh;
        }
        mac_address_from_name(radio_iface_map->interface_name, rmac);
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }
            iface_map = NULL;
            for (k = 0; k < (sizeof(wifi_prop->interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (wifi_prop->interface_map[k].index == vap->vap_index) {
                    iface_map = &(wifi_prop->interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }
            em_bss_info =  (em_bss_info_t *)(proto->get_bss_info(proto->data_model, num_bss));
            if (em_bss_info == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Cannot find bss info for index %d\n", __func__, __LINE__, vap->vap_index);
                continue;
            }
            num_bss++;
            proto->set_num_bss(proto->data_model, num_bss);
            memcpy(&em_bss_info->ruid.mac,&rmac,sizeof(mac_address_t));
            // please move this code to specific vap function like ovsdb_translator
            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_em_bss_config(vap, iface_map, em_bss_info, ssid_vid_map, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_xhs_vap_info_to_em_bss_config(vap, iface_map, em_bss_info, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_psk_vap_info_to_em_bss_config(vap, iface_map, em_bss_info,ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_vap_info_to_em_bss_config(vap, iface_map, em_bss_info, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_em_bss_config(vap, iface_map, em_bss_info, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of backhaul vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_info_to_em_bss_config(vap, iface_map, em_bss_info, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unknown vap type %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }

            if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                // To Do - Implementation similar to AP MLD once vap structure is updated with wifi7
                // details for STA
                // em_bsta_info_t *bsta_info;
                // fill_bsta_info_from_vap(&bsta_info, vap, radio_iface_map);
                // proto->update_bsta_info(proto->data_model, bsta_info);
            } else {
                if (vap->u.bss_info.mld_info.common_info.mld_enable == true) {
                    em_ap_mld_info_t ap_info;
                    fill_ap_mld_info_from_vap(&ap_info, vap, radio_iface_map);
                    proto->update_ap_mld_info(proto->data_model, &ap_info);
                } else {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: AP MLD is not enabled on vap %s\n",
                        __func__, __LINE__, vap->vap_name);
                }
            }
        }
    }
    return webconfig_error_none;
}

//translate_vap_object_to_easymesh_bss_info() converts data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_vap_object_to_easymesh_bss_info(webconfig_subdoc_data_t *data,char *vap_name)
{
    em_bss_info_t *vap_info_row;
    em_ssid_2_vid_map_info_t *ssid_vid_row;
    mac_address_t rmac;
    wifi_vap_info_map_t *vap_map;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    radio_interface_mapping_t *radio_iface_map;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0, k = 0, count = 0, radio_index = 0;
    rdk_wifi_radio_t *radio;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    hal_cap = &data->u.decoded.hal_cap;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_radio_info is NULL\n", __func__, __LINE__);
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
        vap_map = &radio->vaps.vap_map;
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_easymesh;
        }
        mac_address_from_name(radio_iface_map->interface_name, rmac);
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            if (strstr(vap->vap_name,vap_name) == false) {
                continue;
            }
            iface_map = NULL;
            for (k = 0; k < (sizeof(wifi_prop->interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (wifi_prop->interface_map[k].index == vap->vap_index) {
                    iface_map = &(wifi_prop->interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }
            vap_info_row = proto->get_bss_info(proto->data_model, count);
            if (vap_info_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Cannot find the bssid\n", __func__, __LINE__);
                continue;
            }
            count++;
            proto->set_num_bss(proto->data_model, count);
            memcpy(&vap_info_row->ruid.mac,&rmac,sizeof(mac_address_t));
            // please move this code to specific vap function like ovsdb_translator
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
            } else if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unknown vap type %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }
        }
    }
    return webconfig_error_none;
}

//translate_per_radio_vap_object_to_easymesh_bss_info() converts data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_per_radio_vap_object_to_easymesh_bss_info(webconfig_subdoc_data_t *data, wifi_freq_bands_t freq_band)
{
    em_bss_info_t *em_vap_info;
    em_bss_info_t *vap_info_row;
    em_ssid_2_vid_map_info_t *ssid_vid_row;
    wifi_vap_info_map_t *vap_map;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    radio_interface_mapping_t *radio_iface_map;
    mac_address_t rmac;
    unsigned int i = 0,j = 0, k = 0, count = 0, radio_index = 0;
    rdk_wifi_radio_t *radio;
    wifi_radio_operationParam_t *oper_param;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    hal_cap = &data->u.decoded.hal_cap;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_radio_info is NULL\n", __func__, __LINE__);
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
        vap_map = &radio->vaps.vap_map;
        oper_param = &decoded_params->radios[i].oper;
        if (oper_param->band != freq_band) {
            continue;
        }
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_easymesh;
        }
        mac_address_from_name(radio_iface_map->interface_name, rmac);
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            iface_map = NULL;
            for (k = 0; k < (sizeof(wifi_prop->interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (wifi_prop->interface_map[k].index == vap->vap_index) {
                    iface_map = &(wifi_prop->interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }
            vap_info_row = proto->get_bss_info(proto->data_model, count);
            if (vap_info_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Cannot find the bssid\n", __func__, __LINE__);
                continue;
            }
            count++;
            proto->set_num_bss(proto->data_model, count);
            memcpy(&vap_info_row->ruid.mac,&rmac,sizeof(mac_address_t));
            // please move this code to specific vap function like ovsdb_translator
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
            } else if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_info_to_em_bss_config(vap, iface_map, vap_info_row, ssid_vid_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta vap to EM failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_easymesh;
                }
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unknown vap type %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_easymesh;
            }
        }
    }
    return webconfig_error_none;
}

#ifdef EM_APP
// translate_beacon_report_object_to_easymesh_sta_info() converts data elements of
// sta_beacon_report_reponse_t to em_sta_info_t of  easymesh
webconfig_error_t translate_beacon_report_object_to_easymesh_sta_info(webconfig_subdoc_data_t *data)
{
    em_sta_info_t em_sta_dev_info;
    webconfig_external_easymesh_t *proto;
    em_radio_info_t *radio_info;
    em_bss_info_t *bss_info;
    int vap_index = 0, radio_index = 0;
    wifi_platform_property_t *wifi_prop;
    webconfig_subdoc_decoded_data_t *params = &data->u.decoded;
    rdk_wifi_radio_t *radio = NULL;
    wifi_vap_info_t *vap = NULL;
    wifi_vap_info_map_t *vap_map = NULL;
    int i = 0;

    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: decoded_params is NULL\n", __func__,
            __LINE__);
        return webconfig_error_decode;
    }

    vap_index = params->sta_beacon_report.ap_index;
    wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    radio_index = get_radio_index_for_vap_index(wifi_prop, vap_index);

    proto = (webconfig_external_easymesh_t *)params->external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: em_sta_info_t is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    radio = &params->radios[radio_index];
    vap_map = &radio->vaps.vap_map;

    for (i = 0; i < radio->vaps.num_vaps; i++) {
        vap = &vap_map->vap_array[i];
        if (vap->vap_index == vap_index) {
            break;
        }
    }

    if (vap == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap_mode:%d is not wifi_vap_mode_ap\n",
            __func__, __LINE__, vap->vap_mode);
        return webconfig_error_translate_to_easymesh;
    }

    bss_info = proto->get_bss_info_with_mac(proto->data_model, vap->u.bss_info.bssid);

    if (bss_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: bss_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    memcpy(em_sta_dev_info.id, params->sta_beacon_report.mac_addr, sizeof(mac_address_t));
    memcpy(em_sta_dev_info.bssid, bss_info->bssid.mac, sizeof(mac_address_t));
    memcpy(em_sta_dev_info.radiomac, bss_info->ruid.mac, sizeof(mac_address_t));
    em_sta_dev_info.beacon_report_len = params->sta_beacon_report.data_len;
    em_sta_dev_info.num_beacon_meas_report = params->sta_beacon_report.num_br_data;

    memcpy(em_sta_dev_info.beacon_report_elem, params->sta_beacon_report.data, params->sta_beacon_report.data_len);

    proto->put_sta_info(proto->data_model, &em_sta_dev_info, em_target_sta_map_consolidated);

    return webconfig_error_none;
}
#endif

// translate_em_common_to_vap_info_common() converts common data elements of em_bss_info_t to wifi_vap_info_t  of Onewifi
webconfig_error_t translate_em_common_to_vap_info_common( wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: input argument is NULL\n", __func__,
            __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap_mode:%d is not wifi_vap_mode_ap.\n",
            __func__, __LINE__, vap->vap_mode);
        return webconfig_error_translate_from_easymesh;
    }

    vap->u.bss_info.enabled = vap_row->enabled ;
    strncpy(vap->u.bss_info.ssid,vap_row->ssid, sizeof(vap->u.bss_info.ssid));

    memset(vap->u.bss_info.vendor_elements, 0, sizeof(vap->u.bss_info.vendor_elements));
    memcpy(vap->u.bss_info.vendor_elements, vap_row->vendor_elements, vap_row->vendor_elements_len);
    vap->u.bss_info.vendor_elements_len = vap_row->vendor_elements_len;

    return webconfig_error_none;
}

// translate_em_common_to_sta_info_common() converts common data elements of em_bss_info_t to wifi_vap_info_t  of Onewifi
webconfig_error_t translate_em_common_to_sta_info_common(wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{

    wifi_security_modes_t enum_sec;
    int len = 0;
    unsigned k = 0;
    radio_interface_mapping_t *radio_iface_map = NULL;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    vap->u.sta_info.enabled = vap_row->enabled;

    // Copy basic info
    strncpy(vap->u.sta_info.ssid,      vap_row->ssid,       sizeof(vap->u.sta_info.ssid));
    memcpy(vap->u.sta_info.bssid,      vap_row->bssid.mac,  sizeof(mac_address_t));

    // Copy security info (mode/AKMs)
    if ((key_mgmt_conversion(&enum_sec, &len, STRING_TO_ENUM, vap_row->num_fronthaul_akms, (char(*)[])vap_row->fronthaul_akm)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
                "security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
        return webconfig_error_translate_from_easymesh;
    }

    vap->u.sta_info.security.mode = enum_sec;
    // Copy Passphrase
    strncpy(vap->u.sta_info.security.u.key.key, vap_row->mesh_sta_passphrase, sizeof(vap->u.sta_info.security.u.key.key));
    
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

    /*
        if ((key_mgmt_conversion(&enum_sec, &len, STRING_TO_ENUM, vap_row->num_fronthaul_akms, (char(*)[])vap_row->fronthaul_akm)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
                    (vap_row->fronthaul_akm[0]) ? vap_row->fronthaul_akm[0]: "NULL");
            return webconfig_error_translate_from_easymesh;
        }

        strncpy(vap->u.bss_info.security.u.key.key,vap_row->fronthaul_passphrase,strlen(vap->u.bss_info.security.u.key.key));
        vap->u.bss_info.security.mode = enum_sec;
     */

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
    /*
        if ((key_mgmt_conversion(&enum_sec, &len, STRING_TO_ENUM, vap_row->num_xhs_akms, (char(*)[])vap_row->xhs_akm)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
                    (vap_row->xhs_akm[0]) ? vap_row->xhs_akm[0]: "NULL");
            return webconfig_error_translate_from_easymesh;
        }

        strncpy(vap->u.bss_info.security.u.key.key,vap_row->xhs_passphrase,strlen(vap->u.bss_info.security.u.key.key));
        vap->u.bss_info.security.mode = enum_sec;
     */
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

    /*
        if ((key_mgmt_conversion(&enum_sec, &len, STRING_TO_ENUM, vap_row->num_lnf_psk_akms, (char(*)[])vap_row->lnf_psk_akm)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
                    (vap_row->lnf_psk_akm[0]) ? vap_row->lnf_psk_akm[0]: "NULL");
            return webconfig_error_translate_from_easymesh;
        }

        strncpy(vap->u.bss_info.security.u.key.key,vap_row->lnf_psk_passphrase,strlen(vap->u.bss_info.security.u.key.key));
        vap->u.bss_info.security.mode = enum_sec;
     */
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

    /*
        if ((key_mgmt_conversion(&enum_sec, &len, STRING_TO_ENUM, vap_row->num_lnf_radius_akms, (char(*)[])vap_row->lnf_radius_akm)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
                    (vap_row->lnf_radius_akm[0]) ? vap_row->lnf_radius_akm[0]: "NULL");
            return webconfig_error_translate_from_easymesh;
        }

        strncpy(vap->u.bss_info.security.u.key.key,vap_row->lnf_radius_passphrase,strlen(vap->u.bss_info.security.u.key.key));
        vap->u.bss_info.security.mode = enum_sec;
     */
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

    if ((key_mgmt_conversion(&enum_sec, &len, STRING_TO_ENUM, vap_row->num_backhaul_akms, (char(*)[])vap_row->backhaul_akm)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__,
                (vap_row->backhaul_akm[0]) ? vap_row->backhaul_akm[0]: "NULL");
        return webconfig_error_translate_from_easymesh;
    }

    vap->u.bss_info.security.mode = enum_sec;
    /* strncpy(vap->u.bss_info.security.u.key.key,vap_row->backhaul_passphrase,strlen(vap->u.bss_info.security.u.key.key)); */

    return webconfig_error_none;
}

// translate_em_bss_to_mesh_sta_info() em_bss_info_t data elements of wifi_vap_info_t of Onewifi for mesh_sta vaps
webconfig_error_t translate_em_bss_to_mesh_sta_info(wifi_vap_info_t *vap, const em_bss_info_t *vap_row)
{
    wifi_security_modes_t enum_sec;
    int len = 0;


    if (translate_em_common_to_sta_info_common(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    return webconfig_error_none;
}

//TO-DO
//Converting data elements of radio diag stats to easymesh structure   
/*webconfig_error_t translate_radiodiag_stats_to_easymesh(webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *decoded_params;
    webconfig_external_easymesh_t *proto;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    wifi_provider_response_t *radiodiag_stats = decoded_params->collect_stats.stats;
    radio_data_t *diag_stats = radiodiag_stats->stat_pointer;

    em_radio_info_t *radio_info = proto->get_radio_info(proto->data_model, radiodiag_stats->args.radio_index);

    for (int i = 0; i < sizeof(radio_info->ap_ext_metric.uni_bytes_sent); i++) {
        radio_info->ap_ext_metric.uni_bytes_sent[i] = (unsigned char)(diag_stats->radio_BytesSent >> (i * 8));
    }

    for (int i = 0; i < sizeof(radio_info->ap_ext_metric.uni_bytes_recv); i++) {
        radio_info->ap_ext_metric.uni_bytes_recv[i] = (unsigned char)(diag_stats->radio_BytesReceived >> (i * 8));
    }

    return webconfig_error_none;
}
*/

//translating easymesh bss info to onewifi for each vap in a radio
webconfig_error_t translate_from_easymesh_bssinfo_to_vap_per_radio(webconfig_subdoc_data_t *data)
{
    em_bss_info_t *em_vap_info;
    em_bss_info_t *vap_info_row;
    wifi_vap_info_map_t *vap_map;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0, k = 0, count = 0, radio_index = 0;
    rdk_wifi_radio_t *radio;
    wifi_hal_capability_t *hal_cap;
    decoded_params = &data->u.decoded;
    radio_interface_mapping_t *radio_iface_map;
    m2ctrl_radioconfig *radio_config;
    mac_address_t mac;
    em_haul_type_t haultype;
    char bssid_mac_str[32] = {};

    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    radio_config = proto->m2ctrl_radioconfig;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    hal_cap =&data->u.decoded.hal_cap;

    if (data->type == webconfig_subdoc_type_vap_24G) {
        radio_index = 0;
    } else if (data->type == webconfig_subdoc_type_vap_5G) {
        radio_index = 1;
    } else {
        radio_index = 2;
    }

    radio = &decoded_params->radios[radio_index];

    //radio_index = convert_radio_name_to_radio_index(decoded_params->radios[0].name);
    radio_iface_map = NULL;
    for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
        if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
            radio_iface_map = &(wifi_prop->radio_interface_map[k]);
            break;
        }
    }
    if (radio_iface_map == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
            __func__, __LINE__, radio_index);
        return webconfig_error_translate_from_easymesh;
    }
    vap_map = &radio->vaps.vap_map;
    for (j = 0; j < radio->vaps.num_vaps; j++) {
        //Get the corresponding vap
        vap = &vap_map->vap_array[j];
        if (vap->vap_mode == wifi_vap_mode_ap) {
            vap_info_row = proto->get_bss_info_with_mac(proto->data_model, vap->u.bss_info.bssid);
        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            vap_info_row = proto->get_bss_info_with_mac(proto->data_model, vap->u.sta_info.bssid);
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: unhandled vap_mode:%d\n",
                __func__, __LINE__, vap->vap_mode);
            vap_info_row = NULL;
        }
        if (vap_info_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_vap_info is NULL\n", __func__, __LINE__);
            continue;
        }

        if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
            if (translate_em_bss_to_private_vap_info(vap,  vap_info_row) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  private vap failed %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }
        } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
            if (translate_em_bss_to_xhs_vap_info(vap, vap_info_row) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  iot vap  failed  %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }
        } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
            if (translate_em_bss_to_lnf_psk_vap_info(vap,  vap_info_row) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to lnf psk vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }
        } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
            if (translate_em_bss_to_lnf_radius_vap_info(vap, vap_info_row) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  lnf radius vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }
        } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
            if (translate_em_bss_to_mesh_backhaul_vap_info(vap, vap_info_row) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  backhaul vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }
        } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
            if (translate_em_bss_to_mesh_sta_info(vap, vap_info_row) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  mesh sta vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unknown vap type %d\n", __func__, __LINE__, vap->vap_index);
            return webconfig_error_translate_from_easymesh;
        }

        if (radio_config != NULL) {
            for(k = 0; k < radio_config->noofbssconfig; k++) {
                convert_vap_name_to_hault_type(&haultype, (char *)vap->vap_name);
                if (radio_config->haultype[k] == haultype) {
                    wifi_util_info_print(WIFI_WEBCONFIG,
                        "%s:%d: vap_mode:%d ssid=%s sec_mode=%d\n", __func__, __LINE__,
                        vap->vap_mode, radio_config->ssid[k], radio_config->authtype[k]);
                    if (vap->vap_mode == wifi_vap_mode_ap) {
                        vap->u.bss_info.security.mode = radio_config->authtype[k];
                        strncpy(vap->u.bss_info.ssid, radio_config->ssid[k],
                            sizeof(vap->u.bss_info.ssid) - 1);
                        strncpy(vap->u.bss_info.security.u.key.key, radio_config->password[k],
                            sizeof(vap->u.bss_info.security.u.key.key) - 1);
                        vap->u.bss_info.enabled = radio_config->enable[k];
                    } else if (vap->vap_mode == wifi_vap_mode_sta) {
                        vap->u.sta_info.security.mode = radio_config->authtype[k];
                        strncpy(vap->u.sta_info.ssid, radio_config->ssid[k],
                            sizeof(vap->u.sta_info.ssid) - 1);
                        strncpy(vap->u.sta_info.security.u.key.key, radio_config->password[k],
                            sizeof(vap->u.sta_info.security.u.key.key) - 1);
                        vap->u.sta_info.enabled = radio_config->enable[k];
                    } else {
                        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: unhandled vap_mode:%d\n",
                            __func__, __LINE__, vap->vap_mode);
                    }
                }
            }
        }

        if (vap->vap_mode == wifi_vap_mode_ap) {
            uint8_mac_to_string_mac(vap->u.bss_info.bssid, bssid_mac_str);

            em_ap_mld_info_t *ap_mld_info = proto->get_ap_mld_frm_bssid(proto->data_model,
                vap->u.bss_info.bssid);
            if (!ap_mld_info) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,
                    "%s:%d: No AP MLD information available for bssid %s\n", __func__, __LINE__,
                    bssid_mac_str);
                continue;
            }

            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Found AP MLD information for bssid=%s\n",
                __func__, __LINE__, bssid_mac_str);

            // ToDo : Update vap structure based on ap_mld_info
            /* Commented below code as we dont proper value for MLD AP sub doc.
             Currently not needed as mld details are updated from vap structure itself and we are
             not changing. memcpy(vap->u.bss_info.mld_info.common_info.mld_addr,
             &ap_mld_info->mac_addr, sizeof(mac_address_t)); strncpy(vap->u.bss_info.ssid,
             ap_mld_info->ssid, sizeof(ssid_t));

             for (i = 0; i < ap_mld_info->num_affiliated_ap; i++) {
                 //em_affiliated_ap_info_t *affiliated_ap = &ap_mld_info->affiliated_ap[i];
                 if (memcmp(ap_mld_info->affiliated_ap[i].mac_addr, vap->u.bss_info.bssid,
             sizeof(mac_address_t)) == 0) { vap->u.bss_info.mld_info.common_info.mld_link_id =
             ap_mld_info->affiliated_ap[i].link_id; break;
                 }
             } */

        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_mode:%d\n", __func__, __LINE__,
                vap->vap_mode);
            // ToDo : Update vap structure based on sta_mld_info
            // em_sta_mld_info_t *sta_mld_info = proto->get_sta_mld_info(proto->data_model,
            // vap->u.sta_info.bssid);
        }
    }

    return webconfig_error_none;
}

#ifdef EM_APP
//translating onewifi channel stas to easymesh channel stats info structure
webconfig_error_t translate_channel_stats_to_easymesh_channel_info(webconfig_subdoc_data_t *data)
{
    channel_scan_response_t *channel_st;
    webconfig_external_easymesh_t *proto;
    int i, j, count = 0;

    webconfig_subdoc_decoded_data_t *params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: decoded_params is NULL\n", __func__,
            __LINE__);
        return webconfig_error_decode;
    }

    channel_st = (channel_scan_response_t *)params->collect_stats.stats;
    if (channel_st == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Dev Stats is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)params->external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: external proto is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_easymesh;
    }

    for (i = 0; i < channel_st->num_results; i++) {

        em_scan_result_t em_scan_result;
        channel_scan_result_t *src = &channel_st->results[i];

        em_scan_result.id.op_class = src->operating_class;
        em_scan_result.id.channel = src->channel;
        memset(em_scan_result.id.net_id, 0, sizeof(em_scan_result.id.net_id));
        memset(em_scan_result.id.dev_mac, 0, sizeof(em_scan_result.id.dev_mac));
        memcpy(em_scan_result.id.scanner_mac, channel_st->ruid, sizeof(mac_address_t));

        em_scan_result.scan_status = src->scan_status;
        strncpy(em_scan_result.timestamp, src->time_stamp, sizeof(em_scan_result.timestamp) - 1);
        em_scan_result.timestamp[sizeof(em_scan_result.timestamp) - 1] = '\0';
        em_scan_result.util = src->utilization;
        em_scan_result.noise = src->noise;
        em_scan_result.num_neighbors = src->num_neighbors;
        em_scan_result.aggr_scan_duration = 0;
        em_scan_result.scan_type = 0;

        for (j = 0; j < src->num_neighbors && j < EM_MAX_NEIGHBORS; j++) {
            neighbor_bss_t *src_neighbor = &src->neighbors[j];
            em_neighbor_t *dst_neighbor = &em_scan_result.neighbor[j];

            memcpy(dst_neighbor->bssid, src_neighbor->bssid, sizeof(bssid_t));
            strncpy(dst_neighbor->ssid, src_neighbor->ssid, strlen(src_neighbor->ssid) + 1);
            dst_neighbor->signal_strength = (signed char)src_neighbor->signal_strength;
            if (strncmp(src_neighbor->channel_bandwidth, "20", strlen("20")) == 0) {
                dst_neighbor->bandwidth = WIFI_CHANNELBANDWIDTH_20MHZ;
            } else if (strncmp(src_neighbor->channel_bandwidth, "40", strlen("40")) == 0) {
                dst_neighbor->bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
            } else if (strncmp(src_neighbor->channel_bandwidth, "80", strlen("80")) == 0) {
                dst_neighbor->bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
            } else if (strncmp(src_neighbor->channel_bandwidth, "160", strlen("160")) == 0) {
                dst_neighbor->bandwidth = WIFI_CHANNELBANDWIDTH_160MHZ;
            } else if (strncmp(src_neighbor->channel_bandwidth, "320", strlen("320")) == 0) {
                dst_neighbor->bandwidth = WIFI_CHANNELBANDWIDTH_320MHZ;
            }
            dst_neighbor->bss_color = 0x8f;
            dst_neighbor->channel_util = 00;
            dst_neighbor->sta_count = (unsigned short)src_neighbor->station_count;
        }
        count++;
        proto->put_scan_results(proto->data_model, &em_scan_result);
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: No of scan results : %d \n", __func__, __LINE__,
        count);

    return webconfig_error_none;
}
#endif

// translate_from_easymesh_bssinfo_to_vap_object() converts data elements of wifi_vap_info_t to em_bss_info_t of  easymesh
webconfig_error_t translate_from_easymesh_bssinfo_to_vap_object(webconfig_subdoc_data_t *data,char *vap_name)
{
    em_bss_info_t     *em_vap_info;
    em_bss_info_t     *vap_info_row;
    wifi_vap_info_map_t *vap_map;
    webconfig_external_easymesh_t *proto;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    unsigned int i = 0,j = 0, k = 0, count = 0, radio_index = 0;
    rdk_wifi_radio_t *radio;
    wifi_hal_capability_t *hal_cap;
    decoded_params = &data->u.decoded;
    radio_interface_mapping_t *radio_iface_map;
    m2ctrl_radioconfig *radio_config;
    em_haul_type_t haultype;

    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_radio_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    radio_config = proto->m2ctrl_radioconfig;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    hal_cap =&data->u.decoded.hal_cap;
    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            return webconfig_error_translate_from_easymesh;
        }
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            vap_info_row = proto->get_bss_info(proto->data_model, count);
            if (vap_info_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap_info_row is NULL\n", __func__, __LINE__);
                continue;
            }
            count++;
            proto->set_num_bss(proto->data_model, count);
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (is_vap_hotspot(wifi_prop,vap->vap_index) == true) {
                continue;
            }
            if (strstr(vap->vap_name,vap_name) == false) {
                continue;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_private_vap_info(vap,  vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  private vap failed %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_xhs_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  iot vap  failed  %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_lnf_psk_vap_info(vap,  vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to lnf psk vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_lnf_radius_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  lnf radius vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_mesh_backhaul_vap_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  backhaul vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_em_bss_to_mesh_sta_info(vap, vap_info_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation from EM to  mesh sta vap  failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_from_easymesh;
                }
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unknown vap type %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }


            if (radio_config != NULL) {
                for(k = 0; k < radio_config->noofbssconfig; k++) {
                    convert_vap_name_to_hault_type(&haultype, (char *)vap->vap_name );
                    if (radio_config->haultype[k] == haultype) {
                        wifi_util_info_print(WIFI_WEBCONFIG,
                            "%s:%d: vap_mode:%d ssid=%s sec_mode=%d\n", __func__, __LINE__,
                            vap->vap_mode, radio_config->ssid[k], radio_config->authtype[k]);
                        if (vap->vap_mode == wifi_vap_mode_ap) {
                            vap->u.bss_info.security.mode = radio_config->authtype[k];
                            strncpy(vap->u.bss_info.ssid, radio_config->ssid[k],
                                sizeof(vap->u.bss_info.ssid) - 1);
                            strncpy(vap->u.bss_info.security.u.key.key, radio_config->password[k],
                                sizeof(vap->u.bss_info.security.u.key.key) - 1);
                            vap->u.bss_info.enabled = radio_config->enable[k];
                        } else if (vap->vap_mode == wifi_vap_mode_sta) {
                            vap->u.sta_info.security.mode = radio_config->authtype[k];
                            strncpy(vap->u.sta_info.ssid, radio_config->ssid[k],
                                sizeof(vap->u.sta_info.ssid) - 1);
                            strncpy(vap->u.sta_info.security.u.key.key, radio_config->password[k],
                                sizeof(vap->u.sta_info.security.u.key.key) - 1);
                            vap->u.sta_info.enabled = radio_config->enable[k];
                        } else {
                            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: unhandled vap_mode:%d\n",
                                __func__, __LINE__, vap->vap_mode);
                        }
                    }
                }
            }
    
        }
    }
    return webconfig_error_none;
}

//translate_radio_object_from_easymesh_to_radio() converts data elements of  easymesh to Onewifi
webconfig_error_t translate_radio_object_from_easymesh_to_radio(webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_radio_operationParam_t  *oper_param;
    webconfig_external_easymesh_t *proto;
    unsigned int i,j,radio_index, freq_band = 0, per_radio_subdoc = 0;
    rdk_wifi_radio_t *radio;
    em_op_class_info_t *em_op_class_info;
    radio_interface_mapping_t *radio_iface_map;
    unsigned int num;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    mac_address_t ruid;
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

    if (proto->get_op_class_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_op_class_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", 
            __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    if (data->type == webconfig_subdoc_type_radio_24G) {
        freq_band = WIFI_FREQUENCY_2_4_BAND;
        per_radio_subdoc++;
    } else if (data->type == webconfig_subdoc_type_radio_5G) {
        freq_band = WIFI_FREQUENCY_5_BAND;
        per_radio_subdoc++;
    } else if (data->type == webconfig_subdoc_type_radio_6G) {
        freq_band = WIFI_FREQUENCY_6_BAND;
        per_radio_subdoc++;
    }

    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        oper_param = &decoded_params->radios[i].oper;
        if ((per_radio_subdoc > 0) && (oper_param->band != freq_band)) {
            continue;
        }
        num = proto->get_num_op_class(proto->data_model);
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        radio_iface_map = NULL;
        for (unsigned int k = 0; k < (sizeof(wifi_prop->radio_interface_map)/sizeof(radio_interface_mapping_t)); k++) {
            if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
                radio_iface_map = &(wifi_prop->radio_interface_map[k]);
                break;
            }
        }
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the radio map entry for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            return webconfig_error_translate_from_easymesh;
        }
        mac_address_from_name(radio_iface_map->interface_name, ruid);
        for (j = 0; j < num; j++) {
            em_op_class_info = proto->get_op_class_info(proto->data_model, j);
            if ((em_op_class_info != NULL) && (em_op_class_info->id.type == 1) &&
                (memcmp(&ruid, &em_op_class_info->id.ruid, sizeof(mac_address_t)) == 0)) {
                oper_param->operatingClass = em_op_class_info->op_class;
                oper_param->channel = em_op_class_info->channel;
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

    if (proto->get_device_info(proto->data_model) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_device_info is NULL\n");
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_device_info is not NULL\n");
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Value of get_device_info: %p\n", (void *)proto->get_device_info(proto->data_model));
    }

    device_info = proto->get_device_info(proto->data_model);
    if (device_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: device_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }
    network_info = proto->get_network_info(proto->data_model);
    if (network_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:network_info is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    strncpy(wifi_prop->software_version, device_info->software_ver, strlen(device_info->software_ver));
    strncpy(wifi_prop->manufacturerModel,device_info->manufacturer_model, strlen(device_info->manufacturer_model));
    strncpy (wifi_prop->manufacturer, device_info->manufacturer, strlen(device_info->manufacturer));
    strncpy(wifi_prop->serialNo, device_info->serial_number,strlen(device_info->serial_number));
    memcpy( wifi_prop->al_1905_mac, device_info->intf.mac, sizeof(mac_address_t));
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

    if (proto->get_radio_info(proto->data_model, 0) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_radio_info is NULL\n", __func__, __LINE__);
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
        // em_vap_info = em_radio_data[i].bss_info;//Please add NULL check TBD-P
        if (em_vap_info == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: em_vap_info is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_easymesh;
        }
        count = 0;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            em_vap_info = proto->get_bss_info(proto->data_model, j);//Please add NULL check TBD-P
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
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unknown vap type %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_from_easymesh;
            }
        }
    }
    return webconfig_error_none;
}

#ifdef EM_APP
// translate_policy_cfg_object_from_easymesh_to_em_cfg() converts data elements of
// em_policy_cfg_params_t of easymesh to Onewifi
webconfig_error_t translate_policy_cfg_object_from_easymesh_to_em_cfg(webconfig_subdoc_data_t *data)
{
    em_policy_cfg_params_t *em_policy_cfg;
    em_config_t *policy_cfg;
    webconfig_subdoc_decoded_data_t *decoded_params;
    webconfig_external_easymesh_t *proto;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: decoded_params is NULL\n", __func__,
            __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    proto = (webconfig_external_easymesh_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: external_protos is NULL\n", __func__,
            __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    em_policy_cfg = proto->policy_config;
    if (em_policy_cfg == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d:rcvd policy cfg is NULL\n", __func__,
            __LINE__);
        return webconfig_error_translate_from_easymesh;
    }

    policy_cfg = &decoded_params->em_config;

    // ap metric policy
    policy_cfg->ap_metric_policy.interval = em_policy_cfg->metrics_policy.interval;
    strncpy(policy_cfg->ap_metric_policy.managed_client_marker,
        em_policy_cfg->vendor_policy.managed_client_marker,
        strlen(em_policy_cfg->vendor_policy.managed_client_marker) + 1);

    // local steering policy
    policy_cfg->local_steering_dslw_policy.sta_count =
        em_policy_cfg->steering_policy.local_steer_policy.num_sta;
    for (int i = 0; i < policy_cfg->local_steering_dslw_policy.sta_count; i++) {
        memcpy(policy_cfg->local_steering_dslw_policy.disallowed_sta[i],
            em_policy_cfg->steering_policy.local_steer_policy.sta_mac[i], sizeof(mac_addr_t));
    }

    // btm steering policy
    policy_cfg->btm_steering_dslw_policy.sta_count =
        em_policy_cfg->steering_policy.btm_steer_policy.num_sta;
    for (int i = 0; i < policy_cfg->btm_steering_dslw_policy.sta_count; i++) {
        memcpy(policy_cfg->btm_steering_dslw_policy.disallowed_sta[i],
            em_policy_cfg->steering_policy.btm_steer_policy.sta_mac[i], sizeof(mac_addr_t));
    }

    // backhaul bss config policy
    memcpy(policy_cfg->backhaul_bss_config_policy.bssid, em_policy_cfg->bh_bss_cfg_policy.bssid,
        sizeof(bssid_t));
    policy_cfg->backhaul_bss_config_policy.profile_1_bsta_disallowed =
        em_policy_cfg->bh_bss_cfg_policy.p1_bsta_disallowed;
    policy_cfg->backhaul_bss_config_policy.profile_1_bsta_disallowed =
        em_policy_cfg->bh_bss_cfg_policy.p2_bsta_disallowed;

    // channel scan reporting policy
    policy_cfg->channel_scan_reporting_policy.report_independent_channel_scan =
        em_policy_cfg->channel_scan_policy.rprt_ind_ch_scan;

    // radio metrics policy
    policy_cfg->radio_metrics_policies.radio_count = em_policy_cfg->metrics_policy.radios_num;
    for (int i = 0; i < policy_cfg->radio_metrics_policies.radio_count; i++) {
        memcpy(policy_cfg->radio_metrics_policies.radio_metrics_policy[i].ruid,
            em_policy_cfg->metrics_policy.radios[i].ruid, sizeof(mac_addr_t));
        policy_cfg->radio_metrics_policies.radio_metrics_policy[i].sta_rcpi_threshold =
            em_policy_cfg->metrics_policy.radios[i].rcpi_thres;
        policy_cfg->radio_metrics_policies.radio_metrics_policy[i].sta_rcpi_hysteresis =
            em_policy_cfg->metrics_policy.radios[i].rcpi_hysteresis;
        policy_cfg->radio_metrics_policies.radio_metrics_policy[i].ap_util_threshold =
            em_policy_cfg->metrics_policy.radios[i].util_thres;
        policy_cfg->radio_metrics_policies.radio_metrics_policy[i].link_metrics =
            (em_policy_cfg->metrics_policy.radios[i].sta_policy >> 6) & 1;
        policy_cfg->radio_metrics_policies.radio_metrics_policy[i].traffic_stats =
            (em_policy_cfg->metrics_policy.radios[i].sta_policy >> 7) & 1;
        policy_cfg->radio_metrics_policies.radio_metrics_policy[i].sta_status =
            (em_policy_cfg->metrics_policy.radios[i].sta_policy >> 5) & 1;
    }

    return webconfig_error_none;
}
#endif

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

        case webconfig_subdoc_type_mesh_backhaul_sta:
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

        case webconfig_subdoc_type_assocdev_stats:
            if (translate_sta_object_to_easymesh_for_assocdev_stats(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_assocdev_stats assoc_dev translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break; 

        case webconfig_subdoc_type_associated_clients:
            if (translate_associated_clients_to_easymesh_sta_info(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_associated_clients translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

        case webconfig_subdoc_type_radio:
        case webconfig_subdoc_type_radio_24G:
        case webconfig_subdoc_type_radio_5G:
        case webconfig_subdoc_type_radio_6G:
            if (translate_radio_object_to_easymesh_for_radio(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: webconfig_subdoc_type_dml radio_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

          //TO-DO
   /*     case webconfig_subdoc_type_radiodiag_stats:
            if (translate_radiodiag_stats_to_easymesh(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_radiodiag_stats translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break; */

        case webconfig_subdoc_type_vap_24G:
            if (translate_per_radio_vap_object_to_easymesh_bss_info(data, WIFI_FREQUENCY_2_4_BAND) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, 
                    "%s:%d: webconfig_subdoc_type_private vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;
        case webconfig_subdoc_type_vap_5G:
            if (translate_per_radio_vap_object_to_easymesh_bss_info(data, WIFI_FREQUENCY_5_BAND) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, 
                    "%s:%d: webconfig_subdoc_type_private vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;
        case webconfig_subdoc_type_vap_6G:
            if (translate_per_radio_vap_object_to_easymesh_bss_info(data, WIFI_FREQUENCY_6_BAND) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, 
                    "%s:%d: webconfig_subdoc_type_private vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;
#ifdef EM_APP
        case webconfig_subdoc_type_em_channel_stats:
            if (translate_channel_stats_to_easymesh_channel_info(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: webconfig_subdoc_type_em_channel_stats translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;

        case webconfig_subdoc_type_beacon_report:
            if (translate_beacon_report_object_to_easymesh_sta_info(data) !=
                webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: webconfig_subdoc_type_private vap_object translation to easymesh "
                    "failed\n",
                    __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;
            
        case webconfig_subdoc_type_em_sta_link_metrics:
            if(translate_sta_link_metrics_object_to_easy_mesh_sta_info(data) != webconfig_error_none){
                wifi_util_error_print(WIFI_WEBCONFIG, 
                    "%s:%d: webconfig_subdoc_type_em_sta_link_metrics translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;
        case webconfig_subdoc_type_em_ap_metrics_report:
            if(translate_ap_metrics_report_to_easy_mesh_bss_info(data) != webconfig_error_none){
                wifi_util_error_print(WIFI_WEBCONFIG, 
                    "%s:%d: webconfig_subdoc_type_em_ap_metrics_report translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_easymesh;
            }
            break;
#endif

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
        
        case webconfig_subdoc_type_mesh_backhaul_sta:
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

        case webconfig_subdoc_type_radio:
        case webconfig_subdoc_type_radio_24G:
        case webconfig_subdoc_type_radio_5G:
        case webconfig_subdoc_type_radio_6G:
            if (translate_radio_object_from_easymesh_to_radio(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, 
                    "%s:%d: webconfig_subdoc_type_radio translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;

        case webconfig_subdoc_type_vap_24G:
        case webconfig_subdoc_type_vap_5G:
        case webconfig_subdoc_type_vap_6G:
            if (translate_from_easymesh_bssinfo_to_vap_per_radio(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, 
                    "%s:%d: webconfig_subdoc_type_private vap_object translation to easymesh failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;

#ifdef EM_APP
        case webconfig_subdoc_type_em_config:
            if (translate_policy_cfg_object_from_easymesh_to_em_cfg(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: webconfig_subdoc_type_em_config policy_cfg object translation from "
                    "easymesh failed\n",
                    __func__, __LINE__);
                return webconfig_error_translate_from_easymesh;
            }
            break;
#endif

        default:
            break;
    }
    return webconfig_error_none;
}

void webconfig_proto_easymesh_init(webconfig_external_easymesh_t *proto, void *data_model, void *m2ctrl_radioconfig, void *policy_config,
        ext_proto_get_num_radio_t get_num_radios, ext_proto_set_num_radio_t set_num_radios,
        ext_proto_get_num_op_class_t get_num_op_class, ext_proto_set_num_op_class_t set_num_op_class,
        ext_proto_get_num_bss_t get_num_bss, ext_proto_set_num_bss_t set_num_bss,
        ext_proto_em_get_device_info_t get_dev, ext_proto_em_get_network_info_t get_net,
        ext_proto_em_get_radio_info_t get_radio, ext_proto_em_get_ieee_1905_security_info_t get_sec,
        ext_proto_em_get_bss_info_t get_bss, ext_proto_em_get_op_class_info_t get_op_class,
        ext_proto_get_first_sta_info_t get_first_sta, ext_proto_get_next_sta_info_t get_next_sta,
        ext_proto_get_sta_info_t get_sta, ext_proto_put_sta_info_t put_sta, ext_proto_em_get_bss_info_with_mac_t get_bss_with_mac,
        ext_proto_put_scan_results_t put_scan_res, ext_proto_update_ap_mld_info_t update_ap_mld,
        ext_proto_update_bsta_mld_info_t update_bsta_mld, ext_proto_update_assoc_sta_mld_info_t update_assoc_sta_mld,
        ext_proto_get_ap_mld_frm_bssid_t get_ap_mld_frm_bssid)
{
    proto->data_model = data_model;
    proto->m2ctrl_radioconfig = m2ctrl_radioconfig;
	proto->policy_config = policy_config;
    proto->get_num_radio = get_num_radios;
    proto->set_num_radio = set_num_radios;
    proto->get_num_op_class = get_num_op_class;
    proto->set_num_op_class = set_num_op_class;
    proto->get_num_bss = get_num_bss;
    proto->set_num_bss = set_num_bss;
    proto->get_device_info = get_dev;
    proto->get_network_info = get_net;
    proto->get_radio_info = get_radio;
    proto->get_ieee_1905_security_info = get_sec;
    proto->get_bss_info = get_bss;
    proto->get_op_class_info = get_op_class;
    proto->get_first_sta_info = get_first_sta;
    proto->get_next_sta_info = get_next_sta;
    proto->get_sta_info = get_sta;
    proto->put_sta_info = put_sta;
    proto->get_bss_info_with_mac = get_bss_with_mac;
    proto->put_scan_results = put_scan_res;
    proto->update_ap_mld_info = update_ap_mld;
    proto->update_bsta_mld_info = update_bsta_mld;
    proto->update_assoc_sta_mld_info = update_assoc_sta_mld;
    proto->get_ap_mld_frm_bssid = get_ap_mld_frm_bssid;
}
