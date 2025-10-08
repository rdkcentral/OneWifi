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
#include <sys/stat.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_monitor.h"
#include "scheduler.h"
#include <unistd.h>
#include <pthread.h>
#include "wifi_hal_rdk_framework.h"
#include "wifi_passpoint.h"
#include "wifi_stubs.h"

#define NEIGHBOR_SCAN_RESULT_INTERVAL 40000 // 40 sec
#define MAX_VAP_INDEX 24

#define CHAN_UTIL_INTERVAL_MS 900000 // 15 mins
#define TELEMETRY_UPDATE_INTERVAL_MS 3600000 // 1 hour
#define ASSOCIATED_DEVICE_DIAG_INTERVAL_MS 5000 //5 seconds
#define MAX_RESET_RADIO_PARAMS_RETRY_COUNTER  (5000 / 100)

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(arg) \
    arg[0], \
    arg[1], \
    arg[2], \
    arg[3], \
    arg[4], \
    arg[5]

static unsigned msg_id = 1000;

#define RADIO_INDEX_DFS 1
unsigned int temp_ch_list_5g[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

typedef enum {
    hotspot_vap_disable,
    hotspot_vap_enable,
    hotspot_vap_param_update
} wifi_hotspot_action_t;

#define SEC_MODE_STR_MAX 32

int convert_sec_mode_enable_int_str(int sec_mode_enable, char *secModeStr) {

    switch(sec_mode_enable) {
        case wifi_security_mode_wpa_personal:
            strncpy(secModeStr, "WPA-Personal", SEC_MODE_STR_MAX);
            break;

        case wifi_security_mode_wpa2_personal:
            strncpy(secModeStr, "WPA2-Personal", SEC_MODE_STR_MAX);
            break;

        case wifi_security_mode_wpa3_personal:
            strncpy(secModeStr, "WPA3-Personal", SEC_MODE_STR_MAX);
            break;

        case wifi_security_mode_wpa_enterprise:
            strncpy(secModeStr, "WPA-Enterprise", SEC_MODE_STR_MAX);
            break;

        case wifi_security_mode_wpa2_enterprise:
            strncpy(secModeStr, "WPA2-Enterprise", SEC_MODE_STR_MAX);
            break;

        case wifi_security_mode_wpa3_enterprise:
            strncpy(secModeStr, "WPA3-Enterprise", SEC_MODE_STR_MAX);
            break;

        case wifi_security_mode_wpa3_transition:
            strncpy(secModeStr, "WPA3-Personal-Transition", SEC_MODE_STR_MAX);
            break;

        case wifi_security_mode_wpa3_compatibility:
            strncpy(secModeStr, "WPA3-Personal-Compatibility", SEC_MODE_STR_MAX);
            break;

        default:
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid security mode %d\n", __func__, __LINE__, sec_mode_enable);
            return RETURN_ERR;
    }

    return RETURN_OK;
}

void process_channel_change_event(wifi_channel_change_event_t *ch_chg, bool is_nop_start_reboot, unsigned int dfs_timer_secs);

void process_scan_results_event(scan_results_t *results, unsigned int len)
{
    wifi_ctrl_t *ctrl;
    vap_svc_t *ext_svc;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    ctrl = &mgr->ctrl;

    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (is_sta_enabled()) {
        ext_svc->event_fn(ext_svc, wifi_event_type_hal_ind, wifi_event_scan_results, vap_svc_event_none, results);
    }
}

void process_csa_beacon_frame_event(frame_data_t *msg, uint32_t msg_length, wifi_ctrl_t *ctrl)
{
    bus_error_t rc;

    if (ctrl != NULL) {
        raw_data_t rdata;
        memset(&rdata, 0, sizeof(raw_data_t));
        rdata.data_type = bus_data_type_bytes;
        rdata.raw_data.bytes = (void *)msg->data;
        rdata.raw_data_len = msg->frame.len;
        rc = get_bus_descriptor()->bus_event_publish_fn(&ctrl->handle, WIFI_CSA_BEACON_FRAME_RECEIVED,
                &rdata);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d CSA beacon frame publish failed\n", __func__, __LINE__);
        } else {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Published CSA beacon frame\n", __func__, __LINE__);
        }
    } else {
        wifi_util_error_print(WIFI_CTRL,"%s:%d ctrl object is NULL\n", __func__, __LINE__);
    }
}

const char* wifi_hotspot_action_to_string(wifi_hotspot_action_t action) {
    switch (action) {
        case hotspot_vap_disable:
            return "Hotspot VAP Down";
        case hotspot_vap_enable:
            return "Hotspot VAP Up";
        case hotspot_vap_param_update:
            return "Hotspot Param Update";
        default:
            return "unknown";
    }
}

int remove_xfinity_acl_entries(bool remove_all_greylist_entry,bool prefer_private)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d  Enter \n", __FUNCTION__, __LINE__);
    acl_entry_t *tmp_acl_entry = NULL, *acl_entry = NULL;
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    unsigned int itr = 0, itrj = 0;
    mac_addr_str_t mac_str;
    struct timeval tv_now;
    int vap_index = 0;
    int ret = 0;
    char macfilterkey[128];
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    memset(macfilterkey, 0, sizeof(macfilterkey));
    gettimeofday(&tv_now, NULL);

    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_vap_map = get_wifidb_vap_map(itr);
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
            vap_index = wifi_vap_map->vap_array[itrj].vap_index;
            if ((vap_svc_is_public(vap_index) == false)) {
                continue;
            }

            l_rdk_vap_array = get_wifidb_rdk_vap_info(vap_index);

            if (l_rdk_vap_array->acl_map != NULL) {
                acl_entry = hash_map_get_first(l_rdk_vap_array->acl_map);

                while (acl_entry != NULL) {
                    if ((prefer_private && (acl_entry->reason == PREFER_PRIVATE_RFC_REJECT)) || ((acl_entry->reason == WLAN_RADIUS_GREYLIST_REJECT) &&
                        ((acl_entry->expiry_time <= tv_now.tv_sec) || remove_all_greylist_entry))) {

                        to_mac_str(acl_entry->mac, mac_str);
#ifdef NL80211_ACL
                        ret = wifi_hal_delApAclDevice(l_rdk_vap_array->vap_index, mac_str);
#else
                        ret = wifi_delApAclDevice(l_rdk_vap_array->vap_index, mac_str);
#endif
                        if (ret != RETURN_OK) {

                            wifi_util_error_print(WIFI_MGR, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                             __func__, __LINE__, l_rdk_vap_array->vap_index, mac_str);
                            ret = RETURN_ERR;
                        }
                           acl_entry = hash_map_get_next(l_rdk_vap_array->acl_map, acl_entry);

                            tmp_acl_entry = hash_map_remove(l_rdk_vap_array->acl_map, mac_str);
                            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", l_rdk_vap_array->vap_name, mac_str);
                            get_wifidb_obj()->desc.update_wifi_macfilter_config_fn(macfilterkey, tmp_acl_entry, false);
                            free(tmp_acl_entry);
                    }
                    else {
                       acl_entry = hash_map_get_next(l_rdk_vap_array->acl_map, acl_entry);
                    }
                }
            }
       }
    }

    get_wifictrl_obj()->webconfig_state |= ctrl_webconfig_state_macfilter_cfg_rsp_pending;

    return RETURN_OK;
}
void process_unknown_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void process_probe_req_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d rssi:%d phy_rate:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, msg->frame.sig_dbm, msg->frame.phy_rate);
}

void process_auth_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_monitor_data_t data;
    memset(&data, 0, sizeof(wifi_monitor_data_t));
    memcpy(&data.u.msg, msg, sizeof(frame_data_t));
    data.id = msg_id++;
    push_event_to_monitor_queue(&data,wifi_event_monitor_auth_req,NULL);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void process_assoc_req_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_monitor_data_t data;
    memset(&data, 0, sizeof(wifi_monitor_data_t));
    memcpy(&data.u.msg, msg, sizeof(frame_data_t));
    data.id = msg_id++;
    push_event_to_monitor_queue(&data,wifi_event_monitor_assoc_req,NULL);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d rssi:%d phy_rate:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, msg->frame.sig_dbm, msg->frame.phy_rate);
}

void process_assoc_rsp_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void process_reassoc_req_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d rssi:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, msg->frame.sig_dbm);
}

void process_reassoc_rsp_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void process_dpp_public_action_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void process_dpp_config_req_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}


static wifi_anqp_node_t* convert_frame_data_to_anqp(int ap_index, mac_address_t sta, unsigned char token, unsigned char *attrib, unsigned int len)
{
    char macStr[MAC_STR_LEN];
    memset(macStr,0,sizeof(macStr));
    if(sta){
        snprintf(macStr, MAC_STR_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
    }
    else{
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid mac. Return\n", __func__, __LINE__);
    }

    if ((ap_index < 0) || (ap_index > MAX_VAP_INDEX)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid AP Index: %d \n", __func__,__LINE__,ap_index);
        return NULL;
    }

    if((len <= 0) || (attrib == NULL)){
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid Attributes in Request. Return \n", __func__,__LINE__);
        return NULL;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Interworking is enabled on AP: %d \n", __func__,__LINE__,ap_index +1);
    wifi_util_dbg_print(WIFI_CTRL, "Process request from %s. \n",macStr);

    wifi_anqp_element_format_t *anqp_info;
    wifi_hs_2_anqp_element_format_t *anqp_hs_2_info;
    unsigned char wfa_oui[3] = {0x50, 0x6f, 0x9a};
    wifi_anqp_node_t *head = NULL, *tmp = NULL, *prev = NULL;
    wifi_anqp_elem_t *elem;
    signed short anqp_queries_len, anqp_hs_2_queries_len;
    bool first = true;
    unsigned short *query_list_id;
    unsigned char *buff, *query_list_hs_id;

    buff = attrib;

    while (buff < (attrib+len))
    {
        anqp_info = (wifi_anqp_element_format_t *)buff;

        if (anqp_info->info_id == wifi_anqp_element_name_vendor_specific)
        {
            anqp_hs_2_info = (wifi_hs_2_anqp_element_format_t *)buff;

            if (memcmp(anqp_hs_2_info->oi, wfa_oui, sizeof(wfa_oui)) != 0)
            {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid HS2.0  Query; Break\n", __func__,__LINE__);
                break;
            }

            anqp_hs_2_queries_len = anqp_hs_2_info->len - 6;//wifi_oui(3) + Type(1) + SubType(1) + Reserved (1)
            query_list_hs_id = anqp_hs_2_info->payload;

            while (anqp_hs_2_queries_len)
            {

                tmp = (wifi_anqp_node_t *)malloc(sizeof(wifi_anqp_node_t));
                memset((unsigned char *)tmp, 0, sizeof(wifi_anqp_node_t));

                elem = (wifi_anqp_elem_t *)malloc(sizeof(wifi_anqp_elem_t));
                memset((unsigned char *)elem, 0, sizeof(wifi_anqp_elem_t));

                elem->type = wifi_anqp_id_type_hs;
                elem->u.anqp_hs_id = *query_list_hs_id;

                tmp->value = elem;
                tmp->next = NULL;

                if (first == true)
                {
                    head = tmp;
                    first = false;
                    prev = head;
                }
                else
                {
                    prev->next = tmp;
                    prev = tmp;
                }
                anqp_hs_2_queries_len -= sizeof(unsigned char);
                query_list_hs_id++;
            }

            buff = query_list_hs_id;
        }
        else if (anqp_info->info_id == wifi_anqp_element_name_query_list)
        {
            anqp_queries_len = anqp_info->len;

            query_list_id = (unsigned short *)anqp_info->info;

            while (anqp_queries_len > 0)
            {
                tmp = (wifi_anqp_node_t *)malloc(sizeof(wifi_anqp_node_t));
                memset((unsigned char *)tmp, 0, sizeof(wifi_anqp_node_t));

                elem = (wifi_anqp_elem_t *)malloc(sizeof(wifi_anqp_elem_t));
                memset((unsigned char *)elem, 0, sizeof(wifi_anqp_elem_t));

                elem->type = wifi_anqp_id_type_anqp;
                elem->u.anqp_elem_id = *query_list_id;

                tmp->value = elem;
                tmp->next = NULL;

                if (first == true)
                {
                    head = tmp;
                    first = false;
                    prev = head;
                }
                else
                {
                    prev->next = tmp;
                    prev = tmp;
                }

                anqp_queries_len -= sizeof(unsigned short);
                query_list_id++;
            }

            buff = (unsigned char *)query_list_id;
        }
        else
        {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid Query; Break\n", __func__,__LINE__);
            break;
        }
    }

    if(head == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid Query List; Return\n", __func__,__LINE__);
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: callback_anqp_gas_init_frame_received on AP: %d \n", __func__,__LINE__,ap_index +1);
    wifi_util_dbg_print(WIFI_CTRL, "STA:%s\n",macStr);

    return head;
}

void process_anqp_gas_init_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);

    wifi_interworking_t *l_inter = Get_wifi_object_interworking_parameter(msg->frame.ap_index);
    if (l_inter == NULL ||!(l_inter->interworking.interworkingEnabled) || !(l_inter->passpoint.enable)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d interworking data or passpoint is not enabled for vap_indx: %d\n", __func__,__LINE__, msg->frame.ap_index);
        return;
    }
    rdk_wifi_vap_info_t *rdk_vap_info = getRdkVapInfo(msg->frame.ap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get rdk vap info for index %d\n", __func__, __LINE__, msg->frame.ap_index);
        return;
    }

    // convert frame_data_t buf to wifi_anqp_head_t elements

    unsigned char *buf = (unsigned char*)msg->data;
    wifi_anqp_node_t *anqpList_head = convert_frame_data_to_anqp(msg->frame.ap_index, msg->frame.sta_mac, msg->frame.token, buf, msg->frame.len);

    if(anqpList_head == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL anqp frame head\n", __func__,__LINE__);
        return;
    }

    wifi_anqp_node_t *anqpList = anqpList_head;
    int respLength = 0;
    int mallocRetryCount = 0;
    int capLen;
    UCHAR wfa_oui[3] = {0x50, 0x6f, 0x9a};
    UCHAR *data_pos = NULL;

    while(anqpList) {
        anqpList->value->len = 0;
        if(anqpList->value->data){
            free(anqpList->value->data);
            anqpList->value->data = NULL;
        }
        // Update ANQP Request count
        rdk_vap_info->anqp_request_count++;
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: ANQP Request Count for VAP %d is = %d \n", __func__,__LINE__, msg->frame.ap_index+1, rdk_vap_info->anqp_request_count);
        if(anqpList->value->type == wifi_anqp_id_type_anqp){
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received ANQP Request\n", __func__, __LINE__);
            switch (anqpList->value->u.anqp_elem_id){
                //CapabilityListANQPElement
                case wifi_anqp_element_name_capability_list:
                    capLen = (l_inter->anqp.capabilityInfoLength * sizeof(USHORT)) + sizeof(wifi_vendor_specific_anqp_capabilities_t) + l_inter->passpoint.capabilityInfoLength;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received CapabilityListANQPElement Request\n", __func__, __LINE__);
                    anqpList->value->data = malloc(capLen);//To be freed in wifi_anqpSendResponse()
                    if(NULL == anqpList->value->data){
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                        if(mallocRetryCount > 5){
                            break;
                        }
                        mallocRetryCount++;
                        anqpList = anqpList->next;
                        continue;
                    }
                    data_pos = anqpList->value->data;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,capLen);
                    memset(data_pos,0,capLen);
                    memcpy(data_pos,&l_inter->anqp.capabilityInfo,(l_inter->anqp.capabilityInfoLength * sizeof(USHORT)));
                    data_pos += (l_inter->anqp.capabilityInfoLength * sizeof(USHORT));
                    wifi_vendor_specific_anqp_capabilities_t *vendorInfo = (wifi_vendor_specific_anqp_capabilities_t *)data_pos;
                    vendorInfo->info_id = wifi_anqp_element_name_vendor_specific;
                    vendorInfo->len = l_inter->passpoint.capabilityInfoLength + sizeof(vendorInfo->oi) + sizeof(vendorInfo->wfa_type);
                    memcpy(vendorInfo->oi, wfa_oui, sizeof(wfa_oui));
                    vendorInfo->wfa_type = 0x11;
                    data_pos += sizeof(wifi_vendor_specific_anqp_capabilities_t);
                    memcpy(data_pos, &l_inter->passpoint.capabilityInfo, l_inter->passpoint.capabilityInfoLength);
                    anqpList->value->len = capLen;
                    respLength += anqpList->value->len;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied CapabilityListANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    break;
                //IPAddressTypeAvailabilityANQPElement
                case wifi_anqp_element_name_ip_address_availabality:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received IPAddressTypeAvailabilityANQPElement Request\n", __func__, __LINE__);
                    anqpList->value->data = malloc(sizeof(wifi_ipAddressAvailabality_t));//To be freed in wifi_anqpSendResponse()
                    if(NULL == anqpList->value->data){
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                        if(mallocRetryCount > 5){
                            break;
                        }
                        mallocRetryCount++;
                        anqpList = anqpList->next;
                        continue;
                    }
                    mallocRetryCount = 0;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,sizeof(wifi_ipAddressAvailabality_t));
                    memset(anqpList->value->data,0,sizeof(wifi_ipAddressAvailabality_t));
                    memcpy(anqpList->value->data,&l_inter->anqp.ipAddressInfo,sizeof(wifi_ipAddressAvailabality_t));
                    anqpList->value->len = sizeof(wifi_ipAddressAvailabality_t);
                    respLength += anqpList->value->len;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied IPAddressTypeAvailabilityANQPElement Data. Length: %d. Data: %02X\n", __func__, __LINE__,anqpList->value->len, ((wifi_ipAddressAvailabality_t *)anqpList->value->data)->field_format);
                    break;
                //NAIRealmANQPElement
                case wifi_anqp_element_name_nai_realm:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received NAIRealmANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->anqp.realmInfoLength){
                        anqpList->value->data = malloc(l_inter->anqp.realmInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->anqp.realmInfoLength);
                        memset(anqpList->value->data,0,l_inter->anqp.realmInfoLength);
                        memcpy(anqpList->value->data,&l_inter->anqp.realmInfo,l_inter->anqp.realmInfoLength);
                        anqpList->value->len = l_inter->anqp.realmInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied NAIRealmANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                        l_inter->anqp.realmRespCount++;
                    }
                    break;
                //VenueNameANQPElement
                case wifi_anqp_element_name_venue_name:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received VenueNameANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->anqp.venueInfoLength){
                        anqpList->value->data = malloc(l_inter->anqp.venueInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->anqp.venueInfoLength);
                        memset(anqpList->value->data,0,l_inter->anqp.venueInfoLength);
                        memcpy(anqpList->value->data,&l_inter->anqp.venueInfo,l_inter->anqp.venueInfoLength);
                        anqpList->value->len = l_inter->anqp.venueInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied VenueNameANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //3GPPCellularANQPElement
                case wifi_anqp_element_name_3gpp_cellular_network:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received 3GPPCellularANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->anqp.gppInfoLength){
                        anqpList->value->data = malloc(l_inter->anqp.gppInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->anqp.gppInfoLength);
                        memset(anqpList->value->data,0,l_inter->anqp.gppInfoLength);
                        memcpy(anqpList->value->data,&l_inter->anqp.gppInfo,l_inter->anqp.gppInfoLength);
                        anqpList->value->len = l_inter->anqp.gppInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied 3GPPCellularANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                        l_inter->anqp.gppRespCount++;
                    }
                    break;
                //RoamingConsortiumANQPElement
                case wifi_anqp_element_name_roaming_consortium:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received RoamingConsortiumANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->anqp.roamInfoLength){
                        anqpList->value->data = malloc(l_inter->anqp.roamInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->anqp.roamInfoLength);
                        memset(anqpList->value->data,0,l_inter->anqp.roamInfoLength);
                        memcpy(anqpList->value->data,&l_inter->anqp.roamInfo,l_inter->anqp.roamInfoLength);
                        anqpList->value->len = l_inter->anqp.roamInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied RoamingConsortiumANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //DomainANQPElement
                case wifi_anqp_element_name_domain_name:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received DomainANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->anqp.domainInfoLength){
                        anqpList->value->data = malloc(l_inter->anqp.domainInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->anqp.domainInfoLength);
                        memset(anqpList->value->data,0,l_inter->anqp.domainInfoLength);
                        memcpy(anqpList->value->data,&l_inter->anqp.domainNameInfo,l_inter->anqp.domainInfoLength);
                        anqpList->value->len = l_inter->anqp.domainInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied DomainANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                        l_inter->anqp.domainRespCount++;
                    }
                    break;
               default:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received Unsupported ANQPElement Request: %d\n", __func__, __LINE__,anqpList->value->u.anqp_elem_id);
                    break;
            }
        } else if (anqpList->value->type == wifi_anqp_id_type_hs){
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received HS2 ANQP Request\n", __func__, __LINE__);
            switch (anqpList->value->u.anqp_hs_id){
                //CapabilityListANQPElement
                case wifi_anqp_element_hs_subtype_hs_capability_list:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received CapabilityListANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->passpoint.capabilityInfoLength){
                        anqpList->value->data = malloc(l_inter->passpoint.capabilityInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->passpoint.capabilityInfoLength);
                        memset(anqpList->value->data,0,l_inter->passpoint.capabilityInfoLength);
                        memcpy(anqpList->value->data,&l_inter->passpoint.capabilityInfo,l_inter->passpoint.capabilityInfoLength);
                        anqpList->value->len = l_inter->passpoint.capabilityInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied CapabilityListANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //OperatorFriendlyNameANQPElement
                case wifi_anqp_element_hs_subtype_operator_friendly_name:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received OperatorFriendlyNameANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->passpoint.opFriendlyNameInfoLength){
                        anqpList->value->data = malloc(l_inter->passpoint.opFriendlyNameInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->passpoint.opFriendlyNameInfoLength);
                        memset(anqpList->value->data,0,l_inter->passpoint.opFriendlyNameInfoLength);
                        memcpy(anqpList->value->data,&l_inter->passpoint.opFriendlyNameInfo,l_inter->passpoint.opFriendlyNameInfoLength);
                        anqpList->value->len = l_inter->passpoint.opFriendlyNameInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied OperatorFriendlyNameANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //ConnectionCapabilityListANQPElement
                case wifi_anqp_element_hs_subtype_conn_capability:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received ConnectionCapabilityListANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->passpoint.connCapabilityLength){
                        anqpList->value->data = malloc(l_inter->passpoint.connCapabilityLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->passpoint.connCapabilityLength);
                        memset(anqpList->value->data,0,l_inter->passpoint.connCapabilityLength);
                        memcpy(anqpList->value->data,&l_inter->passpoint.connCapabilityInfo,l_inter->passpoint.connCapabilityLength);
                        anqpList->value->len = l_inter->passpoint.connCapabilityLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied ConnectionCapabilityListANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //NAIHomeRealmANQPElement
                case wifi_anqp_element_hs_subtype_nai_home_realm_query:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received NAIHomeRealmANQPElement Request\n", __func__, __LINE__);
                    if(l_inter->passpoint.realmInfoLength){
                        anqpList->value->data = malloc(l_inter->passpoint.realmInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,l_inter->passpoint.realmInfoLength);
                        memset(anqpList->value->data,0,l_inter->passpoint.realmInfoLength);
                        memcpy(anqpList->value->data,&l_inter->passpoint.realmInfo,l_inter->passpoint.realmInfoLength);
                        anqpList->value->len = l_inter->passpoint.realmInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied NAIHomeRealmANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //WANMetricsANQPElement
                case wifi_anqp_element_hs_subtype_wan_metrics:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received WANMetricsANQPElement Request\n", __func__, __LINE__);
                    anqpList->value->data = malloc(sizeof(wifi_HS2_WANMetrics_t));//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                        if(mallocRetryCount > 5){
                            break;
                        }
                        mallocRetryCount++;
                        anqpList = anqpList->next;
                        continue;
                    }
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,sizeof(wifi_HS2_WANMetrics_t));
                    memset(anqpList->value->data,0,sizeof(wifi_HS2_WANMetrics_t));
                    memcpy(anqpList->value->data,&l_inter->passpoint.wanMetricsInfo,sizeof(wifi_HS2_WANMetrics_t));
                    anqpList->value->len = sizeof(wifi_HS2_WANMetrics_t);
                    respLength += anqpList->value->len;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Copied WANMetricsANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    break;
               default:
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Received Unsupported HS2ANQPElement Request: %d\n", __func__, __LINE__,anqpList->value->u.anqp_hs_id);
                    break;
            }
        }else{
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid Request Type\n", __func__, __LINE__);
        }
        anqpList = anqpList->next;
    }

    if(respLength == 0){
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Requested ANQP parameter is NULL\n", __func__, __LINE__);
    }

    //TODO: Update Gas Stats
    //Update ANQP Response count
    int rc = wifi_anqpSendResponse(msg->frame.ap_index, msg->frame.sta_mac, msg->frame.token, anqpList_head);
    if (rc != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Failed to send ANQP Response\n", __func__, __LINE__);
    } else if (rc == 0) {
        rdk_vap_info->anqp_response_count++;
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: ANQP Response Count for VAP %d is = %d \n", __func__,__LINE__, msg->frame.ap_index+1, rdk_vap_info->anqp_response_count);
    }
}


void send_hotspot_status(char* vap_name, bool up)
{
    bus_error_t rc;
    raw_data_t data;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL ctrl object\n", __func__,__LINE__);
        return;
    }

    char *evt_name = up ? WIFI_BUS_HOTSPOT_UP : WIFI_BUS_HOTSPOT_DOWN;

    memset(&data, 0, sizeof(raw_data_t));
    data.data_type = bus_data_type_string;
    data.raw_data.bytes = (void *)vap_name;

    rc = get_bus_descriptor()->bus_event_publish_fn(&ctrl->handle, evt_name, &data);
    if(rc != bus_error_success) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d bus_event_publish_fn %s failed for %s\n", __func__, __LINE__, evt_name, vap_name);
    }
}
/* process_xfinity_vaps()  param can take values 0,1 and 2
    0 ---To disable xfinityvaps,
    1 --To enable xfinty vaps
    0 and 1 are  used for TunnelUp/Down event
    2 --- To not change the enable param of xfinityvaps
    This is used in case of Radius greylist, station disconnect
*/

void process_xfinity_vaps(wifi_hotspot_action_t param, bool hs_evt)
{
    rdk_wifi_vap_info_t *rdk_vap_info;
    vap_svc_t  *pub_svc = NULL;
    wifi_ctrl_t *ctrl;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_vap_info_t *lnf_2g_vap = NULL, *lnf_vap_info = NULL, hotspot_5g_vap_info = { 0 };
    wifi_platform_property_t *wifi_prop = (&(get_wifimgr_obj())->hal_cap.wifi_prop);
    uint8_t num_radios = getNumberRadios();
    bool open_2g_enabled = false, open_5g_enabled = false, open_6g_enabled = false,sec_2g_enabled = false,sec_5g_enabled = false, sec_6g_enabled = false;
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);

    for(int radio_indx = 0; radio_indx < num_radios; ++radio_indx) {
        wifi_vap_info_map_t *wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_indx);
        lnf_vap_info = (wifi_vap_info_t *)get_wifidb_vap_parameters(getApFromRadioIndex(radio_indx, VAP_PREFIX_LNF_PSK));
        if (lnf_vap_info && strstr(lnf_vap_info->vap_name, NAME_FREQUENCY_2_4_G) != NULL) {
            lnf_2g_vap = lnf_vap_info;
        }
        for(unsigned int j = 0; j < wifi_vap_map->num_vaps; ++j) {
            if(strstr(wifi_vap_map->vap_array[j].vap_name, "hotspot") == NULL) {
                continue;
            }
            
            wifi_vap_info_map_t tmp_vap_map;
            memset((unsigned char *)&tmp_vap_map, 0, sizeof(wifi_vap_info_map_t));
            tmp_vap_map.num_vaps = 1;
            memcpy((unsigned char *)&tmp_vap_map.vap_array[0], (unsigned char *)&wifi_vap_map->vap_array[j], sizeof(wifi_vap_info_t));
            rdk_vap_info = get_wifidb_rdk_vap_info(wifi_vap_map->vap_array[j].vap_index);
            if (rdk_vap_info == NULL) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get rdk vap info for index %d\n",
                    __func__, __LINE__, wifi_vap_map->vap_array[j].vap_index);
                continue;
            }

            if(param ==  hotspot_vap_disable) {
                tmp_vap_map.vap_array[0].u.bss_info.enabled = false;
            }
            if (param == hotspot_vap_enable ) {
                if (rfc_param) {
                    open_2g_enabled = rfc_param->hotspot_open_2g_last_enabled;
                    open_5g_enabled = rfc_param->hotspot_open_5g_last_enabled;
                    open_6g_enabled = rfc_param->hotspot_open_6g_last_enabled;
                    sec_2g_enabled = rfc_param->hotspot_secure_2g_last_enabled;
                    sec_5g_enabled = rfc_param->hotspot_secure_5g_last_enabled;
                    sec_6g_enabled = rfc_param->hotspot_secure_6g_last_enabled;
                }
                wifi_util_dbg_print(WIFI_CTRL," vap_name is %s and bool is %d:%d:%d:%d:%d:%d\n",tmp_vap_map.vap_array[0].vap_name,open_2g_enabled,open_5g_enabled,open_6g_enabled,sec_2g_enabled,sec_5g_enabled,sec_6g_enabled);

                if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_open_2g") == 0) && open_2g_enabled)
                    tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

                else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_open_5g") == 0) && open_5g_enabled)
                    tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

                else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_open_6g") == 0) && open_6g_enabled)
                    tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

                else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_secure_2g") == 0) && sec_2g_enabled)
                    tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

                else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_secure_5g") == 0) && sec_5g_enabled)
                    tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

                else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_secure_6g") == 0) && sec_6g_enabled)
                    tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

                wifi_util_dbg_print(WIFI_CTRL,"enabled is %d\n",tmp_vap_map.vap_array[0].u.bss_info.enabled);
            }

            if (isVapHotspotSecure5g(wifi_vap_map->vap_array[j].vap_index))
            {
                memcpy((unsigned char *)&hotspot_5g_vap_info, (unsigned char *)&tmp_vap_map.vap_array[0], sizeof(wifi_vap_info_t));
            }
            if(pub_svc->update_fn(pub_svc,radio_indx, &tmp_vap_map, rdk_vap_info) != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d Unable to create vaps\n", __func__,__LINE__);
                if(hs_evt) {
                    send_hotspot_status(wifi_vap_map->vap_array[j].vap_name, false);
               }
            } else {
                wifi_util_info_print(WIFI_CTRL, "%s:%d Able to create vaps. vap_enable %d and vap_name = %s\n", __func__,__LINE__, param, tmp_vap_map.vap_array[0].vap_name);
                get_wifidb_obj()->desc.print_fn("%s:%d radio_index:%d create vap %s successful\n", __func__,__LINE__, radio_indx, wifi_vap_map->vap_array[j].vap_name);
                if(hs_evt) {
                    send_hotspot_status(wifi_vap_map->vap_array[j].vap_name, true);
                }
                if (!lnf_vap_info)
                {
                    wifi_util_info_print(WIFI_CTRL, "%s:%d lnf_vap_info is NULL for radio index = %d\n", __func__,__LINE__,radio_indx);
                    return;
                }
                if (!strstr(lnf_vap_info->vap_name, NAME_FREQUENCY_2_4_G) && should_process_hotspot_config_change(lnf_vap_info, &tmp_vap_map.vap_array[0])) {
                    if (update_vap_params_to_hal_and_db(lnf_vap_info, tmp_vap_map.vap_array[0].u.bss_info.enabled) == -1) {
                        wifi_util_error_print(WIFI_CTRL, "%s:%d Unable to update LnF vaps as per Hotspot VAPs\n", __func__,__LINE__);
                        return;
                    }
                    wifi_util_info_print(WIFI_CTRL,"%s:%d LnF VAP %s config changed as per %s event\n",__func__,__LINE__,lnf_vap_info->vap_name, wifi_hotspot_action_to_string(param));
                }
            }
        }
    }

    if (is_6g_supported_device(wifi_prop) && param != hotspot_vap_param_update) {
        wifi_util_info_print(WIFI_CTRL,"6g supported device enable rrm\n");
        if (pub_svc->event_fn != NULL) {
            pub_svc->event_fn(pub_svc, wifi_event_type_command, wifi_event_type_xfinity_rrm,
                vap_svc_event_none,NULL);
        }
    }
    if (!lnf_2g_vap)
    {
        wifi_util_error_print(WIFI_CTRL,"%s:%d LnF 2.4GHz VAP is NULL\n", __func__,__LINE__);
        return;
    }
    if (should_process_hotspot_config_change(lnf_2g_vap, &hotspot_5g_vap_info)) {
        if (update_vap_params_to_hal_and_db(lnf_2g_vap, hotspot_5g_vap_info.u.bss_info.enabled) == -1)
        {
            wifi_util_info_print(WIFI_CTRL, "%s:%d Unable to update LnF vaps as per Hotspot VAPs\n", __func__,__LINE__);
        }
        wifi_util_info_print(WIFI_CTRL,"%s:%d LnF VAP %s config changed as per %s event\n",__func__,__LINE__,lnf_vap_info->vap_name ,wifi_hotspot_action_to_string(param));
    }
}

void convert_freq_to_channel(unsigned int freq, unsigned char *channel)
{
    if ((freq >= 2407) && (freq <= 2484)) {
        freq = freq - 2407;
        *channel = (freq / 5);
    } else if ((freq >= 5000) && (freq <= 5980)) {
        freq = freq - 5000;
        *channel = (freq / 5);
    } else if ((freq >= MIN_FREQ_MHZ_6G) && (freq <= MAX_FREQ_MHZ_6G)) {
        freq = freq - 5950;
        *channel = (freq / 5);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d frequency out of range:%d\r\n", __func__,__LINE__, freq);
        return;
    }
}

static void update_sta_presence(rdk_sta_data_t *sta_data)
{
    unsigned int i, j, vap_index;
    wifi_vap_info_map_t *wifi_vap_map;
    rdk_wifi_vap_info_t *rdk_vap_info;

    if (sta_data->stats.connect_status != wifi_connection_status_connected) {
        return;
    }

    vap_index = sta_data->stats.vap_index;
    rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get rdk vap info for index %d\n",
            __func__, __LINE__, vap_index);
        return;
    }

    if (rdk_vap_info->exists == true) {
        return;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d sta connected on deleted vap %s, reset state\n",
        __func__, __LINE__, rdk_vap_info->vap_name);

    // STA connected to deleted by cloud VAP therefore reset state and send all STA VAPs
    for (i = 0; i < getNumberRadios(); i++) {
        wifi_vap_map = get_wifidb_vap_map(i);
        for (j = 0; j < getMaxNumberVAPsPerRadio(i); j++) {
            vap_index = wifi_vap_map->vap_array[j].vap_index;
            if (vap_svc_is_mesh_ext(vap_index) == false) {
                continue;
            }

            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
            if (rdk_vap_info == NULL) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get rdk vap info for index %d\n",
                    __func__, __LINE__, vap_index);
                return;
            }
            rdk_vap_info->exists = true;
        }
    }
}

void process_sta_conn_status_event(rdk_sta_data_t *sta_data, unsigned int len)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    vap_svc_t *ext_svc;

    update_sta_presence(sta_data);

    ctrl->webconfig_state |= ctrl_webconfig_state_sta_conn_status_rsp_pending;

    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);

    if(is_sta_enabled()) {
        ext_svc->event_fn(ext_svc, wifi_event_type_hal_ind, wifi_event_hal_sta_conn_status, vap_svc_event_none, sta_data);
    }
}

void process_active_gw_check_command(bool active_gw_check)
{
    bool is_enabled, was_enabled;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (ctrl->active_gw_check == active_gw_check) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: no change in active gw check, ignore\n", __func__,
            __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d: active gw check: %d\n", __func__, __LINE__,
        active_gw_check);

    was_enabled = is_sta_enabled();
    ctrl->active_gw_check = active_gw_check;
    is_enabled = is_sta_enabled();

    if (was_enabled == is_enabled) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: no sta state change, ignore\n", __func__, __LINE__);
        return;
    }

    if (is_enabled == true) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: stop xfinity vaps\n", __func__, __LINE__);
        process_xfinity_vaps(hotspot_vap_disable, false);
        wifi_util_info_print(WIFI_CTRL, "%s:%d: start mesh sta\n", __func__, __LINE__);
        start_extender_vaps(WIFI_ALL_RADIO_INDICES);
    } else {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: start xfinity vaps\n", __func__, __LINE__);
        process_xfinity_vaps(hotspot_vap_enable, false);
        wifi_util_info_print(WIFI_CTRL, "%s:%d: stop mesh sta\n", __func__, __LINE__);
        stop_extender_vaps(WIFI_ALL_RADIO_INDICES);
    }

    ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending;
}

bool  IsClientConnected(rdk_wifi_vap_info_t* rdk_vap_info, char *check_mac)
{
    assoc_dev_data_t *assoc_dev_data = NULL;

    if((check_mac == NULL) || (rdk_vap_info == NULL)){
        wifi_util_error_print(WIFI_CTRL, "%s:%d Null arguments\n",__func__, __LINE__);
        return false;
    }

    pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
    if (rdk_vap_info->associated_devices_map) {
        str_tolower(check_mac);
        assoc_dev_data = hash_map_get(rdk_vap_info->associated_devices_map, check_mac);
        if (assoc_dev_data != NULL) {
            pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
            return true;
        }
    } else {
        pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
        wifi_util_error_print(WIFI_CTRL, "%s:%d associated_devices_map is NULL for vap : %d\n",__func__, __LINE__, rdk_vap_info->vap_index);
        return false;
    }
    pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);


    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Client is not connected to vap_index\n", __func__, __LINE__);
    return false;
}

static int initiate_kick_config_change(int vap_index, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    if (vap_info->u.bss_info.mac_filter_enable == FALSE) {
#ifdef NL80211_ACL
        if (wifi_hal_setApMacAddressControlMode(vap_index, 2) == RETURN_OK) {
#else
        if (wifi_setApMacAddressControlMode(vap_index, 2) == RETURN_OK) {
#endif
            rdk_vap_info->kick_device_config_change = TRUE;
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Set ACL mode to blacklist for vap %d\n", __func__,
                __LINE__, vap_index);
            return RETURN_OK;
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to set ACL mode for vap %d\n", __func__,
                __LINE__, vap_index);
            return RETURN_ERR;
        }
    }
    return RETURN_ERR;
}

static void finalize_kick_config_change(int vap_index, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    if (rdk_vap_info->kick_device_task_counter > 0) {
        return;
    }

    if (rdk_vap_info->kick_device_config_change == TRUE) {
        int filter_mode = 0;
        if (vap_info->u.bss_info.mac_filter_enable == TRUE) {
            filter_mode =
                (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) ? 2 : 1;
        }

#ifdef NL80211_ACL
        if (wifi_hal_setApMacAddressControlMode(vap_index, filter_mode) == RETURN_OK) {
#else
        if (wifi_setApMacAddressControlMode(vap_index, filter_mode) == RETURN_OK) {
#endif
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Successfully restored ACL mode %d for vap %d\n",
                __func__, __LINE__, filter_mode, vap_index);
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to restore ACL mode for vap %d\n",
                __func__, __LINE__, vap_index);
        }

        rdk_vap_info->kick_device_config_change = FALSE;
    }
}

static int handle_acl_operation(int vap_index, char *mac_str, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, bool is_add_operation)
{
    bool success = false;

    if (rdk_vap_info->kick_device_config_change == TRUE) {
        if (is_add_operation) {
#ifdef NL80211_ACL
            success = (wifi_hal_addApAclDevice(vap_index, mac_str) == RETURN_OK);
#else
            success = (wifi_addApAclDevice(vap_index, mac_str) == RETURN_OK);
#endif
        } else {
#ifdef NL80211_ACL
            success = (wifi_hal_delApAclDevice(vap_index, mac_str) == RETURN_OK);
#else
            success = (wifi_delApAclDevice(vap_index, mac_str) == RETURN_OK);
#endif
        }
        if (!success) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d addApAclDevice failed for vap %d, mac %s\n",
                __func__, __LINE__, vap_index, mac_str);
            return RETURN_ERR;
        }
    } else {
        if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
            if (is_add_operation) {
#ifdef NL80211_ACL
                success = (wifi_hal_addApAclDevice(vap_index, mac_str) == RETURN_OK);
#else
                success = (wifi_addApAclDevice(vap_index, mac_str) == RETURN_OK);
#endif
            } else {
#ifdef NL80211_ACL
                success = (wifi_hal_delApAclDevice(vap_index, mac_str) == RETURN_OK);
#else
                success = (wifi_delApAclDevice(vap_index, mac_str) == RETURN_OK);
#endif
            }
        } else if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
            if (is_add_operation) {
#ifdef NL80211_ACL
                success = (wifi_hal_delApAclDevice(vap_index, mac_str) == RETURN_OK);
#else
                success = (wifi_delApAclDevice(vap_index, mac_str) == RETURN_OK);
#endif
            } else {
#ifdef NL80211_ACL
                success = (wifi_hal_addApAclDevice(vap_index, mac_str) == RETURN_OK);
#else
                success = (wifi_addApAclDevice(vap_index, mac_str) == RETURN_OK);
#endif
            }
        }

        if (!success) {
            const char *operation = is_add_operation ? "add" : "del";
            wifi_util_error_print(WIFI_CTRL, "%s:%d %sApAclDevice failed for vap %d, mac %s\n",
                __func__, __LINE__, operation, vap_index, mac_str);
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

int process_maclist_timeout(void *arg)
{
    if (arg == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL argument\n", __func__,__LINE__);
        return TIMER_TASK_ERROR;
    }

    kick_details_t *kick = (kick_details_t *)arg;
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Entry - vap %d, list: %s\n", __func__, __LINE__, kick->vap_index,
        kick->kick_list ? kick->kick_list : "NULL");

    wifi_vap_info_t *vap_info = getVapInfo(kick->vap_index);
    rdk_wifi_vap_info_t *rdk_vap_info = get_wifidb_rdk_vap_info(kick->vap_index);

    if (vap_info == NULL || rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL vap info for vap %d\n", __func__, __LINE__,
            kick->vap_index);
        goto cleanup;
    }

    if (kick->kick_list != NULL && strlen(kick->kick_list) > 0) {
        char *str_dup = strdup(kick->kick_list);
        if (str_dup == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d strdup failed for vap %d\n", __func__, __LINE__,
                kick->vap_index);
            goto cleanup;
        }

        char *str_str, *cptr;
        str_str = strtok_r(str_dup, ",", &cptr);

        while (str_str != NULL) {
            if (handle_acl_operation(kick->vap_index, str_str, vap_info, rdk_vap_info, false) == RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d Successfully processed MAC %s for vap %d\n",
                    __func__, __LINE__, str_str, kick->vap_index);
            }
            str_str = strtok_r(NULL, ",", &cptr);
        }

        free(str_dup);
    }

    if (rdk_vap_info->kick_device_task_counter > 0) {
        rdk_vap_info->kick_device_task_counter--;
    }

    finalize_kick_config_change(kick->vap_index, vap_info, rdk_vap_info);

cleanup:
    if (kick != NULL && kick->kick_list != NULL) {
        free(kick->kick_list);
        kick->kick_list = NULL;
    }
    if (kick != NULL) {
        free(kick);
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Exit - task completed\n", __func__,__LINE__);
    return TIMER_TASK_COMPLETE;
}

static int schedule_maclist_timeout_task(wifi_ctrl_t *ctrl, rdk_wifi_vap_info_t *rdk_vap_info,
    int vap_index, int timeout, char *assoc_maclist, kick_details_t *kick_details,
    bool has_successful_operations)
{

    if (rdk_vap_info == NULL || assoc_maclist == NULL || kick_details == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid input parameters\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    if (!has_successful_operations || strlen(assoc_maclist) == 0) {
        wifi_util_dbg_print(WIFI_CTRL,
            "%s:%d No successful operations for vap %d, skipping "
            "scheduler\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    int len = strlen(assoc_maclist);
    if (len > 0 && (assoc_maclist)[len - 1] == ',') {
        (assoc_maclist)[len - 1] = '\0';
    }

    kick_details->kick_list = assoc_maclist;
    kick_details->vap_index = vap_index;

    if (scheduler_add_timer_task(ctrl->sched, TRUE, NULL, process_maclist_timeout, kick_details,
            timeout * 1000, 1, FALSE) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to schedule timer task for vap %d\n", __func__,
            __LINE__, vap_index);
        return RETURN_ERR;
    }
    rdk_vap_info->kick_device_task_counter++;
    wifi_util_dbg_print(WIFI_CTRL,
        "%s:%d Incremented task counter to %d for vap %d with MAC list: %s\n", __func__, __LINE__,
        rdk_vap_info->kick_device_task_counter, vap_index, assoc_maclist);
    return RETURN_OK;
}

void kick_all_macs(int vap_index, int timeout, rdk_wifi_vap_info_t *rdk_vap_info, wifi_ctrl_t *ctrl,
    wifi_vap_info_t *vap_info)
{
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Entry - vap %d, timeout %d\n", __func__, __LINE__,vap_index,
        timeout);

    assoc_dev_data_t *assoc_dev_data = NULL;
    char *assoc_maclist = NULL;
    mac_addr_str_t mac_str;
    kick_details_t *kick_details = NULL;
    bool has_successful_operations = false;

    assoc_maclist = (char *)malloc(2048);
    kick_details = (kick_details_t *)malloc(sizeof(kick_details_t));

    if (assoc_maclist == NULL || kick_details == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Memory allocation failed for vap %d\n", __func__, __LINE__,
            vap_index);
        goto cleanup;
    }

    memset(assoc_maclist, 0, 2048);
    memset(kick_details, 0, sizeof(kick_details_t));

    if (rdk_vap_info->associated_devices_map == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Associated devices map is NULL for vap %d\n",
            __func__, __LINE__, vap_index);
        goto cleanup;
    }

    assoc_dev_data = hash_map_get_first(rdk_vap_info->associated_devices_map);
    while (assoc_dev_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);

        if (handle_acl_operation(vap_index, mac_str, vap_info, rdk_vap_info, true) == RETURN_OK) {
            strcat(assoc_maclist, mac_str);
            strcat(assoc_maclist, ",");
            has_successful_operations = true;
        }

        assoc_dev_data = hash_map_get_next(rdk_vap_info->associated_devices_map, assoc_dev_data);
    }

    if (schedule_maclist_timeout_task(ctrl, rdk_vap_info, vap_index, timeout, assoc_maclist,
            kick_details, has_successful_operations) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d No successful operations for vap %d, skipping "
            "scheduler\n", __func__, __LINE__, vap_index);
        goto cleanup;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Exit - vap %d, counter %d, config_change %s\n", __func__, __LINE__,
        vap_index, rdk_vap_info->kick_device_task_counter,
        rdk_vap_info->kick_device_config_change ? "TRUE" : "FALSE");
    return;

cleanup:
    if (assoc_maclist) {
        free(assoc_maclist);
    }
    if (kick_details) {
        free(kick_details);
    }
}

void process_kick_assoc_devices_event(void *data)
{
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Entry\n", __func__, __LINE__);

    char *str_str, *cptr, *str_dup = NULL;
    int itr = 0, timeout = 0, vap_index = 0;
    wifi_ctrl_t *ctrl;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    wifi_vap_info_t *vap_info = NULL;
    char *str, s_vapindex[10], s_maclist[2048], s_timeout[520], *assoc_maclist = NULL;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    kick_details_t *kick_details = NULL;
    ctrl = &p_wifi_mgr->ctrl;
    mac_address_t kick_all = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    mac_address_t mac_bytes;
    bool has_successful_operations = false;
    int config_change_initiated = RETURN_ERR;

    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL data\n", __func__, __LINE__);
        return;
    }

    str = (char *)data;
    str_dup = strdup(str);
    if (str_dup == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d strdup failed\n", __func__, __LINE__);
        return;
    }

    memset(s_vapindex, 0, sizeof(s_vapindex));
    memset(s_maclist, 0, sizeof(s_maclist));
    memset(s_timeout, 0, sizeof(s_timeout));

    str_str = strtok_r(str_dup, "-", &cptr);
    while (str_str != NULL) {
        if (itr > 2) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid input format\n", __func__, __LINE__);
            goto cleanup_all;
        }

        if (itr == 0) {
            strncpy(s_vapindex, str_str, sizeof(s_vapindex) - 1);
        } else if (itr == 1) {
            strncpy(s_maclist, str_str, sizeof(s_maclist) - 1);
        } else if (itr == 2) {
            strncpy(s_timeout, str_str, sizeof(s_timeout) - 1);
        }

        str_str = strtok_r(NULL, "-", &cptr);
        itr++;
    }
    free(str_dup);
    str_dup = NULL;

    if (itr < 3) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid input format\n", __func__, __LINE__);
        return;
    }

    vap_index = atoi(s_vapindex);
    timeout = atoi(s_timeout);

    vap_info = getVapInfo(vap_index);
    rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);

    if (vap_info == NULL || rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL vap info for vap %d\n", __func__, __LINE__, vap_index);
        return;
    }

    config_change_initiated = initiate_kick_config_change(vap_index, vap_info, rdk_vap_info);

    if ((config_change_initiated != RETURN_OK) && !vap_info->u.bss_info.mac_filter_enable) {
        wifi_util_error_print(WIFI_CTRL,
            "%s:%d Exiting as unable to set macmode for vap_name = %s\n", __func__, __LINE__,
            vap_info->vap_name);
        return;
    }

    str_dup = strdup(s_maclist);
    if (str_dup == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d strdup failed for MAC list\n", __func__, __LINE__);
        goto cleanup_all;
    }

    str_str = strtok_r(str_dup, ",", &cptr);
    if (str_str == NULL) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d Empty MAC list\n", __func__, __LINE__);
        goto cleanup_all;
    }

    str_to_mac_bytes(str_str, mac_bytes);
    if (memcmp(mac_bytes, kick_all, sizeof(mac_address_t)) == 0) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d Processing kick_all for vap %d\n", __func__, __LINE__,
            vap_index);
        kick_all_macs(vap_index, timeout, rdk_vap_info, ctrl, vap_info);
        goto cleanup_all;
    }

    assoc_maclist = (char *)malloc(2048);
    kick_details = (kick_details_t *)malloc(sizeof(kick_details_t));

    if (assoc_maclist == NULL || kick_details == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Memory allocation failed for vap %d\n", __func__, __LINE__,
            vap_index);
        goto cleanup_all;
    }

    memset(assoc_maclist, 0, 2048);
    memset(kick_details, 0, sizeof(kick_details_t));

    while (str_str != NULL) {
        str_to_mac_bytes(str_str, mac_bytes);

        if (memcmp(mac_bytes, kick_all, sizeof(mac_address_t)) == 0) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Skipping broadcast MAC\n", __func__, __LINE__);
            str_str = strtok_r(NULL, ",", &cptr);
            continue;
        }

        if (IsClientConnected(rdk_vap_info, str_str)) {
            int mac_processed_successfully = handle_acl_operation(vap_index, str_str, vap_info,
                rdk_vap_info, true);

            if (mac_processed_successfully == RETURN_OK) {
                strcat(assoc_maclist, str_str);
                strcat(assoc_maclist, ",");
                has_successful_operations = true;
            }
        }

        str_str = strtok_r(NULL, ",", &cptr);
    }

    free(str_dup);
    str_dup = NULL;

    if (schedule_maclist_timeout_task(ctrl, rdk_vap_info, vap_index, timeout, assoc_maclist,
            kick_details, has_successful_operations) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d No successful operations for vap %d\n", __func__, __LINE__,
            vap_index);
        goto cleanup_all;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d vap_index %s, mac_list %s, timeout %s\n", __func__, __LINE__,
        s_vapindex, s_maclist, s_timeout);
    return;

cleanup_all:
    if (str_dup) {
        free(str_dup);
    }
    if (assoc_maclist) {
        free(assoc_maclist);
    }
    if (kick_details) {
        free(kick_details);
    }

    if ((config_change_initiated == RETURN_OK) && (rdk_vap_info->kick_device_task_counter == 0)) {
        finalize_kick_config_change(vap_index, vap_info, rdk_vap_info);
    }
}

void process_greylist_mac_filter(void *data)
{
    long int  expiry_time = 0;
    struct timeval tv_now;
    unsigned int itr = 0, itrj = 0;
    int reason = 0;
    int vap_index = 0;
    const char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";
    char log_buf[1024] = {0};
    char time_str[20] = {0};
    time_t now;
    struct tm *time_info;
    bool greylist_client_added = false;

    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    acl_entry_t *acl_entry = NULL;
    acl_entry_t *temp_acl_entry = NULL;
    mac_address_t new_mac;
    mac_addr_str_t new_mac_str;
    char macfilterkey[128];
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    memset(macfilterkey, 0, sizeof(macfilterkey));

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Enter \n", __FUNCTION__, __LINE__);
    greylist_data_t *grey_data = (greylist_data_t *) data;
    reason = grey_data->reason;

    wifi_util_dbg_print(WIFI_CTRL,"Disassociation reason is %d\n",reason);
    if (reason != WLAN_RADIUS_GREYLIST_REJECT){
        wifi_util_dbg_print(WIFI_CTRL,"This Not a Greylisted disassoc device\n");
        return;
    }

    memcpy(new_mac, grey_data->sta_mac, sizeof(mac_address_t));
    gettimeofday(&tv_now, NULL);
    expiry_time = tv_now.tv_sec + GREYLIST_TIMEOUT_IN_SECONDS;
    wifi_util_dbg_print(WIFI_CTRL," time now %d and expiry_time %d\n",tv_now.tv_sec,expiry_time);

    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_vap_map = get_wifidb_vap_map(itr);
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
            vap_index = wifi_vap_map->vap_array[itrj].vap_index;
            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);

            if (rdk_vap_info == NULL) {
                 return;
            }

            if ((strstr(rdk_vap_info->vap_name, "hotspot") == NULL)) {
                continue;
            }

            if (rdk_vap_info->acl_map == NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"GreyList acl_map is NULL\n");
                rdk_vap_info->acl_map = hash_map_create();
            }

            if (memcmp(new_mac, zero_mac, sizeof(mac_address_t)) == 0){
                wifi_util_dbg_print(WIFI_CTRL,"GreyList new_mac is zero mac \n");
                return ;
            }

            to_mac_str(new_mac, new_mac_str);
            str_tolower(new_mac_str);
            wifi_util_dbg_print(WIFI_CTRL,"new_mac_str %s\n",new_mac_str);
            temp_acl_entry = hash_map_get(rdk_vap_info->acl_map,new_mac_str);

            if (temp_acl_entry != NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"Mac is already present in macfilter \n");
                return;
            }

            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            memcpy(acl_entry->mac, new_mac, sizeof(mac_address_t));
            to_mac_str(acl_entry->mac, new_mac_str);
            str_tolower(new_mac_str);
            acl_entry->reason = WLAN_RADIUS_GREYLIST_REJECT;
            acl_entry->expiry_time = expiry_time;

#ifdef NL80211_ACL
            if (wifi_hal_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#else
            if (wifi_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#endif
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: wifi_addApAclDevice failed. vap_index %d, MAC %s \n",
                   __func__, __LINE__, rdk_vap_info->vap_index, new_mac_str);
                free(acl_entry);
                return;
            }

            hash_map_put(rdk_vap_info->acl_map, strdup(new_mac_str), acl_entry);

            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", rdk_vap_info->vap_name, new_mac_str);
            get_wifidb_obj()->desc.update_wifi_macfilter_config_fn(macfilterkey, acl_entry, true);
            greylist_client_added = true;
        }
    }

    get_wifictrl_obj()->webconfig_state |= ctrl_webconfig_state_macfilter_cfg_rsp_pending;

    //Add time and Mac address to wifihealth.txt
    if (greylist_client_added) {
        time(&now);
        time_info = localtime(&now);
        to_mac_str(new_mac, new_mac_str);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);
        sprintf(log_buf,"%s Client added to grey list from RADIUS:%s\n",time_str,new_mac_str);
        write_to_file(wifi_health_log, log_buf);
        wifi_util_dbg_print(WIFI_CTRL,"%s",log_buf);
   }
}

void process_wifi_host_sync()
{
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Inside \n", __func__, __LINE__);
    LM_wifi_hosts_t hosts;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    mac_addr_str_t mac_str;
    char ssid[256];
    char assoc_device[256];
    unsigned int itr, itrj=0, count;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *assoc_dev_data = NULL;

    memset(&hosts, 0, sizeof(LM_wifi_hosts_t));
    memset(ssid, 0, sizeof(ssid));
    memset(assoc_device, 0, sizeof(assoc_device));

    for (itr=0; itr<getTotalNumberVAPs(); itr++) {
        unsigned int vap_index;

        vap_index = VAP_INDEX(p_wifi_mgr->hal_cap, itr);
        if ((isVapPrivate(vap_index)) || (isVapXhs(vap_index))) {
            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
            if (rdk_vap_info == NULL) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d ERROR Null Pointer\n", __func__, __LINE__);
                continue;
            }

            if (hosts.count >= LM_MAX_HOSTS_NUM) {
                wifi_util_info_print(WIFI_CTRL, "%s:%d has reached LM_MAX_HOSTS_NUM\n", __func__, __LINE__);
                break;
            }
            count = 0;
            pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
            if (rdk_vap_info->associated_devices_map != NULL) {
                assoc_dev_data = hash_map_get_first(rdk_vap_info->associated_devices_map);
                while (assoc_dev_data != NULL) {
                    snprintf(ssid, sizeof(ssid), "Device.WiFi.SSID.%d", rdk_vap_info->vap_index+1);
                    snprintf((char *)hosts.host[hosts.count].ssid, sizeof(hosts.host[hosts.count].ssid), "%s", ssid);
                    to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);
                    str_tolower(mac_str);
                    snprintf((char *)hosts.host[hosts.count].phyAddr, sizeof(hosts.host[hosts.count].phyAddr), "%s", mac_str);
                    snprintf(assoc_device, sizeof(assoc_device), "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d", rdk_vap_info->vap_index+1, itrj+1);
                    snprintf((char *)hosts.host[hosts.count].AssociatedDevice, sizeof(hosts.host[hosts.count].AssociatedDevice), "%s", assoc_device);
                    if (assoc_dev_data->dev_stats.cli_Active) {
                        hosts.host[hosts.count].Status = TRUE;
                    } else {
                        hosts.host[hosts.count].Status = FALSE;
                    }
                    hosts.host[hosts.count].RSSI = assoc_dev_data->dev_stats.cli_RSSI;
                    (hosts.count)++;
                    count++;
                    assoc_dev_data = hash_map_get_next(rdk_vap_info->associated_devices_map, assoc_dev_data);
                }
                if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, count, 0) != RETURN_OK) {
                    wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
                }
            } else {
                wifi_util_error_print(WIFI_CTRL,"%s:%d Error associated_devices_map is NULL for vap %d\n", __func__, __LINE__, rdk_vap_info->vap_index);
            }
            pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
        }
    }
    if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, false) != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
    }

}

void lm_notify_disassoc(assoc_dev_data_t *assoc_dev_data, unsigned int vap_index)
{
    char ssid[256]= {0};
    mac_addr_str_t mac_str;
    LM_wifi_hosts_t hosts;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();

    if (assoc_dev_data == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    memset(ssid, 0, sizeof(ssid));
    snprintf(ssid, sizeof(ssid), "Device.WiFi.SSID.%d", vap_index +1);

    memset(&hosts, 0, sizeof(LM_wifi_hosts_t));
    strncpy((char *)hosts.host[0].ssid, ssid, sizeof(hosts.host[0].ssid));

    to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);
    str_tolower(mac_str);
    strncpy((char *)hosts.host[0].phyAddr, mac_str, sizeof(hosts.host[0].phyAddr));
    hosts.host[0].Status = FALSE;
    hosts.host[0].RSSI = 0;

    if (isVapHotspot(vap_index)) {
        if (notify_hotspot(&p_wifi_mgr->ctrl, assoc_dev_data) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to Hotspot\n", __func__, __LINE__);
        }
    } else if ((isVapPrivate(vap_index)) || (isVapXhs(vap_index))) {
        //Code to Publish to LMLite
        if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, true) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
        }
    }
}

int add_client_diff_assoclist(hash_map_t **diff_map, char *mac,  assoc_dev_data_t *assoc_dev_data)
{
    assoc_dev_data_t *tmp_assoc_dev_data = NULL;
    if ((assoc_dev_data == NULL) || (mac == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d input arguements are NULL assocdata : %p mac : %p\n", __func__, __LINE__, assoc_dev_data, mac);
        return RETURN_ERR;
    }

    if (*diff_map == NULL) {
        *diff_map = hash_map_create();
    }

    if (*diff_map != NULL) {
        str_tolower(mac);
        tmp_assoc_dev_data = hash_map_get(*diff_map, mac);
        if (tmp_assoc_dev_data == NULL) {
            tmp_assoc_dev_data =  (assoc_dev_data_t *)malloc(sizeof(assoc_dev_data_t));
            if (tmp_assoc_dev_data == NULL) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d unable to allocate memory for assoclist of mac : %s\n", __func__, __LINE__,  mac);
                return RETURN_ERR;
            }
            memcpy(tmp_assoc_dev_data, assoc_dev_data, sizeof(assoc_dev_data_t));
            hash_map_put(*diff_map, strdup(mac), tmp_assoc_dev_data);
        } else {
            wifi_util_info_print(WIFI_CTRL,"%s:%d assoclist of mac : %s is already present\n", __func__, __LINE__,  mac);
            memcpy(tmp_assoc_dev_data, assoc_dev_data, sizeof(assoc_dev_data_t));
        }
    }

    return RETURN_OK;
}


int process_device_removal(rdk_wifi_vap_info_t *rdk_vap_info,
                            mac_addr_str_t mac_str,
                            assoc_dev_data_t *removed_dev,
                            wifi_mgr_t *p_wifi_mgr,
                            ULONG *new_count,
                            ULONG old_count)
{
    removed_dev->client_state = client_state_disconnected;
    if (add_client_diff_assoclist(&rdk_vap_info->associated_devices_diff_map, mac_str, removed_dev) == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Failed to update diff assoclist for vap %d mac_str : %s\n", __func__, __LINE__, rdk_vap_info->vap_index, mac_str);
        free(removed_dev);
        return RETURN_ERR;
    }
    p_wifi_mgr->ctrl.webconfig_state |= ctrl_webconfig_state_associated_clients_cfg_rsp_pending;
    removed_dev->dev_stats.cli_Active = false;
    lm_notify_disassoc(removed_dev, rdk_vap_info->vap_index);
    free(removed_dev);
    if (old_count > 0) {
        *new_count = old_count - 1;
	}
    if (((isVapPrivate(rdk_vap_info->vap_index)) || (isVapXhs(rdk_vap_info->vap_index)))){
        if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, *new_count, old_count) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
        }
    }
	return RETURN_OK;
}

void process_disassoc_device_event(void *data)
{
    static const mac_address_t BROADCAST_MAC = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const mac_address_t ZERO_MAC = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    if (data == NULL) {
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)data;
    rdk_wifi_vap_info_t *rdk_vap_info = get_wifidb_rdk_vap_info(assoc_data->ap_index);
    
    if (rdk_vap_info == NULL) {
        return;
    }

    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    mac_addr_str_t mac_str;
    to_mac_str(assoc_data->dev_stats.cli_MACAddress, mac_str);
    bool remove_all = (memcmp(assoc_data->dev_stats.cli_MACAddress, 
                              BROADCAST_MAC, sizeof(mac_address_t)) == 0) ||
                      (memcmp(assoc_data->dev_stats.cli_MACAddress, 
                              ZERO_MAC, sizeof(mac_address_t)) == 0);

    pthread_mutex_lock(rdk_vap_info->associated_devices_lock);

    if (rdk_vap_info->associated_devices_map == NULL) {
        pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
        return;
    }

    ULONG old_count = hash_map_count(rdk_vap_info->associated_devices_map);
    ULONG new_count = old_count;

    if (remove_all) {
        assoc_dev_data_t *assoc_dev_data = 
            hash_map_get_first(rdk_vap_info->associated_devices_map);
        
        while (assoc_dev_data != NULL) {
            mac_addr_str_t temp_mac_str;
            to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, temp_mac_str);
            
            assoc_dev_data = hash_map_get_next(rdk_vap_info->associated_devices_map, 
                                               assoc_dev_data);
       
            assoc_dev_data_t *temp = hash_map_remove(rdk_vap_info->associated_devices_map, 
                                                      temp_mac_str);
            if (temp != NULL) {
                if (process_device_removal(rdk_vap_info, temp_mac_str, temp, 
                                          p_wifi_mgr, &new_count, old_count) == RETURN_ERR) {
                    pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
                    return;
                }
            }
        }
        
        new_count = 0; 
        
        wifi_util_info_print(WIFI_CTRL,
            "%s:%d Disassoc event for mac: %s - removed all assoclist entries\n",
            __func__, __LINE__, mac_str);
    } else {
        assoc_dev_data_t *temp = hash_map_remove(rdk_vap_info->associated_devices_map, 
                                                  mac_str);
        if (temp != NULL) {
            if (process_device_removal(rdk_vap_info, mac_str, temp, 
                                      p_wifi_mgr, &new_count, old_count) == RETURN_ERR) {
                pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
                return;
            }
            
            wifi_util_info_print(WIFI_CTRL,
                "%s:%d Disassoc event for mac: %s - removed entry from hashmap\n",
                __func__, __LINE__, mac_str);
        }
    }

    if (new_count != old_count && 
        (isVapPrivate(rdk_vap_info->vap_index) || 
         isVapXhs(rdk_vap_info->vap_index))) {
        if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, 
                                      new_count, old_count) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,
                "%s:%d Unable to send notification for associated entries\n",
                __func__, __LINE__);
        }
    }

    pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
}

void check_and_remove_mac_on_other_vaps(rdk_wifi_vap_info_t *current_vap_info, 
                                        assoc_dev_data_t *assoc_data)
{
    if (assoc_data == NULL) {
        return;
    }

    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    mac_addr_str_t mac_str;
    to_mac_str(assoc_data->dev_stats.cli_MACAddress, mac_str);
    
    unsigned int num_radios = getNumberRadios();
   
    for (unsigned int vap_idx = 0; vap_idx < num_radios; vap_idx++) {
        // Skip the VAP where device is currently associated
        if ((int)vap_idx == assoc_data->ap_index) {
            continue;
        }

        rdk_wifi_vap_info_t *rdk_vap_info = get_wifidb_rdk_vap_info(vap_idx);
        if (rdk_vap_info == NULL) {
            continue;
        }

        pthread_mutex_lock(rdk_vap_info->associated_devices_lock);

        if (rdk_vap_info->associated_devices_map == NULL) {
            pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
            continue;
        }

        ULONG old_count = hash_map_count(rdk_vap_info->associated_devices_map);

        assoc_dev_data_t *removed_dev = 
            hash_map_remove(rdk_vap_info->associated_devices_map, mac_str);

        if (removed_dev != NULL) {
            ULONG new_count = old_count;
         
            if (process_device_removal(rdk_vap_info, mac_str, removed_dev, 
                                      p_wifi_mgr, &new_count, old_count) == RETURN_ERR) {
                pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
                return;
            }
            
            wifi_util_info_print(WIFI_CTRL,
                "%s:%d Removed MAC %s from VAP %d (roaming to VAP %d)\n",
                __func__, __LINE__, mac_str, vap_idx, assoc_data->ap_index);
        }

        pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
    }
}

void process_assoc_device_event(void *data)
{
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    mac_addr_str_t mac_str, temp_mac_str;
    char ssid[256]= {0};
    char assoc_device[256] = {0};
    ULONG old_count = 0, new_count = 0;
    assoc_dev_data_t *p_assoc_data;
    int itrj = 0;
    vap_svc_t  *pub_svc;
    mac_addr_t prefer_private_mac;
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_wifidb_wifi_global_param();
    assoc_dev_data_t *tmp_assoc_dev_data;

    if (data == NULL) {
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;

    rdk_vap_info = get_wifidb_rdk_vap_info(assoc_data->ap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL rdk_vap_info pointer\n", __func__, __LINE__);
        return;
    }

    pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
    if (rdk_vap_info->associated_devices_map == NULL) {
        pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL  associated_devices_map  pointer  for  %d\n", __func__, __LINE__, rdk_vap_info->vap_index);
        return;
    }

    memset(temp_mac_str, 0, sizeof(temp_mac_str));
    memset(mac_str, 0, sizeof(mac_str));
    to_mac_str(assoc_data->dev_stats.cli_MACAddress, mac_str);
    str_tolower(mac_str);

    //check and remove mac_str from other vaps if device is steering
    check_and_remove_mac_on_other_vaps(rdk_vap_info, assoc_data);

    tmp_assoc_dev_data = hash_map_get(rdk_vap_info->associated_devices_map, mac_str);
    if (tmp_assoc_dev_data == NULL) {
        old_count = hash_map_count(rdk_vap_info->associated_devices_map);
        tmp_assoc_dev_data = (assoc_dev_data_t *)malloc(sizeof(assoc_dev_data_t));
        if (tmp_assoc_dev_data == NULL) {
            pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
            wifi_util_error_print(WIFI_CTRL,"%s:%d NULL tmp_assoc_dev_data pointer for vap %d\n", __func__, __LINE__, rdk_vap_info->vap_index);
            return;
        }
        memcpy(tmp_assoc_dev_data, assoc_data, sizeof(assoc_dev_data_t));
        tmp_assoc_dev_data->client_state = client_state_connected;
        if (add_client_diff_assoclist(&rdk_vap_info->associated_devices_diff_map, mac_str, tmp_assoc_dev_data) == RETURN_ERR) {
            pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
            wifi_util_error_print(WIFI_CTRL,"%s:%d Failed to update diff assoclist for vap %d mac_str : %s\n", __func__, __LINE__, rdk_vap_info->vap_index, mac_str);
            free(tmp_assoc_dev_data);
            return;
        }
        str_tolower(mac_str);
        hash_map_put(rdk_vap_info->associated_devices_map, strdup(mac_str), tmp_assoc_dev_data);
        p_wifi_mgr->ctrl.webconfig_state |= ctrl_webconfig_state_associated_clients_cfg_rsp_pending;
        new_count = old_count + 1;
        wifi_util_info_print(WIFI_CTRL,"%s:%d Device %s associated with vapindex %d associated clients count : %d\n", __func__, __LINE__, mac_str, rdk_vap_info->vap_index, new_count);

        if (((isVapPrivate(rdk_vap_info->vap_index)) || (isVapXhs(rdk_vap_info->vap_index)))){
            if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, new_count, old_count) != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
            }
        }
        if (isVapHotspot(rdk_vap_info->vap_index)) {
            if (notify_hotspot(&p_wifi_mgr->ctrl, tmp_assoc_dev_data) != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to Hotspot\n", __func__, __LINE__);
            }

            wifi_util_info_print(WIFI_CTRL, "Client %s is connected to hotspot index %d with rssi=%d  and SNR=%d\n",
              mac_str,rdk_vap_info->vap_index,tmp_assoc_dev_data->dev_stats.cli_RSSI,
              tmp_assoc_dev_data->dev_stats.cli_SNR);

        }
    }
    pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);

    if ((isVapPrivate(rdk_vap_info->vap_index))) {
        if (pcfg != NULL && pcfg->prefer_private) {
            pub_svc = get_svc_by_type(&p_wifi_mgr->ctrl, vap_svc_type_public);
            if (pub_svc->event_fn != NULL) {
                memcpy(prefer_private_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
                pub_svc->event_fn(pub_svc, wifi_event_type_command, wifi_event_type_prefer_private_rfc,
                        add_prefer_private_acl_to_public, &prefer_private_mac);
            }
        }
    }

    //Code to publish event to LMLite.
    if ((isVapPrivate(rdk_vap_info->vap_index)) || (isVapXhs(rdk_vap_info->vap_index))) {
        snprintf(ssid, sizeof(ssid), "Device.WiFi.SSID.%d", rdk_vap_info->vap_index+1);
        LM_wifi_hosts_t hosts;
        memset(&hosts, 0, sizeof(LM_wifi_hosts_t));
        strncpy((char *)hosts.host[0].ssid, ssid, sizeof(hosts.host[0].ssid));

        pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
        if (rdk_vap_info->associated_devices_map != NULL) {
            str_tolower(mac_str);
            itrj = hash_map_count(rdk_vap_info->associated_devices_map);
            p_assoc_data = hash_map_get_first(rdk_vap_info->associated_devices_map);
            while (p_assoc_data != NULL) {
                to_mac_str(p_assoc_data->dev_stats.cli_MACAddress, temp_mac_str);
                str_tolower(temp_mac_str);
                if (strcmp(mac_str, temp_mac_str) == 0) {
                    break;
                }
                itrj--;
                p_assoc_data = hash_map_get_next(rdk_vap_info->associated_devices_map, p_assoc_data);
            }

            strncpy((char *)hosts.host[0].phyAddr, mac_str, sizeof(hosts.host[0].phyAddr));
            if (itrj > 0) {
                snprintf(assoc_device, sizeof(assoc_device), "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d", rdk_vap_info->vap_index+1, itrj);
                wifi_util_info_print(WIFI_CTRL,"%s:%d LMLite notify:%s mac:%s\n", __func__, __LINE__, assoc_device, mac_str);
            } else {
                itrj = hash_map_count(rdk_vap_info->associated_devices_map);
                snprintf(assoc_device, sizeof(assoc_device), "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d", rdk_vap_info->vap_index+1, (itrj + 1));
                wifi_util_info_print(WIFI_CTRL,"%s:%d LMLite_notify:%s mac:%s\n", __func__, __LINE__, assoc_device, mac_str);
            }
            strncpy((char *)hosts.host[0].AssociatedDevice, assoc_device, sizeof(hosts.host[0].AssociatedDevice));
            if (assoc_data->dev_stats.cli_Active) {
                hosts.host[0].Status = TRUE;
            } else {
                hosts.host[0].Status = FALSE;
            }
            hosts.host[0].RSSI = assoc_data->dev_stats.cli_RSSI;

            if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, true) != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite\n", __func__, __LINE__);
            }
        }
        pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
    }
}

static void process_wps_results_event(wifi_wps_event_t *wps_event)
{
#ifdef FEATURE_SUPPORT_WPS
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_vap_info_t *vap_info = NULL;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    unsigned int vap_index = wps_event->vap_index;
    bool wps_push_button = false;

    wifi_util_info_print(WIFI_CTRL, "%s:%d wps event[%d] is received\n", __func__, __LINE__,
        wps_event->event);

    switch (wps_event->event) {
    case wifi_wps_ev_pbc_active:
        wps_push_button = true;
        break;

    case wifi_wps_ev_success:
    case wifi_wps_ev_fail:
    case wifi_wps_ev_pbc_timeout:
    case wifi_wps_ev_pbc_disable:
        wps_push_button = false;
        break;
    }

    vap_info = get_wifidb_vap_parameters(vap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get vap info for index %d\n", __func__,
            __LINE__, vap_index);
        return;
    }

    rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get rdk vap info for index %d\n",
            __func__, __LINE__, vap_index);
        return;
    }

    vap_info->u.bss_info.wpsPushButton = wps_push_button;
    get_wifidb_obj()->desc.update_wifi_vap_info_fn(vap_info->vap_name, vap_info, rdk_vap_info);
    ctrl->webconfig_state |= ctrl_webconfig_state_vap_private_cfg_rsp_pending;
#endif
}

void process_factory_reset_command(bool type)
{
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    p_wifi_mgr->ctrl.factory_reset = type;
    wifi_util_info_print(WIFI_CTRL,"%s:%d and type is %d\n",__func__,__LINE__,type);

    bool db_consolidated = is_db_consolidated();

    if (db_consolidated) {
        system("killall -9 ovsdb-server");
    } else {
        system("killall -9 wifidb-server");
    }
    system("rm -f /nvram/wifi/rdkb-wifi.db");
    system("rm -f /opt/secure/wifi/rdkb-wifi.db");
    get_wifidb_obj()->desc.cleanup_fn();
    if (!db_consolidated) {
        get_wifidb_obj()->desc.start_wifidb_fn();
    }
    wifi_util_dbg_print(WIFI_DB,"WIFI Factory reset started wifi db %d\n",__LINE__);
    get_wifidb_obj()->desc.init_tables_fn();
    get_wifidb_obj()->desc.init_default_value_fn();
    wifi_util_dbg_print(WIFI_DB,"WIFI Factory reset initiated default value %d\n",__LINE__);
    start_wifi_services();
    wifi_util_dbg_print(WIFI_DB,"WIFI Factory reset started wifidb monitor %d\n",__LINE__);
    get_wifidb_obj()->desc.start_monitor_fn();
    p_wifi_mgr->ctrl.webconfig_state |= ctrl_webconfig_state_factoryreset_cfg_rsp_pending;
}

void process_radius_grey_list_rfc(bool type)
{
    bool public_xfinity_vap_status = false;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();

    wifi_util_info_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    rfc_param->radiusgreylist_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    g_wifi_mgr->rfc_dml_parameters.radiusgreylist_rfc = type;

    public_xfinity_vap_status = get_wifi_public_vap_enable_status();

    if (public_xfinity_vap_status) {
        wifi_util_info_print(WIFI_CTRL,"public xfinity vaps are up and running\n");
        process_xfinity_vaps(hotspot_vap_param_update,false);
    }

    if (!rfc_param->radiusgreylist_rfc) {
        wifi_util_info_print(WIFI_CTRL,"Greylist RFC is disabled remove all greylisted entries from DB\n");
        remove_xfinity_acl_entries(true,false);
    }
}

void process_wifi_passpoint_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->wifipasspoint_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    process_xfinity_vaps(hotspot_vap_param_update,false);
}

void process_wifi_interworking_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->wifiinterworking_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
}

void process_wpa3_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    wifi_vap_info_map_t tgt_vap_map;
    wifi_vap_info_t *vapInfo = NULL;
    wifi_radio_operationParam_t *radio_params = NULL;
    vap_svc_t *svc;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    UINT apIndex = 0, ret;
    rdk_wifi_vap_info_t *rdk_vap_info;
    char update_status[128];

    rfc_param->wpa3_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    ctrl->webconfig_state |= ctrl_webconfig_state_vap_private_cfg_rsp_pending;

    for(UINT rIdx = 0; rIdx < getNumberRadios(); rIdx++) {
        apIndex = getPrivateApFromRadioIndex(rIdx);
        vapInfo =  get_wifidb_vap_parameters(apIndex);
        radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(rIdx);

        if ((svc = get_svc_by_name(ctrl, vapInfo->vap_name)) == NULL) {
            continue;
        }

        /* The RFC for WPA3 is primarily for 2.4GHz and 5GHz radios.  6GHz radio always supports WPA3 personal
           security mode irrespective of WPA3 RFC.
        */

        if (radio_params->band == WIFI_FREQUENCY_6_BAND) {
            wifi_util_dbg_print(WIFI_DB,"%s: %d 6GHz radio supports only WPA3 personal mode. WPA3-RFC: %d\n",__FUNCTION__,__LINE__,type);
            continue;
        }

        /* If WPA3-Personal-Compatibility RFC is enabled and security mode is WPA3-Personal-compatibility,
           change in WPA3-Personal-Transition RFC should not change security mode
        */
        if(rfc_param->wpa3_compatibility_enable && vapInfo->u.bss_info.security.mode == wifi_security_mode_wpa3_compatibility) {
            continue;
        }

        if (type) {
            if (vapInfo->u.bss_info.security.mode == wifi_security_mode_wpa3_transition) {
                continue;
            }
            vapInfo->u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
            vapInfo->u.bss_info.security.wpa3_transition_disable = false;
            vapInfo->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
            vapInfo->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
        } else {
            if (vapInfo->u.bss_info.security.mode == wifi_security_mode_wpa2_personal) {
                continue;
            }

            if ((radio_params->band == WIFI_FREQUENCY_2_4_BAND) ||  (radio_params->band == WIFI_FREQUENCY_5_BAND) ||
                (radio_params->band == WIFI_FREQUENCY_5L_BAND) || (radio_params->band == WIFI_FREQUENCY_5H_BAND)) {
                vapInfo->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            }
        }

        memset(&tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
        tgt_vap_map.num_vaps = 1;
        memcpy(&tgt_vap_map.vap_array[0], vapInfo, sizeof(wifi_vap_info_t));
        rdk_vap_info = get_wifidb_rdk_vap_info(apIndex);
        if (rdk_vap_info == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get rdk vap info for index %d\n",
                __func__, __LINE__, apIndex);
            continue;
        }
        ret = svc->update_fn(svc, rIdx, &tgt_vap_map, rdk_vap_info);
        memset(update_status, 0, sizeof(update_status));
        snprintf(update_status, sizeof(update_status), "%s %s", vapInfo->vap_name, (ret == RETURN_OK)?"success":"fail");
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_hal_result, update_status);

        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_DB,"%s:%d: Private vaps service update_fn failed \n",__func__, __LINE__);
        } else {
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Updating security mode for apIndex %d secmode %d \n",__func__, __LINE__,apIndex,vapInfo->u.bss_info.security.mode);
        }
    }
}

void process_dfs_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    rfc_param->dfs_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);

    for(UINT rIdx = 0; rIdx < getNumberRadios(); rIdx++) {
        wifi_radio_operationParam_t *radio_params = NULL;
        wifi_radio_feature_param_t *radio_feat = NULL;
        rdk_wifi_radio_t *l_radio = NULL;
        int ret;
        radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(rIdx);
        radio_feat = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map(rIdx);
        if (radio_params->band == WIFI_FREQUENCY_5_BAND || radio_params->band == WIFI_FREQUENCY_5L_BAND || radio_params->band == WIFI_FREQUENCY_5H_BAND) {
            pthread_mutex_lock(&g_wifidb->data_cache_lock);
            radio_params->DfsEnabled = type;
            //Note : while disabling the dfs, changing the channel from DFS channel
            if (radio_params->DfsEnabled == 0) {
                if ((radio_params->channel >= 52) && (radio_params->channel < 149)) {
                    if ((radio_params->band == WIFI_FREQUENCY_5_BAND) || (radio_params->band == WIFI_FREQUENCY_5L_BAND)) {
                        radio_params->channel = 36;
                    } else if (radio_params->band == WIFI_FREQUENCY_5H_BAND) {
                        radio_params->channel = 149;
                    }
                }
                if (radio_params->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
                    radio_params->channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
                }
                /* Clean up the previous radar data*/
                l_radio = find_radio_config_by_index(rIdx);
                if (l_radio == NULL) {
                    wifi_util_error_print(WIFI_CTRL,"%s:%d radio strucutre is not present for radio %d\n",
                                          __FUNCTION__, __LINE__, rIdx);
                    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                    return;
                }
                l_radio->radarInfo.last_channel = 0;
                l_radio->radarInfo.num_detected = 0;
                l_radio->radarInfo.timestamp = 0;
            }
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
            ret = wifi_hal_setRadioOperatingParameters(rIdx, radio_params);
            if (ret != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s: wifi radio parameter set failure\n",__FUNCTION__);
                return;
            } else {
                wifi_util_info_print(WIFI_CTRL,"%s: wifi radio parameter set success\n",__FUNCTION__);
            }
            g_wifidb->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
            update_wifi_radio_config(rIdx, radio_params, radio_feat);
        }
    }
}

void process_dfs_atbootup_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    rfc_param->dfsatbootup_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);

    for(UINT rIdx = 0; rIdx < getNumberRadios(); rIdx++) {
        int ret;
        wifi_radio_operationParam_t *radio_params = NULL;
        wifi_radio_feature_param_t *radio_feat = NULL;
        radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(rIdx);
        radio_feat = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map(rIdx);
        if (radio_params->band == WIFI_FREQUENCY_5_BAND || radio_params->band == WIFI_FREQUENCY_5L_BAND || radio_params->band == WIFI_FREQUENCY_5H_BAND) {
            pthread_mutex_lock(&g_wifidb->data_cache_lock);
            radio_params->DfsEnabledBootup = type;
            pthread_mutex_unlock(&g_wifidb->data_cache_lock);
            ret = wifi_hal_setRadioOperatingParameters(rIdx, radio_params);
            if (ret != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s: wifi radio parameter set failure\n",__FUNCTION__);
                return;
            } else {
                wifi_util_info_print(WIFI_CTRL,"%s: wifi radio parameter set success\n",__FUNCTION__);
            }
            g_wifidb->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
            update_wifi_radio_config(rIdx, radio_params, radio_feat);
        }
    }
}

int enable_wifi_radio_ax_mode(unsigned int radio_index, wifi_radio_operationParam_t *radio_params, wifi_radio_feature_param_t *radio_feat_params, bool value)
{
    wifi_mgr_t *g_wifidb;
    int ret = RETURN_ERR;
    unsigned int old_variant = 0;
    g_wifidb = get_wifimgr_obj();

    if (radio_params == NULL || radio_feat_params == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d wifi radio[%d] param is NULL\n", __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    old_variant = radio_params->variant;
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    if (value == true) {
        radio_params->variant |= WIFI_80211_VARIANT_AX;
    } else {
        if (radio_params->variant & WIFI_80211_VARIANT_AX) {
            radio_params->variant ^= WIFI_80211_VARIANT_AX;
        }
    }
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    ret = wifi_hal_setRadioOperatingParameters(radio_index, radio_params);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d wifi radio[%d] parameter set[%d] failure\n",__func__, __LINE__, radio_index, radio_params->variant);
        radio_params->variant = old_variant;
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_CTRL,"%s:%d wifi radio[%d] parameter set[%d] success\n",__func__, __LINE__, radio_index, radio_params->variant);
    }
    g_wifidb->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
    update_wifi_radio_config(radio_index, radio_params, radio_feat_params);

    return RETURN_OK;
}

void process_twoG80211axEnable_rfc(bool type)
{
    unsigned int radio_index = 0;
    int ret = 0;
    wifi_radio_operationParam_t *radio_params = NULL;
    wifi_radio_feature_param_t *radio_feat_params = NULL;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();

    wifi_util_info_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();

    for(radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);
        radio_feat_params = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map(radio_index);
        if (radio_params == NULL || radio_feat_params == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d wifi radio[%d] param global cache failure\n", __func__, __LINE__, radio_index);
            return;
        }

        if (radio_params->band == WIFI_FREQUENCY_2_4_BAND) {
            break;
        }
    }

    if (radio_index >= getNumberRadios()) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Input radio_index=%d not found, out of range\n", __func__, __LINE__, radio_index);
        return;
    }
    ret = enable_wifi_radio_ax_mode(radio_index, radio_params, radio_feat_params, type);
    if (ret == RETURN_OK) {
        rfc_param->twoG80211axEnable_rfc = type;
        ret = get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
        if (ret == 0) {
            g_wifi_mgr->rfc_dml_parameters.twoG80211axEnable_rfc = type;
        }
    }
}

void process_prefer_private_rfc(bool type)
{
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    vap_svc_t  *pub_svc;
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();

    if (!type) {
        wifi_util_dbg_print(WIFI_CTRL,"Prefer private is set to false\n");
        remove_xfinity_acl_entries(false,true);
    }
    if (!type &&  rfc_param->radiusgreylist_rfc) {
        wifi_util_dbg_print(WIFI_CTRL,"RadiusGreylist is enabled hence not setting macmode\n");
        return ;
    }
    pub_svc = get_svc_by_type(&p_wifi_mgr->ctrl, vap_svc_type_public);
    if (pub_svc->event_fn != NULL) {
        pub_svc->event_fn(pub_svc, wifi_event_type_command, wifi_event_type_prefer_private_rfc,
                            add_macmode_to_public, &type);
    }
}

static void process_memwraptool_app_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB, "WIFI Enter RFC Func %s: %d : bool %d\n", __FUNCTION__, __LINE__,
        type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    rfc_param->memwraptool_app_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
}

void process_wifi_offchannelscan_app_rfc(bool type) // ocs scan for 5g radio in gateway
{
    wifi_util_dbg_print(WIFI_DB, "WIFI Enter RFC Func %s: %d : bool %d\n", __FUNCTION__, __LINE__,
        type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    rfc_param->wifi_offchannelscan_app_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
}

void process_wifi_offchannelscan_sm_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB, "WIFI Enter RFC Func %s: %d : bool %d\n", __FUNCTION__, __LINE__,
        type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    rfc_param->wifi_offchannelscan_sm_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
}

void process_levl_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_CTRL,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    if (rfc_param == NULL) {
        wifi_util_error_print(WIFI_CTRL,"Unable to fetch CTRL RFC %s:%d\n", __func__, __LINE__);
        return;
    }

    rfc_param->levl_enabled_rfc = type;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr = NULL;
    wifi_app_t *levl_app = NULL;
    if (ctrl != NULL) {
        apps_mgr = &ctrl->apps_mgr;
        levl_app = (wifi_app_t *)get_app_by_inst(apps_mgr, wifi_app_inst_levl);
        if (levl_app != NULL) {
            levl_app->desc.rfc  = rfc_param->levl_enabled_rfc;
            levl_app->desc.update_fn(levl_app);
        }
    }
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    return;
}

int update_wifi_app_rfc(wifi_app_inst_t inst, bool status)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr = NULL;
    wifi_app_t *p_app = NULL;
    if (ctrl != NULL) {
        apps_mgr = &ctrl->apps_mgr;
        p_app = (wifi_app_t *)get_app_by_inst(apps_mgr, inst);
        if (p_app != NULL) {
            p_app->desc.rfc = status;
            p_app->desc.update_fn(p_app);
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s:%d app:%d is not found\n", __func__, __LINE__,
                inst);
        }
    }
    return RETURN_OK;
}

void process_csi_analytics_rfc(bool type)
{
    wifi_util_info_print(WIFI_CTRL, "WIFI Enter RFC Func %s: %d : bool %d\n", __func__, __LINE__,
        type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    if (rfc_param == NULL) {
        wifi_util_error_print(WIFI_CTRL, "Unable to fetch CTRL RFC %s:%d\n", __func__, __LINE__);
        return;
    }

    rfc_param->csi_analytics_enabled_rfc = type;
    update_wifi_app_rfc(wifi_app_inst_csi_analytics, type);
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    return;
}

void process_tcm_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB, "Enter func %s: %d : Tcm RFC: %d\n", __FUNCTION__, __LINE__,
        type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    rfc_param->tcm_enabled_rfc = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    wifi_util_dbg_print(WIFI_DB, "Exit func %s: %d : Tcm RFC: %d\n", __FUNCTION__, __LINE__,
        type);
}

void process_wps_command_event(unsigned int vap_index)
{
#ifdef FEATURE_SUPPORT_WPS
    wifi_util_info_print(WIFI_CTRL,"%s:%d wifi wps test vap index = %d\n",__func__, __LINE__, vap_index);
    wifi_hal_setApWpsButtonPush(vap_index);
#endif
}

void process_wps_pin_command_event(void *data)
{
#ifdef FEATURE_SUPPORT_WPS
    wps_pin_config_t  *wps_config = (wps_pin_config_t *)data;
    if (wps_config == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d wps pin config data is NULL\n",__func__, __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_CTRL,"%s:%d wifi wps pin vap index = %d, wps_pin:%s\n",__func__, __LINE__,
                                        wps_config->vap_index, wps_config->wps_pin);
    wifi_hal_setApWpsPin(wps_config->vap_index, wps_config->wps_pin);
#endif
}

static void process_wps_cancel_event(void *data)
{
#ifdef FEATURE_SUPPORT_WPS
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d data is NULL\n",__func__, __LINE__);
        return;
    }

    INT vap_index = *(INT*)data;

    wifi_util_info_print(WIFI_CTRL,"%s:%d wps pbc cancel vap index = %d\n",
        __func__, __LINE__, vap_index);
    wifi_hal_setApWpsCancel(vap_index);
#endif
}

void marker_list_config_event(char *data, marker_list_t list_type)
{
    int ret = -1;
    bool is_config_changed = false;
    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();

    if (g_wifidb == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d wifi mgr object is NULL\n",__func__, __LINE__);
        return;
    }

    switch (list_type) {

        case normalized_rssi_list_type:
            if (strcmp(global_param->normalized_rssi_list, data) != 0) {
                strncpy(global_param->normalized_rssi_list, data, sizeof(global_param->normalized_rssi_list)-1);
                global_param->normalized_rssi_list[sizeof(global_param->normalized_rssi_list)-1]= '\0';
                is_config_changed = true;
            }
            break;

        case snr_list_type:
            if (strcmp(global_param->snr_list, data) != 0 ) {
                strncpy(global_param->snr_list, data, sizeof(global_param->snr_list)-1);
                global_param->snr_list[sizeof(global_param->snr_list)-1]= '\0';
                is_config_changed = true;
            }
            break;

        case cli_stat_list_type:
            if (strcmp(global_param->cli_stat_list, data) != 0) {
                strncpy(global_param->cli_stat_list, data, sizeof(global_param->cli_stat_list)-1);
                global_param->cli_stat_list[sizeof(global_param->cli_stat_list)-1]= '\0';
                is_config_changed = true;
            }
            break;

        case txrx_rate_list_type:
            if (strcmp(global_param->txrx_rate_list, data) != 0) {
                strncpy(global_param->txrx_rate_list, data, sizeof(global_param->txrx_rate_list)-1);
                global_param->txrx_rate_list[sizeof(global_param->txrx_rate_list)-1]= '\0';
                is_config_changed = true;
            }
            break;

        default:
            wifi_util_info_print(WIFI_CTRL,"[%s]: List type not supported this event %x\r\n",__FUNCTION__, list_type);
            return;
    }

    wifi_util_info_print(WIFI_CTRL,"[%s]:%d List type :%d value:%s is_config_changed:%d\r\n",__func__, __LINE__, list_type, data, is_config_changed);
    if (is_config_changed == true) {
        g_wifidb->ctrl.webconfig_state |= ctrl_webconfig_state_wifi_config_cfg_rsp_pending;

        ret = update_wifi_global_config(global_param);
        if ( ret < 0 ) {
            wifi_util_dbg_print(WIFI_CTRL,"[%s]: Failed to update global config for type  %x\r\n",__FUNCTION__, list_type);
        }
    }
    return;

}

static void update_wifi_vap_config(int device_mode)
{
    unsigned int vap_index;
    wifi_vap_info_t *vap_info;
    rdk_wifi_vap_info_t *rdk_vap_info;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    if (device_mode != rdk_dev_mode_type_ext) {
        return;
    }

    for (unsigned int i = 0; i < getTotalNumberVAPs(); i++) {
        vap_index = VAP_INDEX(wifi_mgr->hal_cap, i);
        vap_info = get_wifidb_vap_parameters(vap_index);
        if (vap_info == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get vap info for index %d\n",
                __func__, __LINE__, vap_index);
            return;
        }
        rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
        if (rdk_vap_info == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get rdk vap info for index %d\n",
                __func__, __LINE__, vap_index);
            return;
        }

        // Enable STA interfaces in extender mode
        if (isVapSTAMesh(vap_index)) {
            rdk_vap_info->exists = true;
            get_wifidb_obj()->desc.update_wifi_vap_info_fn(vap_info->vap_name, vap_info, rdk_vap_info);
        }
    }
}

void process_device_mode_command_event(int device_mode)
{
    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_CTRL, "%s:%d: device mode changed: %d\n", __func__, __LINE__,
        device_mode);

    ctrl->network_mode = device_mode;

    if (global_param->device_network_mode != device_mode) {
        global_param->device_network_mode = device_mode;
        update_wifi_global_config(global_param);
        update_wifi_vap_config(device_mode);
        if (device_mode == rdk_dev_mode_type_ext) {
            if (is_sta_enabled() == true) {
                wifi_util_info_print(WIFI_CTRL, "%s:%d: start mesh sta\n", __func__, __LINE__);
                start_extender_vaps(WIFI_ALL_RADIO_INDICES);
            } else {
                wifi_util_info_print(WIFI_CTRL, "%s:%d: mesh sta disabled\n", __func__, __LINE__);
            }
        } else if (device_mode == rdk_dev_mode_type_gw) {
            if (is_sta_enabled() == false) {
                wifi_util_info_print(WIFI_CTRL, "%s:%d: stop mesh sta\n", __func__, __LINE__);
                stop_extender_vaps(WIFI_ALL_RADIO_INDICES);
            }
            wifi_util_info_print(WIFI_CTRL, "%s:%d: start gw vaps\n", __func__, __LINE__);
            start_gateway_vaps(WIFI_ALL_RADIO_INDICES);
        }
    }
    ctrl->webconfig_state |= ctrl_webconfig_state_vap_all_cfg_rsp_pending;
}

void process_sta_trigger_disconnection(unsigned int disconnection_type)
{
    wifi_mgr_t *g_wifidb;
    wifi_ctrl_t *ctrl;
    vap_svc_t *ext_svc;
    g_wifidb = get_wifimgr_obj();

    if (g_wifidb != NULL) {
        ctrl = &g_wifidb->ctrl;
        if (ctrl->network_mode == rdk_dev_mode_type_ext) {
            ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
            if (ext_svc != NULL) {
                ext_svc->event_fn(ext_svc, wifi_event_type_command,
                    wifi_event_type_trigger_disconnection, vap_svc_event_none, &disconnection_type);
            } else {
                wifi_util_error_print(WIFI_CTRL, "%s:%d NULL svc Pointer not triggering disconnection\r\n", __func__, __LINE__);
            }
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer not triggering disconnection\r\n", __func__, __LINE__);
    }
    return;
}

static int reset_radio_operating_parameters(void *args)
{
    wifi_radio_operationParam_t *radio_params = NULL;
    wifi_ctrl_t *ctrl;
    int ret;
    unsigned int radio_index;

    if (args == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio_index = *(unsigned int *) args;
    ctrl =  &((wifi_mgr_t *)get_wifimgr_obj())->ctrl;

    radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);
    if (radio_params == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d: wrong index for radio map: %d\n",__FUNCTION__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    ret = wifi_hal_setRadioOperatingParameters(radio_index, radio_params);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d: wifi radio parameter set failure: radio_index:%d\n",
            __FUNCTION__, __LINE__, radio_index);
        ctrl->reset_params_retry_counter[radio_index]++;
        if (ctrl->reset_params_retry_counter[radio_index] >= MAX_RESET_RADIO_PARAMS_RETRY_COUNTER) {
            ctrl->reset_params_retry_counter[radio_index] = 0;
        } else {
            scheduler_add_timer_task(ctrl->sched, FALSE, NULL, reset_radio_operating_parameters,
                args, 100, 1, FALSE);
        }
    } else {
        wifi_util_info_print(WIFI_CTRL,"%s:%d: wifi radio parameter set success: radio_index:%d\n",
            __FUNCTION__, __LINE__, radio_index);
        ctrl->reset_params_retry_counter[radio_index] = 0;
    }

    return RETURN_OK;
}

int update_db_radar_detected(char *radar_detected_ch_time)
{
    wifi_radio_operationParam_t *radio_params = NULL;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(RADIO_INDEX_DFS);

    char *pos_ch_radar_time = strstr(radio_params->radarDetected, radar_detected_ch_time);
    size_t len_ch_radar_time = strlen(radar_detected_ch_time);
    if( strlen(radio_params->radarDetected) == len_ch_radar_time ){
        strncpy(radio_params->radarDetected, " ", sizeof(radio_params->radarDetected));
        wifi_util_info_print(WIFI_CTRL,"%s:%d radarDetected:%s. \n",__FUNCTION__, __LINE__, radio_params->radarDetected);
        return RETURN_OK;
    }

    if(pos_ch_radar_time) {
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        memmove(radio_params->radarDetected, pos_ch_radar_time + len_ch_radar_time + 1, strlen(radio_params->radarDetected) + 1);
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
    wifi_util_info_print(WIFI_CTRL,"%s: radarDetected:%s. \n",__FUNCTION__, radio_params->radarDetected);

    if(strlen(radio_params->radarDetected) == 0) {
        strncpy(radio_params->radarDetected, " ", sizeof(radio_params->radarDetected));
    }

    return RETURN_OK;
}

int dfs_nop_start_timer(void *args)
{
    wifi_channel_change_event_t radio_channel_param;
    wifi_radio_operationParam_t *radio_params = NULL;

    radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(RADIO_INDEX_DFS);
    memset(&radio_channel_param, 0, sizeof(radio_channel_param));

    char *str_r, *radar_detected_ch_time;
    char radarDetected_temp[128];
    strncpy(radarDetected_temp, radio_params->radarDetected, sizeof(radarDetected_temp));

    radarDetected_temp[sizeof(radarDetected_temp) - 1] = '\0';

    if( !strcmp(radarDetected_temp, " ") || radarDetected_temp == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d No radar detected \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radar_detected_ch_time = strtok_r(radarDetected_temp, ";", &str_r);
    while(radar_detected_ch_time != NULL) {
        int i = 0; long long int radar_detected_time = 0;
        unsigned int dfs_radar_channel, dfs_timer_secs = 0;
        wifi_channelBandwidth_t dfs_radar_ch_bw = 0;
        time_t time_now = time(NULL);
        wifi_radio_feature_param_t *radio_feat = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map(RADIO_INDEX_DFS);
        if (radio_feat == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s: wrong index for radio map: %d\n",__FUNCTION__, RADIO_INDEX_DFS);
            return RETURN_ERR;
        }

        dfs_radar_channel = atoi(radar_detected_ch_time);
        while(radar_detected_ch_time[i] != ',') {
            if(radar_detected_ch_time[i] == '\0') {
                wifi_util_error_print(WIFI_CTRL,"%s:%d Invalid radarDetected:%s, Removing entry\n",__FUNCTION__, __LINE__, radio_params->radarDetected);
                update_db_radar_detected(radar_detected_ch_time);
                update_wifi_radio_config(RADIO_INDEX_DFS, radio_params, radio_feat);
                return RETURN_ERR;
            }
            i++;
        }
        dfs_radar_ch_bw = (wifi_channelBandwidth_t) atoi(&radar_detected_ch_time[++i]);
        while(radar_detected_ch_time[i] != ',') {
            if(radar_detected_ch_time[i] == '\0') {
                wifi_util_error_print(WIFI_CTRL,"%s: Invalid radarDetected:%s, Removing entry\n",__FUNCTION__, radio_params->radarDetected);
                update_db_radar_detected(radar_detected_ch_time);
                update_wifi_radio_config(RADIO_INDEX_DFS, radio_params, radio_feat);
                return RETURN_ERR;
            }
            i++;
        }
        radar_detected_time = atol(&radar_detected_ch_time[++i]);

        radio_channel_param.radioIndex = RADIO_INDEX_DFS;
        radio_channel_param.event = WIFI_EVENT_DFS_RADAR_DETECTED;
        radio_channel_param.sub_event = WIFI_EVENT_RADAR_DETECTED;
        radio_channel_param.channel = dfs_radar_channel;
        radio_channel_param.channelWidth = dfs_radar_ch_bw;
        radio_channel_param.op_class = radio_params->operatingClass;

        dfs_timer_secs = ((time_now - radar_detected_time)<(radio_params->DFSTimer * 60) && (time_now > radar_detected_time)) ? ( (radio_params->DFSTimer * 60) - (time_now - radar_detected_time)) : 0;
        if(dfs_timer_secs == 0) {
            update_db_radar_detected(radar_detected_ch_time);
            update_wifi_radio_config(RADIO_INDEX_DFS, radio_params, radio_feat);
            wifi_util_dbg_print(WIFI_CTRL, "%s Radar event time-out for dfs_radar_channel:%d \n", __FUNCTION__, dfs_radar_channel);
        } else {
            bool is_nop_start_reboot = 1;
            wifi_util_dbg_print(WIFI_CTRL, "%s dfs_radar_channel:%d bw:%d radar_detected_time:%lld radar_detected_ch_time[%d]:%c dfs_timer_secs:%d \n", __FUNCTION__, dfs_radar_channel, dfs_radar_ch_bw, radar_detected_time, i, radar_detected_ch_time[i], dfs_timer_secs);
            process_channel_change_event(&radio_channel_param, is_nop_start_reboot, dfs_timer_secs);
        }

        radar_detected_ch_time = strtok_r(NULL, ";", &str_r);
    }

    if(strlen(radio_params->radarDetected) == 0) {
        strncpy(radio_params->radarDetected, " ", sizeof(radio_params->radarDetected));
    }

    return TIMER_TASK_COMPLETE;
}

int dfs_nop_finish_timer(void *args)
{
    wifi_channel_change_event_t radio_channel_param;
    wifi_radio_operationParam_t *radio_params = NULL;
    char *str_re, *radar_detected_ch_time;
    char radarDetected_temp[128];
    unsigned int ch_temp;

    if (args == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    unsigned int nop_fin_dfs_ch = *(unsigned int *) args;
    radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(RADIO_INDEX_DFS);
    memset(&radio_channel_param, 0, sizeof(radio_channel_param));
    strncpy(radarDetected_temp, radio_params->radarDetected, sizeof(radarDetected_temp));

    radarDetected_temp[sizeof(radarDetected_temp) - 1] = '\0';

    radar_detected_ch_time = strtok_r(radarDetected_temp, ";", &str_re);
    while(radar_detected_ch_time != NULL) {
        ch_temp = atoi(radar_detected_ch_time);
        if(ch_temp == nop_fin_dfs_ch) {
            wifi_channelBandwidth_t dfs_radar_ch_bw = 0;
            int i = 0;
            bool is_nop_start_reboot = 0; unsigned int dfs_timer_secs = 0;

            while(radar_detected_ch_time[i] != ',' && radar_detected_ch_time[i] != '\0') i++;
            dfs_radar_ch_bw = (radar_detected_ch_time[i] != '\0') ? (wifi_channelBandwidth_t) atoi(&radar_detected_ch_time[++i]) : radio_params->channelWidth;

            radio_channel_param.radioIndex = RADIO_INDEX_DFS;
            radio_channel_param.event = WIFI_EVENT_DFS_RADAR_DETECTED;
            radio_channel_param.sub_event = WIFI_EVENT_RADAR_NOP_FINISHED;
            radio_channel_param.channel = nop_fin_dfs_ch;
            radio_channel_param.channelWidth = dfs_radar_ch_bw;
            radio_channel_param.op_class = radio_params->operatingClass;

            wifi_util_dbg_print(WIFI_CTRL, "%s Nop_Finish for channel:%d BW:0x%x \n", __func__, nop_fin_dfs_ch, dfs_radar_ch_bw);
            process_channel_change_event(&radio_channel_param, is_nop_start_reboot, dfs_timer_secs);

            break;
        }
        radar_detected_ch_time = strtok_r(NULL, ";", &str_re);
    }

    return TIMER_TASK_COMPLETE;
}

void process_channel_change_event(wifi_channel_change_event_t *ch_chg, bool is_nop_start_reboot, unsigned int dfs_timer_secs)
{
    wifi_radio_operationParam_t *radio_params = NULL;
    wifi_radio_feature_param_t *radio_feat = NULL;
    wifi_radio_operationParam_t temp_radio_params;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();
    wifi_ctrl_t *ctrl;
    vap_svc_t *ext_svc;
    vap_svc_t  *pub_svc = NULL;
    int ret = 0;
    wifi_monitor_data_t *data = NULL;

    radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(ch_chg->radioIndex);
    if (radio_params == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s: wrong index for radio map: %d\n",__FUNCTION__, ch_chg->radioIndex);
        return;
    }

    radio_feat = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map(ch_chg->radioIndex);
    if (radio_feat == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s: wrong index for radio map: %d\n",__FUNCTION__, ch_chg->radioIndex);
        return;
    }

    if (ch_chg->event == WIFI_EVENT_CHANNELS_CHANGED) {
        memset(&temp_radio_params, 0, sizeof(wifi_radio_operationParam_t));
        temp_radio_params.band = radio_params->band;
        temp_radio_params.channel = ch_chg->channel;
        temp_radio_params.channelWidth = ch_chg->channelWidth;
        temp_radio_params.DfsEnabled = radio_params->DfsEnabled;
        // Channel change completed flag
        g_wifidb->channel_change_in_progress[ch_chg->radioIndex] = false;
        wifi_util_dbg_print(WIFI_CTRL,
            "%s:%d Channel change is completed, setting channel change progress to false\n",
            __func__, __LINE__);
    }

    ctrl = &g_wifidb->ctrl;
    if ((ch_chg->event == WIFI_EVENT_CHANNELS_CHANGED) && (ctrl->network_mode == rdk_dev_mode_type_ext)) {

        ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
        if (wifi_radio_operationParam_validation(&g_wifidb->hal_cap, &temp_radio_params) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d: channel: %d bw: %d on radio: %d could not be set\n",
                __FUNCTION__, __LINE__, ch_chg->channel, ch_chg->channelWidth, ch_chg->radioIndex);
            return;
        }
        ext_svc->event_fn(ext_svc, wifi_event_type_hal_ind, wifi_event_hal_channel_change, vap_svc_event_none, ch_chg);
    }

    if (radio_params->band == WIFI_FREQUENCY_6_BAND ) {
        pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);
        wifi_util_info_print(WIFI_CTRL,"6G radio channel changed update rrm\n");
        if (pub_svc->event_fn != NULL) {
            pub_svc->event_fn(pub_svc, wifi_event_type_command, wifi_event_type_xfinity_rrm,
                vap_svc_event_none,NULL);
        }
    }

    wifi_radio_capabilities_t radio_capab = g_wifidb->hal_cap.wifi_prop.radiocap[ch_chg->radioIndex];
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d channel change on radio:%d old channel:%d new channel:%d channel change event type:%d \
                            radar_event_type %d op_class:%d\n", __func__, __LINE__, ch_chg->radioIndex, radio_params->channel,
                            ch_chg->channel, ch_chg->event, ch_chg->sub_event, ch_chg->op_class);

    stop_wifi_sched_timer(ch_chg->radioIndex, ctrl, wifi_csa_sched);
    stop_wifi_sched_timer(ch_chg->radioIndex, ctrl, wifi_acs_sched);

    if ((ch_chg->event == WIFI_EVENT_CHANNELS_CHANGED) && ((radio_params->channel == ch_chg->channel)
                && (radio_params->channelWidth == ch_chg->channelWidth))) {
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d channel change: old channelWidth:%d new channelWidth:%d\r\n",
                            __func__, __LINE__, radio_params->channelWidth, ch_chg->channelWidth);

    if (ch_chg->event == WIFI_EVENT_CHANNELS_CHANGED) {
        if (wifi_radio_operationParam_validation(&g_wifidb->hal_cap, &temp_radio_params) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d: received invalid channel: %d bw: %d from driver on radio %d\n",
                __FUNCTION__, __LINE__, ch_chg->channel, ch_chg->channelWidth, ch_chg->radioIndex);
            ret = wifi_hal_setRadioOperatingParameters(ch_chg->radioIndex, radio_params);
            if (ret != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d: wifi radio parameter set failure: radio_index:%d\n",
                    __FUNCTION__, __LINE__, ch_chg->radioIndex);
                scheduler_add_timer_task(ctrl->sched, FALSE, NULL, reset_radio_operating_parameters,
                        &g_wifidb->hal_cap.wifi_prop.radiocap[ch_chg->radioIndex].index, 100, 1, FALSE);
            } else {
                wifi_util_info_print(WIFI_CTRL,"%s:%d: wifi radio parameter set success: radio_index:%d\n",
                    __FUNCTION__, __LINE__, ch_chg->radioIndex);
            }
            return;
        }
        pthread_mutex_lock(&g_wifidb->data_cache_lock);
        radio_params->channel = ch_chg->channel;
        radio_params->channelWidth = ch_chg->channelWidth;
        radio_params->operatingClass = ch_chg->op_class;
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    }
    else if ( (ch_chg->event == WIFI_EVENT_DFS_RADAR_DETECTED) && (radio_params->band == WIFI_FREQUENCY_5_BAND || radio_params->band == WIFI_FREQUENCY_5L_BAND || radio_params->band == WIFI_FREQUENCY_5H_BAND) ) {
        UINT channelsInBlock = 1;
        UINT inputChannelBlock = 0;
        UINT firstChannelInBand = 36;
        //UINT lastChannelInRadar = 144;
        int blockStartChannel = 0;
        //UINT blockEndChannel = 0;
        UINT channelGap = 4;
        wifi_channelState_t chan_state = CHAN_STATE_DFS_NOP_FINISHED;
        rdk_wifi_radio_t *l_radio = NULL;
        time_t time_now = time(NULL);
        l_radio = find_radio_config_by_index(ch_chg->radioIndex);

        if (l_radio == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d radio strucutre is not present for radio %d\n",
                                __FUNCTION__, __LINE__,  ch_chg->radioIndex);
            return;
        }

        if( ((ch_chg->channel >= 36 && ch_chg->channel < 52) && (ch_chg->channelWidth != WIFI_CHANNELBANDWIDTH_160MHZ )) || (ch_chg->channel > 144 && ch_chg->channel <= 165) ) {
            wifi_util_error_print(WIFI_CTRL,"%s: Wrong radar in radio_index:%d chan:%u \n",__FUNCTION__, ch_chg->radioIndex, ch_chg->channel);
            return ;
        }

        switch (ch_chg->sub_event)
        {
            case WIFI_EVENT_RADAR_DETECTED :
                chan_state = CHAN_STATE_DFS_NOP_START;
                if((l_radio->radarInfo.timestamp != 0) && ((time_now - l_radio->radarInfo.timestamp) <= 2) && ((unsigned int)l_radio->radarInfo.last_channel == ch_chg->channel) ) {
                    /* Ignore the duplicate radar events for the same channel triggered within 2 seconds */
                    break;
                }
                unsigned int channel_index = 0;
                l_radio->radarInfo.last_channel = ch_chg->channel;
                l_radio->radarInfo.num_detected++;
                l_radio->radarInfo.timestamp = (dfs_timer_secs == 0) ? (long int) time_now : (long int) (time_now - (radio_params->DFSTimer - dfs_timer_secs));

                if(!is_nop_start_reboot) {
                    pthread_mutex_lock(&g_wifidb->data_cache_lock);
                    if( !strcmp(radio_params->radarDetected, " ") ) {
                        snprintf(radio_params->radarDetected, sizeof(radio_params->radarDetected), "%d,%x,%lld", l_radio->radarInfo.last_channel, ch_chg->channelWidth, l_radio->radarInfo.timestamp);
                    } else {
                        int len = strlen(radio_params->radarDetected);
                        snprintf(radio_params->radarDetected + len, sizeof(radio_params->radarDetected) - len, ";%d,%x,%lld", l_radio->radarInfo.last_channel, ch_chg->channelWidth, l_radio->radarInfo.timestamp);
                    }
                    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
                }

                for(channel_index = 0; channel_index < sizeof(temp_ch_list_5g)/sizeof(int); channel_index++) {
                    if(temp_ch_list_5g[channel_index] == ch_chg->channel && !is_nop_start_reboot) {
                        scheduler_add_timer_task(ctrl->sched, FALSE, NULL, dfs_nop_finish_timer, &temp_ch_list_5g[channel_index], radio_params->DFSTimer * (1000 * 60), 1, FALSE);
                        wifi_util_dbg_print(WIFI_CTRL,"%s: Scheduled nop_finish DFSTimer %d for chan:%d \n",__FUNCTION__, radio_params->DFSTimer, ch_chg->channel);
                        break;
                    } else if(temp_ch_list_5g[channel_index] == ch_chg->channel && is_nop_start_reboot) {
                        scheduler_add_timer_task(ctrl->sched, FALSE, NULL, dfs_nop_finish_timer, &temp_ch_list_5g[channel_index], (dfs_timer_secs * 1000), 1, FALSE);
                        wifi_util_dbg_print(WIFI_CTRL,"%s: Scheduled nop_finish dfs_timer_secs %d for chan:%d \n",__FUNCTION__, dfs_timer_secs, ch_chg->channel);
                        break;
                    }
                }

                break;
            case WIFI_EVENT_RADAR_CAC_FINISHED :
                chan_state = CHAN_STATE_DFS_CAC_COMPLETED;
                break;
            case WIFI_EVENT_RADAR_CAC_ABORTED :
                chan_state = CHAN_STATE_DFS_CAC_COMPLETED;
                break;
            case WIFI_EVENT_RADAR_NOP_FINISHED :
                if( (unsigned int)l_radio->radarInfo.last_channel == ch_chg->channel && (time_now - l_radio->radarInfo.timestamp >= 1800)) {
                    l_radio->radarInfo.last_channel = 0;
                    l_radio->radarInfo.num_detected = 0;
                    l_radio->radarInfo.timestamp = 0;
                } else if (l_radio->radarInfo.num_detected > 1){
                    l_radio->radarInfo.num_detected--;
                }
                if (strcmp(radio_params->radarDetected, " ")) {
                    char *str_re, *radar_detected_ch_time;
                    char radarDetected_temp[128];
                    unsigned int ch_temp;

                    strncpy(radarDetected_temp, radio_params->radarDetected, sizeof(radarDetected_temp));
                    radarDetected_temp[sizeof(radarDetected_temp) - 1] = '\0';

                    radar_detected_ch_time = strtok_r(radarDetected_temp, ";", &str_re);
                    while(radar_detected_ch_time != NULL) {
                        ch_temp = atoi(radar_detected_ch_time);
                        if(ch_temp == ch_chg->channel) {
                            if(update_db_radar_detected(radar_detected_ch_time) != RETURN_OK) {
                                wifi_util_error_print(WIFI_CTRL, "%s update_db_radar_detected returned error for channel:%d \n", __FUNCTION__, ch_chg->channel);
                            }
                            break;
                        }
                        radar_detected_ch_time = strtok_r(NULL, ";", &str_re);
                    }
                }
                chan_state = CHAN_STATE_DFS_NOP_FINISHED;
                break;
            case WIFI_EVENT_RADAR_PRE_CAC_EXPIRED :
                chan_state = CHAN_STATE_DFS_NOP_FINISHED;
                break;
            case WIFI_EVENT_RADAR_CAC_STARTED :
                chan_state = CHAN_STATE_DFS_CAC_START;
                break;
        }

        if (ch_chg->sub_event == WIFI_EVENT_RADAR_DETECTED) {
            wifi_util_info_print(WIFI_CTRL,"%s:%d DFS RADAR_DETECTED on ch %d and will not be available for 30 mins\n",
                                 __func__, __LINE__, ch_chg->channel);
        } else if (ch_chg->sub_event == WIFI_EVENT_RADAR_NOP_FINISHED) {
            wifi_util_info_print(WIFI_CTRL,"%s:%d DFS Blocked RADAR channel %d is now ready for use\n",
                                 __func__, __LINE__, ch_chg->channel);
        }

        switch (ch_chg->channelWidth)
        {
            case WIFI_CHANNELBANDWIDTH_20MHZ:
                channelsInBlock = 1;
                break;
            case WIFI_CHANNELBANDWIDTH_40MHZ:
                channelsInBlock = 2;
                break;
            case WIFI_CHANNELBANDWIDTH_80MHZ:
                channelsInBlock = 4;
                break;
            case WIFI_CHANNELBANDWIDTH_160MHZ:
                channelsInBlock = 8;
                break;
            case WIFI_CHANNELBANDWIDTH_80_80MHZ:
            default:
                wifi_util_error_print(WIFI_CTRL,"%s: Invaliid BW for radio %d\n",__FUNCTION__, ch_chg->radioIndex);
                break;
        }
        inputChannelBlock = (ch_chg->channel - firstChannelInBand)/(channelGap*channelsInBlock);
        blockStartChannel = firstChannelInBand + (inputChannelBlock*channelGap*channelsInBlock);
        //blockEndChannel = firstChannelInBand + (inputChannelBlock*channelGap*channelsInBlock) + (channelGap*(channelsInBlock-1));
        if ((blockStartChannel < 52) && (ch_chg->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ)) {
            blockStartChannel = 52;
            channelsInBlock -= 4;
        }

        for (int i=0; i<radio_capab.channel_list[0].num_channels; i++)
        {
            if ( blockStartChannel == radio_capab.channel_list[0].channels_list[i] )
            {
                for (UINT j = i; j < i+channelsInBlock; j++)
                {
                    radio_params->channel_map[j].ch_state = chan_state;
                }
                break;
            }
        }
    } else {
        wifi_util_error_print(WIFI_CTRL,"%s: Invalid event for radio %d\n",__FUNCTION__, ch_chg->radioIndex);
        return;
    }
    data = (wifi_monitor_data_t *)calloc(1, sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Memory allocation failed\n", __func__, __LINE__);
    } else {
        data->u.channel_status_map.radio_index = ch_chg->radioIndex;
        memcpy(data->u.channel_status_map.channel_map, radio_params->channel_map,
            sizeof(data->u.channel_status_map.channel_map));
        if (push_event_to_monitor_queue(data, wifi_event_monitor_channel_status, NULL) !=
            RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,
                "%s:%d: Failed to push channel status map to monitor queue\n", __func__, __LINE__);
        }
        free(data);
    }
    g_wifidb->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
    start_wifi_sched_timer(ch_chg->radioIndex, ctrl, wifi_radio_sched);
    update_wifi_radio_config(ch_chg->radioIndex, radio_params, radio_feat);
}

#define MAX_NEIGHBOURS 250

int get_neighbor_scan_results(void *arg)
{
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    wifi_monitor_data_t *data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    wifi_event_route_t route;

    //Stop neighbor scan 
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        snprintf(monitor_param->neighbor_scan_cfg.DiagnosticsState, sizeof(monitor_param->neighbor_scan_cfg.DiagnosticsState), "Completed" );
        return TIMER_TASK_ERROR;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));

    data->u.mon_stats_config.req_state = mon_stats_request_state_stop;
    //request from core thread
    data->u.mon_stats_config.inst = wifi_app_inst_core;
    //dummy value since it will be cancelled after first result
    data->u.mon_stats_config.interval_ms = 60*60*1000;
    data->u.mon_stats_config.data_type = mon_stats_type_neighbor_stats;
    data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_FULL;
    data->u.mon_stats_config.args.app_info = 0;

    memset(&route, 0, sizeof(wifi_event_route_t));
    route.dst = wifi_sub_component_mon;
    route.u.inst_bit_map = 0;
    /* Request to get channel utilization */
    for (UINT radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        data->u.mon_stats_config.args.radio_index = radioIndex;
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d pushing the event to collect neighborrs on radio %d\n", __func__, __LINE__, radioIndex);
        push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
    }
    free(data);

    monitor_param->neighbor_scan_cfg.ResultCount = 0;
    for(UINT rIdx = 0; rIdx < getNumberRadios(); rIdx++)
    {
        monitor_param->neighbor_scan_cfg.ResultCount += monitor_param->neighbor_scan_cfg.resultCountPerRadio[rIdx];
    }
    monitor_param->neighbor_scan_cfg.ResultCount = (monitor_param->neighbor_scan_cfg.ResultCount > MAX_NEIGHBOURS) ? MAX_NEIGHBOURS : monitor_param->neighbor_scan_cfg.ResultCount;
    snprintf(monitor_param->neighbor_scan_cfg.DiagnosticsState, sizeof(monitor_param->neighbor_scan_cfg.DiagnosticsState), "Completed" );
    return TIMER_TASK_COMPLETE;
}

void process_acs_keep_out_channels_event(const char* json_data)
{
    unsigned int numOfRadios = getNumberRadios();
    webconfig_subdoc_data_t data;
    wifi_radio_operationParam_t *radio_oper = NULL;
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    decode_acs_keep_out_json(json_data,numOfRadios,&data);
    for(unsigned int i=0;i<numOfRadios;i++)
    {
        radio_oper = (wifi_radio_operationParam_t *)get_wifidb_radio_map(i);
        if(radio_oper)
        {
            radio_oper->acs_keep_out_reset = data.u.decoded.radios[i].oper.acs_keep_out_reset;
            memcpy(radio_oper->channels_per_bandwidth, data.u.decoded.radios[i].oper.channels_per_bandwidth,sizeof(data.u.decoded.radios[i].oper.channels_per_bandwidth));
            if(radio_oper->acs_keep_out_reset)
            {
                wifi_hal_set_acs_keep_out_chans(NULL,i);
                radio_oper->acs_keep_out_reset = false;
            }
            else
            {
                wifi_hal_set_acs_keep_out_chans(radio_oper,i);
            }
        }
    }
}

void process_neighbor_scan_command_event()
{
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_event_route_t route;

    if(strcmp(monitor_param->neighbor_scan_cfg.DiagnosticsState, "Requested") == 0) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Scan already in Progress!!!\n", __func__, __LINE__);
        return;
    }
    
    get_stubs_descriptor()->strcpy_fn(monitor_param->neighbor_scan_cfg.DiagnosticsState, sizeof(monitor_param->neighbor_scan_cfg.DiagnosticsState), "Requested");

    wifi_monitor_data_t *data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));
    data->u.mon_stats_config.req_state = mon_stats_request_state_start;
    //request from core thread
    data->u.mon_stats_config.inst = wifi_app_inst_core;
    //dummy value since it will be cancelled after first result
    data->u.mon_stats_config.interval_ms = 60*60*1000;
    data->u.mon_stats_config.data_type = mon_stats_type_neighbor_stats;
    data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_FULL;
    data->u.mon_stats_config.args.app_info = 0;
    data->u.mon_stats_config.start_immediately = true;


    memset(&route, 0, sizeof(wifi_event_route_t));
    route.dst = wifi_sub_component_mon;
    route.u.inst_bit_map = 0;
    /* Request to get channel utilization */
    for (UINT radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        data->u.mon_stats_config.args.radio_index = radioIndex;
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d pushing the event to collect neighbor on radio %d\n", __func__, __LINE__, radioIndex);
        push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
    }
    free(data);
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, get_neighbor_scan_results, NULL,
                    NEIGHBOR_SCAN_RESULT_INTERVAL, 1, FALSE);
}

int wifidb_vap_status_update(bool status)
{
    wifi_vap_name_t backhauls[MAX_NUM_RADIOS];
    int count;
    wifi_vap_info_t vap_config;
    rdk_wifi_vap_info_t rdk_vap_config;
    memset(&vap_config, 0, sizeof(vap_config));
    memset(&rdk_vap_config, 0, sizeof(rdk_vap_config));

    /* get a list of mesh backhaul names of all radios */
    count = get_list_of_mesh_backhaul(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, sizeof(backhauls)/sizeof(wifi_vap_name_t), backhauls);

    for (int i = 0; i < count; i++) {
        if (get_wifidb_obj()->desc.get_wifi_vpa_info_fn(&backhauls[i][0], &vap_config, &rdk_vap_config) == RETURN_OK) {
            vap_config.u.bss_info.enabled = status;
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi mesh backhaul status save:%d\n", __func__, __LINE__, status);
            update_wifi_vap_info(&backhauls[i][0], &vap_config, &rdk_vap_config);
        }
    }

    return RETURN_OK;
}

void process_mesh_status_command(bool mesh_enable_status)
{
    vap_svc_t *mesh_gw_svc;
    unsigned int value;
    wifi_ctrl_t *ctrl;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    mesh_gw_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_gw);

    // start mesh gateway if mesh is enabled
    value = get_wifi_mesh_vap_enable_status();
    if ((value != true) && (mesh_enable_status == true)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Mesh_service start\n", __func__, __LINE__);
        mesh_gw_svc->start_fn(mesh_gw_svc, WIFI_ALL_RADIO_INDICES, NULL);
        wifidb_vap_status_update(mesh_enable_status);
        ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
    } else if ((value == true) && (mesh_enable_status == false)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Mesh_service stop\n", __func__, __LINE__);
        mesh_gw_svc->stop_fn(mesh_gw_svc, WIFI_ALL_RADIO_INDICES, NULL);
        wifidb_vap_status_update(mesh_enable_status);
        ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
    }
}

static void process_eth_bh_status_command(bool eth_bh_status)
{
    bool was_enabled, is_enabled;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (ctrl->eth_bh_status == eth_bh_status) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: eth bh status not changed, ignore\n", __func__,
            __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d: eth bh status changed: %d\n", __func__, __LINE__,
        eth_bh_status);

    was_enabled = is_sta_enabled();
    ctrl->eth_bh_status = eth_bh_status;
    is_enabled = is_sta_enabled();

    if (was_enabled == is_enabled) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: no sta state change, ignore\n", __func__, __LINE__);
        return;
    }

    if (is_enabled == true) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: start mesh sta\n", __func__, __LINE__);
        start_extender_vaps(WIFI_ALL_RADIO_INDICES);
    } else {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: stop mesh sta\n", __func__, __LINE__);
        stop_extender_vaps(WIFI_ALL_RADIO_INDICES);
    }

    ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending;
}


#define ASSOCIATED_DEVICE_DIAG_INTERVAL_MS 5000 // 5 seconds

static void process_monitor_init_command(void)
{
    //request client diagnostic collection every 5 seconds
    //required by rapid reconnect detection
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    unsigned int radio_index;
    unsigned int vapArrayIndex = 0;
    wifi_event_route_t route;

    wifi_monitor_data_t *data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d data allocation failed. Error: Could not start client diag stats\r\n", __func__, __LINE__);
        return;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));
    data->u.mon_stats_config.req_state = mon_stats_request_state_start;
    //request from core thread
    data->u.mon_stats_config.inst = wifi_app_inst_core;
    data->u.mon_stats_config.interval_ms = ASSOCIATED_DEVICE_DIAG_INTERVAL_MS;
    data->u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;
    data->u.mon_stats_config.args.app_info = 0;
    data->u.mon_stats_config.start_immediately = false;
    
    memset(&route, 0, sizeof(wifi_event_route_t));
    route.dst = wifi_sub_component_mon;
    route.u.inst_bit_map = 0;

    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        //for each vap push the event to monitor queue
        for (vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(radio_index); vapArrayIndex++) {
            data->u.mon_stats_config.args.vap_index = wifi_mgr->radio_config[radio_index].vaps.rdk_vap_array[vapArrayIndex].vap_index;
            if (!isVapSTAMesh(data->u.mon_stats_config.args.vap_index)) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d pushing the event to collect client diag on vap %d\n", __func__, __LINE__, data->u.mon_stats_config.args.vap_index);    
                push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
            }
        }
    }
    free(data);
}

void process_send_action_frame_command(void *data, unsigned int len)
{
    action_frame_params_t *params;

    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }

    if (len < sizeof(action_frame_params_t) + 1) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid parameter size \r\n", __func__, __LINE__);
        return;
    }

    params = (action_frame_params_t *)data;

    if (wifi_sendActionFrameExt(params->ap_index, params->dest_addr, params->frequency,
            params->wait_time_ms, params->frame_data, params->frame_len)) {

        wifi_util_error_print(WIFI_CTRL,
            "%s:%d HAL sendActionFrame method failed (ap_index:%d, dest_addr:" MAC_FMT
            ", frequency:%d, wait_time_ms:%d)\n",
            __func__, __LINE__, params->ap_index, MAC_ARG(params->dest_addr), params->frequency,
            params->wait_time_ms);
        return;
    }

    return;
}

void process_rsn_override_rfc(bool type)
{
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    vap_svc_t *svc;
    wifi_vap_info_map_t tgt_vap_map;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_radio_operationParam_t *radio_params = NULL;
    UINT apIndex = 0, ret;
    rdk_wifi_vap_info_t *rdk_vap_info;
    wifi_vap_info_t *vapInfo = NULL;
    char update_status[128], old_sec_mode[32], new_sec_mode[32];

    rfc_param->wpa3_compatibility_enable = type;
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    ctrl->webconfig_state |= ctrl_webconfig_state_vap_private_cfg_rsp_pending;

    for(UINT rIdx = 0; rIdx < getNumberRadios(); rIdx++) {
        apIndex = getPrivateApFromRadioIndex(rIdx);
        vapInfo =  get_wifidb_vap_parameters(apIndex);
        radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(rIdx);

        if ((svc = get_svc_by_name(ctrl, vapInfo->vap_name)) == NULL) {
            continue;
        }

        if (radio_params->band == WIFI_FREQUENCY_6_BAND) {
            wifi_util_info_print(WIFI_CTRL,"%s: %d 6GHz radio supports only WPA3 personal mode. WPA3-RFC: %d\n",__FUNCTION__,__LINE__,type);
            continue;
        }

        memset(old_sec_mode, 0, sizeof(old_sec_mode));
        memset(new_sec_mode, 0, sizeof(new_sec_mode));
        ret = convert_sec_mode_enable_int_str(vapInfo->u.bss_info.security.mode, old_sec_mode);
        if(ret != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: Error converting security mode to string old_mode:%d new_mode\n", __func__, __LINE__);
        }

        if(type) {
            if(vapInfo->u.bss_info.security.mode == wifi_security_mode_wpa3_compatibility) {
                continue;
            }
            vapInfo->u.bss_info.security.mode = wifi_security_mode_wpa3_compatibility;
            vapInfo->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
            vapInfo->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        } else {
            if (vapInfo->u.bss_info.security.mode == wifi_security_mode_wpa2_personal) {
                continue;
            }

            if ((radio_params->band == WIFI_FREQUENCY_2_4_BAND) || (radio_params->band == WIFI_FREQUENCY_5_BAND) ||
                (radio_params->band == WIFI_FREQUENCY_5L_BAND) || (radio_params->band == WIFI_FREQUENCY_5H_BAND)) {
                    vapInfo->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
                    vapInfo->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            }

	    if(rfc_param->wpa3_rfc) {
                vapInfo->u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
                vapInfo->u.bss_info.security.wpa3_transition_disable = false;
                vapInfo->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
                vapInfo->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
            }
        }
        ret = convert_sec_mode_enable_int_str(vapInfo->u.bss_info.security.mode, new_sec_mode);
        if(ret != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: Error converting security mode to string old_mode:%d new_mode\n", __func__, __LINE__);
        }

        wifi_util_info_print(WIFI_CTRL,"%s:%d: old_sec_mode %s new_sec_mode %s\n",
            __func__, __LINE__, old_sec_mode, new_sec_mode);
        if( (strcmp(old_sec_mode, new_sec_mode) != 0) && (new_sec_mode != NULL || old_sec_mode != NULL)) {
            notify_wifi_sec_mode_enabled(ctrl, apIndex, old_sec_mode, new_sec_mode);
        }

        memset(&tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
        tgt_vap_map.num_vaps = 1;
        memcpy(&tgt_vap_map.vap_array[0], vapInfo, sizeof(wifi_vap_info_t));
        rdk_vap_info = get_wifidb_rdk_vap_info(apIndex);
        if (rdk_vap_info == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get rdk vap info for index %d\n",
                __func__, __LINE__, apIndex);
            continue;
        }
        ret = svc->update_fn(svc, rIdx, &tgt_vap_map, rdk_vap_info);
        memset(update_status, 0, sizeof(update_status));
        snprintf(update_status, sizeof(update_status), "%s %s", vapInfo->vap_name, (ret == RETURN_OK)?"success":"fail");
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_hal_result, update_status);

        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d: Private vaps service update_fn failed \n",__func__, __LINE__);
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Updating security mode for apIndex %d secmode %d \n",__func__, __LINE__,apIndex,vapInfo->u.bss_info.security.mode);
        }
    }
}

void handle_command_event(wifi_ctrl_t *ctrl, void *data, unsigned int len,
    wifi_event_subtype_t subtype)
{
    switch (subtype) {
    case wifi_event_type_active_gw_check:
        process_active_gw_check_command(*(bool *)data);
        break;

    case wifi_event_type_command_factory_reset:
        process_factory_reset_command(*(bool *)data);
        break;
    case wifi_event_type_radius_grey_list_rfc:
        process_radius_grey_list_rfc(*(bool *)data);
        break;
    case wifi_event_type_wifi_passpoint_rfc:
        process_wifi_passpoint_rfc(*(bool *)data);
        break;
    case wifi_event_type_memwraptool_app_rfc:
        process_memwraptool_app_rfc(*(bool *)data);
        break;
    case wifi_event_type_wifi_offchannelscan_app_rfc:
        process_wifi_offchannelscan_app_rfc(*(bool *)data);
        break;
    case wifi_event_type_wifi_offchannelscan_sm_rfc:
        process_wifi_offchannelscan_sm_rfc(*(bool *)data);
        break;
    case wifi_event_type_wifi_interworking_rfc:
        process_wifi_interworking_rfc(*(bool *)data);
        break;
    case wifi_event_type_levl_rfc:
        process_levl_rfc(*(bool *)data);
        break;
    case wifi_event_type_wpa3_rfc:
        process_wpa3_rfc(*(bool *)data);
        break;
    case wifi_event_type_dfs_rfc:
        process_dfs_rfc(*(bool *)data);
        break;
    case wifi_event_type_dfs_atbootup_rfc:
        process_dfs_atbootup_rfc(*(bool *)data);
        break;
    case wifi_event_type_twoG80211axEnable_rfc:
        process_twoG80211axEnable_rfc(*(bool *)data);
        break;
    case wifi_event_type_command_kickmac:
        break;

    case wifi_event_type_xfinity_tunnel_up:
        process_xfinity_vaps(hotspot_vap_enable, true);
        break;

    case wifi_event_type_xfinity_tunnel_down:
        process_xfinity_vaps(hotspot_vap_disable, true);
        break;
    case wifi_event_type_command_kick_assoc_devices:
        process_kick_assoc_devices_event(data);
        break;

    case wifi_event_type_command_wps:
        process_wps_command_event(*(unsigned int *)data);
        break;

    case wifi_event_type_command_wps_pin:
        process_wps_pin_command_event(data);
        break;

    case wifi_event_type_command_wps_cancel:
        process_wps_cancel_event(data);
        break;

    case wifi_event_type_command_wifi_host_sync:
        process_wifi_host_sync();
        break;

    case wifi_event_type_device_network_mode:
        process_device_mode_command_event(*(int *)data);
        break;

    case wifi_event_type_command_wifi_neighborscan:
        process_neighbor_scan_command_event();
        break;

    case wifi_event_type_command_mesh_status:
        process_mesh_status_command(*(bool *)data);
        break;

    case wifi_event_type_normalized_rssi:
        marker_list_config_event((char *)data, normalized_rssi_list_type);
        break;

    case wifi_event_type_snr:
        marker_list_config_event((char *)data, snr_list_type);
        break;

    case wifi_event_type_cli_stat:
        marker_list_config_event((char *)data, cli_stat_list_type);
        break;

    case wifi_event_type_txrx_rate:
        marker_list_config_event((char *)data, txrx_rate_list_type);
        break;

    case wifi_event_type_prefer_private_rfc:
        process_prefer_private_rfc(*(bool *)data);
        break;

    case wifi_event_type_tcm_rfc:
        process_tcm_rfc(*(bool *)data);
        break;

    case wifi_event_type_trigger_disconnection:
        process_sta_trigger_disconnection(*(unsigned int *)data);
        break;

    case wifi_event_type_managed_wifi_disable:
        process_managed_wifi_disable();
        break;

    case wifi_event_type_eth_bh_status:
        process_eth_bh_status_command(*(bool *)data);
        break;
    case wifi_event_type_notify_monitor_done:
        process_monitor_init_command();
        break;
    case wifi_event_type_send_action_frame:
        process_send_action_frame_command(data, len);
        break;
    case wifi_event_type_rsn_override_rfc:
        process_rsn_override_rfc(*(bool *)data);
        break;
    case wifi_event_type_csi_analytics_rfc:
        process_csi_analytics_rfc(*(bool *)data);
        break;
    case wifi_event_type_mgmt_frame_bus_rfc:
    case wifi_event_type_sta_connect_in_progress:
    case wifi_event_type_udhcp_ip_fail:
    case wifi_event_type_trigger_disconnection_analytics:
    case wifi_event_type_new_bssid:
    case wifi_event_type_xfinity_enable:
    case wifi_event_type_start_inst_msmt:
    case wifi_event_type_stop_inst_msmt:
    case wifi_event_type_xfinity_rrm:
    case wifi_event_type_sm_app_enable:
        // not handle here
        break;
    default:
        wifi_util_error_print(WIFI_CTRL, "[%s]:WIFI hal handler not supported this event %s\r\n",
            __FUNCTION__, wifi_event_subtype_to_string(subtype));
        break;
    }

    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, subtype, data);
}

void handle_hal_indication(wifi_ctrl_t *ctrl, void *data, unsigned int len,
    wifi_event_subtype_t subtype)
{
    bool nop_start_reboot = 0;
    unsigned int dfs_timer_secs = 0;
    switch (subtype) {
    case wifi_event_hal_unknown_frame:
        process_unknown_frame_event(data, len);
        break;

    case wifi_event_hal_probe_req_frame:
        process_probe_req_frame_event(data, len);
        break;

    case wifi_event_hal_auth_frame:
        process_auth_frame_event(data, len);
        break;

    case wifi_event_hal_assoc_req_frame:
        process_assoc_req_frame_event(data, len);
        break;

    case wifi_event_hal_assoc_rsp_frame:
        process_assoc_rsp_frame_event(data, len);
        break;

    case wifi_event_hal_reassoc_req_frame:
        process_reassoc_req_frame_event(data, len);
        break;

    case wifi_event_hal_reassoc_rsp_frame:
        process_reassoc_rsp_frame_event(data, len);
        break;

    case wifi_event_hal_dpp_public_action_frame:
        process_dpp_public_action_frame_event(data, len);
        break;

    case wifi_event_hal_dpp_config_req_frame:
        process_dpp_config_req_frame_event(data, len);
        break;

    case wifi_event_hal_anqp_gas_init_frame:
        process_anqp_gas_init_frame_event(data, len);
        break;

    case wifi_event_hal_sta_conn_status:
        process_sta_conn_status_event(data, len);
        break;

    case wifi_event_hal_assoc_device:
        process_assoc_device_event(data);
        break;

    case wifi_event_hal_disassoc_device:
        process_disassoc_device_event(data);
        break;

    case wifi_event_radius_greylist:
        process_greylist_mac_filter(data);
        break;

    case wifi_event_scan_results:
        process_scan_results_event(data, len);
        break;

    case wifi_event_hal_channel_change:
        process_channel_change_event(data, nop_start_reboot, dfs_timer_secs);
        break;

    case wifi_event_hal_csa_beacon_frame:
        process_csa_beacon_frame_event(data, len, ctrl);
        break;

    case wifi_event_hal_wps_results:
        process_wps_results_event(data);
        break;

    default:

        wifi_util_error_print(WIFI_CTRL, "[%s]:WIFI hal handler not supported this event %s\r\n",
            __FUNCTION__, wifi_event_subtype_to_string(subtype));
        break;
    }
#if ONEWIFI_ANALYTICS_APP_SUPPORT
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_hal_ind, subtype, data);
#endif
}

void update_subdoc_data(webconfig_subdoc_data_t *data, unsigned int num_ssid,
    wifi_vap_name_t *vap_names)
{
    unsigned int i = 0;
    int radio_index = -1;
    int vap_array_index = -1;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    for (i = 0; i < num_ssid; i++) {
        radio_index = convert_vap_name_to_radio_array_index(&mgr->hal_cap.wifi_prop, vap_names[i]);
        vap_array_index = convert_vap_name_to_array_index(&mgr->hal_cap.wifi_prop, vap_names[i]);

        if ((vap_array_index == -1) || (radio_index == -1)) {
            wifi_util_error_print(WIFI_CTRL,
                "%s:%d: invalid index radio_index %d vap_array_index  %d for vapname : %s\n",
                __func__, __LINE__, radio_index, vap_array_index, vap_names[i]);
            continue;
        }

        memcpy(&data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index],
            &mgr->radio_config[radio_index].vaps.vap_map.vap_array[vap_array_index],
            sizeof(wifi_vap_info_t));
        memcpy(&data->u.decoded.radios[radio_index].vaps.rdk_vap_array[vap_array_index],
            &mgr->radio_config[radio_index].vaps.rdk_vap_array[vap_array_index],
            sizeof(rdk_wifi_vap_info_t));
    }
}

int free_event_webconfig_data(webconfig_subdoc_type_t type, webconfig_subdoc_decoded_data_t *data)
{
    switch (type) {
    case webconfig_subdoc_type_csi:
        wifi_util_info_print(WIFI_CTRL, "%s:%d decoded csi queue:%p\n", __func__, __LINE__,
            data->csi_data_queue);
        if (data->csi_data_queue != NULL) {
            queue_destroy(data->csi_data_queue);
            data->csi_data_queue = NULL;
        }
        break;
    default:
        break;
    }

    return RETURN_OK;
}

int free_webconfig_msg_payload(wifi_event_subtype_t sub_type, webconfig_subdoc_data_t *data)
{
    switch (sub_type) {
    case wifi_event_webconfig_set_data:
    case wifi_event_webconfig_set_data_dml:
        free_event_webconfig_data(data->type, &data->u.decoded);
        break;
    default:
        break;
    }

    return RETURN_OK;
}

void handle_webconfig_event(wifi_ctrl_t *ctrl, const char *raw, unsigned int len,
    wifi_event_subtype_t subtype)
{
    webconfig_t *config;
    webconfig_subdoc_data_t data = { 0 };
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_event_t *wifi_event = NULL;
    config = &ctrl->webconfig;
    webconfig_subdoc_type_t subdoc_type;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    unsigned int num_ssid = 0;
    cJSON *json = NULL;

    switch (subtype) {
    case wifi_event_webconfig_set_data:
    case wifi_event_webconfig_set_data_dml:
    case wifi_event_webconfig_set_data_webconfig:
    case wifi_event_webconfig_set_data_ovsm:
    case wifi_event_webconfig_data_resched_to_ctrl_queue:
    case wifi_event_webconfig_set_data_force_apply:
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap,
            sizeof(wifi_hal_capability_t));

        if (raw == NULL) {
            return;
        }

        json = cJSON_Parse(raw);
        subdoc_type = find_subdoc_type(config, json);
        cJSON_Delete(json);
        switch (subdoc_type) {
        case webconfig_subdoc_type_private:
            num_ssid += get_list_of_private_ssid(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            break;
        case webconfig_subdoc_type_home:
            num_ssid += get_list_of_iot_ssid(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            break;
        case webconfig_subdoc_type_xfinity:
            num_ssid += get_list_of_hotspot_open(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            num_ssid += get_list_of_hotspot_secure(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            break;
        case webconfig_subdoc_type_mesh_backhaul:
            num_ssid += get_list_of_mesh_backhaul(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            break;
        case webconfig_subdoc_type_lnf:
            num_ssid += get_list_of_lnf_psk(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            num_ssid += get_list_of_lnf_radius(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            break;
        case webconfig_subdoc_type_mesh_sta:
            num_ssid += get_list_of_mesh_sta(&mgr->hal_cap.wifi_prop, MAX_NUM_RADIOS,
                &vap_names[num_ssid]);
            break;

        default:
            break;
        }

        if (num_ssid != 0) {
            update_subdoc_data(&data, num_ssid, vap_names);
        }

        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, subtype, NULL);
        webconfig_decode(config, &data, raw);
        wifi_event = (wifi_event_t *)malloc(sizeof(wifi_event_t));
        if (wifi_event != NULL) {
            memset(wifi_event, 0, sizeof(wifi_event_t));
            wifi_event->event_type = wifi_event_type_webconfig;
            wifi_event->sub_type = subtype;
            wifi_event->u.webconfig_data = &data;
            apps_mgr_event(&ctrl->apps_mgr, wifi_event);
            free_webconfig_msg_payload(subtype, &data);
            if (wifi_event != NULL) {
                free(wifi_event);
            }
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s:%d NULL event pointer\n", __func__, __LINE__);
        }
        webconfig_data_free(&data);
        break;

    case wifi_event_webconfig_set_data_tunnel:
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap,
            sizeof(wifi_hal_capability_t));
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, subtype, NULL);
        webconfig_decode(config, &data, raw);
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, subtype, NULL);
        webconfig_data_free(&data);
        break;

    case wifi_event_webconfig_get_data:
        // copy the global config
        memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config,
            sizeof(wifi_global_config_t));

        // copy the radios and vaps data
        memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config,
            getNumberRadios() * sizeof(rdk_wifi_radio_t));

        // copy HAL Cap data
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap,
            sizeof(wifi_hal_capability_t));
        data.u.decoded.num_radios = getNumberRadios();

        // tell webconfig to encode
        webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_dml);
        webconfig_data_free(&data);
        break;

    case wifi_event_webconfig_data_req_from_dml:
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, subtype, NULL);
        ctrl->webconfig_state |= ctrl_webconfig_state_trigger_dml_thread_data_update_pending;
        break;
    
    case wifi_event_webconfig_data_to_hal_apply: //Re-factor this for Phase 2
        process_acs_keep_out_channels_event(raw);
        break;

    default:
        wifi_util_error_print(WIFI_CTRL,
            "[%s]:WIFI webconfig handler not supported this event %s\r\n", __FUNCTION__,
            wifi_event_subtype_to_string(subtype));
        break;
    }
}

void handle_wifiapi_event(void *data, unsigned int len, wifi_event_subtype_t subtype)
{
    switch (subtype) {
    case wifi_event_type_wifiapi_execution:
        process_wifiapi_command((char *)data, len);
        break;

    default:
        wifi_util_error_print(WIFI_CTRL,
            "[%s]: wifi_api handler does not support this event %s\r\n", __FUNCTION__,
            wifi_event_subtype_to_string(subtype));
        break;
    }
}

void handle_monitor_event(wifi_ctrl_t *ctrl, void *data, unsigned int len, wifi_event_subtype_t subtype)
{
    switch (subtype) {
        case wifi_event_type_collect_stats:
            stats_bus_publish(ctrl, data);
            break;
        default:
            break;
    }
}
