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

#define SCHEMA_VERSION_STR           "7.11.203"
#define SCHEMA_VERSION               0x071120300
#define SCHEMA_VERSION_MAIN          7
#define SCHEMA_VERSION_MAJOR         11
#define SCHEMA_VERSION_MINOR         203


#define PJS_SCHEMA_AWLAN_Node \
    PJS(schema_AWLAN_Node, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(id, 128 + 1) \
        PJS_OVS_STRING_Q(model, 128 + 1) \
        PJS_OVS_STRING(revision, 128 + 1) \
        PJS_OVS_STRING_Q(serial_number, 128 + 1) \
        PJS_OVS_STRING_Q(sku_number, 128 + 1) \
        PJS_OVS_STRING(redirector_addr, 128 + 1) \
        PJS_OVS_STRING(manager_addr, 128 + 1) \
        PJS_OVS_SMAP_STRING(led_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(mqtt_settings, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(mqtt_topics, 128, 64 + 1) \
        PJS_OVS_SMAP_STRING(mqtt_headers, 64, 64 + 1) \
        PJS_OVS_STRING(platform_version, 128 + 1) \
        PJS_OVS_STRING(firmware_version, 128 + 1) \
        PJS_OVS_STRING(firmware_url, 256 + 1) \
        PJS_OVS_STRING(firmware_pass, 256 + 1) \
        PJS_OVS_INT(upgrade_timer) \
        PJS_OVS_INT(upgrade_dl_timer) \
        PJS_OVS_INT(upgrade_status) \
        PJS_OVS_STRING_Q(device_mode, 128 + 1) \
        PJS_OVS_BOOL_Q(factory_reset) \
        PJS_OVS_SMAP_STRING(version_matrix, 64, 64 + 1) \
        PJS_OVS_INT(min_backoff) \
        PJS_OVS_INT(max_backoff) \
    )

#define PJS_SCHEMA_Wifi_Device_Config \
    PJS(schema_Wifi_Device_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(device_mac, 128 + 1) \
        PJS_OVS_STRING(device_name, 128 + 1) \
        PJS_OVS_STRING(vap_name, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Security_Config \
    PJS(schema_Wifi_Security_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(security_mode) \
        PJS_OVS_INT(encryption_method) \
        PJS_OVS_STRING(mfp_config, 10 + 1) \
        PJS_OVS_INT(key_type)\
        PJS_OVS_STRING(keyphrase, 64 + 1)\
        PJS_OVS_STRING(radius_server_ip, 36 + 1) \
        PJS_OVS_INT(radius_server_port) \
        PJS_OVS_STRING(radius_server_key, 64 + 1) \
        PJS_OVS_STRING(secondary_radius_server_ip, 36 + 1) \
        PJS_OVS_INT(secondary_radius_server_port) \
        PJS_OVS_STRING(secondary_radius_server_key, 64 + 1) \
        PJS_OVS_STRING(vap_name, 128 + 1) \
        PJS_OVS_STRING(das_ip, 64 + 1) \
        PJS_OVS_INT(das_port)\
        PJS_OVS_STRING(das_key, 64 + 1)\
        PJS_OVS_INT(rekey_interval)\
        PJS_OVS_BOOL(strict_rekey)\
        PJS_OVS_INT(eapol_key_timeout)\
        PJS_OVS_INT(eapol_key_retries)\
        PJS_OVS_INT(eap_identity_req_timeout)\
        PJS_OVS_INT(eap_identity_req_retries)\
        PJS_OVS_INT(eap_req_timeout)\
        PJS_OVS_INT(eap_req_retries)\
        PJS_OVS_BOOL(disable_pmksa_caching)\
        PJS_OVS_INT(max_auth_attempts)\
        PJS_OVS_INT(blacklist_table_timeout)\
        PJS_OVS_INT(identity_req_retry_interval)\
        PJS_OVS_INT(server_retries)\
        PJS_OVS_BOOL(wpa3_transition_disable)\
    )

#define PJS_SCHEMA_Wifi_VAP_Config \
    PJS(schema_Wifi_VAP_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(vap_name, 128 + 1) \
        PJS_OVS_STRING(radio_name, 128 +1 ) \
        PJS_OVS_STRING(ssid, 128 + 1) \
        PJS_OVS_BOOL(enabled) \
        PJS_OVS_BOOL(exists) \
        PJS_OVS_BOOL(ssid_advertisement_enabled) \
        PJS_OVS_BOOL(isolation_enabled) \
        PJS_OVS_INT(mgmt_power_control) \
        PJS_OVS_INT(bss_max_sta) \
        PJS_OVS_BOOL(bss_transition_activated) \
        PJS_OVS_BOOL(nbr_report_activated) \
        PJS_OVS_BOOL(rapid_connect_enabled) \
        PJS_OVS_INT(rapid_connect_threshold) \
        PJS_OVS_BOOL(vap_stats_enable) \
        PJS_OVS_UUID(security) \
        PJS_OVS_UUID(mac_filter) \
        PJS_OVS_UUID(interworking) \
        PJS_OVS_BOOL(mac_filter_enabled) \
        PJS_OVS_INT(mac_filter_mode) \
        PJS_OVS_BOOL(mac_addr_acl_enabled) \
        PJS_OVS_BOOL(wmm_enabled) \
        PJS_OVS_STRING(anqp_parameters, 4096 + 1)\
        PJS_OVS_STRING(hs2_parameters, 4096 + 1)\
        PJS_OVS_BOOL(uapsd_enabled) \
        PJS_OVS_INT(beacon_rate) \
        PJS_OVS_STRING(bridge_name, 32 + 1)\
        PJS_OVS_INT(wmm_noack) \
        PJS_OVS_INT(wep_key_length) \
        PJS_OVS_BOOL(bss_hotspot) \
        PJS_OVS_INT(wps_push_button) \
        PJS_OVS_INT(wps_config_methods) \
        PJS_OVS_BOOL(wps_enabled) \
        PJS_OVS_STRING(beacon_rate_ctl, 32 + 1) \
        PJS_OVS_BOOL(network_initiated_greylist) \
        PJS_OVS_STRING(mfp_config, 10 + 1) \
        PJS_OVS_INT_Q(period) \
        PJS_OVS_INT_Q(channel) \
        PJS_OVS_INT_Q(freq_band) \
        PJS_OVS_STRING(repurposed_vap_name, 64 + 1) \
        PJS_OVS_BOOL(connected_building_enabled)\
    )

#define PJS_SCHEMA_Wifi_Interworking_Config \
   PJS(schema_Wifi_Interworking_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING(vap_name, 128 + 1) \
        PJS_OVS_INT(access_network_type) \
        PJS_OVS_BOOL(internet) \
        PJS_OVS_BOOL(asra) \
        PJS_OVS_BOOL(esr) \
        PJS_OVS_BOOL(uesa) \
        PJS_OVS_BOOL(hess_option_present) \
        PJS_OVS_STRING(hessid, 18 + 1) \
        PJS_OVS_INT(venue_group) \
        PJS_OVS_INT(venue_type) \
   )

#define PJS_SCHEMA_Wifi_GAS_Config \
   PJS(schema_Wifi_GAS_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(advertisement_id, 4 + 1)\
        PJS_OVS_BOOL(pause_for_server_response)\
        PJS_OVS_INT(response_timeout)\
        PJS_OVS_INT(comeback_delay)\
        PJS_OVS_INT(response_buffering_time)\
        PJS_OVS_INT(query_responselength_limit)\
   )

#define PJS_SCHEMA_Wifi_Rfc_Config \
   PJS(schema_Wifi_Rfc_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(rfc_id, 4 + 1)\
        PJS_OVS_BOOL(wifipasspoint_rfc) \
        PJS_OVS_BOOL(wifiinterworking_rfc) \
        PJS_OVS_BOOL(radiusgreylist_rfc) \
        PJS_OVS_BOOL(dfsatbootup_rfc) \
        PJS_OVS_BOOL(dfs_rfc) \
        PJS_OVS_BOOL(wpa3_rfc) \
        PJS_OVS_BOOL(levl_enabled_rfc) \
        PJS_OVS_BOOL(twoG80211axEnable_rfc) \
        PJS_OVS_BOOL(hotspot_open_2g_last_enabled) \
        PJS_OVS_BOOL(hotspot_open_5g_last_enabled) \
        PJS_OVS_BOOL(hotspot_open_6g_last_enabled) \
        PJS_OVS_BOOL(hotspot_secure_2g_last_enabled) \
        PJS_OVS_BOOL(hotspot_secure_5g_last_enabled) \
        PJS_OVS_BOOL(hotspot_secure_6g_last_enabled) \
        PJS_OVS_BOOL(wifioffchannelscan_rfc) \
  )

#define PJS_SCHEMA_Wifi_MacFilter_Config \
   PJS(schema_Wifi_MacFilter_Config, \
       PJS_OVS_UUID_Q(_uuid)\
       PJS_OVS_UUID_Q(_version)\
       PJS_OVS_STRING(macfilter_key, 128 + 1) \
       PJS_OVS_STRING(device_name, 128 + 1) \
       PJS_OVS_STRING(device_mac, 128 + 1) \
       PJS_OVS_INT(reason)\
       PJS_OVS_INT(expiry_time)\
   )

#define PJS_SCHEMA_Alarms \
    PJS(schema_Alarms, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(code, 128 + 1) \
        PJS_OVS_INT(timestamp) \
        PJS_OVS_STRING(source, 128 + 1) \
        PJS_OVS_STRING(add_info, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Master_State \
    PJS(schema_Wifi_Master_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_type, 128 + 1) \
        PJS_OVS_UUID(if_uuid) \
        PJS_OVS_STRING(if_name, 128 + 1) \
        PJS_OVS_STRING_Q(port_state, 128 + 1) \
        PJS_OVS_STRING_Q(network_state, 128 + 1) \
        PJS_OVS_STRING_Q(inet_addr, 128 + 1) \
        PJS_OVS_STRING_Q(netmask, 128 + 1) \
        PJS_OVS_SMAP_STRING(dhcpc, 64, 64 + 1) \
        PJS_OVS_STRING_Q(onboard_type, 128 + 1) \
        PJS_OVS_INT_Q(uplink_priority) \
    )

#define PJS_SCHEMA_Wifi_Ethernet_State \
    PJS(schema_Wifi_Ethernet_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(mac, 128 + 1) \
        PJS_OVS_BOOL_Q(enabled) \
        PJS_OVS_BOOL_Q(connected) \
    )

#define PJS_SCHEMA_Connection_Manager_Uplink \
    PJS(schema_Connection_Manager_Uplink, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_type, 128 + 1) \
        PJS_OVS_STRING(if_name, 128 + 1) \
        PJS_OVS_INT_Q(priority) \
        PJS_OVS_BOOL_Q(loop) \
        PJS_OVS_BOOL_Q(has_L2) \
        PJS_OVS_BOOL_Q(has_L3) \
        PJS_OVS_BOOL_Q(is_used) \
        PJS_OVS_BOOL_Q(ntp_state) \
        PJS_OVS_INT_Q(unreachable_link_counter) \
        PJS_OVS_INT_Q(unreachable_router_counter) \
        PJS_OVS_INT_Q(unreachable_internet_counter) \
        PJS_OVS_INT_Q(unreachable_cloud_counter) \
    )

#define PJS_SCHEMA_Wifi_Inet_Config \
    PJS(schema_Wifi_Inet_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_name, 128 + 1) \
        PJS_OVS_STRING(if_type, 128 + 1) \
        PJS_OVS_STRING(if_uuid, 128 + 1) \
        PJS_OVS_BOOL(enabled) \
        PJS_OVS_BOOL(network) \
        PJS_OVS_BOOL_Q(NAT) \
        PJS_OVS_STRING_Q(ip_assign_scheme, 128 + 1) \
        PJS_OVS_STRING_Q(inet_addr, 128 + 1) \
        PJS_OVS_STRING_Q(netmask, 128 + 1) \
        PJS_OVS_STRING_Q(gateway, 128 + 1) \
        PJS_OVS_STRING_Q(broadcast, 128 + 1) \
        PJS_OVS_STRING_Q(gre_remote_inet_addr, 128 + 1) \
        PJS_OVS_STRING_Q(gre_local_inet_addr, 128 + 1) \
        PJS_OVS_STRING_Q(gre_ifname, 128 + 1) \
        PJS_OVS_STRING_Q(gre_remote_mac_addr, 128 + 1) \
        PJS_OVS_INT_Q(mtu) \
        PJS_OVS_SMAP_STRING(dns, 64, 32 + 1) \
        PJS_OVS_SMAP_STRING(dhcpd, 64, 64 + 1) \
        PJS_OVS_STRING_Q(upnp_mode, 128 + 1) \
        PJS_OVS_BOOL_Q(dhcp_sniff) \
        PJS_OVS_INT_Q(vlan_id) \
        PJS_OVS_STRING_Q(parent_ifname, 128 + 1) \
        PJS_OVS_SMAP_STRING(ppp_options, 64, 64 + 1) \
        PJS_OVS_STRING_Q(softwds_mac_addr, 128 + 1) \
        PJS_OVS_BOOL_Q(softwds_wrap) \
        PJS_OVS_STRING_Q(igmp_proxy, 128 + 1) \
        PJS_OVS_STRING_Q(mld_proxy, 128 + 1) \
        PJS_OVS_BOOL_Q(igmp) \
        PJS_OVS_INT_Q(igmp_age) \
        PJS_OVS_INT_Q(igmp_tsize) \
    )

#define PJS_SCHEMA_Wifi_Inet_State \
    PJS(schema_Wifi_Inet_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_name, 128 + 1) \
        PJS_OVS_UUID_Q(inet_config) \
        PJS_OVS_STRING(if_type, 128 + 1) \
        PJS_OVS_STRING(if_uuid, 128 + 1) \
        PJS_OVS_BOOL(enabled) \
        PJS_OVS_BOOL(network) \
        PJS_OVS_BOOL_Q(NAT) \
        PJS_OVS_STRING_Q(ip_assign_scheme, 128 + 1) \
        PJS_OVS_STRING_Q(inet_addr, 128 + 1) \
        PJS_OVS_STRING_Q(netmask, 128 + 1) \
        PJS_OVS_STRING_Q(gateway, 128 + 1) \
        PJS_OVS_STRING_Q(broadcast, 128 + 1) \
        PJS_OVS_STRING_Q(gre_remote_inet_addr, 128 + 1) \
        PJS_OVS_STRING_Q(gre_local_inet_addr, 128 + 1) \
        PJS_OVS_STRING_Q(gre_ifname, 128 + 1) \
        PJS_OVS_INT_Q(mtu) \
        PJS_OVS_SMAP_STRING(dns, 64, 32 + 1) \
        PJS_OVS_SMAP_STRING(dhcpd, 64, 64 + 1) \
        PJS_OVS_STRING(hwaddr, 128 + 1) \
        PJS_OVS_SMAP_STRING(dhcpc, 64, 64 + 1) \
        PJS_OVS_STRING_Q(upnp_mode, 128 + 1) \
        PJS_OVS_INT_Q(vlan_id) \
        PJS_OVS_STRING_Q(parent_ifname, 128 + 1) \
        PJS_OVS_STRING_Q(softwds_mac_addr, 128 + 1) \
        PJS_OVS_BOOL(softwds_wrap) \
    )

#define PJS_SCHEMA_Wifi_Route_State \
    PJS(schema_Wifi_Route_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_name, 31 + 1) \
        PJS_OVS_STRING(dest_addr, 15 + 1) \
        PJS_OVS_STRING(dest_mask, 15 + 1) \
        PJS_OVS_STRING(gateway, 15 + 1) \
        PJS_OVS_STRING_Q(gateway_hwaddr, 17 + 1) \
    )

#define PJS_SCHEMA_Wifi_Radio_Config_ovs \
    PJS(schema_Wifi_Radio_Config_ovs, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(if_name, 128 + 1) \
        PJS_OVS_STRING(freq_band, 128 + 1) \
        PJS_OVS_BOOL_Q(enabled) \
        PJS_OVS_BOOL_Q(dfs_demo) \
        PJS_OVS_STRING_Q(hw_type, 128 + 1) \
        PJS_OVS_SMAP_STRING(hw_config, 64, 64 + 1) \
        PJS_OVS_STRING_Q(country, 128 + 1) \
        PJS_OVS_INT_Q(channel) \
        PJS_OVS_INT_Q(channel_sync) \
        PJS_OVS_STRING_Q(channel_mode, 128 + 1) \
        PJS_OVS_STRING_Q(hw_mode, 128 + 1) \
        PJS_OVS_STRING_Q(ht_mode, 128 + 1) \
        PJS_OVS_INT_Q(thermal_shutdown) \
        PJS_OVS_INT_Q(thermal_downgrade_temp) \
        PJS_OVS_INT_Q(thermal_upgrade_temp) \
        PJS_OVS_INT_Q(thermal_integration) \
        PJS_OVS_DMAP_STRING(temperature_control, 64, 64 + 1) \
        PJS_OVS_SET_UUID(vif_configs, 64) \
        PJS_OVS_INT_Q(tx_power) \
        PJS_OVS_INT_Q(bcn_int) \
        PJS_OVS_INT_Q(tx_chainmask) \
        PJS_OVS_INT_Q(thermal_tx_chainmask) \
        PJS_OVS_SMAP_INT(fallback_parents, 8) \
        PJS_OVS_STRING_Q(zero_wait_dfs, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Radio_State \
    PJS(schema_Wifi_Radio_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(if_name, 128 + 1) \
        PJS_OVS_UUID_Q(radio_config) \
        PJS_OVS_STRING(freq_band, 128 + 1) \
        PJS_OVS_BOOL_Q(enabled) \
        PJS_OVS_BOOL_Q(dfs_demo) \
        PJS_OVS_STRING_Q(hw_type, 128 + 1) \
        PJS_OVS_SMAP_STRING(hw_params, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(radar, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(hw_config, 64, 64 + 1) \
        PJS_OVS_STRING_Q(country, 128 + 1) \
        PJS_OVS_INT_Q(channel) \
        PJS_OVS_INT_Q(channel_sync) \
        PJS_OVS_STRING_Q(channel_mode, 128 + 1) \
        PJS_OVS_STRING_Q(mac, 128 + 1) \
        PJS_OVS_STRING_Q(hw_mode, 128 + 1) \
        PJS_OVS_STRING_Q(ht_mode, 128 + 1) \
        PJS_OVS_INT_Q(thermal_shutdown) \
        PJS_OVS_INT_Q(thermal_downgrade_temp) \
        PJS_OVS_INT_Q(thermal_upgrade_temp) \
        PJS_OVS_INT_Q(thermal_integration) \
        PJS_OVS_BOOL_Q(thermal_downgraded) \
        PJS_OVS_DMAP_STRING(temperature_control, 64, 64 + 1) \
        PJS_OVS_SET_UUID(vif_states, 64) \
        PJS_OVS_INT_Q(tx_power) \
        PJS_OVS_INT_Q(bcn_int) \
        PJS_OVS_INT_Q(tx_chainmask) \
        PJS_OVS_INT_Q(thermal_tx_chainmask) \
        PJS_OVS_SET_INT(allowed_channels, 64) \
        PJS_OVS_SMAP_STRING(channels, 64, 64 + 1) \
        PJS_OVS_SMAP_INT(fallback_parents, 8) \
        PJS_OVS_STRING_Q(zero_wait_dfs, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Credential_Config \
    PJS(schema_Wifi_Credential_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(ssid, 36 + 1) \
        PJS_OVS_SMAP_STRING(security, 64, 64 + 1) \
        PJS_OVS_STRING_Q(onboard_type, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_VIF_Config \
    PJS(schema_Wifi_VIF_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_name, 128 + 1) \
        PJS_OVS_BOOL_Q(enabled) \
        PJS_OVS_STRING_Q(mode, 128 + 1) \
        PJS_OVS_STRING_Q(parent, 17 + 1) \
        PJS_OVS_INT_Q(vif_radio_idx) \
        PJS_OVS_INT_Q(vif_dbg_lvl) \
        PJS_OVS_BOOL_Q(wds) \
        PJS_OVS_STRING_Q(ssid, 36 + 1) \
        PJS_OVS_STRING_Q(ssid_broadcast, 128 + 1) \
        PJS_OVS_SMAP_STRING(security, 64, 64 + 1) \
        PJS_OVS_SET_UUID(credential_configs, 64) \
        PJS_OVS_STRING_Q(bridge, 128 + 1) \
        PJS_OVS_SET_STRING(mac_list, 64, 64 + 1) \
        PJS_OVS_STRING_Q(mac_list_type, 128 + 1) \
        PJS_OVS_INT_Q(vlan_id) \
        PJS_OVS_STRING_Q(min_hw_mode, 128 + 1) \
        PJS_OVS_BOOL_Q(uapsd_enable) \
        PJS_OVS_INT_Q(group_rekey) \
        PJS_OVS_BOOL_Q(ap_bridge) \
        PJS_OVS_INT_Q(ft_psk) \
        PJS_OVS_INT_Q(ft_mobility_domain) \
        PJS_OVS_INT_Q(rrm) \
        PJS_OVS_INT_Q(btm) \
        PJS_OVS_BOOL_Q(dynamic_beacon) \
        PJS_OVS_BOOL_Q(mcast2ucast) \
        PJS_OVS_STRING_Q(multi_ap, 128 + 1) \
        PJS_OVS_BOOL_Q(wps) \
        PJS_OVS_BOOL_Q(wps_pbc) \
        PJS_OVS_STRING(wps_pbc_key_id, 128 + 1) \
        PJS_OVS_BOOL_Q(wpa) \
        PJS_OVS_SET_STRING(wpa_key_mgmt, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(wpa_psks, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(wpa_oftags, 64, 64 + 1) \
        PJS_OVS_STRING_Q(radius_srv_addr, 128 + 1) \
        PJS_OVS_INT_Q(radius_srv_port) \
        PJS_OVS_STRING_Q(radius_srv_secret, 128 + 1) \
        PJS_OVS_STRING_Q(default_oftag, 128 + 1) \
        PJS_OVS_STRING_Q(dpp_connector, 1024 + 1) \
        PJS_OVS_STRING_Q(dpp_csign_hex, 512 + 1) \
        PJS_OVS_STRING_Q(dpp_netaccesskey_hex, 512 + 1) \
    )

#define PJS_SCHEMA_Wifi_VIF_State \
    PJS(schema_Wifi_VIF_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_UUID_Q(vif_config) \
        PJS_OVS_BOOL_Q(enabled) \
        PJS_OVS_STRING(if_name, 128 + 1) \
        PJS_OVS_STRING_Q(mode, 128 + 1) \
        PJS_OVS_STRING_Q(state, 128 + 1) \
        PJS_OVS_INT_Q(channel) \
        PJS_OVS_STRING_Q(mac, 17 + 1) \
        PJS_OVS_INT_Q(vif_radio_idx) \
        PJS_OVS_BOOL_Q(wds) \
        PJS_OVS_STRING_Q(parent, 17 + 1) \
        PJS_OVS_STRING_Q(ssid, 36 + 1) \
        PJS_OVS_STRING_Q(ssid_broadcast, 128 + 1) \
        PJS_OVS_SMAP_STRING(security, 64, 64 + 1) \
        PJS_OVS_STRING_Q(bridge, 128 + 1) \
        PJS_OVS_SET_STRING(mac_list, 64, 64 + 1) \
        PJS_OVS_STRING_Q(mac_list_type, 128 + 1) \
        PJS_OVS_SET_UUID(associated_clients, 64) \
        PJS_OVS_INT_Q(vlan_id) \
        PJS_OVS_STRING_Q(min_hw_mode, 128 + 1) \
        PJS_OVS_BOOL_Q(uapsd_enable) \
        PJS_OVS_INT_Q(group_rekey) \
        PJS_OVS_BOOL_Q(ap_bridge) \
        PJS_OVS_INT_Q(ft_psk) \
        PJS_OVS_INT_Q(ft_mobility_domain) \
        PJS_OVS_INT_Q(rrm) \
        PJS_OVS_INT_Q(btm) \
        PJS_OVS_BOOL_Q(dynamic_beacon) \
        PJS_OVS_BOOL_Q(mcast2ucast) \
        PJS_OVS_STRING_Q(multi_ap, 128 + 1) \
        PJS_OVS_STRING_Q(ap_vlan_sta_addr, 17 + 1) \
        PJS_OVS_BOOL_Q(wps) \
        PJS_OVS_BOOL_Q(wps_pbc) \
        PJS_OVS_STRING(wps_pbc_key_id, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Associated_Clients \
    PJS(schema_Wifi_Associated_Clients, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(mac, 128 + 1) \
        PJS_OVS_STRING_Q(state, 128 + 1) \
        PJS_OVS_SET_STRING(capabilities, 64, 64 + 1) \
        PJS_OVS_STRING_Q(key_id, 31 + 1) \
        PJS_OVS_STRING_Q(oftag, 64 + 1) \
        PJS_OVS_INT_Q(uapsd) \
        PJS_OVS_SMAP_STRING(kick, 64, 2 + 1) \
    )

#define PJS_SCHEMA_DHCP_leased_IP \
    PJS(schema_DHCP_leased_IP, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(hwaddr, 128 + 1) \
        PJS_OVS_STRING(inet_addr, 128 + 1) \
        PJS_OVS_STRING(hostname, 128 + 1) \
        PJS_OVS_STRING(fingerprint, 128 + 1) \
        PJS_OVS_STRING(vendor_class, 128 + 1) \
        PJS_OVS_INT(lease_time) \
    )

#define PJS_SCHEMA_Wifi_Test_Config \
    PJS(schema_Wifi_Test_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(test_id, 128 + 1) \
        PJS_OVS_SMAP_STRING(params, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Wifi_Test_State \
    PJS(schema_Wifi_Test_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(test_id, 128 + 1) \
        PJS_OVS_STRING(state, 128 + 1) \
    )

#define PJS_SCHEMA_AW_LM_Config \
    PJS(schema_AW_LM_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 16 + 1) \
        PJS_OVS_STRING_Q(periodicity, 128 + 1) \
        PJS_OVS_STRING_Q(upload_location, 128 + 1) \
        PJS_OVS_STRING_Q(upload_token, 64 + 1) \
    )

#define PJS_SCHEMA_AW_LM_State \
    PJS(schema_AW_LM_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 16 + 1) \
        PJS_OVS_INT(log_trigger) \
    )

#define PJS_SCHEMA_AW_Debug \
    PJS(schema_AW_Debug, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 16 + 1) \
        PJS_OVS_STRING(log_severity, 128 + 1) \
    )

#define PJS_SCHEMA_AW_Bluetooth_Config \
    PJS(schema_AW_Bluetooth_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(mode, 128 + 1) \
        PJS_OVS_INT_Q(interval_millis) \
        PJS_OVS_INT_Q(txpower) \
        PJS_OVS_STRING_Q(command, 128 + 1) \
        PJS_OVS_STRING_Q(payload, 18 + 1) \
    )

#define PJS_SCHEMA_AW_Bluetooth_State \
    PJS(schema_AW_Bluetooth_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(mode, 128 + 1) \
        PJS_OVS_INT_Q(interval_millis) \
        PJS_OVS_INT_Q(txpower) \
        PJS_OVS_STRING_Q(command, 128 + 1) \
        PJS_OVS_STRING_Q(payload, 18 + 1) \
    )

#define PJS_SCHEMA_Open_vSwitch \
    PJS(schema_Open_vSwitch, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_SET_UUID(bridges, 64) \
        PJS_OVS_SET_UUID(manager_options, 64) \
        PJS_OVS_UUID_Q(ssl) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
        PJS_OVS_INT(next_cfg) \
        PJS_OVS_INT(cur_cfg) \
        PJS_OVS_SMAP_STRING(statistics, 64, 64 + 1) \
        PJS_OVS_STRING_Q(ovs_version, 128 + 1) \
        PJS_OVS_STRING_Q(db_version, 128 + 1) \
        PJS_OVS_STRING_Q(system_type, 128 + 1) \
        PJS_OVS_STRING_Q(system_version, 128 + 1) \
        PJS_OVS_SET_STRING(datapath_types, 64, 64 + 1) \
        PJS_OVS_SET_STRING(iface_types, 64, 64 + 1) \
        PJS_OVS_BOOL(dpdk_initialized) \
        PJS_OVS_STRING_Q(dpdk_version, 128 + 1) \
    )

#define PJS_SCHEMA_Bridge \
    PJS(schema_Bridge, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 128 + 1) \
        PJS_OVS_STRING(datapath_type, 128 + 1) \
        PJS_OVS_STRING(datapath_version, 128 + 1) \
        PJS_OVS_STRING_Q(datapath_id, 128 + 1) \
        PJS_OVS_BOOL(stp_enable) \
        PJS_OVS_BOOL(rstp_enable) \
        PJS_OVS_BOOL(mcast_snooping_enable) \
        PJS_OVS_SET_UUID(ports, 64) \
        PJS_OVS_SET_UUID(mirrors, 64) \
        PJS_OVS_UUID_Q(netflow) \
        PJS_OVS_UUID_Q(sflow) \
        PJS_OVS_UUID_Q(ipfix) \
        PJS_OVS_SET_UUID(controller, 64) \
        PJS_OVS_SET_STRING(protocols, 64, 64 + 1) \
        PJS_OVS_STRING_Q(fail_mode, 128 + 1) \
        PJS_OVS_SMAP_STRING(status, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(rstp_status, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
        PJS_OVS_SET_INT(flood_vlans, 4096) \
        PJS_OVS_DMAP_UUID(flow_tables, 64) \
        PJS_OVS_UUID_Q(auto_attach) \
    )

#define PJS_SCHEMA_Port \
    PJS(schema_Port, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 128 + 1) \
        PJS_OVS_SET_UUID(interfaces, 64) \
        PJS_OVS_SET_INT(trunks, 4096) \
        PJS_OVS_SET_INT(cvlans, 4096) \
        PJS_OVS_INT_Q(tag) \
        PJS_OVS_STRING_Q(vlan_mode, 128 + 1) \
        PJS_OVS_UUID_Q(qos) \
        PJS_OVS_STRING_Q(mac, 128 + 1) \
        PJS_OVS_STRING_Q(bond_mode, 128 + 1) \
        PJS_OVS_STRING_Q(lacp, 128 + 1) \
        PJS_OVS_INT(bond_updelay) \
        PJS_OVS_INT(bond_downdelay) \
        PJS_OVS_STRING_Q(bond_active_slave, 128 + 1) \
        PJS_OVS_BOOL(bond_fake_iface) \
        PJS_OVS_BOOL(fake_bridge) \
        PJS_OVS_SMAP_STRING(status, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(rstp_status, 64, 64 + 1) \
        PJS_OVS_SMAP_INT(rstp_statistics, 64) \
        PJS_OVS_SMAP_INT(statistics, 64) \
        PJS_OVS_BOOL(port_protected) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Interface \
    PJS(schema_Interface, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 128 + 1) \
        PJS_OVS_STRING(type, 128 + 1) \
        PJS_OVS_SMAP_STRING(options, 64, 64 + 1) \
        PJS_OVS_INT(ingress_policing_rate) \
        PJS_OVS_INT(ingress_policing_burst) \
        PJS_OVS_STRING_Q(mac_in_use, 128 + 1) \
        PJS_OVS_STRING_Q(mac, 128 + 1) \
        PJS_OVS_INT_Q(ifindex) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
        PJS_OVS_INT_Q(ofport) \
        PJS_OVS_INT_Q(ofport_request) \
        PJS_OVS_SMAP_STRING(bfd, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(bfd_status, 64, 64 + 1) \
        PJS_OVS_INT_Q(cfm_mpid) \
        PJS_OVS_SET_INT(cfm_remote_mpids, 64) \
        PJS_OVS_INT_Q(cfm_flap_count) \
        PJS_OVS_BOOL_Q(cfm_fault) \
        PJS_OVS_SET_STRING(cfm_fault_status, 64, 64 + 1) \
        PJS_OVS_STRING_Q(cfm_remote_opstate, 128 + 1) \
        PJS_OVS_INT_Q(cfm_health) \
        PJS_OVS_BOOL_Q(lacp_current) \
        PJS_OVS_SMAP_STRING(lldp, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_INT(statistics, 64) \
        PJS_OVS_SMAP_STRING(status, 64, 64 + 1) \
        PJS_OVS_STRING_Q(admin_state, 128 + 1) \
        PJS_OVS_STRING_Q(link_state, 128 + 1) \
        PJS_OVS_INT_Q(link_resets) \
        PJS_OVS_INT_Q(link_speed) \
        PJS_OVS_STRING_Q(duplex, 128 + 1) \
        PJS_OVS_INT_Q(mtu) \
        PJS_OVS_INT_Q(mtu_request) \
        PJS_OVS_STRING_Q(error, 128 + 1) \
    )

#define PJS_SCHEMA_Flow_Table \
    PJS(schema_Flow_Table, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(name, 128 + 1) \
        PJS_OVS_INT_Q(flow_limit) \
        PJS_OVS_STRING_Q(overflow_policy, 128 + 1) \
        PJS_OVS_SET_STRING(groups, 64, 64 + 1) \
        PJS_OVS_SET_STRING(prefixes, 64, 3 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_QoS \
    PJS(schema_QoS, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(type, 128 + 1) \
        PJS_OVS_DMAP_UUID(queues, 64) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Queue \
    PJS(schema_Queue, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT_Q(dscp) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Mirror \
    PJS(schema_Mirror, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 128 + 1) \
        PJS_OVS_BOOL(select_all) \
        PJS_OVS_SET_UUID(select_src_port, 64) \
        PJS_OVS_SET_UUID(select_dst_port, 64) \
        PJS_OVS_SET_INT(select_vlan, 4096) \
        PJS_OVS_UUID_Q(output_port) \
        PJS_OVS_INT_Q(output_vlan) \
        PJS_OVS_INT_Q(snaplen) \
        PJS_OVS_SMAP_INT(statistics, 64) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_NetFlow \
    PJS(schema_NetFlow, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_SET_STRING(targets, 64, 64 + 1) \
        PJS_OVS_INT_Q(engine_type) \
        PJS_OVS_INT_Q(engine_id) \
        PJS_OVS_BOOL(add_id_to_interface) \
        PJS_OVS_INT(active_timeout) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_sFlow \
    PJS(schema_sFlow, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_SET_STRING(targets, 64, 64 + 1) \
        PJS_OVS_INT_Q(sampling) \
        PJS_OVS_INT_Q(polling) \
        PJS_OVS_INT_Q(header) \
        PJS_OVS_STRING_Q(agent, 128 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_IPFIX \
    PJS(schema_IPFIX, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_SET_STRING(targets, 64, 64 + 1) \
        PJS_OVS_INT_Q(sampling) \
        PJS_OVS_INT_Q(obs_domain_id) \
        PJS_OVS_INT_Q(obs_point_id) \
        PJS_OVS_INT_Q(cache_active_timeout) \
        PJS_OVS_INT_Q(cache_max_flows) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Flow_Sample_Collector_Set \
    PJS(schema_Flow_Sample_Collector_Set, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(id) \
        PJS_OVS_UUID(bridge) \
        PJS_OVS_UUID_Q(ipfix) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Controller \
    PJS(schema_Controller, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(target, 128 + 1) \
        PJS_OVS_INT_Q(max_backoff) \
        PJS_OVS_INT_Q(inactivity_probe) \
        PJS_OVS_STRING_Q(connection_mode, 128 + 1) \
        PJS_OVS_STRING_Q(local_ip, 128 + 1) \
        PJS_OVS_STRING_Q(local_netmask, 128 + 1) \
        PJS_OVS_STRING_Q(local_gateway, 128 + 1) \
        PJS_OVS_BOOL_Q(enable_async_messages) \
        PJS_OVS_INT_Q(controller_rate_limit) \
        PJS_OVS_INT_Q(controller_burst_limit) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
        PJS_OVS_BOOL(is_connected) \
        PJS_OVS_STRING_Q(role, 128 + 1) \
        PJS_OVS_SMAP_STRING(status, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Manager \
    PJS(schema_Manager, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(target, 128 + 1) \
        PJS_OVS_INT_Q(max_backoff) \
        PJS_OVS_INT_Q(inactivity_probe) \
        PJS_OVS_STRING_Q(connection_mode, 128 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
        PJS_OVS_BOOL(is_connected) \
        PJS_OVS_SMAP_STRING(status, 64, 64 + 1) \
    )

#define PJS_SCHEMA_SSL \
    PJS(schema_SSL, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(private_key, 128 + 1) \
        PJS_OVS_STRING(certificate, 128 + 1) \
        PJS_OVS_STRING(ca_cert, 128 + 1) \
        PJS_OVS_BOOL(bootstrap_ca_cert) \
        PJS_OVS_SMAP_STRING(external_ids, 64, 64 + 1) \
    )

#define PJS_SCHEMA_AutoAttach \
    PJS(schema_AutoAttach, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(system_name, 128 + 1) \
        PJS_OVS_STRING(system_description, 128 + 1) \
        PJS_OVS_DMAP_INT(mappings, 64) \
    )

#define PJS_SCHEMA_BeaconReport \
    PJS(schema_BeaconReport, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_name, 128 + 1) \
        PJS_OVS_STRING(DstMac, 128 + 1) \
        PJS_OVS_STRING(Bssid, 128 + 1) \
        PJS_OVS_INT(RegulatoryClass) \
        PJS_OVS_INT(ChanNum) \
        PJS_OVS_INT(RandomInterval) \
        PJS_OVS_INT(Duration) \
        PJS_OVS_INT(Mode) \
    )

#define PJS_SCHEMA_Wifi_Stats_Config \
    PJS(schema_Wifi_Stats_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(stats_type, 128 + 1) \
        PJS_OVS_STRING_Q(report_type, 128 + 1) \
        PJS_OVS_STRING(radio_type, 128 + 1) \
        PJS_OVS_STRING_Q(survey_type, 128 + 1) \
        PJS_OVS_INT(reporting_interval) \
        PJS_OVS_INT(reporting_count) \
        PJS_OVS_INT(sampling_interval) \
        PJS_OVS_INT_Q(survey_interval_ms) \
        PJS_OVS_SET_INT(channel_list, 64) \
        PJS_OVS_SMAP_INT(threshold, 4) \
    )

#define PJS_SCHEMA_DHCP_reserved_IP \
    PJS(schema_DHCP_reserved_IP, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING_Q(hostname, 63 + 1) \
        PJS_OVS_STRING(ip_addr, 15 + 1) \
        PJS_OVS_STRING(hw_addr, 17 + 1) \
    )

#define PJS_SCHEMA_IP_Port_Forward \
    PJS(schema_IP_Port_Forward, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(protocol, 128 + 1) \
        PJS_OVS_STRING(src_ifname, 15 + 1) \
        PJS_OVS_INT(src_port) \
        PJS_OVS_INT(dst_port) \
        PJS_OVS_STRING(dst_ipaddr, 15 + 1) \
    )

#define PJS_SCHEMA_OVS_MAC_Learning \
    PJS(schema_OVS_MAC_Learning, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(brname, 15 + 1) \
        PJS_OVS_STRING(ifname, 15 + 1) \
        PJS_OVS_STRING(hwaddr, 17 + 1) \
        PJS_OVS_INT(vlan) \
    )

#define PJS_SCHEMA_Wifi_Speedtest_Config \
    PJS(schema_Wifi_Speedtest_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(testid) \
        PJS_OVS_REAL(traffic_cap) \
        PJS_OVS_INT(delay) \
        PJS_OVS_STRING(test_type, 128 + 1) \
        PJS_OVS_SET_INT(preferred_list, 32) \
        PJS_OVS_INT_Q(select_server_id) \
        PJS_OVS_STRING_Q(st_server, 128 + 1) \
        PJS_OVS_INT_Q(st_port) \
        PJS_OVS_INT_Q(st_len) \
        PJS_OVS_INT_Q(st_parallel) \
        PJS_OVS_BOOL_Q(st_udp) \
        PJS_OVS_INT_Q(st_bw) \
        PJS_OVS_INT_Q(st_pkt_len) \
        PJS_OVS_STRING_Q(st_dir, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Speedtest_Status \
    PJS(schema_Wifi_Speedtest_Status, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(testid) \
        PJS_OVS_REAL_Q(UL) \
        PJS_OVS_REAL_Q(DL) \
        PJS_OVS_STRING_Q(server_name, 128 + 1) \
        PJS_OVS_STRING_Q(server_IP, 128 + 1) \
        PJS_OVS_STRING_Q(ISP, 128 + 1) \
        PJS_OVS_REAL_Q(RTT) \
        PJS_OVS_REAL_Q(jitter) \
        PJS_OVS_REAL_Q(duration) \
        PJS_OVS_INT_Q(timestamp) \
        PJS_OVS_INT(status) \
        PJS_OVS_INT_Q(DL_bytes) \
        PJS_OVS_INT_Q(UL_bytes) \
        PJS_OVS_REAL_Q(DL_duration) \
        PJS_OVS_REAL_Q(UL_duration) \
        PJS_OVS_STRING_Q(test_type, 128 + 1) \
        PJS_OVS_BOOL_Q(pref_selected) \
        PJS_OVS_BOOL_Q(hranked_offered) \
        PJS_OVS_REAL_Q(DL_pkt_loss) \
        PJS_OVS_REAL_Q(UL_pkt_loss) \
        PJS_OVS_REAL_Q(DL_jitter) \
        PJS_OVS_REAL_Q(UL_jitter) \
        PJS_OVS_STRING_Q(host_remote, 128 + 1) \
    )

#define PJS_SCHEMA_Band_Steering_Config \
    PJS(schema_Band_Steering_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(if_name_2g, 16 + 1) \
        PJS_OVS_STRING(if_name_5g, 16 + 1) \
        PJS_OVS_INT(chan_util_check_sec) \
        PJS_OVS_INT(chan_util_avg_count) \
        PJS_OVS_INT(chan_util_hwm) \
        PJS_OVS_INT(chan_util_lwm) \
        PJS_OVS_INT(inact_check_sec) \
        PJS_OVS_INT(inact_tmout_sec_normal) \
        PJS_OVS_INT(inact_tmout_sec_overload) \
        PJS_OVS_INT(def_rssi_inact_xing) \
        PJS_OVS_INT(def_rssi_low_xing) \
        PJS_OVS_INT(def_rssi_xing) \
        PJS_OVS_INT(kick_debounce_thresh) \
        PJS_OVS_INT(kick_debounce_period) \
        PJS_OVS_INT(success_threshold_secs) \
        PJS_OVS_INT(stats_report_interval) \
        PJS_OVS_BOOL_Q(dbg_2g_raw_chan_util) \
        PJS_OVS_BOOL_Q(dbg_5g_raw_chan_util) \
        PJS_OVS_BOOL_Q(dbg_2g_raw_rssi) \
        PJS_OVS_BOOL_Q(dbg_5g_raw_rssi) \
        PJS_OVS_INT(debug_level) \
        PJS_OVS_BOOL_Q(gw_only) \
        PJS_OVS_SMAP_STRING(ifnames, 64, 16 + 1) \
    )

#define PJS_SCHEMA_Band_Steering_Clients \
    PJS(schema_Band_Steering_Clients, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(mac, 17 + 1) \
        PJS_OVS_INT(hwm) \
        PJS_OVS_INT(lwm) \
        PJS_OVS_STRING(kick_type, 128 + 1) \
        PJS_OVS_INT(kick_reason) \
        PJS_OVS_STRING(reject_detection, 128 + 1) \
        PJS_OVS_INT(max_rejects) \
        PJS_OVS_INT(rejects_tmout_secs) \
        PJS_OVS_INT(backoff_secs) \
        PJS_OVS_INT_Q(backoff_exp_base) \
        PJS_OVS_BOOL_Q(steer_during_backoff) \
        PJS_OVS_INT_Q(sticky_kick_guard_time) \
        PJS_OVS_INT_Q(steering_kick_guard_time) \
        PJS_OVS_INT_Q(sticky_kick_backoff_time) \
        PJS_OVS_INT_Q(steering_kick_backoff_time) \
        PJS_OVS_INT_Q(settling_backoff_time) \
        PJS_OVS_BOOL_Q(send_rrm_after_assoc) \
        PJS_OVS_BOOL_Q(send_rrm_after_xing) \
        PJS_OVS_INT_Q(rrm_better_factor) \
        PJS_OVS_INT_Q(rrm_age_time) \
        PJS_OVS_INT_Q(active_treshold_bps) \
        PJS_OVS_INT(steering_success_cnt) \
        PJS_OVS_INT(steering_fail_cnt) \
        PJS_OVS_INT(steering_kick_cnt) \
        PJS_OVS_INT(sticky_kick_cnt) \
        PJS_OVS_SMAP_INT(stats_2g, 32) \
        PJS_OVS_SMAP_INT(stats_5g, 32) \
        PJS_OVS_INT(kick_debounce_period) \
        PJS_OVS_STRING_Q(sc_kick_type, 128 + 1) \
        PJS_OVS_INT(sc_kick_reason) \
        PJS_OVS_INT(sc_kick_debounce_period) \
        PJS_OVS_INT(sticky_kick_debounce_period) \
        PJS_OVS_STRING_Q(cs_mode, 128 + 1) \
        PJS_OVS_SMAP_STRING(cs_params, 32, 16 + 1) \
        PJS_OVS_STRING_Q(cs_state, 128 + 1) \
        PJS_OVS_STRING_Q(sticky_kick_type, 128 + 1) \
        PJS_OVS_INT(sticky_kick_reason) \
        PJS_OVS_SMAP_STRING(steering_btm_params, 32, 32 + 1) \
        PJS_OVS_SMAP_STRING(sc_btm_params, 32, 32 + 1) \
        PJS_OVS_SMAP_STRING(sticky_btm_params, 32, 32 + 1) \
        PJS_OVS_STRING_Q(pref_5g, 128 + 1) \
        PJS_OVS_BOOL_Q(kick_upon_idle) \
        PJS_OVS_BOOL_Q(pre_assoc_auth_block) \
        PJS_OVS_SMAP_STRING(rrm_bcn_rpt_params, 32, 32 + 1) \
        PJS_OVS_STRING_Q(force_kick, 128 + 1) \
        PJS_OVS_STRING_Q(pref_bs_allowed, 128 + 1) \
        PJS_OVS_INT_Q(preq_snr_thr) \
    )

#define PJS_SCHEMA_Openflow_Config \
    PJS(schema_Openflow_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(bridge, 16 + 1) \
        PJS_OVS_INT(table) \
        PJS_OVS_INT(priority) \
        PJS_OVS_STRING_Q(rule, 255 + 1) \
        PJS_OVS_STRING(action, 128 + 1) \
        PJS_OVS_STRING(token, 64 + 1) \
    )

#define PJS_SCHEMA_Openflow_State \
    PJS(schema_Openflow_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(bridge, 16 + 1) \
        PJS_OVS_UUID_Q(openflow_config) \
        PJS_OVS_STRING(token, 32 + 1) \
        PJS_OVS_BOOL_Q(success) \
    )

#define PJS_SCHEMA_Openflow_Tag \
    PJS(schema_Openflow_Tag, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 32 + 1) \
        PJS_OVS_SET_STRING(device_value, 64, 255 + 1) \
        PJS_OVS_SET_STRING(cloud_value, 64, 255 + 1) \
    )

#define PJS_SCHEMA_Openflow_Tag_Group \
    PJS(schema_Openflow_Tag_Group, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 32 + 1) \
        PJS_OVS_SET_STRING(tags, 32, 128 + 1) \
    )

#define PJS_SCHEMA_Client_Nickname_Config \
    PJS(schema_Client_Nickname_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(nickname, 255 + 1) \
        PJS_OVS_STRING(mac, 255 + 1) \
    )

#define PJS_SCHEMA_Client_Freeze_Config \
    PJS(schema_Client_Freeze_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(mac, 255 + 1) \
        PJS_OVS_STRING_Q(source, 128 + 1) \
        PJS_OVS_STRING_Q(type, 128 + 1) \
        PJS_OVS_BOOL_Q(blocked) \
    )

#define PJS_SCHEMA_Node_Config \
    PJS(schema_Node_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL_Q(persist) \
        PJS_OVS_STRING(module, 32 + 1) \
        PJS_OVS_STRING(key, 64 + 1) \
        PJS_OVS_STRING(value, 1024 + 1) \
    )

#define PJS_SCHEMA_Node_State \
    PJS(schema_Node_State, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL_Q(persist) \
        PJS_OVS_STRING(module, 32 + 1) \
        PJS_OVS_STRING(key, 64 + 1) \
        PJS_OVS_STRING(value, 1024 + 1) \
    )

#define PJS_SCHEMA_Flow_Service_Manager_Config \
    PJS(schema_Flow_Service_Manager_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(handler, 64 + 1) \
        PJS_OVS_STRING_Q(type, 128 + 1) \
        PJS_OVS_STRING(if_name, 32 + 1) \
        PJS_OVS_STRING(pkt_capt_filter, 512 + 1) \
        PJS_OVS_STRING(plugin, 128 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 128, 64 + 1) \
    )

#define PJS_SCHEMA_FSM_Policy \
    PJS(schema_FSM_Policy, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 32 + 1) \
        PJS_OVS_INT(idx) \
        PJS_OVS_STRING_Q(mac_op, 128 + 1) \
        PJS_OVS_SET_STRING(macs, 256, 64 + 1) \
        PJS_OVS_STRING_Q(fqdn_op, 128 + 1) \
        PJS_OVS_SET_STRING(fqdns, 256, 64 + 1) \
        PJS_OVS_STRING_Q(fqdncat_op, 128 + 1) \
        PJS_OVS_SET_INT(fqdncats, 512) \
        PJS_OVS_STRING_Q(ipaddr_op, 128 + 1) \
        PJS_OVS_SET_STRING(ipaddrs, 48, 64 + 1) \
        PJS_OVS_INT_Q(risk_level) \
        PJS_OVS_STRING_Q(risk_op, 128 + 1) \
        PJS_OVS_STRING_Q(log, 128 + 1) \
        PJS_OVS_STRING_Q(action, 128 + 1) \
        PJS_OVS_SMAP_INT(next, 2) \
        PJS_OVS_STRING_Q(policy, 256 + 1) \
        PJS_OVS_SET_STRING(redirect, 256, 2 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Wifi_VIF_Neighbors \
    PJS(schema_Wifi_VIF_Neighbors, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(bssid, 32 + 1) \
        PJS_OVS_STRING(if_name, 32 + 1) \
        PJS_OVS_INT_Q(channel) \
        PJS_OVS_STRING_Q(ht_mode, 128 + 1) \
        PJS_OVS_INT_Q(priority) \
    )

#define PJS_SCHEMA_FCM_Collector_Config \
    PJS(schema_FCM_Collector_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 32 + 1) \
        PJS_OVS_INT(interval) \
        PJS_OVS_STRING_Q(filter_name, 32 + 1) \
        PJS_OVS_STRING_Q(report_name, 32 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
    )

#define PJS_SCHEMA_FCM_Filter \
    PJS(schema_FCM_Filter, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 128 + 1) \
        PJS_OVS_INT(index) \
        PJS_OVS_SET_STRING(smac, 64, 64 + 1) \
        PJS_OVS_SET_STRING(dmac, 64, 64 + 1) \
        PJS_OVS_SET_INT(vlanid, 64) \
        PJS_OVS_SET_STRING(src_ip, 64, 64 + 1) \
        PJS_OVS_SET_STRING(dst_ip, 64, 64 + 1) \
        PJS_OVS_SET_STRING(src_port, 64, 64 + 1) \
        PJS_OVS_SET_STRING(dst_port, 64, 64 + 1) \
        PJS_OVS_SET_INT(proto, 64) \
        PJS_OVS_SET_STRING(appnames, 64, 64 + 1) \
        PJS_OVS_STRING_Q(appname_op, 128 + 1) \
        PJS_OVS_SET_STRING(apptags, 64, 64 + 1) \
        PJS_OVS_STRING_Q(apptag_op, 128 + 1) \
        PJS_OVS_STRING_Q(smac_op, 128 + 1) \
        PJS_OVS_STRING_Q(dmac_op, 128 + 1) \
        PJS_OVS_STRING_Q(vlanid_op, 128 + 1) \
        PJS_OVS_STRING_Q(src_ip_op, 128 + 1) \
        PJS_OVS_STRING_Q(dst_ip_op, 128 + 1) \
        PJS_OVS_STRING_Q(src_port_op, 128 + 1) \
        PJS_OVS_STRING_Q(dst_port_op, 128 + 1) \
        PJS_OVS_STRING_Q(proto_op, 128 + 1) \
        PJS_OVS_INT_Q(pktcnt) \
        PJS_OVS_STRING_Q(pktcnt_op, 128 + 1) \
        PJS_OVS_STRING_Q(action, 128 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
    )

#define PJS_SCHEMA_FCM_Report_Config \
    PJS(schema_FCM_Report_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 32 + 1) \
        PJS_OVS_INT(interval) \
        PJS_OVS_STRING_Q(format, 128 + 1) \
        PJS_OVS_INT(hist_interval) \
        PJS_OVS_STRING_Q(hist_filter, 32 + 1) \
        PJS_OVS_STRING_Q(report_filter, 32 + 1) \
        PJS_OVS_STRING_Q(mqtt_topic, 256 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
    )

#define PJS_SCHEMA_IP_Interface \
    PJS(schema_IP_Interface, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 64 + 1) \
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING_Q(status, 128 + 1) \
        PJS_OVS_SET_UUID(interfaces, 4) \
        PJS_OVS_STRING_Q(if_name, 64 + 1) \
        PJS_OVS_SET_UUID(ipv4_addr, 64) \
        PJS_OVS_SET_UUID(ipv6_addr, 64) \
        PJS_OVS_SET_UUID(ipv6_prefix, 64) \
    )

#define PJS_SCHEMA_IPv4_Address \
    PJS(schema_IPv4_Address, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING_Q(status, 128 + 1) \
        PJS_OVS_STRING(address, 15 + 1) \
        PJS_OVS_STRING(subnet_mask, 15 + 1) \
        PJS_OVS_STRING(type, 128 + 1) \
    )

#define PJS_SCHEMA_IPv6_Address \
    PJS(schema_IPv6_Address, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING_Q(status, 128 + 1) \
        PJS_OVS_STRING_Q(address_status, 128 + 1) \
        PJS_OVS_STRING(address, 49 + 1) \
        PJS_OVS_STRING_Q(origin, 128 + 1) \
        PJS_OVS_STRING(prefix, 49 + 1) \
        PJS_OVS_STRING_Q(preferred_lifetime, 64 + 1) \
        PJS_OVS_STRING_Q(valid_lifetime, 64 + 1) \
    )

#define PJS_SCHEMA_IPv6_Prefix \
    PJS(schema_IPv6_Prefix, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING_Q(status, 128 + 1) \
        PJS_OVS_STRING_Q(prefix_status, 128 + 1) \
        PJS_OVS_STRING(address, 49 + 1) \
        PJS_OVS_STRING_Q(origin, 128 + 1) \
        PJS_OVS_STRING(static_type, 128 + 1) \
        PJS_OVS_UUID_Q(parent_prefix) \
        PJS_OVS_STRING_Q(child_prefix_bits, 49 + 1) \
        PJS_OVS_BOOL(on_link) \
        PJS_OVS_BOOL(autonomous) \
        PJS_OVS_STRING_Q(preferred_lifetime, 64 + 1) \
        PJS_OVS_STRING_Q(valid_lifetime, 64 + 1) \
    )

#define PJS_SCHEMA_DHCPv4_Client \
    PJS(schema_DHCPv4_Client, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_UUID(ip_interface) \
        PJS_OVS_SET_INT(request_options, 32) \
        PJS_OVS_SET_UUID(received_options, 32) \
        PJS_OVS_SET_UUID(send_options, 32) \
    )

#define PJS_SCHEMA_DHCPv6_Client \
    PJS(schema_DHCPv6_Client, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_UUID(ip_interface) \
        PJS_OVS_BOOL(request_address) \
        PJS_OVS_BOOL(request_prefixes) \
        PJS_OVS_BOOL(rapid_commit) \
        PJS_OVS_BOOL(renew) \
        PJS_OVS_SET_INT(request_options, 32) \
        PJS_OVS_SET_UUID(received_options, 32) \
        PJS_OVS_SET_UUID(send_options, 32) \
    )

#define PJS_SCHEMA_DHCP_Option \
    PJS(schema_DHCP_Option, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING(version, 128 + 1) \
        PJS_OVS_STRING(type, 128 + 1) \
        PJS_OVS_INT(tag) \
        PJS_OVS_STRING(value, 340 + 1) \
    )

#define PJS_SCHEMA_Netfilter \
    PJS(schema_Netfilter, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 64 + 1) \
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING_Q(status, 128 + 1) \
        PJS_OVS_STRING(protocol, 128 + 1) \
        PJS_OVS_STRING(table, 128 + 1) \
        PJS_OVS_STRING(chain, 64 + 1) \
        PJS_OVS_INT(priority) \
        PJS_OVS_STRING(rule, 512 + 1) \
        PJS_OVS_STRING(target, 64 + 1) \
    )

#define PJS_SCHEMA_Routing \
    PJS(schema_Routing, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_STRING_Q(status, 128 + 1) \
        PJS_OVS_STRING(protocol, 128 + 1) \
        PJS_OVS_STRING(type, 128 + 1) \
        PJS_OVS_UUID_Q(ip_interface) \
        PJS_OVS_STRING_Q(dest, 49 + 1) \
        PJS_OVS_STRING_Q(gateway, 49 + 1) \
    )

#define PJS_SCHEMA_DHCPv4_Server \
    PJS(schema_DHCPv4_Server, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_UUID(interface) \
        PJS_OVS_STRING(status, 128 + 1) \
        PJS_OVS_STRING(min_address, 15 + 1) \
        PJS_OVS_STRING(max_address, 15 + 1) \
        PJS_OVS_INT(lease_time) \
        PJS_OVS_SET_UUID(options, 256) \
        PJS_OVS_SET_UUID(static_address, 64) \
        PJS_OVS_SET_UUID(leased_address, 256) \
    )

#define PJS_SCHEMA_DHCPv4_Lease \
    PJS(schema_DHCPv4_Lease, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(status, 128 + 1) \
        PJS_OVS_STRING(address, 15 + 1) \
        PJS_OVS_STRING(hwaddr, 17 + 1) \
        PJS_OVS_STRING_Q(hostname, 64 + 1) \
        PJS_OVS_INT_Q(leased_time) \
        PJS_OVS_STRING_Q(leased_fingerprint, 256 + 1) \
    )

#define PJS_SCHEMA_DHCPv6_Server \
    PJS(schema_DHCPv6_Server, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_UUID(interface) \
        PJS_OVS_STRING(status, 128 + 1) \
        PJS_OVS_SET_UUID(prefixes, 64) \
        PJS_OVS_BOOL_Q(prefix_delegation) \
        PJS_OVS_SET_UUID(options, 256) \
        PJS_OVS_SET_UUID(lease_prefix, 256) \
        PJS_OVS_SET_UUID(static_prefix, 64) \
    )

#define PJS_SCHEMA_DHCPv6_Lease \
    PJS(schema_DHCPv6_Lease, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(status, 128 + 1) \
        PJS_OVS_STRING(prefix, 49 + 1) \
        PJS_OVS_STRING_Q(duid, 260 + 1) \
        PJS_OVS_STRING_Q(hwaddr, 17 + 1) \
        PJS_OVS_STRING_Q(hostname, 64 + 1) \
        PJS_OVS_INT_Q(leased_time) \
    )

#define PJS_SCHEMA_IPv6_RouteAdv \
    PJS(schema_IPv6_RouteAdv, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_UUID(interface) \
        PJS_OVS_STRING(status, 128 + 1) \
        PJS_OVS_SET_UUID(prefixes, 64) \
        PJS_OVS_BOOL_Q(managed) \
        PJS_OVS_BOOL_Q(other_config) \
        PJS_OVS_BOOL_Q(home_agent) \
        PJS_OVS_INT_Q(max_adv_interval) \
        PJS_OVS_INT_Q(min_adv_interval) \
        PJS_OVS_INT_Q(default_lifetime) \
        PJS_OVS_STRING(preferred_router, 128 + 1) \
        PJS_OVS_INT_Q(mtu) \
        PJS_OVS_INT_Q(reachable_time) \
        PJS_OVS_INT_Q(retrans_timer) \
        PJS_OVS_INT_Q(current_hop_limit) \
        PJS_OVS_SET_UUID(rdnss, 16) \
        PJS_OVS_SET_STRING(dnssl, 253, 16 + 1) \
    )

#define PJS_SCHEMA_IPv6_Neighbors \
    PJS(schema_IPv6_Neighbors, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(address, 49 + 1) \
        PJS_OVS_STRING(hwaddr, 17 + 1) \
        PJS_OVS_STRING(if_name, 31 + 1) \
    )

#define PJS_SCHEMA_IGMP_Config \
    PJS(schema_IGMP_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(query_interval) \
        PJS_OVS_INT(query_response_interval) \
        PJS_OVS_INT(last_member_query_interval) \
        PJS_OVS_INT(query_robustness_value) \
        PJS_OVS_INT(maximum_groups) \
        PJS_OVS_INT(maximum_sources) \
        PJS_OVS_INT(maximum_members) \
        PJS_OVS_BOOL(fast_leave_enable) \
    )

#define PJS_SCHEMA_MLD_Config \
    PJS(schema_MLD_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(query_interval) \
        PJS_OVS_INT(query_response_interval) \
        PJS_OVS_INT(last_member_query_interval) \
        PJS_OVS_INT(query_robustness_value) \
        PJS_OVS_INT(maximum_groups) \
        PJS_OVS_INT(maximum_sources) \
        PJS_OVS_INT(maximum_members) \
        PJS_OVS_BOOL(fast_leave_enable) \
    )

#define PJS_SCHEMA_Reboot_Status \
    PJS(schema_Reboot_Status, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(count) \
        PJS_OVS_STRING(type, 128 + 1) \
        PJS_OVS_STRING(reason, 128 + 1) \
    )

#define PJS_SCHEMA_Service_Announcement \
    PJS(schema_Service_Announcement, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(name, 31 + 1) \
        PJS_OVS_STRING(protocol, 31 + 1) \
        PJS_OVS_INT(port) \
        PJS_OVS_SMAP_STRING(txt, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Node_Services \
    PJS(schema_Node_Services, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(service, 128 + 1) \
        PJS_OVS_BOOL_Q(enable) \
        PJS_OVS_STRING_Q(status, 128 + 1) \
        PJS_OVS_SMAP_STRING(other_config, 64, 64 + 1) \
    )

#define PJS_SCHEMA_Wifi_Anqp_Config \
    PJS(schema_Wifi_Anqp_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_INT(capability_length) \
        PJS_OVS_STRING(capability_element, 128 + 1) \
        PJS_OVS_INT(ipv6_address_type) \
        PJS_OVS_INT(ipv4_address_type) \
        PJS_OVS_INT(domain_name_length) \
        PJS_OVS_STRING(domain_name_element, 128 + 1) \
        PJS_OVS_INT(roaming_consortium_length) \
        PJS_OVS_STRING(roaming_consortium_element, 128 + 1) \
        PJS_OVS_INT(nai_realm_length) \
        PJS_OVS_STRING(nai_realm_element, 1024 + 1) \
        PJS_OVS_INT(gpp_cellular_length) \
        PJS_OVS_STRING(gpp_cellular_element, 128 + 1) \
        PJS_OVS_INT(venue_name_length) \
        PJS_OVS_STRING(venue_name_element, 128 + 1) \
        PJS_OVS_STRING(vap_name, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Passpoint_Config \
    PJS(schema_Wifi_Passpoint_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_BOOL(enable) \
        PJS_OVS_BOOL(group_addressed_forwarding_disable) \
        PJS_OVS_BOOL(p2p_cross_connect_disable) \
        PJS_OVS_INT(capability_length) \
        PJS_OVS_STRING(capability_element, 128 + 1) \
        PJS_OVS_INT(nai_home_realm_length) \
        PJS_OVS_STRING(nai_home_realm_element, 128 + 1) \
        PJS_OVS_INT(operator_friendly_name_length) \
        PJS_OVS_STRING(operator_friendly_name_element, 128 + 1) \
        PJS_OVS_INT(connection_capability_length) \
        PJS_OVS_STRING(connection_capability_element, 128 + 1) \
        PJS_OVS_STRING(vap_name,128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Radio_Config \
    PJS(schema_Wifi_Radio_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_STRING(radio_name, 36 + 1) \
        PJS_OVS_BOOL(enabled)\
        PJS_OVS_INT(freq_band) \
        PJS_OVS_BOOL(auto_channel_enabled) \
        PJS_OVS_INT(channel) \
        PJS_OVS_INT(num_secondary_channels) \
        PJS_OVS_STRING(secondary_channels_list, 128 + 1) \
        PJS_OVS_INT(channel_width) \
        PJS_OVS_INT(hw_mode) \
        PJS_OVS_INT(csa_beacon_count) \
        PJS_OVS_INT(country) \
        PJS_OVS_INT(operating_environment) \
        PJS_OVS_BOOL(dcs_enabled) \
        PJS_OVS_BOOL(dfs_enabled) \
        PJS_OVS_UUID(vap_configs) \
        PJS_OVS_INT(dtim_period) \
        PJS_OVS_INT(beacon_interval) \
        PJS_OVS_INT(operating_class) \
        PJS_OVS_INT(basic_data_transmit_rate) \
        PJS_OVS_INT(operational_data_transmit_rate) \
        PJS_OVS_INT(fragmentation_threshold) \
        PJS_OVS_INT(guard_interval) \
        PJS_OVS_INT(transmit_power) \
        PJS_OVS_INT(rts_threshold) \
        PJS_OVS_INT(factory_reset_ssid) \
        PJS_OVS_INT(radio_stats_measuring_rate) \
        PJS_OVS_INT(radio_stats_measuring_interval) \
        PJS_OVS_BOOL(cts_protection) \
        PJS_OVS_BOOL(obss_coex) \
        PJS_OVS_BOOL(stbc_enable) \
        PJS_OVS_BOOL(greenfield_enable) \
        PJS_OVS_INT(user_control) \
        PJS_OVS_INT(admin_control) \
        PJS_OVS_INT(chan_util_threshold) \
        PJS_OVS_BOOL(chan_util_selfheal_enable) \
        PJS_OVS_BOOL(eco_power_down) \
        PJS_OVS_INT(Tscan) \
        PJS_OVS_INT(Nscan) \
        PJS_OVS_INT(Tidle) \
    )

#define PJS_SCHEMA_Wifi_Global_Config \
    PJS(schema_Wifi_Global_Config, \
        PJS_OVS_UUID_Q(_uuid)\
        PJS_OVS_UUID_Q(_version)\
        PJS_OVS_UUID(gas_config)\
        PJS_OVS_BOOL(notify_wifi_changes) \
        PJS_OVS_BOOL(prefer_private) \
        PJS_OVS_BOOL(prefer_private_configure) \
        PJS_OVS_BOOL(factory_reset) \
        PJS_OVS_BOOL(tx_overflow_selfheal) \
        PJS_OVS_BOOL(inst_wifi_client_enabled) \
        PJS_OVS_INT(inst_wifi_client_reporting_period) \
        PJS_OVS_STRING(inst_wifi_client_mac, 128+1) \
        PJS_OVS_INT(inst_wifi_client_def_reporting_period) \
        PJS_OVS_BOOL(wifi_active_msmt_enabled) \
        PJS_OVS_INT(wifi_active_msmt_pktsize) \
        PJS_OVS_INT(wifi_active_msmt_num_samples) \
        PJS_OVS_INT(wifi_active_msmt_sample_duration) \
        PJS_OVS_INT(vlan_cfg_version) \
        PJS_OVS_STRING(wps_pin, 64+1) \
        PJS_OVS_BOOL(bandsteering_enable) \
        PJS_OVS_INT(good_rssi_threshold) \
        PJS_OVS_INT(assoc_count_threshold) \
        PJS_OVS_INT(assoc_gate_time) \
        PJS_OVS_INT(whix_log_interval) \
        PJS_OVS_INT(whix_chutility_loginterval) \
        PJS_OVS_INT(assoc_monitor_duration) \
        PJS_OVS_BOOL(rapid_reconnect_enable) \
        PJS_OVS_BOOL(vap_stats_feature) \
        PJS_OVS_BOOL(mfp_config_feature) \
        PJS_OVS_BOOL(force_disable_radio_feature) \
        PJS_OVS_BOOL(force_disable_radio_status) \
        PJS_OVS_INT(fixed_wmm_params) \
        PJS_OVS_STRING(wifi_region_code,4+1) \
        PJS_OVS_BOOL(diagnostic_enable) \
        PJS_OVS_BOOL(validate_ssid) \
        PJS_OVS_INT(device_network_mode) \
        PJS_OVS_STRING(normalized_rssi_list, 128 + 1) \
        PJS_OVS_STRING(snr_list, 128 + 1) \
        PJS_OVS_STRING(cli_stat_list, 128 + 1) \
        PJS_OVS_STRING(txrx_rate_list, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Preassoc_Control_Config \
    PJS(schema_Wifi_Preassoc_Control_Config, \
        PJS_OVS_UUID_Q(_uuid) \
        PJS_OVS_UUID_Q(_version) \
        PJS_OVS_STRING(rssi_up_threshold, 128 + 1) \
        PJS_OVS_STRING(snr_threshold, 128 + 1) \
        PJS_OVS_STRING(cu_threshold, 128 + 1) \
        PJS_OVS_STRING(basic_data_transmit_rates, 128 + 1) \
        PJS_OVS_STRING(operational_data_transmit_rates, 128 + 1) \
        PJS_OVS_STRING(supported_data_transmit_rates, 128 + 1) \
        PJS_OVS_STRING(minimum_advertised_mcs, 128 + 1) \
        PJS_OVS_STRING(sixGOpInfoMinRate, 128 + 1) \
        PJS_OVS_STRING(vap_name, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Postassoc_Control_Config \
    PJS(schema_Wifi_Postassoc_Control_Config, \
        PJS_OVS_UUID_Q(_uuid) \
        PJS_OVS_UUID_Q(_version) \
        PJS_OVS_STRING(rssi_up_threshold, 128 + 1) \
        PJS_OVS_STRING(sampling_interval, 128 + 1) \
        PJS_OVS_STRING(snr_threshold, 128 + 1) \
        PJS_OVS_STRING(sampling_count, 128 + 1) \
        PJS_OVS_STRING(cu_threshold, 128 + 1) \
        PJS_OVS_STRING(vap_name, 128 + 1) \
    )

#define PJS_SCHEMA_Wifi_Connection_Control_Config \
    PJS(schema_Wifi_Connection_Control_Config, \
        PJS_OVS_UUID_Q(_uuid) \
        PJS_OVS_UUID_Q(_version) \
        PJS_OVS_STRING(vap_name, 128 + 1) \
        PJS_OVS_UUID(pre_assoc) \
        PJS_OVS_UUID(post_assoc) \
    )

#define PJS_GEN_TABLE \
     PJS_SCHEMA_AWLAN_Node \
     PJS_SCHEMA_Wifi_Device_Config \
     PJS_SCHEMA_Wifi_Security_Config \
     PJS_SCHEMA_Wifi_VAP_Config \
     PJS_SCHEMA_Wifi_Interworking_Config \
     PJS_SCHEMA_Wifi_GAS_Config \
     PJS_SCHEMA_Alarms \
     PJS_SCHEMA_Wifi_Master_State \
     PJS_SCHEMA_Wifi_MacFilter_Config \
     PJS_SCHEMA_Wifi_Rfc_Config \
     PJS_SCHEMA_Wifi_Ethernet_State \
     PJS_SCHEMA_Connection_Manager_Uplink \
     PJS_SCHEMA_Wifi_Inet_Config \
     PJS_SCHEMA_Wifi_Inet_State \
     PJS_SCHEMA_Wifi_Route_State \
     PJS_SCHEMA_Wifi_Radio_Config \
     PJS_SCHEMA_Wifi_Radio_Config_ovs \
     PJS_SCHEMA_Wifi_Global_Config \
     PJS_SCHEMA_Wifi_Preassoc_Control_Config \
     PJS_SCHEMA_Wifi_Postassoc_Control_Config \
     PJS_SCHEMA_Wifi_Connection_Control_Config \
     PJS_SCHEMA_Wifi_Anqp_Config \
     PJS_SCHEMA_Wifi_Passpoint_Config \
     PJS_SCHEMA_Wifi_Radio_State \
     PJS_SCHEMA_Wifi_Credential_Config \
     PJS_SCHEMA_Wifi_VIF_Config \
     PJS_SCHEMA_Wifi_VIF_State \
     PJS_SCHEMA_Wifi_Associated_Clients \
     PJS_SCHEMA_DHCP_leased_IP \
     PJS_SCHEMA_Wifi_Test_Config \
     PJS_SCHEMA_Wifi_Test_State \
     PJS_SCHEMA_AW_LM_Config \
     PJS_SCHEMA_AW_LM_State \
     PJS_SCHEMA_AW_Debug \
     PJS_SCHEMA_AW_Bluetooth_Config \
     PJS_SCHEMA_AW_Bluetooth_State \
     PJS_SCHEMA_Open_vSwitch \
     PJS_SCHEMA_Bridge \
     PJS_SCHEMA_Port \
     PJS_SCHEMA_Interface \
     PJS_SCHEMA_Flow_Table \
     PJS_SCHEMA_QoS \
     PJS_SCHEMA_Queue \
     PJS_SCHEMA_Mirror \
     PJS_SCHEMA_NetFlow \
     PJS_SCHEMA_sFlow \
     PJS_SCHEMA_IPFIX \
     PJS_SCHEMA_Flow_Sample_Collector_Set \
     PJS_SCHEMA_Controller \
     PJS_SCHEMA_Manager \
     PJS_SCHEMA_SSL \
     PJS_SCHEMA_AutoAttach \
     PJS_SCHEMA_BeaconReport \
     PJS_SCHEMA_Wifi_Stats_Config \
     PJS_SCHEMA_DHCP_reserved_IP \
     PJS_SCHEMA_IP_Port_Forward \
     PJS_SCHEMA_OVS_MAC_Learning \
     PJS_SCHEMA_Wifi_Speedtest_Config \
     PJS_SCHEMA_Wifi_Speedtest_Status \
     PJS_SCHEMA_Band_Steering_Config \
     PJS_SCHEMA_Band_Steering_Clients \
     PJS_SCHEMA_Openflow_Config \
     PJS_SCHEMA_Openflow_State \
     PJS_SCHEMA_Openflow_Tag \
     PJS_SCHEMA_Openflow_Tag_Group \
     PJS_SCHEMA_Client_Nickname_Config \
     PJS_SCHEMA_Client_Freeze_Config \
     PJS_SCHEMA_Node_Config \
     PJS_SCHEMA_Node_State \
     PJS_SCHEMA_Flow_Service_Manager_Config \
     PJS_SCHEMA_FSM_Policy \
     PJS_SCHEMA_Wifi_VIF_Neighbors \
     PJS_SCHEMA_FCM_Collector_Config \
     PJS_SCHEMA_FCM_Filter \
     PJS_SCHEMA_FCM_Report_Config \
     PJS_SCHEMA_IP_Interface \
     PJS_SCHEMA_IPv4_Address \
     PJS_SCHEMA_IPv6_Address \
     PJS_SCHEMA_IPv6_Prefix \
     PJS_SCHEMA_DHCPv4_Client \
     PJS_SCHEMA_DHCPv6_Client \
     PJS_SCHEMA_DHCP_Option \
     PJS_SCHEMA_Netfilter \
     PJS_SCHEMA_Routing \
     PJS_SCHEMA_DHCPv4_Server \
     PJS_SCHEMA_DHCPv4_Lease \
     PJS_SCHEMA_DHCPv6_Server \
     PJS_SCHEMA_DHCPv6_Lease \
     PJS_SCHEMA_IPv6_RouteAdv \
     PJS_SCHEMA_IPv6_Neighbors \
     PJS_SCHEMA_IGMP_Config \
     PJS_SCHEMA_MLD_Config \
     PJS_SCHEMA_Reboot_Status \
     PJS_SCHEMA_Service_Announcement \
     PJS_SCHEMA_Node_Services

#define SCHEMA_LIST \
    SCHEMA(AWLAN_Node) \
    SCHEMA(Wifi_Device_Config) \
    SCHEMA(Wifi_Security_Config) \
    SCHEMA(Wifi_VAP_Config) \
    SCHEMA(Wifi_Interworking_Config) \
    SCHEMA(Wifi_GAS_Config) \
    SCHEMA(Wifi_Rfc_Config) \
    SCHEMA(Alarms) \
    SCHEMA(Wifi_Master_State) \
    SCHEMA(Wifi_Ethernet_State) \
    SCHEMA(Connection_Manager_Uplink) \
    SCHEMA(Wifi_Inet_Config) \
    SCHEMA(Wifi_Inet_State) \
    SCHEMA(Wifi_Route_State) \
    SCHEMA(Wifi_Radio_Config) \
    SCHEMA(Wifi_Radio_Config_ovs) \
    SCHEMA(Wifi_MacFilter_Config) \
    SCHEMA(Wifi_Global_Config) \
    SCHEMA(Wifi_Preassoc_Control_Config) \
    SCHEMA(Wifi_Postassoc_Control_Config) \
    SCHEMA(Wifi_Connection_Control_Config) \
    SCHEMA(Wifi_Anqp_Config) \
    SCHEMA(Wifi_Passpoint_Config) \
    SCHEMA(Wifi_Radio_State) \
    SCHEMA(Wifi_Credential_Config) \
    SCHEMA(Wifi_VIF_Config) \
    SCHEMA(Wifi_VIF_State) \
    SCHEMA(Wifi_Associated_Clients) \
    SCHEMA(DHCP_leased_IP) \
    SCHEMA(Wifi_Test_Config) \
    SCHEMA(Wifi_Test_State) \
    SCHEMA(AW_LM_Config) \
    SCHEMA(AW_LM_State) \
    SCHEMA(AW_Debug) \
    SCHEMA(AW_Bluetooth_Config) \
    SCHEMA(AW_Bluetooth_State) \
    SCHEMA(Open_vSwitch) \
    SCHEMA(Bridge) \
    SCHEMA(Port) \
    SCHEMA(Interface) \
    SCHEMA(Flow_Table) \
    SCHEMA(QoS) \
    SCHEMA(Queue) \
    SCHEMA(Mirror) \
    SCHEMA(NetFlow) \
    SCHEMA(sFlow) \
    SCHEMA(IPFIX) \
    SCHEMA(Flow_Sample_Collector_Set) \
    SCHEMA(Controller) \
    SCHEMA(Manager) \
    SCHEMA(SSL) \
    SCHEMA(AutoAttach) \
    SCHEMA(BeaconReport) \
    SCHEMA(Wifi_Stats_Config) \
    SCHEMA(DHCP_reserved_IP) \
    SCHEMA(IP_Port_Forward) \
    SCHEMA(OVS_MAC_Learning) \
    SCHEMA(Wifi_Speedtest_Config) \
    SCHEMA(Wifi_Speedtest_Status) \
    SCHEMA(Band_Steering_Config) \
    SCHEMA(Band_Steering_Clients) \
    SCHEMA(Openflow_Config) \
    SCHEMA(Openflow_State) \
    SCHEMA(Openflow_Tag) \
    SCHEMA(Openflow_Tag_Group) \
    SCHEMA(Client_Nickname_Config) \
    SCHEMA(Client_Freeze_Config) \
    SCHEMA(Node_Config) \
    SCHEMA(Node_State) \
    SCHEMA(Flow_Service_Manager_Config) \
    SCHEMA(FSM_Policy) \
    SCHEMA(Wifi_VIF_Neighbors) \
    SCHEMA(FCM_Collector_Config) \
    SCHEMA(FCM_Filter) \
    SCHEMA(FCM_Report_Config) \
    SCHEMA(IP_Interface) \
    SCHEMA(IPv4_Address) \
    SCHEMA(IPv6_Address) \
    SCHEMA(IPv6_Prefix) \
    SCHEMA(DHCPv4_Client) \
    SCHEMA(DHCPv6_Client) \
    SCHEMA(DHCP_Option) \
    SCHEMA(Netfilter) \
    SCHEMA(Routing) \
    SCHEMA(DHCPv4_Server) \
    SCHEMA(DHCPv4_Lease) \
    SCHEMA(DHCPv6_Server) \
    SCHEMA(DHCPv6_Lease) \
    SCHEMA(IPv6_RouteAdv) \
    SCHEMA(IPv6_Neighbors) \
    SCHEMA(IGMP_Config) \
    SCHEMA(MLD_Config) \
    SCHEMA(Reboot_Status) \
    SCHEMA(Service_Announcement) \
    SCHEMA(Node_Services)

#define SCHEMA_LISTX(SCHEMA) \
    SCHEMA(AWLAN_Node) \
    SCHEMA(Wifi_Device_Config) \
    SCHEMA(Wifi_Security_Config) \
    SCHEMA(Wifi_VAP_Config) \
    SCHEMA(Wifi_Interworking_Config) \
    SCHEMA(Wifi_GAS_Config) \
    SCHEMA(Wifi_Rfc_Config) \
    SCHEMA(Alarms) \
    SCHEMA(Wifi_MacFilter_Config) \
    SCHEMA(Wifi_Master_State) \
    SCHEMA(Wifi_Ethernet_State) \
    SCHEMA(Connection_Manager_Uplink) \
    SCHEMA(Wifi_Inet_Config) \
    SCHEMA(Wifi_Inet_State) \
    SCHEMA(Wifi_Route_State) \
    SCHEMA(Wifi_Radio_Config) \
    SCHEMA(Wifi_Radio_Config_ovs) \
    SCHEMA(Wifi_Anqp_Config) \
    SCHEMA(Wifi_Passpoint_Config) \
    SCHEMA(Wifi_Global_Config) \
    SCHEMA(Wifi_Preassoc_Control_Config) \
    SCHEMA(Wifi_Postassoc_Control_Config) \
    SCHEMA(Wifi_Connection_Control_Config) \
    SCHEMA(Wifi_Radio_State) \
    SCHEMA(Wifi_Credential_Config) \
    SCHEMA(Wifi_VIF_Config) \
    SCHEMA(Wifi_VIF_State) \
    SCHEMA(Wifi_Associated_Clients) \
    SCHEMA(DHCP_leased_IP) \
    SCHEMA(Wifi_Test_Config) \
    SCHEMA(Wifi_Test_State) \
    SCHEMA(AW_LM_Config) \
    SCHEMA(AW_LM_State) \
    SCHEMA(AW_Debug) \
    SCHEMA(AW_Bluetooth_Config) \
    SCHEMA(AW_Bluetooth_State) \
    SCHEMA(Open_vSwitch) \
    SCHEMA(Bridge) \
    SCHEMA(Port) \
    SCHEMA(Interface) \
    SCHEMA(Flow_Table) \
    SCHEMA(QoS) \
    SCHEMA(Queue) \
    SCHEMA(Mirror) \
    SCHEMA(NetFlow) \
    SCHEMA(sFlow) \
    SCHEMA(IPFIX) \
    SCHEMA(Flow_Sample_Collector_Set) \
    SCHEMA(Controller) \
    SCHEMA(Manager) \
    SCHEMA(SSL) \
    SCHEMA(AutoAttach) \
    SCHEMA(BeaconReport) \
    SCHEMA(Wifi_Stats_Config) \
    SCHEMA(DHCP_reserved_IP) \
    SCHEMA(IP_Port_Forward) \
    SCHEMA(OVS_MAC_Learning) \
    SCHEMA(Wifi_Speedtest_Config) \
    SCHEMA(Wifi_Speedtest_Status) \
    SCHEMA(Band_Steering_Config) \
    SCHEMA(Band_Steering_Clients) \
    SCHEMA(Openflow_Config) \
    SCHEMA(Openflow_State) \
    SCHEMA(Openflow_Tag) \
    SCHEMA(Openflow_Tag_Group) \
    SCHEMA(Client_Nickname_Config) \
    SCHEMA(Client_Freeze_Config) \
    SCHEMA(Node_Config) \
    SCHEMA(Node_State) \
    SCHEMA(Flow_Service_Manager_Config) \
    SCHEMA(FSM_Policy) \
    SCHEMA(Wifi_VIF_Neighbors) \
    SCHEMA(FCM_Collector_Config) \
    SCHEMA(FCM_Filter) \
    SCHEMA(FCM_Report_Config) \
    SCHEMA(IP_Interface) \
    SCHEMA(IPv4_Address) \
    SCHEMA(IPv6_Address) \
    SCHEMA(IPv6_Prefix) \
    SCHEMA(DHCPv4_Client) \
    SCHEMA(DHCPv6_Client) \
    SCHEMA(DHCP_Option) \
    SCHEMA(Netfilter) \
    SCHEMA(Routing) \
    SCHEMA(DHCPv4_Server) \
    SCHEMA(DHCPv4_Lease) \
    SCHEMA(DHCPv6_Server) \
    SCHEMA(DHCPv6_Lease) \
    SCHEMA(IPv6_RouteAdv) \
    SCHEMA(IPv6_Neighbors) \
    SCHEMA(IGMP_Config) \
    SCHEMA(MLD_Config) \
    SCHEMA(Reboot_Status) \
    SCHEMA(Service_Announcement) \
    SCHEMA(Node_Services)

#define SCHEMA__AWLAN_Node "AWLAN_Node"
#define SCHEMA_COLUMN__AWLAN_Node(COLUMN) \
    COLUMN(id) \
    COLUMN(model) \
    COLUMN(revision) \
    COLUMN(serial_number) \
    COLUMN(sku_number) \
    COLUMN(redirector_addr) \
    COLUMN(manager_addr) \
    COLUMN(led_config) \
    COLUMN(mqtt_settings) \
    COLUMN(mqtt_topics) \
    COLUMN(mqtt_headers) \
    COLUMN(platform_version) \
    COLUMN(firmware_version) \
    COLUMN(firmware_url) \
    COLUMN(firmware_pass) \
    COLUMN(upgrade_timer) \
    COLUMN(upgrade_dl_timer) \
    COLUMN(upgrade_status) \
    COLUMN(device_mode) \
    COLUMN(factory_reset) \
    COLUMN(version_matrix) \
    COLUMN(min_backoff) \
    COLUMN(max_backoff)

#define SCHEMA__Wifi_Device_Config "Wifi_Device_Config"
#define SCHEMA_COLUMN__Wifi_Device_Config(COLUMN) \
    COLUMN(device_mac) \
    COLUMN(device_name) \
    COLUMN(vap_name)

#define SCHEMA__Wifi_Security_Config "Wifi_Security_Config"
#define SCHEMA_COLUMN__Wifi_Security_Config(COLUMN) \
    COLUMN(security_mode) \
    COLUMN(encryption_method) \
    COLUMN(mfp_config)\
    COLUMN(key_type)\
    COLUMN(keyphrase)\
    COLUMN(radius_server_ip) \
    COLUMN(radius_server_port) \
    COLUMN(radius_server_key) \
    COLUMN(secondary_radius_server_ip) \
    COLUMN(secondary_radius_server_port) \
    COLUMN(secondary_radius_server_key) \
    COLUMN(vap_name)\
    COLUMN(das_ip) \
    COLUMN(das_port) \
    COLUMN(das_key)\
    COLUMN(rekey_interval)\
    COLUMN(strict_rekey)\
    COLUMN(eapol_key_timeout)\
    COLUMN(eapol_key_retries)\
    COLUMN(eap_identity_req_timeout)\
    COLUMN(eap_identity_req_retries)\
    COLUMN(eap_req_timeout)\
    COLUMN(eap_req_retries)\
    COLUMN(disable_pmksa_caching)\
    COLUMN(max_auth_attempts)\
    COLUMN(blacklist_table_timeout)\
    COLUMN(identity_req_retry_interval)\
    COLUMN(server_retries)\
    COLUMN(wpa3_transition_disable)

#define SCHEMA__Wifi_VAP_Config "Wifi_VAP_Config"
#define SCHEMA_COLUMN__Wifi_VAP_Config(COLUMN) \
    COLUMN(vap_name) \
    COLUMN(radio_name) \
    COLUMN(ssid)        \
    COLUMN(enabled) \
    COLUMN(exists) \
    COLUMN(ssid_advertisement_enabled) \
    COLUMN(isolation_enabled) \
    COLUMN(mgmt_power_control) \
    COLUMN(bss_max_sta) \
    COLUMN(bss_transition_activated) \
    COLUMN(nbr_report_activated) \
    COLUMN(rapid_connect_enabled) \
    COLUMN(rapid_connect_threshold) \
    COLUMN(vap_stats_enable) \
    COLUMN(security) \
    COLUMN(interworking) \
    COLUMN(mac_filter_enabled) \
    COLUMN(mac_filter_mode) \
    COLUMN(mac_addr_acl_enabled) \
    COLUMN(mac_filter) \
    COLUMN(wmm_enabled)\
    COLUMN(anqp_parameters)\
    COLUMN(hs2_parameters)\
    COLUMN(uapsd_enabled) \
    COLUMN(beacon_rate) \
    COLUMN(bridge_name)\
    COLUMN(wmm_noack) \
    COLUMN(wep_key_length) \
    COLUMN(bss_hotspot) \
    COLUMN(wps_push_button) \
    COLUMN(wps_config_methods) \
    COLUMN(wps_enabled) \
    COLUMN(beacon_rate_ctl) \
    COLUMN(network_initiated_greylist) \
    COLUMN(mfp_config)\
    COLUMN(period)\
    COLUMN(channel)\
    COLUMN(freq_band)\
    COLUMN(repurposed_vap_name)\
    COLUMN(connected_building_enabled)

#define SCHEMA__Wifi_Interworking_Config "Wifi_Interworking_Config"
#define SCHEMA_COLUMN__Wifi_Interworking_Config(COLUMN) \
    COLUMN(enable) \
    COLUMN(vap_name) \
    COLUMN(access_network_type) \
    COLUMN(internet) \
    COLUMN(asra) \
    COLUMN(esr) \
    COLUMN(uesa) \
    COLUMN(hess_option_present) \
    COLUMN(hessid) \
    COLUMN(venue_group) \
    COLUMN(venue_type)

#define SCHEMA__Wifi_GAS_Config "Wifi_GAS_Config"
#define SCHEMA_COLUMN__Wifi_GAS_Config(COLUMN) \
    COLUMN(advertisement_id) \
    COLUMN(pause_for_server_response) \
    COLUMN(response_timeout) \
    COLUMN(comeback_delay) \
    COLUMN(response_buffering_time) \
    COLUMN(query_responselength_limit)

#define SCHEMA__Wifi_Rfc_Config "Wifi_Rfc_Config"
#define SCHEMA_COLUMN__Wifi_Rfc_Config(COLUMN) \
    COLUMN(rfc_id) \
    COLUMN(wifipasspoint_rfc) \
    COLUMN(wifiinterworking_rfc) \
    COLUMN(radiusgreylist_rfc) \
    COLUMN(dfsatbootup_rfc) \
    COLUMN(dfs_rfc) \
    COLUMN(wpa3_rfc) \
    COLUMN(levl_enabled_rfc) \
    COLUMN(twoG80211axEnable_rfc) \
    COLUMN(hotspot_open_2g_last_enabled) \
    COLUMN(hotspot_open_5g_last_enabled) \
    COLUMN(hotspot_open_6g_last_enabled) \
    COLUMN(hotspot_secure_2g_last_enabled) \
    COLUMN(hotspot_secure_5g_last_enabled) \
    COLUMN(hotspot_secure_6g_last_enabled) \
    COLUMN(wifioffchannelscan_rfc)

#define SCHEMA__Wifi_MacFilter_Config "Wifi_MacFilter_Config"
#define SCHEMA_COLUMN__Wifi_MacFilter_Config(COLUMN) \
    COLUMN(macfilter_key) \
    COLUMN(device_name) \
    COLUMN(device_mac) \
    COLUMN(reason) \
    COLUMN(expiry_time)

#define SCHEMA__Alarms "Alarms"
#define SCHEMA_COLUMN__Alarms(COLUMN) \
    COLUMN(code) \
    COLUMN(timestamp) \
    COLUMN(source) \
    COLUMN(add_info)

#define SCHEMA__Wifi_Master_State "Wifi_Master_State"
#define SCHEMA_COLUMN__Wifi_Master_State(COLUMN) \
    COLUMN(if_type) \
    COLUMN(if_uuid) \
    COLUMN(if_name) \
    COLUMN(port_state) \
    COLUMN(network_state) \
    COLUMN(inet_addr) \
    COLUMN(netmask) \
    COLUMN(dhcpc) \
    COLUMN(onboard_type) \
    COLUMN(uplink_priority)

#define SCHEMA__Wifi_Ethernet_State "Wifi_Ethernet_State"
#define SCHEMA_COLUMN__Wifi_Ethernet_State(COLUMN) \
    COLUMN(mac) \
    COLUMN(enabled) \
    COLUMN(connected)

#define SCHEMA__Connection_Manager_Uplink "Connection_Manager_Uplink"
#define SCHEMA_COLUMN__Connection_Manager_Uplink(COLUMN) \
    COLUMN(if_type) \
    COLUMN(if_name) \
    COLUMN(priority) \
    COLUMN(loop) \
    COLUMN(has_L2) \
    COLUMN(has_L3) \
    COLUMN(is_used) \
    COLUMN(ntp_state) \
    COLUMN(unreachable_link_counter) \
    COLUMN(unreachable_router_counter) \
    COLUMN(unreachable_internet_counter) \
    COLUMN(unreachable_cloud_counter)

#define SCHEMA__Wifi_Inet_Config "Wifi_Inet_Config"
#define SCHEMA_COLUMN__Wifi_Inet_Config(COLUMN) \
    COLUMN(if_name) \
    COLUMN(if_type) \
    COLUMN(if_uuid) \
    COLUMN(enabled) \
    COLUMN(network) \
    COLUMN(NAT) \
    COLUMN(ip_assign_scheme) \
    COLUMN(inet_addr) \
    COLUMN(netmask) \
    COLUMN(gateway) \
    COLUMN(broadcast) \
    COLUMN(gre_remote_inet_addr) \
    COLUMN(gre_local_inet_addr) \
    COLUMN(gre_ifname) \
    COLUMN(gre_remote_mac_addr) \
    COLUMN(mtu) \
    COLUMN(dns) \
    COLUMN(dhcpd) \
    COLUMN(upnp_mode) \
    COLUMN(dhcp_sniff) \
    COLUMN(vlan_id) \
    COLUMN(parent_ifname) \
    COLUMN(ppp_options) \
    COLUMN(softwds_mac_addr) \
    COLUMN(softwds_wrap) \
    COLUMN(igmp_proxy) \
    COLUMN(mld_proxy) \
    COLUMN(igmp) \
    COLUMN(igmp_age) \
    COLUMN(igmp_tsize)

#define SCHEMA__Wifi_Inet_State "Wifi_Inet_State"
#define SCHEMA_COLUMN__Wifi_Inet_State(COLUMN) \
    COLUMN(if_name) \
    COLUMN(inet_config) \
    COLUMN(if_type) \
    COLUMN(if_uuid) \
    COLUMN(enabled) \
    COLUMN(network) \
    COLUMN(NAT) \
    COLUMN(ip_assign_scheme) \
    COLUMN(inet_addr) \
    COLUMN(netmask) \
    COLUMN(gateway) \
    COLUMN(broadcast) \
    COLUMN(gre_remote_inet_addr) \
    COLUMN(gre_local_inet_addr) \
    COLUMN(gre_ifname) \
    COLUMN(mtu) \
    COLUMN(dns) \
    COLUMN(dhcpd) \
    COLUMN(hwaddr) \
    COLUMN(dhcpc) \
    COLUMN(upnp_mode) \
    COLUMN(vlan_id) \
    COLUMN(parent_ifname) \
    COLUMN(softwds_mac_addr) \
    COLUMN(softwds_wrap)

#define SCHEMA__Wifi_Route_State "Wifi_Route_State"
#define SCHEMA_COLUMN__Wifi_Route_State(COLUMN) \
    COLUMN(if_name) \
    COLUMN(dest_addr) \
    COLUMN(dest_mask) \
    COLUMN(gateway) \
    COLUMN(gateway_hwaddr)

#define SCHEMA__Wifi_Radio_Config_ovs "Wifi_Radio_Config_ovs"
#define SCHEMA_COLUMN__Wifi_Radio_Config_ovs(COLUMN) \
    COLUMN(if_name) \
    COLUMN(freq_band) \
    COLUMN(enabled) \
    COLUMN(dfs_demo) \
    COLUMN(hw_type) \
    COLUMN(hw_config) \
    COLUMN(country) \
    COLUMN(channel) \
    COLUMN(channel_sync) \
    COLUMN(channel_mode) \
    COLUMN(hw_mode) \
    COLUMN(ht_mode) \
    COLUMN(thermal_shutdown) \
    COLUMN(thermal_downgrade_temp) \
    COLUMN(thermal_upgrade_temp) \
    COLUMN(thermal_integration) \
    COLUMN(temperature_control) \
    COLUMN(vif_configs) \
    COLUMN(tx_power) \
    COLUMN(bcn_int) \
    COLUMN(tx_chainmask) \
    COLUMN(thermal_tx_chainmask) \
    COLUMN(fallback_parents) \
    COLUMN(zero_wait_dfs)

#define SCHEMA__Wifi_Radio_State "Wifi_Radio_State"
#define SCHEMA_COLUMN__Wifi_Radio_State(COLUMN) \
    COLUMN(if_name) \
    COLUMN(radio_config) \
    COLUMN(freq_band) \
    COLUMN(enabled) \
    COLUMN(dfs_demo) \
    COLUMN(hw_type) \
    COLUMN(hw_params) \
    COLUMN(radar) \
    COLUMN(hw_config) \
    COLUMN(country) \
    COLUMN(channel) \
    COLUMN(channel_sync) \
    COLUMN(channel_mode) \
    COLUMN(mac) \
    COLUMN(hw_mode) \
    COLUMN(ht_mode) \
    COLUMN(thermal_shutdown) \
    COLUMN(thermal_downgrade_temp) \
    COLUMN(thermal_upgrade_temp) \
    COLUMN(thermal_integration) \
    COLUMN(thermal_downgraded) \
    COLUMN(temperature_control) \
    COLUMN(vif_states) \
    COLUMN(tx_power) \
    COLUMN(bcn_int) \
    COLUMN(tx_chainmask) \
    COLUMN(thermal_tx_chainmask) \
    COLUMN(allowed_channels) \
    COLUMN(channels) \
    COLUMN(fallback_parents) \
    COLUMN(zero_wait_dfs)

#define SCHEMA__Wifi_Credential_Config "Wifi_Credential_Config"
#define SCHEMA_COLUMN__Wifi_Credential_Config(COLUMN) \
    COLUMN(ssid) \
    COLUMN(security) \
    COLUMN(onboard_type)

#define SCHEMA__Wifi_VIF_Config "Wifi_VIF_Config"
#define SCHEMA_COLUMN__Wifi_VIF_Config(COLUMN) \
    COLUMN(if_name) \
    COLUMN(enabled) \
    COLUMN(mode) \
    COLUMN(parent) \
    COLUMN(vif_radio_idx) \
    COLUMN(vif_dbg_lvl) \
    COLUMN(wds) \
    COLUMN(ssid) \
    COLUMN(ssid_broadcast) \
    COLUMN(security) \
    COLUMN(credential_configs) \
    COLUMN(bridge) \
    COLUMN(mac_list) \
    COLUMN(mac_list_type) \
    COLUMN(vlan_id) \
    COLUMN(min_hw_mode) \
    COLUMN(uapsd_enable) \
    COLUMN(group_rekey) \
    COLUMN(ap_bridge) \
    COLUMN(ft_psk) \
    COLUMN(ft_mobility_domain) \
    COLUMN(rrm) \
    COLUMN(btm) \
    COLUMN(dynamic_beacon) \
    COLUMN(mcast2ucast) \
    COLUMN(multi_ap) \
    COLUMN(wps) \
    COLUMN(wps_pbc) \
    COLUMN(wps_pbc_key_id) \
    COLUMN(wpa) \
    COLUMN(wpa_key_mgmt) \
    COLUMN(wpa_psks) \
    COLUMN(wpa_oftags) \
    COLUMN(radius_srv_addr) \
    COLUMN(radius_srv_port) \
    COLUMN(radius_srv_secret) \
    COLUMN(default_oftag) \
    COLUMN(dpp_connector) \
    COLUMN(dpp_csign_hex) \
    COLUMN(dpp_netaccesskey_hex)

#define SCHEMA__Wifi_VIF_State "Wifi_VIF_State"
#define SCHEMA_COLUMN__Wifi_VIF_State(COLUMN) \
    COLUMN(vif_config) \
    COLUMN(enabled) \
    COLUMN(if_name) \
    COLUMN(mode) \
    COLUMN(state) \
    COLUMN(channel) \
    COLUMN(mac) \
    COLUMN(vif_radio_idx) \
    COLUMN(wds) \
    COLUMN(parent) \
    COLUMN(ssid) \
    COLUMN(ssid_broadcast) \
    COLUMN(security) \
    COLUMN(bridge) \
    COLUMN(mac_list) \
    COLUMN(mac_list_type) \
    COLUMN(associated_clients) \
    COLUMN(vlan_id) \
    COLUMN(min_hw_mode) \
    COLUMN(uapsd_enable) \
    COLUMN(group_rekey) \
    COLUMN(ap_bridge) \
    COLUMN(ft_psk) \
    COLUMN(ft_mobility_domain) \
    COLUMN(rrm) \
    COLUMN(btm) \
    COLUMN(dynamic_beacon) \
    COLUMN(mcast2ucast) \
    COLUMN(multi_ap) \
    COLUMN(ap_vlan_sta_addr) \
    COLUMN(wps) \
    COLUMN(wps_pbc) \
    COLUMN(wps_pbc_key_id)

#define SCHEMA__Wifi_Associated_Clients "Wifi_Associated_Clients"
#define SCHEMA_COLUMN__Wifi_Associated_Clients(COLUMN) \
    COLUMN(mac) \
    COLUMN(state) \
    COLUMN(capabilities) \
    COLUMN(key_id) \
    COLUMN(oftag) \
    COLUMN(uapsd) \
    COLUMN(kick)

#define SCHEMA__DHCP_leased_IP "DHCP_leased_IP"
#define SCHEMA_COLUMN__DHCP_leased_IP(COLUMN) \
    COLUMN(hwaddr) \
    COLUMN(inet_addr) \
    COLUMN(hostname) \
    COLUMN(fingerprint) \
    COLUMN(vendor_class) \
    COLUMN(lease_time)

#define SCHEMA__Wifi_Test_Config "Wifi_Test_Config"
#define SCHEMA_COLUMN__Wifi_Test_Config(COLUMN) \
    COLUMN(test_id) \
    COLUMN(params)

#define SCHEMA__Wifi_Test_State "Wifi_Test_State"
#define SCHEMA_COLUMN__Wifi_Test_State(COLUMN) \
    COLUMN(test_id) \
    COLUMN(state)

#define SCHEMA__AW_LM_Config "AW_LM_Config"
#define SCHEMA_COLUMN__AW_LM_Config(COLUMN) \
    COLUMN(name) \
    COLUMN(periodicity) \
    COLUMN(upload_location) \
    COLUMN(upload_token)

#define SCHEMA__AW_LM_State "AW_LM_State"
#define SCHEMA_COLUMN__AW_LM_State(COLUMN) \
    COLUMN(name) \
    COLUMN(log_trigger)

#define SCHEMA__AW_Debug "AW_Debug"
#define SCHEMA_COLUMN__AW_Debug(COLUMN) \
    COLUMN(name) \
    COLUMN(log_severity)

#define SCHEMA__AW_Bluetooth_Config "AW_Bluetooth_Config"
#define SCHEMA_COLUMN__AW_Bluetooth_Config(COLUMN) \
    COLUMN(mode) \
    COLUMN(interval_millis) \
    COLUMN(txpower) \
    COLUMN(command) \
    COLUMN(payload)

#define SCHEMA__AW_Bluetooth_State "AW_Bluetooth_State"
#define SCHEMA_COLUMN__AW_Bluetooth_State(COLUMN) \
    COLUMN(mode) \
    COLUMN(interval_millis) \
    COLUMN(txpower) \
    COLUMN(command) \
    COLUMN(payload)

#define SCHEMA__Open_vSwitch "Wifi_Rdk_Database"
#define SCHEMA_COLUMN__Open_vSwitch(COLUMN) \
    COLUMN(bridges) \
    COLUMN(manager_options) \
    COLUMN(ssl) \
    COLUMN(other_config) \
    COLUMN(external_ids) \
    COLUMN(next_cfg) \
    COLUMN(cur_cfg) \
    COLUMN(statistics) \
    COLUMN(ovs_version) \
    COLUMN(db_version) \
    COLUMN(system_type) \
    COLUMN(system_version) \
    COLUMN(datapath_types) \
    COLUMN(iface_types) \
    COLUMN(dpdk_initialized) \
    COLUMN(dpdk_version)

#define SCHEMA__Bridge "Bridge"
#define SCHEMA_COLUMN__Bridge(COLUMN) \
    COLUMN(name) \
    COLUMN(datapath_type) \
    COLUMN(datapath_version) \
    COLUMN(datapath_id) \
    COLUMN(stp_enable) \
    COLUMN(rstp_enable) \
    COLUMN(mcast_snooping_enable) \
    COLUMN(ports) \
    COLUMN(mirrors) \
    COLUMN(netflow) \
    COLUMN(sflow) \
    COLUMN(ipfix) \
    COLUMN(controller) \
    COLUMN(protocols) \
    COLUMN(fail_mode) \
    COLUMN(status) \
    COLUMN(rstp_status) \
    COLUMN(other_config) \
    COLUMN(external_ids) \
    COLUMN(flood_vlans) \
    COLUMN(flow_tables) \
    COLUMN(auto_attach)

#define SCHEMA__Port "Port"
#define SCHEMA_COLUMN__Port(COLUMN) \
    COLUMN(name) \
    COLUMN(interfaces) \
    COLUMN(trunks) \
    COLUMN(cvlans) \
    COLUMN(tag) \
    COLUMN(vlan_mode) \
    COLUMN(qos) \
    COLUMN(mac) \
    COLUMN(bond_mode) \
    COLUMN(lacp) \
    COLUMN(bond_updelay) \
    COLUMN(bond_downdelay) \
    COLUMN(bond_active_slave) \
    COLUMN(bond_fake_iface) \
    COLUMN(fake_bridge) \
    COLUMN(status) \
    COLUMN(rstp_status) \
    COLUMN(rstp_statistics) \
    COLUMN(statistics) \
    COLUMN(port_protected) \
    COLUMN(other_config) \
    COLUMN(external_ids)

#define SCHEMA__Interface "Interface"
#define SCHEMA_COLUMN__Interface(COLUMN) \
    COLUMN(name) \
    COLUMN(type) \
    COLUMN(options) \
    COLUMN(ingress_policing_rate) \
    COLUMN(ingress_policing_burst) \
    COLUMN(mac_in_use) \
    COLUMN(mac) \
    COLUMN(ifindex) \
    COLUMN(external_ids) \
    COLUMN(ofport) \
    COLUMN(ofport_request) \
    COLUMN(bfd) \
    COLUMN(bfd_status) \
    COLUMN(cfm_mpid) \
    COLUMN(cfm_remote_mpids) \
    COLUMN(cfm_flap_count) \
    COLUMN(cfm_fault) \
    COLUMN(cfm_fault_status) \
    COLUMN(cfm_remote_opstate) \
    COLUMN(cfm_health) \
    COLUMN(lacp_current) \
    COLUMN(lldp) \
    COLUMN(other_config) \
    COLUMN(statistics) \
    COLUMN(status) \
    COLUMN(admin_state) \
    COLUMN(link_state) \
    COLUMN(link_resets) \
    COLUMN(link_speed) \
    COLUMN(duplex) \
    COLUMN(mtu) \
    COLUMN(mtu_request) \
    COLUMN(error)

#define SCHEMA__Flow_Table "Flow_Table"
#define SCHEMA_COLUMN__Flow_Table(COLUMN) \
    COLUMN(name) \
    COLUMN(flow_limit) \
    COLUMN(overflow_policy) \
    COLUMN(groups) \
    COLUMN(prefixes) \
    COLUMN(external_ids)

#define SCHEMA__QoS "QoS"
#define SCHEMA_COLUMN__QoS(COLUMN) \
    COLUMN(type) \
    COLUMN(queues) \
    COLUMN(other_config) \
    COLUMN(external_ids)

#define SCHEMA__Queue "Queue"
#define SCHEMA_COLUMN__Queue(COLUMN) \
    COLUMN(dscp) \
    COLUMN(other_config) \
    COLUMN(external_ids)

#define SCHEMA__Mirror "Mirror"
#define SCHEMA_COLUMN__Mirror(COLUMN) \
    COLUMN(name) \
    COLUMN(select_all) \
    COLUMN(select_src_port) \
    COLUMN(select_dst_port) \
    COLUMN(select_vlan) \
    COLUMN(output_port) \
    COLUMN(output_vlan) \
    COLUMN(snaplen) \
    COLUMN(statistics) \
    COLUMN(external_ids)

#define SCHEMA__NetFlow "NetFlow"
#define SCHEMA_COLUMN__NetFlow(COLUMN) \
    COLUMN(targets) \
    COLUMN(engine_type) \
    COLUMN(engine_id) \
    COLUMN(add_id_to_interface) \
    COLUMN(active_timeout) \
    COLUMN(external_ids)

#define SCHEMA__sFlow "sFlow"
#define SCHEMA_COLUMN__sFlow(COLUMN) \
    COLUMN(targets) \
    COLUMN(sampling) \
    COLUMN(polling) \
    COLUMN(header) \
    COLUMN(agent) \
    COLUMN(external_ids)

#define SCHEMA__IPFIX "IPFIX"
#define SCHEMA_COLUMN__IPFIX(COLUMN) \
    COLUMN(targets) \
    COLUMN(sampling) \
    COLUMN(obs_domain_id) \
    COLUMN(obs_point_id) \
    COLUMN(cache_active_timeout) \
    COLUMN(cache_max_flows) \
    COLUMN(other_config) \
    COLUMN(external_ids)

#define SCHEMA__Flow_Sample_Collector_Set "Flow_Sample_Collector_Set"
#define SCHEMA_COLUMN__Flow_Sample_Collector_Set(COLUMN) \
    COLUMN(id) \
    COLUMN(bridge) \
    COLUMN(ipfix) \
    COLUMN(external_ids)

#define SCHEMA__Controller "Controller"
#define SCHEMA_COLUMN__Controller(COLUMN) \
    COLUMN(target) \
    COLUMN(max_backoff) \
    COLUMN(inactivity_probe) \
    COLUMN(connection_mode) \
    COLUMN(local_ip) \
    COLUMN(local_netmask) \
    COLUMN(local_gateway) \
    COLUMN(enable_async_messages) \
    COLUMN(controller_rate_limit) \
    COLUMN(controller_burst_limit) \
    COLUMN(other_config) \
    COLUMN(external_ids) \
    COLUMN(is_connected) \
    COLUMN(role) \
    COLUMN(status)

#define SCHEMA__Manager "Manager"
#define SCHEMA_COLUMN__Manager(COLUMN) \
    COLUMN(target) \
    COLUMN(max_backoff) \
    COLUMN(inactivity_probe) \
    COLUMN(connection_mode) \
    COLUMN(other_config) \
    COLUMN(external_ids) \
    COLUMN(is_connected) \
    COLUMN(status)

#define SCHEMA__SSL "SSL"
#define SCHEMA_COLUMN__SSL(COLUMN) \
    COLUMN(private_key) \
    COLUMN(certificate) \
    COLUMN(ca_cert) \
    COLUMN(bootstrap_ca_cert) \
    COLUMN(external_ids)

#define SCHEMA__AutoAttach "AutoAttach"
#define SCHEMA_COLUMN__AutoAttach(COLUMN) \
    COLUMN(system_name) \
    COLUMN(system_description) \
    COLUMN(mappings)

#define SCHEMA__BeaconReport "BeaconReport"
#define SCHEMA_COLUMN__BeaconReport(COLUMN) \
    COLUMN(if_name) \
    COLUMN(DstMac) \
    COLUMN(Bssid) \
    COLUMN(RegulatoryClass) \
    COLUMN(ChanNum) \
    COLUMN(RandomInterval) \
    COLUMN(Duration) \
    COLUMN(Mode)

#define SCHEMA__Wifi_Stats_Config "Wifi_Stats_Config"
#define SCHEMA_COLUMN__Wifi_Stats_Config(COLUMN) \
    COLUMN(stats_type) \
    COLUMN(report_type) \
    COLUMN(radio_type) \
    COLUMN(survey_type) \
    COLUMN(reporting_interval) \
    COLUMN(reporting_count) \
    COLUMN(sampling_interval) \
    COLUMN(survey_interval_ms) \
    COLUMN(channel_list) \
    COLUMN(threshold)

#define SCHEMA__DHCP_reserved_IP "DHCP_reserved_IP"
#define SCHEMA_COLUMN__DHCP_reserved_IP(COLUMN) \
    COLUMN(hostname) \
    COLUMN(ip_addr) \
    COLUMN(hw_addr)

#define SCHEMA__IP_Port_Forward "IP_Port_Forward"
#define SCHEMA_COLUMN__IP_Port_Forward(COLUMN) \
    COLUMN(protocol) \
    COLUMN(src_ifname) \
    COLUMN(src_port) \
    COLUMN(dst_port) \
    COLUMN(dst_ipaddr)

#define SCHEMA__OVS_MAC_Learning "OVS_MAC_Learning"
#define SCHEMA_COLUMN__OVS_MAC_Learning(COLUMN) \
    COLUMN(brname) \
    COLUMN(ifname) \
    COLUMN(hwaddr) \
    COLUMN(vlan)

#define SCHEMA__Wifi_Speedtest_Config "Wifi_Speedtest_Config"
#define SCHEMA_COLUMN__Wifi_Speedtest_Config(COLUMN) \
    COLUMN(testid) \
    COLUMN(traffic_cap) \
    COLUMN(delay) \
    COLUMN(test_type) \
    COLUMN(preferred_list) \
    COLUMN(select_server_id) \
    COLUMN(st_server) \
    COLUMN(st_port) \
    COLUMN(st_len) \
    COLUMN(st_parallel) \
    COLUMN(st_udp) \
    COLUMN(st_bw) \
    COLUMN(st_pkt_len) \
    COLUMN(st_dir)

#define SCHEMA__Wifi_Speedtest_Status "Wifi_Speedtest_Status"
#define SCHEMA_COLUMN__Wifi_Speedtest_Status(COLUMN) \
    COLUMN(testid) \
    COLUMN(UL) \
    COLUMN(DL) \
    COLUMN(server_name) \
    COLUMN(server_IP) \
    COLUMN(ISP) \
    COLUMN(RTT) \
    COLUMN(jitter) \
    COLUMN(duration) \
    COLUMN(timestamp) \
    COLUMN(status) \
    COLUMN(DL_bytes) \
    COLUMN(UL_bytes) \
    COLUMN(DL_duration) \
    COLUMN(UL_duration) \
    COLUMN(test_type) \
    COLUMN(pref_selected) \
    COLUMN(hranked_offered) \
    COLUMN(DL_pkt_loss) \
    COLUMN(UL_pkt_loss) \
    COLUMN(DL_jitter) \
    COLUMN(UL_jitter) \
    COLUMN(host_remote)

#define SCHEMA__Band_Steering_Config "Band_Steering_Config"
#define SCHEMA_COLUMN__Band_Steering_Config(COLUMN) \
    COLUMN(if_name_2g) \
    COLUMN(if_name_5g) \
    COLUMN(chan_util_check_sec) \
    COLUMN(chan_util_avg_count) \
    COLUMN(chan_util_hwm) \
    COLUMN(chan_util_lwm) \
    COLUMN(inact_check_sec) \
    COLUMN(inact_tmout_sec_normal) \
    COLUMN(inact_tmout_sec_overload) \
    COLUMN(def_rssi_inact_xing) \
    COLUMN(def_rssi_low_xing) \
    COLUMN(def_rssi_xing) \
    COLUMN(kick_debounce_thresh) \
    COLUMN(kick_debounce_period) \
    COLUMN(success_threshold_secs) \
    COLUMN(stats_report_interval) \
    COLUMN(dbg_2g_raw_chan_util) \
    COLUMN(dbg_5g_raw_chan_util) \
    COLUMN(dbg_2g_raw_rssi) \
    COLUMN(dbg_5g_raw_rssi) \
    COLUMN(debug_level) \
    COLUMN(gw_only) \
    COLUMN(ifnames)

#define SCHEMA__Band_Steering_Clients "Band_Steering_Clients"
#define SCHEMA_COLUMN__Band_Steering_Clients(COLUMN) \
    COLUMN(mac) \
    COLUMN(hwm) \
    COLUMN(lwm) \
    COLUMN(kick_type) \
    COLUMN(kick_reason) \
    COLUMN(reject_detection) \
    COLUMN(max_rejects) \
    COLUMN(rejects_tmout_secs) \
    COLUMN(backoff_secs) \
    COLUMN(backoff_exp_base) \
    COLUMN(steer_during_backoff) \
    COLUMN(sticky_kick_guard_time) \
    COLUMN(steering_kick_guard_time) \
    COLUMN(sticky_kick_backoff_time) \
    COLUMN(steering_kick_backoff_time) \
    COLUMN(settling_backoff_time) \
    COLUMN(send_rrm_after_assoc) \
    COLUMN(send_rrm_after_xing) \
    COLUMN(rrm_better_factor) \
    COLUMN(rrm_age_time) \
    COLUMN(active_treshold_bps) \
    COLUMN(steering_success_cnt) \
    COLUMN(steering_fail_cnt) \
    COLUMN(steering_kick_cnt) \
    COLUMN(sticky_kick_cnt) \
    COLUMN(stats_2g) \
    COLUMN(stats_5g) \
    COLUMN(kick_debounce_period) \
    COLUMN(sc_kick_type) \
    COLUMN(sc_kick_reason) \
    COLUMN(sc_kick_debounce_period) \
    COLUMN(sticky_kick_debounce_period) \
    COLUMN(cs_mode) \
    COLUMN(cs_params) \
    COLUMN(cs_state) \
    COLUMN(sticky_kick_type) \
    COLUMN(sticky_kick_reason) \
    COLUMN(steering_btm_params) \
    COLUMN(sc_btm_params) \
    COLUMN(sticky_btm_params) \
    COLUMN(pref_5g) \
    COLUMN(kick_upon_idle) \
    COLUMN(pre_assoc_auth_block) \
    COLUMN(rrm_bcn_rpt_params) \
    COLUMN(force_kick) \
    COLUMN(pref_bs_allowed) \
    COLUMN(preq_snr_thr)

#define SCHEMA__Openflow_Config "Openflow_Config"
#define SCHEMA_COLUMN__Openflow_Config(COLUMN) \
    COLUMN(bridge) \
    COLUMN(table) \
    COLUMN(priority) \
    COLUMN(rule) \
    COLUMN(action) \
    COLUMN(token)

#define SCHEMA__Openflow_State "Openflow_State"
#define SCHEMA_COLUMN__Openflow_State(COLUMN) \
    COLUMN(bridge) \
    COLUMN(openflow_config) \
    COLUMN(token) \
    COLUMN(success)

#define SCHEMA__Openflow_Tag "Openflow_Tag"
#define SCHEMA_COLUMN__Openflow_Tag(COLUMN) \
    COLUMN(name) \
    COLUMN(device_value) \
    COLUMN(cloud_value)

#define SCHEMA__Openflow_Tag_Group "Openflow_Tag_Group"
#define SCHEMA_COLUMN__Openflow_Tag_Group(COLUMN) \
    COLUMN(name) \
    COLUMN(tags)

#define SCHEMA__Client_Nickname_Config "Client_Nickname_Config"
#define SCHEMA_COLUMN__Client_Nickname_Config(COLUMN) \
    COLUMN(nickname) \
    COLUMN(mac)

#define SCHEMA__Client_Freeze_Config "Client_Freeze_Config"
#define SCHEMA_COLUMN__Client_Freeze_Config(COLUMN) \
    COLUMN(mac) \
    COLUMN(source) \
    COLUMN(type) \
    COLUMN(blocked)

#define SCHEMA__Node_Config "Node_Config"
#define SCHEMA_COLUMN__Node_Config(COLUMN) \
    COLUMN(persist) \
    COLUMN(module) \
    COLUMN(key) \
    COLUMN(value)

#define SCHEMA__Node_State "Node_State"
#define SCHEMA_COLUMN__Node_State(COLUMN) \
    COLUMN(persist) \
    COLUMN(module) \
    COLUMN(key) \
    COLUMN(value)

#define SCHEMA__Flow_Service_Manager_Config "Flow_Service_Manager_Config"
#define SCHEMA_COLUMN__Flow_Service_Manager_Config(COLUMN) \
    COLUMN(handler) \
    COLUMN(type) \
    COLUMN(if_name) \
    COLUMN(pkt_capt_filter) \
    COLUMN(plugin) \
    COLUMN(other_config)

#define SCHEMA__FSM_Policy "FSM_Policy"
#define SCHEMA_COLUMN__FSM_Policy(COLUMN) \
    COLUMN(name) \
    COLUMN(idx) \
    COLUMN(mac_op) \
    COLUMN(macs) \
    COLUMN(fqdn_op) \
    COLUMN(fqdns) \
    COLUMN(fqdncat_op) \
    COLUMN(fqdncats) \
    COLUMN(ipaddr_op) \
    COLUMN(ipaddrs) \
    COLUMN(risk_level) \
    COLUMN(risk_op) \
    COLUMN(log) \
    COLUMN(action) \
    COLUMN(next) \
    COLUMN(policy) \
    COLUMN(redirect) \
    COLUMN(other_config)

#define SCHEMA__Wifi_VIF_Neighbors "Wifi_VIF_Neighbors"
#define SCHEMA_COLUMN__Wifi_VIF_Neighbors(COLUMN) \
    COLUMN(bssid) \
    COLUMN(if_name) \
    COLUMN(channel) \
    COLUMN(ht_mode) \
    COLUMN(priority)

#define SCHEMA__FCM_Collector_Config "FCM_Collector_Config"
#define SCHEMA_COLUMN__FCM_Collector_Config(COLUMN) \
    COLUMN(name) \
    COLUMN(interval) \
    COLUMN(filter_name) \
    COLUMN(report_name) \
    COLUMN(other_config)

#define SCHEMA__FCM_Filter "FCM_Filter"
#define SCHEMA_COLUMN__FCM_Filter(COLUMN) \
    COLUMN(name) \
    COLUMN(index) \
    COLUMN(smac) \
    COLUMN(dmac) \
    COLUMN(vlanid) \
    COLUMN(src_ip) \
    COLUMN(dst_ip) \
    COLUMN(src_port) \
    COLUMN(dst_port) \
    COLUMN(proto) \
    COLUMN(appnames) \
    COLUMN(appname_op) \
    COLUMN(apptags) \
    COLUMN(apptag_op) \
    COLUMN(smac_op) \
    COLUMN(dmac_op) \
    COLUMN(vlanid_op) \
    COLUMN(src_ip_op) \
    COLUMN(dst_ip_op) \
    COLUMN(src_port_op) \
    COLUMN(dst_port_op) \
    COLUMN(proto_op) \
    COLUMN(pktcnt) \
    COLUMN(pktcnt_op) \
    COLUMN(action) \
    COLUMN(other_config)

#define SCHEMA__FCM_Report_Config "FCM_Report_Config"
#define SCHEMA_COLUMN__FCM_Report_Config(COLUMN) \
    COLUMN(name) \
    COLUMN(interval) \
    COLUMN(format) \
    COLUMN(hist_interval) \
    COLUMN(hist_filter) \
    COLUMN(report_filter) \
    COLUMN(mqtt_topic) \
    COLUMN(other_config)

#define SCHEMA__IP_Interface "IP_Interface"
#define SCHEMA_COLUMN__IP_Interface(COLUMN) \
    COLUMN(name) \
    COLUMN(enable) \
    COLUMN(status) \
    COLUMN(interfaces) \
    COLUMN(if_name) \
    COLUMN(ipv4_addr) \
    COLUMN(ipv6_addr) \
    COLUMN(ipv6_prefix)

#define SCHEMA__IPv4_Address "IPv4_Address"
#define SCHEMA_COLUMN__IPv4_Address(COLUMN) \
    COLUMN(enable) \
    COLUMN(status) \
    COLUMN(address) \
    COLUMN(subnet_mask) \
    COLUMN(type)

#define SCHEMA__IPv6_Address "IPv6_Address"
#define SCHEMA_COLUMN__IPv6_Address(COLUMN) \
    COLUMN(enable) \
    COLUMN(status) \
    COLUMN(address_status) \
    COLUMN(address) \
    COLUMN(origin) \
    COLUMN(prefix) \
    COLUMN(preferred_lifetime) \
    COLUMN(valid_lifetime)

#define SCHEMA__IPv6_Prefix "IPv6_Prefix"
#define SCHEMA_COLUMN__IPv6_Prefix(COLUMN) \
    COLUMN(enable) \
    COLUMN(status) \
    COLUMN(prefix_status) \
    COLUMN(address) \
    COLUMN(origin) \
    COLUMN(static_type) \
    COLUMN(parent_prefix) \
    COLUMN(child_prefix_bits) \
    COLUMN(on_link) \
    COLUMN(autonomous) \
    COLUMN(preferred_lifetime) \
    COLUMN(valid_lifetime)

#define SCHEMA__DHCPv4_Client "DHCPv4_Client"
#define SCHEMA_COLUMN__DHCPv4_Client(COLUMN) \
    COLUMN(enable) \
    COLUMN(ip_interface) \
    COLUMN(request_options) \
    COLUMN(received_options) \
    COLUMN(send_options)

#define SCHEMA__DHCPv6_Client "DHCPv6_Client"
#define SCHEMA_COLUMN__DHCPv6_Client(COLUMN) \
    COLUMN(enable) \
    COLUMN(ip_interface) \
    COLUMN(request_address) \
    COLUMN(request_prefixes) \
    COLUMN(rapid_commit) \
    COLUMN(renew) \
    COLUMN(request_options) \
    COLUMN(received_options) \
    COLUMN(send_options)

#define SCHEMA__DHCP_Option "DHCP_Option"
#define SCHEMA_COLUMN__DHCP_Option(COLUMN) \
    COLUMN(enable) \
    COLUMN(version) \
    COLUMN(type) \
    COLUMN(tag) \
    COLUMN(value)

#define SCHEMA__Netfilter "Netfilter"
#define SCHEMA_COLUMN__Netfilter(COLUMN) \
    COLUMN(name) \
    COLUMN(enable) \
    COLUMN(status) \
    COLUMN(protocol) \
    COLUMN(table) \
    COLUMN(chain) \
    COLUMN(priority) \
    COLUMN(rule) \
    COLUMN(target)

#define SCHEMA__Routing "Routing"
#define SCHEMA_COLUMN__Routing(COLUMN) \
    COLUMN(enable) \
    COLUMN(status) \
    COLUMN(protocol) \
    COLUMN(type) \
    COLUMN(ip_interface) \
    COLUMN(dest) \
    COLUMN(gateway)

#define SCHEMA__DHCPv4_Server "DHCPv4_Server"
#define SCHEMA_COLUMN__DHCPv4_Server(COLUMN) \
    COLUMN(interface) \
    COLUMN(status) \
    COLUMN(min_address) \
    COLUMN(max_address) \
    COLUMN(lease_time) \
    COLUMN(options) \
    COLUMN(static_address) \
    COLUMN(leased_address)

#define SCHEMA__DHCPv4_Lease "DHCPv4_Lease"
#define SCHEMA_COLUMN__DHCPv4_Lease(COLUMN) \
    COLUMN(status) \
    COLUMN(address) \
    COLUMN(hwaddr) \
    COLUMN(hostname) \
    COLUMN(leased_time) \
    COLUMN(leased_fingerprint)

#define SCHEMA__DHCPv6_Server "DHCPv6_Server"
#define SCHEMA_COLUMN__DHCPv6_Server(COLUMN) \
    COLUMN(interface) \
    COLUMN(status) \
    COLUMN(prefixes) \
    COLUMN(prefix_delegation) \
    COLUMN(options) \
    COLUMN(lease_prefix) \
    COLUMN(static_prefix)

#define SCHEMA__DHCPv6_Lease "DHCPv6_Lease"
#define SCHEMA_COLUMN__DHCPv6_Lease(COLUMN) \
    COLUMN(status) \
    COLUMN(prefix) \
    COLUMN(duid) \
    COLUMN(hwaddr) \
    COLUMN(hostname) \
    COLUMN(leased_time)

#define SCHEMA__IPv6_RouteAdv "IPv6_RouteAdv"
#define SCHEMA_COLUMN__IPv6_RouteAdv(COLUMN) \
    COLUMN(interface) \
    COLUMN(status) \
    COLUMN(prefixes) \
    COLUMN(managed) \
    COLUMN(other_config) \
    COLUMN(home_agent) \
    COLUMN(max_adv_interval) \
    COLUMN(min_adv_interval) \
    COLUMN(default_lifetime) \
    COLUMN(preferred_router) \
    COLUMN(mtu) \
    COLUMN(reachable_time) \
    COLUMN(retrans_timer) \
    COLUMN(current_hop_limit) \
    COLUMN(rdnss) \
    COLUMN(dnssl)

#define SCHEMA__IPv6_Neighbors "IPv6_Neighbors"
#define SCHEMA_COLUMN__IPv6_Neighbors(COLUMN) \
    COLUMN(address) \
    COLUMN(hwaddr) \
    COLUMN(if_name)

#define SCHEMA__IGMP_Config "IGMP_Config"
#define SCHEMA_COLUMN__IGMP_Config(COLUMN) \
    COLUMN(query_interval) \
    COLUMN(query_response_interval) \
    COLUMN(last_member_query_interval) \
    COLUMN(query_robustness_value) \
    COLUMN(maximum_groups) \
    COLUMN(maximum_sources) \
    COLUMN(maximum_members) \
    COLUMN(fast_leave_enable)

#define SCHEMA__MLD_Config "MLD_Config"
#define SCHEMA_COLUMN__MLD_Config(COLUMN) \
    COLUMN(query_interval) \
    COLUMN(query_response_interval) \
    COLUMN(last_member_query_interval) \
    COLUMN(query_robustness_value) \
    COLUMN(maximum_groups) \
    COLUMN(maximum_sources) \
    COLUMN(maximum_members) \
    COLUMN(fast_leave_enable)

#define SCHEMA__Reboot_Status "Reboot_Status"
#define SCHEMA_COLUMN__Reboot_Status(COLUMN) \
    COLUMN(count) \
    COLUMN(type) \
    COLUMN(reason)

#define SCHEMA__Service_Announcement "Service_Announcement"
#define SCHEMA_COLUMN__Service_Announcement(COLUMN) \
    COLUMN(name) \
    COLUMN(protocol) \
    COLUMN(port) \
    COLUMN(txt)

#define SCHEMA__Node_Services "Node_Services"
#define SCHEMA_COLUMN__Node_Services(COLUMN) \
    COLUMN(service) \
    COLUMN(enable) \
    COLUMN(status) \
    COLUMN(other_config)

#define SCHEMA__Wifi_Anqp_Config "Wifi_Anqp_Config"
#define SCHEMA_COLUMN__Wifi_Anqp_Config(COLUMN) \
    COLUMN(capability_length) \
    COLUMN(capability_element) \
    COLUMN(ipv6_address_type) \
    COLUMN(ipv4_address_type) \
    COLUMN(domain_name_length) \
    COLUMN(domain_name_element) \
    COLUMN(roaming_consortium_length) \
    COLUMN(roaming_consortium_element) \
    COLUMN(nai_realm_length) \
    COLUMN(nai_realm_element) \
    COLUMN(gpp_cellular_length) \
    COLUMN(gpp_cellular_element) \
    COLUMN(venue_name_length) \
    COLUMN(venue_name_element) \
    COLUMN(vap_name)

#define SCHEMA__Wifi_Passpoint_Config "Wifi_Passpoint_Config"
#define SCHEMA_COLUMN__Wifi_Passpoint_Config(COLUMN) \
    COLUMN(enable) \
    COLUMN(group_addressed_forwarding_disable) \
    COLUMN(p2p_cross_connect_disable) \
    COLUMN(capability_length) \
    COLUMN(capability_element) \
    COLUMN(nai_home_realm_length) \
    COLUMN(nai_home_realm_element) \
    COLUMN(operator_friendly_name_length) \
    COLUMN(operator_friendly_name_element) \
    COLUMN(connection_capability_length) \
    COLUMN(connection_capability_element) \
    COLUMN(vap_name)

#define SCHEMA__Wifi_Radio_Config "Wifi_Radio_Config"
#define SCHEMA_COLUMN__Wifi_Radio_Config(COLUMN) \
    COLUMN(radio_name) \
    COLUMN(enabled) \
    COLUMN(freq_band) \
    COLUMN(auto_channel_enabled) \
    COLUMN(channel) \
    COLUMN(num_secondary_channels) \
    COLUMN(secondary_channels_list) \
    COLUMN(channel_width) \
    COLUMN(hw_mode) \
    COLUMN(csa_beacon_count) \
    COLUMN(country) \
    COLUMN(operating_environment) \
    COLUMN(dcs_enabled) \
    COLUMN(dfs_enabled) \
    COLUMN(vap_configs) \
    COLUMN(dtim_period) \
    COLUMN(beacon_interval) \
    COLUMN(operating_class) \
    COLUMN(basic_data_transmit_rate) \
    COLUMN(operational_data_transmit_rate) \
    COLUMN(fragmentation_threshold) \
    COLUMN(guard_interval) \
    COLUMN(transmit_power) \
    COLUMN(rts_threshold) \
    COLUMN(factory_reset_ssid) \
    COLUMN(radio_stats_measuring_rate) \
    COLUMN(radio_stats_measuring_interval) \
    COLUMN(cts_protection) \
    COLUMN(obss_coex) \
    COLUMN(stbc_enable) \
    COLUMN(greenfield_enable) \
    COLUMN(user_control) \
    COLUMN(admin_control) \
    COLUMN(chan_util_threshold) \
    COLUMN(chan_util_selfheal_enable) \
    COLUMN(eco_power_down) \
    COLUMN(Tscan) \
    COLUMN(Nscan) \
    COLUMN(Tidle)

#define SCHEMA__Wifi_Global_Config "Wifi_Global_Config"
#define SCHEMA_COLUMN__Wifi_Global_Config(COLUMN) \
    COLUMN(gas_config) \
    COLUMN(notify_wifi_changes) \
    COLUMN(prefer_private) \
    COLUMN(prefer_private_configure) \
    COLUMN(factory_reset) \
    COLUMN(tx_overflow_selfheal) \
    COLUMN(inst_wifi_client_enabled) \
    COLUMN(inst_wifi_client_reporting_period) \
    COLUMN(inst_wifi_client_mac) \
    COLUMN(inst_wifi_client_def_reporting_period) \
    COLUMN(wifi_active_msmt_enabled) \
    COLUMN(wifi_active_msmt_pktsize) \
    COLUMN(wifi_active_msmt_num_samples) \
    COLUMN(wifi_active_msmt_sample_duration) \
    COLUMN(vlan_cfg_version) \
    COLUMN(wps_pin) \
    COLUMN(bandsteering_enable) \
    COLUMN(good_rssi_threshold) \
    COLUMN(assoc_count_threshold) \
    COLUMN(assoc_gate_time) \
    COLUMN(whix_log_interval) \
    COLUMN(whix_chutility_loginterval) \
    COLUMN(assoc_monitor_duration) \
    COLUMN(rapid_reconnect_enable) \
    COLUMN(vap_stats_feature) \
    COLUMN(mfp_config_feature) \
    COLUMN(force_disable_radio_feature) \
    COLUMN(force_disable_radio_status) \
    COLUMN(fixed_wmm_params) \
    COLUMN(wifi_region_code) \
    COLUMN(diagnostic_enable) \
    COLUMN(validate_ssid) \
    COLUMN(device_network_mode) \
    COLUMN(normalized_rssi_list) \
    COLUMN(snr_list) \
    COLUMN(cli_stat_list) \
    COLUMN(txrx_rate_list) \

#define SCHEMA__Wifi_Preassoc_Control_Config "Wifi_Preassoc_Control_Config"
#define SCHEMA_COLUMN__Wifi_Preassoc_Control_Config(COLUMN) \
    COLUMN(rssi_up_threshold) \
    COLUMN(snr_threshold) \
    COLUMN(cu_threshold) \
    COLUMN(basic_data_transmit_rates) \
    COLUMN(operational_data_transmit_rates) \
    COLUMN(supported_data_transmit_rates) \
    COLUMN(minimum_advertised_mcs) \
    COLUMN(sixGOpInfoMinRate) \
    COLUMN(vap_name) \

#define SCHEMA__Wifi_Postassoc_Control_Config "Wifi_Postassoc_Control_Config"
#define SCHEMA_COLUMN__Wifi_Postassoc_Control_Config(COLUMN) \
    COLUMN(rssi_up_threshold) \
    COLUMN(sampling_interval) \
    COLUMN(snr_threshold) \
    COLUMN(sampling_count) \
    COLUMN(cu_threshold) \
    COLUMN(vap_name) \

#define SCHEMA__Wifi_Connection_Control_Config "Wifi_Connection_Control_Config"
#define SCHEMA_COLUMN__Wifi_Connection_Control_Config(COLUMN) \
    COLUMN(vap_name) \
    COLUMN(pre_assoc) \
    COLUMN(post_assoc) \

#define SCHEMA__AWLAN_Node__id "id"
#define SCHEMA__AWLAN_Node__model "model"
#define SCHEMA__AWLAN_Node__revision "revision"
#define SCHEMA__AWLAN_Node__serial_number "serial_number"
#define SCHEMA__AWLAN_Node__sku_number "sku_number"
#define SCHEMA__AWLAN_Node__redirector_addr "redirector_addr"
#define SCHEMA__AWLAN_Node__manager_addr "manager_addr"
#define SCHEMA__AWLAN_Node__led_config "led_config"
#define SCHEMA__AWLAN_Node__mqtt_settings "mqtt_settings"
#define SCHEMA__AWLAN_Node__mqtt_topics "mqtt_topics"
#define SCHEMA__AWLAN_Node__mqtt_headers "mqtt_headers"
#define SCHEMA__AWLAN_Node__platform_version "platform_version"
#define SCHEMA__AWLAN_Node__firmware_version "firmware_version"
#define SCHEMA__AWLAN_Node__firmware_url "firmware_url"
#define SCHEMA__AWLAN_Node__firmware_pass "firmware_pass"
#define SCHEMA__AWLAN_Node__upgrade_timer "upgrade_timer"
#define SCHEMA__AWLAN_Node__upgrade_dl_timer "upgrade_dl_timer"
#define SCHEMA__AWLAN_Node__upgrade_status "upgrade_status"
#define SCHEMA__AWLAN_Node__device_mode "device_mode"
#define SCHEMA__AWLAN_Node__factory_reset "factory_reset"
#define SCHEMA__AWLAN_Node__version_matrix "version_matrix"
#define SCHEMA__AWLAN_Node__min_backoff "min_backoff"
#define SCHEMA__AWLAN_Node__max_backoff "max_backoff"

#define SCHEMA__Wifi_Device_Config__device_mac "device_mac"
#define SCHEMA__Wifi_Device_Config__device_name "device_name"
#define SCHEMA__Wifi_Device_Config__vap_name "vap_name"

#define SCHEMA__Wifi_Security_Config__security_mode "security_mode"
#define SCHEMA__Wifi_Security_Config__encryption_method "encryption_method"
#define SCHEMA__Wifi_Security_Config__mfp_config "mfp_config"
#define SCHEMA__Wifi_Security_Config__key_type "key_type"
#define SCHEMA__Wifi_Security_Config__keyphrase "keyphrase"
#define SCHEMA__Wifi_Security_Config__radius_server_ip "radius_server_ip"
#define SCHEMA__Wifi_Security_Config__radius_server_port "radius_server_port"
#define SCHEMA__Wifi_Security_Config__radius_server_key "radius_server_key"
#define SCHEMA__Wifi_Security_Config__secondary_radius_server_ip "secondary_radius_server_ip"
#define SCHEMA__Wifi_Security_Config__secondary_radius_server_port "secondary_radius_server_port"
#define SCHEMA__Wifi_Security_Config__secondary_radius_server_key "secondary_radius_server_key"
#define SCHEMA__Wifi_Security_Config__vap_name "vap_name"
#define SCHEMA__Wifi_Security_Config__das_ip "das_ip"
#define SCHEMA__Wifi_Security_Config__das_port "das_port"
#define SCHEMA__Wifi_Security_Config__das_key "das_key"
#define SCHEMA__Wifi_Security_Config__rekey_interval "rekey_interval"
#define SCHEMA__Wifi_Security_Config__strict_rekey "strict_rekey"
#define SCHEMA__Wifi_Security_Config__eapol_key_timeout "eapol_key_timeout"
#define SCHEMA__Wifi_Security_Config__eapol_key_retries "eapol_key_retries"
#define SCHEMA__Wifi_Security_Config__eap_identity_req_timeout "eap_identity_req_timeout"
#define SCHEMA__Wifi_Security_Config__eap_identity_req_retries "eap_identity_req_retries"
#define SCHEMA__Wifi_Security_Config__eap_req_timeout "eap_req_timeout"
#define SCHEMA__Wifi_Security_Config__eap_req_retries "eap_req_retries"
#define SCHEMA__Wifi_Security_Config__disable_pmksa_caching "disable_pmksa_caching"
#define SCHEMA__Wifi_Security_Config__max_auth_attempts "max_auth_attempts"
#define SCHEMA__Wifi_Security_Config__blacklist_table_timeout "blacklist_table_timeout"
#define SCHEMA__Wifi_Security_Config__identity_req_retry_interval "identity_req_retry_interval"
#define SCHEMA__Wifi_Security_Config__server_retries "server_retries"
#define SCHEMA__Wifi_Security_Config__wpa3_transition_disable "wpa3_transition_disable"

#define SCHEMA__Wifi_VAP_Config__vap_name "vap_name"
#define SCHEMA__Wifi_VAP_Config__radio_name "radio_name"
#define SCHEMA__Wifi_VAP_Config__ssid "ssid"
#define SCHEMA__Wifi_VAP_Config__enabled "enabled"
#define SCHEMA__Wifi_VAP_Config__exists "exists"
#define SCHEMA__Wifi_VAP_Config__ssid_advertisement_enabled "ssid_advertisement_enabled"
#define SCHEMA__Wifi_VAP_Config__isolation_enabled "isolation_enabled"
#define SCHEMA__Wifi_VAP_Config__mgmt_power_control "mgmt_power_control"
#define SCHEMA__Wifi_VAP_Config__bss_max_sta "bss_max_sta"
#define SCHEMA__Wifi_VAP_Config__bss_transition_activated "bss_transition_activated"
#define SCHEMA__Wifi_VAP_Config__nbr_report_activated "nbr_report_activated"
#define SCHEMA__Wifi_VAP_Config__rapid_connect_enabled "rapid_connect_enabled"
#define SCHEMA__Wifi_VAP_Config__rapid_connect_threshold "rapid_connect_threshold"
#define SCHEMA__Wifi_VAP_Config__vap_stats_enable "vap_stats_enable"
#define SCHEMA__Wifi_VAP_Config__security "security"
#define SCHEMA__Wifi_VAP_Config__interworking "interworking"
#define SCHEMA__Wifi_VAP_Config__mac_filter_enabled "mac_filter_enabled"
#define SCHEMA__Wifi_VAP_Config__mac_filter_mode "mac_filter_mode"
#define SCHEMA__Wifi_VAP_Config__mac_filter "mac_filter"
#define SCHEMA__Wifi_VAP_Config__mac_addr_acl_enabled "mac_addr_acl_enabled"
#define SCHEMA__Wifi_VAP_Config__wmm_enabled "wmm_enabled"
#define SCHEMA__Wifi_VAP_Config__anqp_parameters "anqp_parameters"
#define SCHEMA__Wifi_VAP_Config__hs2_parameters "hs2_parameters"
#define SCHEMA__Wifi_VAP_Config__uapsd_enabled "uapsd_enabled"
#define SCHEMA__Wifi_VAP_Config__beacon_rate "beacon_rate"
#define SCHEMA__Wifi_VAP_Config__bridge_name "bridge_name"
#define SCHEMA__Wifi_VAP_Config__wmm_noack "wmm_noack"
#define SCHEMA__Wifi_VAP_Config__wep_key_length "wep_key_length"
#define SCHEMA__Wifi_VAP_Config__bss_hotspot "bss_hotspot"
#define SCHEMA__Wifi_VAP_Config__wps_push_button "wps_push_button"
#define SCHEMA__Wifi_VAP_Config__wps_config_methods "wps_config_methods"
#define SCHEMA__Wifi_VAP_Config__wps_enabled "wps_enabled"
#define SCHEMA__Wifi_VAP_Config__beacon_rate_ctl "beacon_rate_ctl"
#define SCHEMA__Wifi_VAP_Config__network_initiated_greylist "network_initiated_greylist"
#define SCHEMA__Wifi_VAP_Config__mfp_config "mfp_config"
#define SCHEMA__Wifi_VAP_Config__period "period"
#define SCHEMA__Wifi_VAP_Config__channel "channel"
#define SCHEMA__Wifi_VAP_Config__freq_band "freq_band"
#define SCHEMA__Wifi_VAP_Config__repurposed_vap_name "repurposed_vap_name"
#define SCHEMA__Wifi_VAP_Config__connected_building_enabled "connected_building_enabled"

#define SCHEMA__Wifi_Interworking_Config__enable "enable"
#define SCHEMA__Wifi_Interworking_Config__vap_name "vap_name"
#define SCHEMA__Wifi_Interworking_Config__access_network_type "access_network_type"
#define SCHEMA__Wifi_Interworking_Config__internet "internet"
#define SCHEMA__Wifi_Interworking_Config__asra "asra"
#define SCHEMA__Wifi_Interworking_Config__esr "esr"
#define SCHEMA__Wifi_Interworking_Config__uesa "uesa"
#define SCHEMA__Wifi_Interworking_Config__hess_option_present "hess_option_present"
#define SCHEMA__Wifi_Interworking_Config__hessid "hessid"
#define SCHEMA__Wifi_Interworking_Config__venue_group "venue_group"
#define SCHEMA__Wifi_Interworking_Config__venue_type "venue_type"

#define SCHEMA__Wifi_GAS_Config__advertisement_id "advertisement_id"
#define SCHEMA__Wifi_GAS_Config__pause_for_server_response "pause_for_server_response"
#define SCHEMA__Wifi_GAS_Config__response_timeout "response_timeout"
#define SCHEMA__Wifi_GAS_Config__comeback_delay "comeback_delay"
#define SCHEMA__Wifi_GAS_Config__response_buffering_time "response_buffering_time"
#define SCHEMA__Wifi_GAS_Config__query_responselength_limit "query_responselength_limit"

#define SCHEMA__Wifi_Rfc_Config__rfc_id "rfc_id"
#define SCHEMA__Wifi_Rfc_Config__dfs_rfc "dfs_rfc"
#define SCHEMA__Wifi_Rfc_Config__wifipasspoint_rfc "wifipasspoint_rfc"
#define SCHEMA__Wifi_Rfc_Config__wifiinterworking_rfc  "wifiinterworking_rfc"
#define SCHEMA__Wifi_Rfc_Config__radiusgreylist_rfc "radiusgreylist_rfc"
#define SCHEMA__Wifi_Rfc_Config__dfsatbootup_rfc "dfsatbootup_rfc"
#define SCHEMA__Wifi_Rfc_Config__wpa3_rfc "wpa3_rfc"
#define SCHEMA__Wifi_Rfc_Config__twoG80211axEnable_rfc "twoG80211axEnable_rfc"
#define SCHEMA__Wifi_Rfc_Config__hotspot_open_2g_last_enabled "hotspot_open_2g_last_enabled"
#define SCHEMA__Wifi_Rfc_Config__hotspot_open_5g_last_enabled "hotspot_open_5g_last_enabled"
#define SCHEMA__Wifi_Rfc_Config__hotspot_open_6g_last_enabled "hotspot_open_6g_last_enabled"
#define SCHEMA__Wifi_Rfc_Config__hotspot_secure_2g_last_enabled "hotspot_secure_2g_last_enabled"
#define SCHEMA__Wifi_Rfc_Config__hotspot_secure_5g_last_enabled "hotspot_secure_5g_last_enabled"
#define SCHEMA__Wifi_Rfc_Config__hotspot_secure_6g_last_enabled "hotspot_secure_6g_last_enabled"
#define SCHEMA__Wifi_Rfc_Config__wifioffchannelscan_rfc "wifioffchannelscan_rfc"
#define SCHEMA__Wifi_Rfc_Config__Levl_rfc "levl_enabled_rfc"

#define SCHEMA__Alarms__code "code"
#define SCHEMA__Alarms__timestamp "timestamp"
#define SCHEMA__Alarms__source "source"
#define SCHEMA__Alarms__add_info "add_info"

#define SCHEMA__Wifi_MacFilter_Config__macfilter_key "macfilter_key"
#define SCHEMA__Wifi_MacFilter_Config__device_name "device_name"
#define SCHEMA__Wifi_MacFilter_Config__devie_mac "device_mac"
#define SCHEMA__Wifi_MacFilter_Config__reason "reason"
#define SCHEMA__Wifi_MacFilter_Config__expiry_time "expiry_time"

#define SCHEMA__Wifi_Master_State__if_type "if_type"
#define SCHEMA__Wifi_Master_State__if_uuid "if_uuid"
#define SCHEMA__Wifi_Master_State__if_name "if_name"
#define SCHEMA__Wifi_Master_State__port_state "port_state"
#define SCHEMA__Wifi_Master_State__network_state "network_state"
#define SCHEMA__Wifi_Master_State__inet_addr "inet_addr"
#define SCHEMA__Wifi_Master_State__netmask "netmask"
#define SCHEMA__Wifi_Master_State__dhcpc "dhcpc"
#define SCHEMA__Wifi_Master_State__onboard_type "onboard_type"
#define SCHEMA__Wifi_Master_State__uplink_priority "uplink_priority"


#define SCHEMA__Wifi_Ethernet_State__mac "mac"
#define SCHEMA__Wifi_Ethernet_State__enabled "enabled"
#define SCHEMA__Wifi_Ethernet_State__connected "connected"


#define SCHEMA__Connection_Manager_Uplink__if_type "if_type"
#define SCHEMA__Connection_Manager_Uplink__if_name "if_name"
#define SCHEMA__Connection_Manager_Uplink__priority "priority"
#define SCHEMA__Connection_Manager_Uplink__loop "loop"
#define SCHEMA__Connection_Manager_Uplink__has_L2 "has_L2"
#define SCHEMA__Connection_Manager_Uplink__has_L3 "has_L3"
#define SCHEMA__Connection_Manager_Uplink__is_used "is_used"
#define SCHEMA__Connection_Manager_Uplink__ntp_state "ntp_state"
#define SCHEMA__Connection_Manager_Uplink__unreachable_link_counter "unreachable_link_counter"
#define SCHEMA__Connection_Manager_Uplink__unreachable_router_counter "unreachable_router_counter"
#define SCHEMA__Connection_Manager_Uplink__unreachable_internet_counter "unreachable_internet_counter"
#define SCHEMA__Connection_Manager_Uplink__unreachable_cloud_counter "unreachable_cloud_counter"


#define SCHEMA__Wifi_Inet_Config__if_name "if_name"
#define SCHEMA__Wifi_Inet_Config__if_type "if_type"
#define SCHEMA__Wifi_Inet_Config__if_uuid "if_uuid"
#define SCHEMA__Wifi_Inet_Config__enabled "enabled"
#define SCHEMA__Wifi_Inet_Config__network "network"
#define SCHEMA__Wifi_Inet_Config__NAT "NAT"
#define SCHEMA__Wifi_Inet_Config__ip_assign_scheme "ip_assign_scheme"
#define SCHEMA__Wifi_Inet_Config__inet_addr "inet_addr"
#define SCHEMA__Wifi_Inet_Config__netmask "netmask"
#define SCHEMA__Wifi_Inet_Config__gateway "gateway"
#define SCHEMA__Wifi_Inet_Config__broadcast "broadcast"
#define SCHEMA__Wifi_Inet_Config__gre_remote_inet_addr "gre_remote_inet_addr"
#define SCHEMA__Wifi_Inet_Config__gre_local_inet_addr "gre_local_inet_addr"
#define SCHEMA__Wifi_Inet_Config__gre_ifname "gre_ifname"
#define SCHEMA__Wifi_Inet_Config__gre_remote_mac_addr "gre_remote_mac_addr"
#define SCHEMA__Wifi_Inet_Config__mtu "mtu"
#define SCHEMA__Wifi_Inet_Config__dns "dns"
#define SCHEMA__Wifi_Inet_Config__dhcpd "dhcpd"
#define SCHEMA__Wifi_Inet_Config__upnp_mode "upnp_mode"
#define SCHEMA__Wifi_Inet_Config__dhcp_sniff "dhcp_sniff"
#define SCHEMA__Wifi_Inet_Config__vlan_id "vlan_id"
#define SCHEMA__Wifi_Inet_Config__parent_ifname "parent_ifname"
#define SCHEMA__Wifi_Inet_Config__ppp_options "ppp_options"
#define SCHEMA__Wifi_Inet_Config__softwds_mac_addr "softwds_mac_addr"
#define SCHEMA__Wifi_Inet_Config__softwds_wrap "softwds_wrap"
#define SCHEMA__Wifi_Inet_Config__igmp_proxy "igmp_proxy"
#define SCHEMA__Wifi_Inet_Config__mld_proxy "mld_proxy"
#define SCHEMA__Wifi_Inet_Config__igmp "igmp"
#define SCHEMA__Wifi_Inet_Config__igmp_age "igmp_age"
#define SCHEMA__Wifi_Inet_Config__igmp_tsize "igmp_tsize"


#define SCHEMA__Wifi_Inet_State__if_name "if_name"
#define SCHEMA__Wifi_Inet_State__inet_config "inet_config"
#define SCHEMA__Wifi_Inet_State__if_type "if_type"
#define SCHEMA__Wifi_Inet_State__if_uuid "if_uuid"
#define SCHEMA__Wifi_Inet_State__enabled "enabled"
#define SCHEMA__Wifi_Inet_State__network "network"
#define SCHEMA__Wifi_Inet_State__NAT "NAT"
#define SCHEMA__Wifi_Inet_State__ip_assign_scheme "ip_assign_scheme"
#define SCHEMA__Wifi_Inet_State__inet_addr "inet_addr"
#define SCHEMA__Wifi_Inet_State__netmask "netmask"
#define SCHEMA__Wifi_Inet_State__gateway "gateway"
#define SCHEMA__Wifi_Inet_State__broadcast "broadcast"
#define SCHEMA__Wifi_Inet_State__gre_remote_inet_addr "gre_remote_inet_addr"
#define SCHEMA__Wifi_Inet_State__gre_local_inet_addr "gre_local_inet_addr"
#define SCHEMA__Wifi_Inet_State__gre_ifname "gre_ifname"
#define SCHEMA__Wifi_Inet_State__mtu "mtu"
#define SCHEMA__Wifi_Inet_State__dns "dns"
#define SCHEMA__Wifi_Inet_State__dhcpd "dhcpd"
#define SCHEMA__Wifi_Inet_State__hwaddr "hwaddr"
#define SCHEMA__Wifi_Inet_State__dhcpc "dhcpc"
#define SCHEMA__Wifi_Inet_State__upnp_mode "upnp_mode"
#define SCHEMA__Wifi_Inet_State__vlan_id "vlan_id"
#define SCHEMA__Wifi_Inet_State__parent_ifname "parent_ifname"
#define SCHEMA__Wifi_Inet_State__softwds_mac_addr "softwds_mac_addr"
#define SCHEMA__Wifi_Inet_State__softwds_wrap "softwds_wrap"


#define SCHEMA__Wifi_Route_State__if_name "if_name"
#define SCHEMA__Wifi_Route_State__dest_addr "dest_addr"
#define SCHEMA__Wifi_Route_State__dest_mask "dest_mask"
#define SCHEMA__Wifi_Route_State__gateway "gateway"
#define SCHEMA__Wifi_Route_State__gateway_hwaddr "gateway_hwaddr"

#define SCHEMA__Wifi_Radio_Config_ovs__if_name "if_name"
#define SCHEMA__Wifi_Radio_Config_ovs__freq_band "freq_band"
#define SCHEMA__Wifi_Radio_Config_ovs__enabled "enabled"
#define SCHEMA__Wifi_Radio_Config_ovs__dfs_demo "dfs_demo"
#define SCHEMA__Wifi_Radio_Config_ovs__hw_type "hw_type"
#define SCHEMA__Wifi_Radio_Config_ovs__hw_config "hw_config"
#define SCHEMA__Wifi_Radio_Config_ovs__country "country"
#define SCHEMA__Wifi_Radio_Config_ovs__channel "channel"
#define SCHEMA__Wifi_Radio_Config_ovs__channel_sync "channel_sync"
#define SCHEMA__Wifi_Radio_Config_ovs__channel_mode "channel_mode"
#define SCHEMA__Wifi_Radio_Config_ovs__hw_mode "hw_mode"
#define SCHEMA__Wifi_Radio_Config_ovs__ht_mode "ht_mode"
#define SCHEMA__Wifi_Radio_Config_ovs__thermal_shutdown "thermal_shutdown"
#define SCHEMA__Wifi_Radio_Config_ovs__thermal_downgrade_temp "thermal_downgrade_temp"
#define SCHEMA__Wifi_Radio_Config_ovs__thermal_upgrade_temp "thermal_upgrade_temp"
#define SCHEMA__Wifi_Radio_Config_ovs__thermal_integration "thermal_integration"
#define SCHEMA__Wifi_Radio_Config_ovs__temperature_control "temperature_control"
#define SCHEMA__Wifi_Radio_Config_ovs__vif_configs "vif_configs"
#define SCHEMA__Wifi_Radio_Config_ovs__tx_power "tx_power"
#define SCHEMA__Wifi_Radio_Config_ovs__bcn_int "bcn_int"
#define SCHEMA__Wifi_Radio_Config_ovs__tx_chainmask "tx_chainmask"
#define SCHEMA__Wifi_Radio_Config_ovs__thermal_tx_chainmask "thermal_tx_chainmask"
#define SCHEMA__Wifi_Radio_Config_ovs__fallback_parents "fallback_parents"
#define SCHEMA__Wifi_Radio_Config_ovs__zero_wait_dfs "zero_wait_dfs"

#define SCHEMA__Wifi_Radio_State__if_name "if_name"
#define SCHEMA__Wifi_Radio_State__radio_config "radio_config"
#define SCHEMA__Wifi_Radio_State__freq_band "freq_band"
#define SCHEMA__Wifi_Radio_State__enabled "enabled"
#define SCHEMA__Wifi_Radio_State__dfs_demo "dfs_demo"
#define SCHEMA__Wifi_Radio_State__hw_type "hw_type"
#define SCHEMA__Wifi_Radio_State__hw_params "hw_params"
#define SCHEMA__Wifi_Radio_State__radar "radar"
#define SCHEMA__Wifi_Radio_State__hw_config "hw_config"
#define SCHEMA__Wifi_Radio_State__country "country"
#define SCHEMA__Wifi_Radio_State__channel "channel"
#define SCHEMA__Wifi_Radio_State__channel_sync "channel_sync"
#define SCHEMA__Wifi_Radio_State__channel_mode "channel_mode"
#define SCHEMA__Wifi_Radio_State__mac "mac"
#define SCHEMA__Wifi_Radio_State__hw_mode "hw_mode"
#define SCHEMA__Wifi_Radio_State__ht_mode "ht_mode"
#define SCHEMA__Wifi_Radio_State__thermal_shutdown "thermal_shutdown"
#define SCHEMA__Wifi_Radio_State__thermal_downgrade_temp "thermal_downgrade_temp"
#define SCHEMA__Wifi_Radio_State__thermal_upgrade_temp "thermal_upgrade_temp"
#define SCHEMA__Wifi_Radio_State__thermal_integration "thermal_integration"
#define SCHEMA__Wifi_Radio_State__thermal_downgraded "thermal_downgraded"
#define SCHEMA__Wifi_Radio_State__temperature_control "temperature_control"
#define SCHEMA__Wifi_Radio_State__vif_states "vif_states"
#define SCHEMA__Wifi_Radio_State__tx_power "tx_power"
#define SCHEMA__Wifi_Radio_State__bcn_int "bcn_int"
#define SCHEMA__Wifi_Radio_State__tx_chainmask "tx_chainmask"
#define SCHEMA__Wifi_Radio_State__thermal_tx_chainmask "thermal_tx_chainmask"
#define SCHEMA__Wifi_Radio_State__allowed_channels "allowed_channels"
#define SCHEMA__Wifi_Radio_State__channels "channels"
#define SCHEMA__Wifi_Radio_State__fallback_parents "fallback_parents"
#define SCHEMA__Wifi_Radio_State__zero_wait_dfs "zero_wait_dfs"


#define SCHEMA__Wifi_Credential_Config__ssid "ssid"
#define SCHEMA__Wifi_Credential_Config__security "security"
#define SCHEMA__Wifi_Credential_Config__onboard_type "onboard_type"


#define SCHEMA__Wifi_VIF_Config__if_name "if_name"
#define SCHEMA__Wifi_VIF_Config__enabled "enabled"
#define SCHEMA__Wifi_VIF_Config__mode "mode"
#define SCHEMA__Wifi_VIF_Config__parent "parent"
#define SCHEMA__Wifi_VIF_Config__vif_radio_idx "vif_radio_idx"
#define SCHEMA__Wifi_VIF_Config__vif_dbg_lvl "vif_dbg_lvl"
#define SCHEMA__Wifi_VIF_Config__wds "wds"
#define SCHEMA__Wifi_VIF_Config__ssid "ssid"
#define SCHEMA__Wifi_VIF_Config__ssid_broadcast "ssid_broadcast"
#define SCHEMA__Wifi_VIF_Config__security "security"
#define SCHEMA__Wifi_VIF_Config__credential_configs "credential_configs"
#define SCHEMA__Wifi_VIF_Config__bridge "bridge"
#define SCHEMA__Wifi_VIF_Config__mac_list "mac_list"
#define SCHEMA__Wifi_VIF_Config__mac_list_type "mac_list_type"
#define SCHEMA__Wifi_VIF_Config__vlan_id "vlan_id"
#define SCHEMA__Wifi_VIF_Config__min_hw_mode "min_hw_mode"
#define SCHEMA__Wifi_VIF_Config__uapsd_enable "uapsd_enable"
#define SCHEMA__Wifi_VIF_Config__group_rekey "group_rekey"
#define SCHEMA__Wifi_VIF_Config__ap_bridge "ap_bridge"
#define SCHEMA__Wifi_VIF_Config__ft_psk "ft_psk"
#define SCHEMA__Wifi_VIF_Config__ft_mobility_domain "ft_mobility_domain"
#define SCHEMA__Wifi_VIF_Config__rrm "rrm"
#define SCHEMA__Wifi_VIF_Config__btm "btm"
#define SCHEMA__Wifi_VIF_Config__dynamic_beacon "dynamic_beacon"
#define SCHEMA__Wifi_VIF_Config__mcast2ucast "mcast2ucast"
#define SCHEMA__Wifi_VIF_Config__multi_ap "multi_ap"
#define SCHEMA__Wifi_VIF_Config__wps "wps"
#define SCHEMA__Wifi_VIF_Config__wps_pbc "wps_pbc"
#define SCHEMA__Wifi_VIF_Config__wps_pbc_key_id "wps_pbc_key_id"
#define SCHEMA__Wifi_VIF_Config__wpa "wpa"
#define SCHEMA__Wifi_VIF_Config__wpa_key_mgmt "wpa_key_mgmt"
#define SCHEMA__Wifi_VIF_Config__wpa_psks "wpa_psks"
#define SCHEMA__Wifi_VIF_Config__wpa_oftags "wpa_oftags"
#define SCHEMA__Wifi_VIF_Config__radius_srv_addr "radius_srv_addr"
#define SCHEMA__Wifi_VIF_Config__radius_srv_port "radius_srv_port"
#define SCHEMA__Wifi_VIF_Config__radius_srv_secret "radius_srv_secret"
#define SCHEMA__Wifi_VIF_Config__default_oftag "default_oftag"
#define SCHEMA__Wifi_VIF_Config__dpp_connector "dpp_connector"
#define SCHEMA__Wifi_VIF_Config__dpp_csign_hex "dpp_csign_hex"
#define SCHEMA__Wifi_VIF_Config__dpp_netaccesskey_hex "dpp_netaccesskey_hex"


#define SCHEMA__Wifi_VIF_State__vif_config "vif_config"
#define SCHEMA__Wifi_VIF_State__enabled "enabled"
#define SCHEMA__Wifi_VIF_State__if_name "if_name"
#define SCHEMA__Wifi_VIF_State__mode "mode"
#define SCHEMA__Wifi_VIF_State__state "state"
#define SCHEMA__Wifi_VIF_State__channel "channel"
#define SCHEMA__Wifi_VIF_State__mac "mac"
#define SCHEMA__Wifi_VIF_State__vif_radio_idx "vif_radio_idx"
#define SCHEMA__Wifi_VIF_State__wds "wds"
#define SCHEMA__Wifi_VIF_State__parent "parent"
#define SCHEMA__Wifi_VIF_State__ssid "ssid"
#define SCHEMA__Wifi_VIF_State__ssid_broadcast "ssid_broadcast"
#define SCHEMA__Wifi_VIF_State__security "security"
#define SCHEMA__Wifi_VIF_State__bridge "bridge"
#define SCHEMA__Wifi_VIF_State__mac_list "mac_list"
#define SCHEMA__Wifi_VIF_State__mac_list_type "mac_list_type"
#define SCHEMA__Wifi_VIF_State__associated_clients "associated_clients"
#define SCHEMA__Wifi_VIF_State__vlan_id "vlan_id"
#define SCHEMA__Wifi_VIF_State__min_hw_mode "min_hw_mode"
#define SCHEMA__Wifi_VIF_State__uapsd_enable "uapsd_enable"
#define SCHEMA__Wifi_VIF_State__group_rekey "group_rekey"
#define SCHEMA__Wifi_VIF_State__ap_bridge "ap_bridge"
#define SCHEMA__Wifi_VIF_State__ft_psk "ft_psk"
#define SCHEMA__Wifi_VIF_State__ft_mobility_domain "ft_mobility_domain"
#define SCHEMA__Wifi_VIF_State__rrm "rrm"
#define SCHEMA__Wifi_VIF_State__btm "btm"
#define SCHEMA__Wifi_VIF_State__dynamic_beacon "dynamic_beacon"
#define SCHEMA__Wifi_VIF_State__mcast2ucast "mcast2ucast"
#define SCHEMA__Wifi_VIF_State__multi_ap "multi_ap"
#define SCHEMA__Wifi_VIF_State__ap_vlan_sta_addr "ap_vlan_sta_addr"
#define SCHEMA__Wifi_VIF_State__wps "wps"
#define SCHEMA__Wifi_VIF_State__wps_pbc "wps_pbc"
#define SCHEMA__Wifi_VIF_State__wps_pbc_key_id "wps_pbc_key_id"


#define SCHEMA__Wifi_Associated_Clients__mac "mac"
#define SCHEMA__Wifi_Associated_Clients__state "state"
#define SCHEMA__Wifi_Associated_Clients__capabilities "capabilities"
#define SCHEMA__Wifi_Associated_Clients__key_id "key_id"
#define SCHEMA__Wifi_Associated_Clients__oftag "oftag"
#define SCHEMA__Wifi_Associated_Clients__uapsd "uapsd"
#define SCHEMA__Wifi_Associated_Clients__kick "kick"


#define SCHEMA__DHCP_leased_IP__hwaddr "hwaddr"
#define SCHEMA__DHCP_leased_IP__inet_addr "inet_addr"
#define SCHEMA__DHCP_leased_IP__hostname "hostname"
#define SCHEMA__DHCP_leased_IP__fingerprint "fingerprint"
#define SCHEMA__DHCP_leased_IP__vendor_class "vendor_class"
#define SCHEMA__DHCP_leased_IP__lease_time "lease_time"


#define SCHEMA__Wifi_Test_Config__test_id "test_id"
#define SCHEMA__Wifi_Test_Config__params "params"


#define SCHEMA__Wifi_Test_State__test_id "test_id"
#define SCHEMA__Wifi_Test_State__state "state"


#define SCHEMA__AW_LM_Config__name "name"
#define SCHEMA__AW_LM_Config__periodicity "periodicity"
#define SCHEMA__AW_LM_Config__upload_location "upload_location"
#define SCHEMA__AW_LM_Config__upload_token "upload_token"


#define SCHEMA__AW_LM_State__name "name"
#define SCHEMA__AW_LM_State__log_trigger "log_trigger"


#define SCHEMA__AW_Debug__name "name"
#define SCHEMA__AW_Debug__log_severity "log_severity"


#define SCHEMA__AW_Bluetooth_Config__mode "mode"
#define SCHEMA__AW_Bluetooth_Config__interval_millis "interval_millis"
#define SCHEMA__AW_Bluetooth_Config__txpower "txpower"
#define SCHEMA__AW_Bluetooth_Config__command "command"
#define SCHEMA__AW_Bluetooth_Config__payload "payload"


#define SCHEMA__AW_Bluetooth_State__mode "mode"
#define SCHEMA__AW_Bluetooth_State__interval_millis "interval_millis"
#define SCHEMA__AW_Bluetooth_State__txpower "txpower"
#define SCHEMA__AW_Bluetooth_State__command "command"
#define SCHEMA__AW_Bluetooth_State__payload "payload"


#define SCHEMA__Open_vSwitch__bridges "bridges"
#define SCHEMA__Open_vSwitch__manager_options "manager_options"
#define SCHEMA__Open_vSwitch__ssl "ssl"
#define SCHEMA__Open_vSwitch__other_config "other_config"
#define SCHEMA__Open_vSwitch__external_ids "external_ids"
#define SCHEMA__Open_vSwitch__next_cfg "next_cfg"
#define SCHEMA__Open_vSwitch__cur_cfg "cur_cfg"
#define SCHEMA__Open_vSwitch__statistics "statistics"
#define SCHEMA__Open_vSwitch__ovs_version "ovs_version"
#define SCHEMA__Open_vSwitch__db_version "db_version"
#define SCHEMA__Open_vSwitch__system_type "system_type"
#define SCHEMA__Open_vSwitch__system_version "system_version"
#define SCHEMA__Open_vSwitch__datapath_types "datapath_types"
#define SCHEMA__Open_vSwitch__iface_types "iface_types"
#define SCHEMA__Open_vSwitch__dpdk_initialized "dpdk_initialized"
#define SCHEMA__Open_vSwitch__dpdk_version "dpdk_version"


#define SCHEMA__Bridge__name "name"
#define SCHEMA__Bridge__datapath_type "datapath_type"
#define SCHEMA__Bridge__datapath_version "datapath_version"
#define SCHEMA__Bridge__datapath_id "datapath_id"
#define SCHEMA__Bridge__stp_enable "stp_enable"
#define SCHEMA__Bridge__rstp_enable "rstp_enable"
#define SCHEMA__Bridge__mcast_snooping_enable "mcast_snooping_enable"
#define SCHEMA__Bridge__ports "ports"
#define SCHEMA__Bridge__mirrors "mirrors"
#define SCHEMA__Bridge__netflow "netflow"
#define SCHEMA__Bridge__sflow "sflow"
#define SCHEMA__Bridge__ipfix "ipfix"
#define SCHEMA__Bridge__controller "controller"
#define SCHEMA__Bridge__protocols "protocols"
#define SCHEMA__Bridge__fail_mode "fail_mode"
#define SCHEMA__Bridge__status "status"
#define SCHEMA__Bridge__rstp_status "rstp_status"
#define SCHEMA__Bridge__other_config "other_config"
#define SCHEMA__Bridge__external_ids "external_ids"
#define SCHEMA__Bridge__flood_vlans "flood_vlans"
#define SCHEMA__Bridge__flow_tables "flow_tables"
#define SCHEMA__Bridge__auto_attach "auto_attach"


#define SCHEMA__Port__name "name"
#define SCHEMA__Port__interfaces "interfaces"
#define SCHEMA__Port__trunks "trunks"
#define SCHEMA__Port__cvlans "cvlans"
#define SCHEMA__Port__tag "tag"
#define SCHEMA__Port__vlan_mode "vlan_mode"
#define SCHEMA__Port__qos "qos"
#define SCHEMA__Port__mac "mac"
#define SCHEMA__Port__bond_mode "bond_mode"
#define SCHEMA__Port__lacp "lacp"
#define SCHEMA__Port__bond_updelay "bond_updelay"
#define SCHEMA__Port__bond_downdelay "bond_downdelay"
#define SCHEMA__Port__bond_active_slave "bond_active_slave"
#define SCHEMA__Port__bond_fake_iface "bond_fake_iface"
#define SCHEMA__Port__fake_bridge "fake_bridge"
#define SCHEMA__Port__status "status"
#define SCHEMA__Port__rstp_status "rstp_status"
#define SCHEMA__Port__rstp_statistics "rstp_statistics"
#define SCHEMA__Port__statistics "statistics"
#define SCHEMA__Port__protected "port_protected"
#define SCHEMA__Port__other_config "other_config"
#define SCHEMA__Port__external_ids "external_ids"


#define SCHEMA__Interface__name "name"
#define SCHEMA__Interface__type "type"
#define SCHEMA__Interface__options "options"
#define SCHEMA__Interface__ingress_policing_rate "ingress_policing_rate"
#define SCHEMA__Interface__ingress_policing_burst "ingress_policing_burst"
#define SCHEMA__Interface__mac_in_use "mac_in_use"
#define SCHEMA__Interface__mac "mac"
#define SCHEMA__Interface__ifindex "ifindex"
#define SCHEMA__Interface__external_ids "external_ids"
#define SCHEMA__Interface__ofport "ofport"
#define SCHEMA__Interface__ofport_request "ofport_request"
#define SCHEMA__Interface__bfd "bfd"
#define SCHEMA__Interface__bfd_status "bfd_status"
#define SCHEMA__Interface__cfm_mpid "cfm_mpid"
#define SCHEMA__Interface__cfm_remote_mpids "cfm_remote_mpids"
#define SCHEMA__Interface__cfm_flap_count "cfm_flap_count"
#define SCHEMA__Interface__cfm_fault "cfm_fault"
#define SCHEMA__Interface__cfm_fault_status "cfm_fault_status"
#define SCHEMA__Interface__cfm_remote_opstate "cfm_remote_opstate"
#define SCHEMA__Interface__cfm_health "cfm_health"
#define SCHEMA__Interface__lacp_current "lacp_current"
#define SCHEMA__Interface__lldp "lldp"
#define SCHEMA__Interface__other_config "other_config"
#define SCHEMA__Interface__statistics "statistics"
#define SCHEMA__Interface__status "status"
#define SCHEMA__Interface__admin_state "admin_state"
#define SCHEMA__Interface__link_state "link_state"
#define SCHEMA__Interface__link_resets "link_resets"
#define SCHEMA__Interface__link_speed "link_speed"
#define SCHEMA__Interface__duplex "duplex"
#define SCHEMA__Interface__mtu "mtu"
#define SCHEMA__Interface__mtu_request "mtu_request"
#define SCHEMA__Interface__error "error"


#define SCHEMA__Flow_Table__name "name"
#define SCHEMA__Flow_Table__flow_limit "flow_limit"
#define SCHEMA__Flow_Table__overflow_policy "overflow_policy"
#define SCHEMA__Flow_Table__groups "groups"
#define SCHEMA__Flow_Table__prefixes "prefixes"
#define SCHEMA__Flow_Table__external_ids "external_ids"


#define SCHEMA__QoS__type "type"
#define SCHEMA__QoS__queues "queues"
#define SCHEMA__QoS__other_config "other_config"
#define SCHEMA__QoS__external_ids "external_ids"


#define SCHEMA__Queue__dscp "dscp"
#define SCHEMA__Queue__other_config "other_config"
#define SCHEMA__Queue__external_ids "external_ids"


#define SCHEMA__Mirror__name "name"
#define SCHEMA__Mirror__select_all "select_all"
#define SCHEMA__Mirror__select_src_port "select_src_port"
#define SCHEMA__Mirror__select_dst_port "select_dst_port"
#define SCHEMA__Mirror__select_vlan "select_vlan"
#define SCHEMA__Mirror__output_port "output_port"
#define SCHEMA__Mirror__output_vlan "output_vlan"
#define SCHEMA__Mirror__snaplen "snaplen"
#define SCHEMA__Mirror__statistics "statistics"
#define SCHEMA__Mirror__external_ids "external_ids"


#define SCHEMA__NetFlow__targets "targets"
#define SCHEMA__NetFlow__engine_type "engine_type"
#define SCHEMA__NetFlow__engine_id "engine_id"
#define SCHEMA__NetFlow__add_id_to_interface "add_id_to_interface"
#define SCHEMA__NetFlow__active_timeout "active_timeout"
#define SCHEMA__NetFlow__external_ids "external_ids"


#define SCHEMA__sFlow__targets "targets"
#define SCHEMA__sFlow__sampling "sampling"
#define SCHEMA__sFlow__polling "polling"
#define SCHEMA__sFlow__header "header"
#define SCHEMA__sFlow__agent "agent"
#define SCHEMA__sFlow__external_ids "external_ids"


#define SCHEMA__IPFIX__targets "targets"
#define SCHEMA__IPFIX__sampling "sampling"
#define SCHEMA__IPFIX__obs_domain_id "obs_domain_id"
#define SCHEMA__IPFIX__obs_point_id "obs_point_id"
#define SCHEMA__IPFIX__cache_active_timeout "cache_active_timeout"
#define SCHEMA__IPFIX__cache_max_flows "cache_max_flows"
#define SCHEMA__IPFIX__other_config "other_config"
#define SCHEMA__IPFIX__external_ids "external_ids"


#define SCHEMA__Flow_Sample_Collector_Set__id "id"
#define SCHEMA__Flow_Sample_Collector_Set__bridge "bridge"
#define SCHEMA__Flow_Sample_Collector_Set__ipfix "ipfix"
#define SCHEMA__Flow_Sample_Collector_Set__external_ids "external_ids"


#define SCHEMA__Controller__target "target"
#define SCHEMA__Controller__max_backoff "max_backoff"
#define SCHEMA__Controller__inactivity_probe "inactivity_probe"
#define SCHEMA__Controller__connection_mode "connection_mode"
#define SCHEMA__Controller__local_ip "local_ip"
#define SCHEMA__Controller__local_netmask "local_netmask"
#define SCHEMA__Controller__local_gateway "local_gateway"
#define SCHEMA__Controller__enable_async_messages "enable_async_messages"
#define SCHEMA__Controller__controller_rate_limit "controller_rate_limit"
#define SCHEMA__Controller__controller_burst_limit "controller_burst_limit"
#define SCHEMA__Controller__other_config "other_config"
#define SCHEMA__Controller__external_ids "external_ids"
#define SCHEMA__Controller__is_connected "is_connected"
#define SCHEMA__Controller__role "role"
#define SCHEMA__Controller__status "status"


#define SCHEMA__Manager__target "target"
#define SCHEMA__Manager__max_backoff "max_backoff"
#define SCHEMA__Manager__inactivity_probe "inactivity_probe"
#define SCHEMA__Manager__connection_mode "connection_mode"
#define SCHEMA__Manager__other_config "other_config"
#define SCHEMA__Manager__external_ids "external_ids"
#define SCHEMA__Manager__is_connected "is_connected"
#define SCHEMA__Manager__status "status"


#define SCHEMA__SSL__private_key "private_key"
#define SCHEMA__SSL__certificate "certificate"
#define SCHEMA__SSL__ca_cert "ca_cert"
#define SCHEMA__SSL__bootstrap_ca_cert "bootstrap_ca_cert"
#define SCHEMA__SSL__external_ids "external_ids"


#define SCHEMA__AutoAttach__system_name "system_name"
#define SCHEMA__AutoAttach__system_description "system_description"
#define SCHEMA__AutoAttach__mappings "mappings"


#define SCHEMA__BeaconReport__if_name "if_name"
#define SCHEMA__BeaconReport__DstMac "DstMac"
#define SCHEMA__BeaconReport__Bssid "Bssid"
#define SCHEMA__BeaconReport__RegulatoryClass "RegulatoryClass"
#define SCHEMA__BeaconReport__ChanNum "ChanNum"
#define SCHEMA__BeaconReport__RandomInterval "RandomInterval"
#define SCHEMA__BeaconReport__Duration "Duration"
#define SCHEMA__BeaconReport__Mode "Mode"


#define SCHEMA__Wifi_Stats_Config__stats_type "stats_type"
#define SCHEMA__Wifi_Stats_Config__report_type "report_type"
#define SCHEMA__Wifi_Stats_Config__radio_type "radio_type"
#define SCHEMA__Wifi_Stats_Config__survey_type "survey_type"
#define SCHEMA__Wifi_Stats_Config__reporting_interval "reporting_interval"
#define SCHEMA__Wifi_Stats_Config__reporting_count "reporting_count"
#define SCHEMA__Wifi_Stats_Config__sampling_interval "sampling_interval"
#define SCHEMA__Wifi_Stats_Config__survey_interval_ms "survey_interval_ms"
#define SCHEMA__Wifi_Stats_Config__channel_list "channel_list"
#define SCHEMA__Wifi_Stats_Config__threshold "threshold"


#define SCHEMA__DHCP_reserved_IP__hostname "hostname"
#define SCHEMA__DHCP_reserved_IP__ip_addr "ip_addr"
#define SCHEMA__DHCP_reserved_IP__hw_addr "hw_addr"


#define SCHEMA__IP_Port_Forward__protocol "protocol"
#define SCHEMA__IP_Port_Forward__src_ifname "src_ifname"
#define SCHEMA__IP_Port_Forward__src_port "src_port"
#define SCHEMA__IP_Port_Forward__dst_port "dst_port"
#define SCHEMA__IP_Port_Forward__dst_ipaddr "dst_ipaddr"


#define SCHEMA__OVS_MAC_Learning__brname "brname"
#define SCHEMA__OVS_MAC_Learning__ifname "ifname"
#define SCHEMA__OVS_MAC_Learning__hwaddr "hwaddr"
#define SCHEMA__OVS_MAC_Learning__vlan "vlan"


#define SCHEMA__Wifi_Speedtest_Config__testid "testid"
#define SCHEMA__Wifi_Speedtest_Config__traffic_cap "traffic_cap"
#define SCHEMA__Wifi_Speedtest_Config__delay "delay"
#define SCHEMA__Wifi_Speedtest_Config__test_type "test_type"
#define SCHEMA__Wifi_Speedtest_Config__preferred_list "preferred_list"
#define SCHEMA__Wifi_Speedtest_Config__select_server_id "select_server_id"
#define SCHEMA__Wifi_Speedtest_Config__st_server "st_server"
#define SCHEMA__Wifi_Speedtest_Config__st_port "st_port"
#define SCHEMA__Wifi_Speedtest_Config__st_len "st_len"
#define SCHEMA__Wifi_Speedtest_Config__st_parallel "st_parallel"
#define SCHEMA__Wifi_Speedtest_Config__st_udp "st_udp"
#define SCHEMA__Wifi_Speedtest_Config__st_bw "st_bw"
#define SCHEMA__Wifi_Speedtest_Config__st_pkt_len "st_pkt_len"
#define SCHEMA__Wifi_Speedtest_Config__st_dir "st_dir"


#define SCHEMA__Wifi_Speedtest_Status__testid "testid"
#define SCHEMA__Wifi_Speedtest_Status__UL "UL"
#define SCHEMA__Wifi_Speedtest_Status__DL "DL"
#define SCHEMA__Wifi_Speedtest_Status__server_name "server_name"
#define SCHEMA__Wifi_Speedtest_Status__server_IP "server_IP"
#define SCHEMA__Wifi_Speedtest_Status__ISP "ISP"
#define SCHEMA__Wifi_Speedtest_Status__RTT "RTT"
#define SCHEMA__Wifi_Speedtest_Status__jitter "jitter"
#define SCHEMA__Wifi_Speedtest_Status__duration "duration"
#define SCHEMA__Wifi_Speedtest_Status__timestamp "timestamp"
#define SCHEMA__Wifi_Speedtest_Status__status "status"
#define SCHEMA__Wifi_Speedtest_Status__DL_bytes "DL_bytes"
#define SCHEMA__Wifi_Speedtest_Status__UL_bytes "UL_bytes"
#define SCHEMA__Wifi_Speedtest_Status__DL_duration "DL_duration"
#define SCHEMA__Wifi_Speedtest_Status__UL_duration "UL_duration"
#define SCHEMA__Wifi_Speedtest_Status__test_type "test_type"
#define SCHEMA__Wifi_Speedtest_Status__pref_selected "pref_selected"
#define SCHEMA__Wifi_Speedtest_Status__hranked_offered "hranked_offered"
#define SCHEMA__Wifi_Speedtest_Status__DL_pkt_loss "DL_pkt_loss"
#define SCHEMA__Wifi_Speedtest_Status__UL_pkt_loss "UL_pkt_loss"
#define SCHEMA__Wifi_Speedtest_Status__DL_jitter "DL_jitter"
#define SCHEMA__Wifi_Speedtest_Status__UL_jitter "UL_jitter"
#define SCHEMA__Wifi_Speedtest_Status__host_remote "host_remote"


#define SCHEMA__Band_Steering_Config__if_name_2g "if_name_2g"
#define SCHEMA__Band_Steering_Config__if_name_5g "if_name_5g"
#define SCHEMA__Band_Steering_Config__chan_util_check_sec "chan_util_check_sec"
#define SCHEMA__Band_Steering_Config__chan_util_avg_count "chan_util_avg_count"
#define SCHEMA__Band_Steering_Config__chan_util_hwm "chan_util_hwm"
#define SCHEMA__Band_Steering_Config__chan_util_lwm "chan_util_lwm"
#define SCHEMA__Band_Steering_Config__inact_check_sec "inact_check_sec"
#define SCHEMA__Band_Steering_Config__inact_tmout_sec_normal "inact_tmout_sec_normal"
#define SCHEMA__Band_Steering_Config__inact_tmout_sec_overload "inact_tmout_sec_overload"
#define SCHEMA__Band_Steering_Config__def_rssi_inact_xing "def_rssi_inact_xing"
#define SCHEMA__Band_Steering_Config__def_rssi_low_xing "def_rssi_low_xing"
#define SCHEMA__Band_Steering_Config__def_rssi_xing "def_rssi_xing"
#define SCHEMA__Band_Steering_Config__kick_debounce_thresh "kick_debounce_thresh"
#define SCHEMA__Band_Steering_Config__kick_debounce_period "kick_debounce_period"
#define SCHEMA__Band_Steering_Config__success_threshold_secs "success_threshold_secs"
#define SCHEMA__Band_Steering_Config__stats_report_interval "stats_report_interval"
#define SCHEMA__Band_Steering_Config__dbg_2g_raw_chan_util "dbg_2g_raw_chan_util"
#define SCHEMA__Band_Steering_Config__dbg_5g_raw_chan_util "dbg_5g_raw_chan_util"
#define SCHEMA__Band_Steering_Config__dbg_2g_raw_rssi "dbg_2g_raw_rssi"
#define SCHEMA__Band_Steering_Config__dbg_5g_raw_rssi "dbg_5g_raw_rssi"
#define SCHEMA__Band_Steering_Config__debug_level "debug_level"
#define SCHEMA__Band_Steering_Config__gw_only "gw_only"
#define SCHEMA__Band_Steering_Config__ifnames "ifnames"


#define SCHEMA__Band_Steering_Clients__mac "mac"
#define SCHEMA__Band_Steering_Clients__hwm "hwm"
#define SCHEMA__Band_Steering_Clients__lwm "lwm"
#define SCHEMA__Band_Steering_Clients__kick_type "kick_type"
#define SCHEMA__Band_Steering_Clients__kick_reason "kick_reason"
#define SCHEMA__Band_Steering_Clients__reject_detection "reject_detection"
#define SCHEMA__Band_Steering_Clients__max_rejects "max_rejects"
#define SCHEMA__Band_Steering_Clients__rejects_tmout_secs "rejects_tmout_secs"
#define SCHEMA__Band_Steering_Clients__backoff_secs "backoff_secs"
#define SCHEMA__Band_Steering_Clients__backoff_exp_base "backoff_exp_base"
#define SCHEMA__Band_Steering_Clients__steer_during_backoff "steer_during_backoff"
#define SCHEMA__Band_Steering_Clients__sticky_kick_guard_time "sticky_kick_guard_time"
#define SCHEMA__Band_Steering_Clients__steering_kick_guard_time "steering_kick_guard_time"
#define SCHEMA__Band_Steering_Clients__sticky_kick_backoff_time "sticky_kick_backoff_time"
#define SCHEMA__Band_Steering_Clients__steering_kick_backoff_time "steering_kick_backoff_time"
#define SCHEMA__Band_Steering_Clients__settling_backoff_time "settling_backoff_time"
#define SCHEMA__Band_Steering_Clients__send_rrm_after_assoc "send_rrm_after_assoc"
#define SCHEMA__Band_Steering_Clients__send_rrm_after_xing "send_rrm_after_xing"
#define SCHEMA__Band_Steering_Clients__rrm_better_factor "rrm_better_factor"
#define SCHEMA__Band_Steering_Clients__rrm_age_time "rrm_age_time"
#define SCHEMA__Band_Steering_Clients__active_treshold_bps "active_treshold_bps"
#define SCHEMA__Band_Steering_Clients__steering_success_cnt "steering_success_cnt"
#define SCHEMA__Band_Steering_Clients__steering_fail_cnt "steering_fail_cnt"
#define SCHEMA__Band_Steering_Clients__steering_kick_cnt "steering_kick_cnt"
#define SCHEMA__Band_Steering_Clients__sticky_kick_cnt "sticky_kick_cnt"
#define SCHEMA__Band_Steering_Clients__stats_2g "stats_2g"
#define SCHEMA__Band_Steering_Clients__stats_5g "stats_5g"
#define SCHEMA__Band_Steering_Clients__kick_debounce_period "kick_debounce_period"
#define SCHEMA__Band_Steering_Clients__sc_kick_type "sc_kick_type"
#define SCHEMA__Band_Steering_Clients__sc_kick_reason "sc_kick_reason"
#define SCHEMA__Band_Steering_Clients__sc_kick_debounce_period "sc_kick_debounce_period"
#define SCHEMA__Band_Steering_Clients__sticky_kick_debounce_period "sticky_kick_debounce_period"
#define SCHEMA__Band_Steering_Clients__cs_mode "cs_mode"
#define SCHEMA__Band_Steering_Clients__cs_params "cs_params"
#define SCHEMA__Band_Steering_Clients__cs_state "cs_state"
#define SCHEMA__Band_Steering_Clients__sticky_kick_type "sticky_kick_type"
#define SCHEMA__Band_Steering_Clients__sticky_kick_reason "sticky_kick_reason"
#define SCHEMA__Band_Steering_Clients__steering_btm_params "steering_btm_params"
#define SCHEMA__Band_Steering_Clients__sc_btm_params "sc_btm_params"
#define SCHEMA__Band_Steering_Clients__sticky_btm_params "sticky_btm_params"
#define SCHEMA__Band_Steering_Clients__pref_5g "pref_5g"
#define SCHEMA__Band_Steering_Clients__kick_upon_idle "kick_upon_idle"
#define SCHEMA__Band_Steering_Clients__pre_assoc_auth_block "pre_assoc_auth_block"
#define SCHEMA__Band_Steering_Clients__rrm_bcn_rpt_params "rrm_bcn_rpt_params"
#define SCHEMA__Band_Steering_Clients__force_kick "force_kick"
#define SCHEMA__Band_Steering_Clients__pref_bs_allowed "pref_bs_allowed"
#define SCHEMA__Band_Steering_Clients__preq_snr_thr "preq_snr_thr"


#define SCHEMA__Openflow_Config__bridge "bridge"
#define SCHEMA__Openflow_Config__table "table"
#define SCHEMA__Openflow_Config__priority "priority"
#define SCHEMA__Openflow_Config__rule "rule"
#define SCHEMA__Openflow_Config__action "action"
#define SCHEMA__Openflow_Config__token "token"


#define SCHEMA__Openflow_State__bridge "bridge"
#define SCHEMA__Openflow_State__openflow_config "openflow_config"
#define SCHEMA__Openflow_State__token "token"
#define SCHEMA__Openflow_State__success "success"


#define SCHEMA__Openflow_Tag__name "name"
#define SCHEMA__Openflow_Tag__device_value "device_value"
#define SCHEMA__Openflow_Tag__cloud_value "cloud_value"


#define SCHEMA__Openflow_Tag_Group__name "name"
#define SCHEMA__Openflow_Tag_Group__tags "tags"


#define SCHEMA__Client_Nickname_Config__nickname "nickname"
#define SCHEMA__Client_Nickname_Config__mac "mac"


#define SCHEMA__Client_Freeze_Config__mac "mac"
#define SCHEMA__Client_Freeze_Config__source "source"
#define SCHEMA__Client_Freeze_Config__type "type"
#define SCHEMA__Client_Freeze_Config__blocked "blocked"


#define SCHEMA__Node_Config__persist "persist"
#define SCHEMA__Node_Config__module "module"
#define SCHEMA__Node_Config__key "key"
#define SCHEMA__Node_Config__value "value"


#define SCHEMA__Node_State__persist "persist"
#define SCHEMA__Node_State__module "module"
#define SCHEMA__Node_State__key "key"
#define SCHEMA__Node_State__value "value"


#define SCHEMA__Flow_Service_Manager_Config__handler "handler"
#define SCHEMA__Flow_Service_Manager_Config__type "type"
#define SCHEMA__Flow_Service_Manager_Config__if_name "if_name"
#define SCHEMA__Flow_Service_Manager_Config__pkt_capt_filter "pkt_capt_filter"
#define SCHEMA__Flow_Service_Manager_Config__plugin "plugin"
#define SCHEMA__Flow_Service_Manager_Config__other_config "other_config"


#define SCHEMA__FSM_Policy__name "name"
#define SCHEMA__FSM_Policy__idx "idx"
#define SCHEMA__FSM_Policy__mac_op "mac_op"
#define SCHEMA__FSM_Policy__macs "macs"
#define SCHEMA__FSM_Policy__fqdn_op "fqdn_op"
#define SCHEMA__FSM_Policy__fqdns "fqdns"
#define SCHEMA__FSM_Policy__fqdncat_op "fqdncat_op"
#define SCHEMA__FSM_Policy__fqdncats "fqdncats"
#define SCHEMA__FSM_Policy__ipaddr_op "ipaddr_op"
#define SCHEMA__FSM_Policy__ipaddrs "ipaddrs"
#define SCHEMA__FSM_Policy__risk_level "risk_level"
#define SCHEMA__FSM_Policy__risk_op "risk_op"
#define SCHEMA__FSM_Policy__log "log"
#define SCHEMA__FSM_Policy__action "action"
#define SCHEMA__FSM_Policy__next "next"
#define SCHEMA__FSM_Policy__policy "policy"
#define SCHEMA__FSM_Policy__redirect "redirect"
#define SCHEMA__FSM_Policy__other_config "other_config"


#define SCHEMA__Wifi_VIF_Neighbors__bssid "bssid"
#define SCHEMA__Wifi_VIF_Neighbors__if_name "if_name"
#define SCHEMA__Wifi_VIF_Neighbors__channel "channel"
#define SCHEMA__Wifi_VIF_Neighbors__ht_mode "ht_mode"
#define SCHEMA__Wifi_VIF_Neighbors__priority "priority"


#define SCHEMA__FCM_Collector_Config__name "name"
#define SCHEMA__FCM_Collector_Config__interval "interval"
#define SCHEMA__FCM_Collector_Config__filter_name "filter_name"
#define SCHEMA__FCM_Collector_Config__report_name "report_name"
#define SCHEMA__FCM_Collector_Config__other_config "other_config"


#define SCHEMA__FCM_Filter__name "name"
#define SCHEMA__FCM_Filter__index "index"
#define SCHEMA__FCM_Filter__smac "smac"
#define SCHEMA__FCM_Filter__dmac "dmac"
#define SCHEMA__FCM_Filter__vlanid "vlanid"
#define SCHEMA__FCM_Filter__src_ip "src_ip"
#define SCHEMA__FCM_Filter__dst_ip "dst_ip"
#define SCHEMA__FCM_Filter__src_port "src_port"
#define SCHEMA__FCM_Filter__dst_port "dst_port"
#define SCHEMA__FCM_Filter__proto "proto"
#define SCHEMA__FCM_Filter__appnames "appnames"
#define SCHEMA__FCM_Filter__appname_op "appname_op"
#define SCHEMA__FCM_Filter__apptags "apptags"
#define SCHEMA__FCM_Filter__apptag_op "apptag_op"
#define SCHEMA__FCM_Filter__smac_op "smac_op"
#define SCHEMA__FCM_Filter__dmac_op "dmac_op"
#define SCHEMA__FCM_Filter__vlanid_op "vlanid_op"
#define SCHEMA__FCM_Filter__src_ip_op "src_ip_op"
#define SCHEMA__FCM_Filter__dst_ip_op "dst_ip_op"
#define SCHEMA__FCM_Filter__src_port_op "src_port_op"
#define SCHEMA__FCM_Filter__dst_port_op "dst_port_op"
#define SCHEMA__FCM_Filter__proto_op "proto_op"
#define SCHEMA__FCM_Filter__pktcnt "pktcnt"
#define SCHEMA__FCM_Filter__pktcnt_op "pktcnt_op"
#define SCHEMA__FCM_Filter__action "action"
#define SCHEMA__FCM_Filter__other_config "other_config"


#define SCHEMA__FCM_Report_Config__name "name"
#define SCHEMA__FCM_Report_Config__interval "interval"
#define SCHEMA__FCM_Report_Config__format "format"
#define SCHEMA__FCM_Report_Config__hist_interval "hist_interval"
#define SCHEMA__FCM_Report_Config__hist_filter "hist_filter"
#define SCHEMA__FCM_Report_Config__report_filter "report_filter"
#define SCHEMA__FCM_Report_Config__mqtt_topic "mqtt_topic"
#define SCHEMA__FCM_Report_Config__other_config "other_config"


#define SCHEMA__IP_Interface__name "name"
#define SCHEMA__IP_Interface__enable "enable"
#define SCHEMA__IP_Interface__status "status"
#define SCHEMA__IP_Interface__interfaces "interfaces"
#define SCHEMA__IP_Interface__if_name "if_name"
#define SCHEMA__IP_Interface__ipv4_addr "ipv4_addr"
#define SCHEMA__IP_Interface__ipv6_addr "ipv6_addr"
#define SCHEMA__IP_Interface__ipv6_prefix "ipv6_prefix"


#define SCHEMA__IPv4_Address__enable "enable"
#define SCHEMA__IPv4_Address__status "status"
#define SCHEMA__IPv4_Address__address "address"
#define SCHEMA__IPv4_Address__subnet_mask "subnet_mask"
#define SCHEMA__IPv4_Address__type "type"


#define SCHEMA__IPv6_Address__enable "enable"
#define SCHEMA__IPv6_Address__status "status"
#define SCHEMA__IPv6_Address__address_status "address_status"
#define SCHEMA__IPv6_Address__address "address"
#define SCHEMA__IPv6_Address__origin "origin"
#define SCHEMA__IPv6_Address__prefix "prefix"
#define SCHEMA__IPv6_Address__preferred_lifetime "preferred_lifetime"
#define SCHEMA__IPv6_Address__valid_lifetime "valid_lifetime"


#define SCHEMA__IPv6_Prefix__enable "enable"
#define SCHEMA__IPv6_Prefix__status "status"
#define SCHEMA__IPv6_Prefix__prefix_status "prefix_status"
#define SCHEMA__IPv6_Prefix__address "address"
#define SCHEMA__IPv6_Prefix__origin "origin"
#define SCHEMA__IPv6_Prefix__static_type "static_type"
#define SCHEMA__IPv6_Prefix__parent_prefix "parent_prefix"
#define SCHEMA__IPv6_Prefix__child_prefix_bits "child_prefix_bits"
#define SCHEMA__IPv6_Prefix__on_link "on_link"
#define SCHEMA__IPv6_Prefix__autonomous "autonomous"
#define SCHEMA__IPv6_Prefix__preferred_lifetime "preferred_lifetime"
#define SCHEMA__IPv6_Prefix__valid_lifetime "valid_lifetime"


#define SCHEMA__DHCPv4_Client__enable "enable"
#define SCHEMA__DHCPv4_Client__ip_interface "ip_interface"
#define SCHEMA__DHCPv4_Client__request_options "request_options"
#define SCHEMA__DHCPv4_Client__received_options "received_options"
#define SCHEMA__DHCPv4_Client__send_options "send_options"


#define SCHEMA__DHCPv6_Client__enable "enable"
#define SCHEMA__DHCPv6_Client__ip_interface "ip_interface"
#define SCHEMA__DHCPv6_Client__request_address "request_address"
#define SCHEMA__DHCPv6_Client__request_prefixes "request_prefixes"
#define SCHEMA__DHCPv6_Client__rapid_commit "rapid_commit"
#define SCHEMA__DHCPv6_Client__renew "renew"
#define SCHEMA__DHCPv6_Client__request_options "request_options"
#define SCHEMA__DHCPv6_Client__received_options "received_options"
#define SCHEMA__DHCPv6_Client__send_options "send_options"


#define SCHEMA__DHCP_Option__enable "enable"
#define SCHEMA__DHCP_Option__version "version"
#define SCHEMA__DHCP_Option__type "type"
#define SCHEMA__DHCP_Option__tag "tag"
#define SCHEMA__DHCP_Option__value "value"


#define SCHEMA__Netfilter__name "name"
#define SCHEMA__Netfilter__enable "enable"
#define SCHEMA__Netfilter__status "status"
#define SCHEMA__Netfilter__protocol "protocol"
#define SCHEMA__Netfilter__table "table"
#define SCHEMA__Netfilter__chain "chain"
#define SCHEMA__Netfilter__priority "priority"
#define SCHEMA__Netfilter__rule "rule"
#define SCHEMA__Netfilter__target "target"


#define SCHEMA__Routing__enable "enable"
#define SCHEMA__Routing__status "status"
#define SCHEMA__Routing__protocol "protocol"
#define SCHEMA__Routing__type "type"
#define SCHEMA__Routing__ip_interface "ip_interface"
#define SCHEMA__Routing__dest "dest"
#define SCHEMA__Routing__gateway "gateway"


#define SCHEMA__DHCPv4_Server__interface "interface"
#define SCHEMA__DHCPv4_Server__status "status"
#define SCHEMA__DHCPv4_Server__min_address "min_address"
#define SCHEMA__DHCPv4_Server__max_address "max_address"
#define SCHEMA__DHCPv4_Server__lease_time "lease_time"
#define SCHEMA__DHCPv4_Server__options "options"
#define SCHEMA__DHCPv4_Server__static_address "static_address"
#define SCHEMA__DHCPv4_Server__leased_address "leased_address"


#define SCHEMA__DHCPv4_Lease__status "status"
#define SCHEMA__DHCPv4_Lease__address "address"
#define SCHEMA__DHCPv4_Lease__hwaddr "hwaddr"
#define SCHEMA__DHCPv4_Lease__hostname "hostname"
#define SCHEMA__DHCPv4_Lease__leased_time "leased_time"
#define SCHEMA__DHCPv4_Lease__leased_fingerprint "leased_fingerprint"


#define SCHEMA__DHCPv6_Server__interface "interface"
#define SCHEMA__DHCPv6_Server__status "status"
#define SCHEMA__DHCPv6_Server__prefixes "prefixes"
#define SCHEMA__DHCPv6_Server__prefix_delegation "prefix_delegation"
#define SCHEMA__DHCPv6_Server__options "options"
#define SCHEMA__DHCPv6_Server__lease_prefix "lease_prefix"
#define SCHEMA__DHCPv6_Server__static_prefix "static_prefix"


#define SCHEMA__DHCPv6_Lease__status "status"
#define SCHEMA__DHCPv6_Lease__prefix "prefix"
#define SCHEMA__DHCPv6_Lease__duid "duid"
#define SCHEMA__DHCPv6_Lease__hwaddr "hwaddr"
#define SCHEMA__DHCPv6_Lease__hostname "hostname"
#define SCHEMA__DHCPv6_Lease__leased_time "leased_time"


#define SCHEMA__IPv6_RouteAdv__interface "interface"
#define SCHEMA__IPv6_RouteAdv__status "status"
#define SCHEMA__IPv6_RouteAdv__prefixes "prefixes"
#define SCHEMA__IPv6_RouteAdv__managed "managed"
#define SCHEMA__IPv6_RouteAdv__other_config "other_config"
#define SCHEMA__IPv6_RouteAdv__home_agent "home_agent"
#define SCHEMA__IPv6_RouteAdv__max_adv_interval "max_adv_interval"
#define SCHEMA__IPv6_RouteAdv__min_adv_interval "min_adv_interval"
#define SCHEMA__IPv6_RouteAdv__default_lifetime "default_lifetime"
#define SCHEMA__IPv6_RouteAdv__preferred_router "preferred_router"
#define SCHEMA__IPv6_RouteAdv__mtu "mtu"
#define SCHEMA__IPv6_RouteAdv__reachable_time "reachable_time"
#define SCHEMA__IPv6_RouteAdv__retrans_timer "retrans_timer"
#define SCHEMA__IPv6_RouteAdv__current_hop_limit "current_hop_limit"
#define SCHEMA__IPv6_RouteAdv__rdnss "rdnss"
#define SCHEMA__IPv6_RouteAdv__dnssl "dnssl"


#define SCHEMA__IPv6_Neighbors__address "address"
#define SCHEMA__IPv6_Neighbors__hwaddr "hwaddr"
#define SCHEMA__IPv6_Neighbors__if_name "if_name"


#define SCHEMA__IGMP_Config__query_interval "query_interval"
#define SCHEMA__IGMP_Config__query_response_interval "query_response_interval"
#define SCHEMA__IGMP_Config__last_member_query_interval "last_member_query_interval"
#define SCHEMA__IGMP_Config__query_robustness_value "query_robustness_value"
#define SCHEMA__IGMP_Config__maximum_groups "maximum_groups"
#define SCHEMA__IGMP_Config__maximum_sources "maximum_sources"
#define SCHEMA__IGMP_Config__maximum_members "maximum_members"
#define SCHEMA__IGMP_Config__fast_leave_enable "fast_leave_enable"


#define SCHEMA__MLD_Config__query_interval "query_interval"
#define SCHEMA__MLD_Config__query_response_interval "query_response_interval"
#define SCHEMA__MLD_Config__last_member_query_interval "last_member_query_interval"
#define SCHEMA__MLD_Config__query_robustness_value "query_robustness_value"
#define SCHEMA__MLD_Config__maximum_groups "maximum_groups"
#define SCHEMA__MLD_Config__maximum_sources "maximum_sources"
#define SCHEMA__MLD_Config__maximum_members "maximum_members"
#define SCHEMA__MLD_Config__fast_leave_enable "fast_leave_enable"


#define SCHEMA__Reboot_Status__count "count"
#define SCHEMA__Reboot_Status__type "type"
#define SCHEMA__Reboot_Status__reason "reason"


#define SCHEMA__Service_Announcement__name "name"
#define SCHEMA__Service_Announcement__protocol "protocol"
#define SCHEMA__Service_Announcement__port "port"
#define SCHEMA__Service_Announcement__txt "txt"


#define SCHEMA__Node_Services__service "service"
#define SCHEMA__Node_Services__enable "enable"
#define SCHEMA__Node_Services__status "status"
#define SCHEMA__Node_Services__other_config "other_config"


// largest table: Band_Steering_Clients
#define SCHEMA_MAX_COLUMNS 47

#define SCHEMA__Wifi_Anqp_Config__capability_length "capability_length"
#define SCHEMA__Wifi_Anqp_Config__capability_element "capability_element"
#define SCHEMA__Wifi_Anqp_Config__ipv6_address_type "ipv6_address_type"
#define SCHEMA__Wifi_Anqp_Config__ipv4_address_type "ipv4_address_type"
#define SCHEMA__Wifi_Anqp_Config__domain_name_length "domain_name_length"
#define SCHEMA__Wifi_Anqp_Config__domain_name_element "domain_name_element"
#define SCHEMA__Wifi_Anqp_Config__roaming_consortium_length "roaming_consortium_length"
#define SCHEMA__Wifi_Anqp_Config__roaming_consortium_element "roaming_consortium_element"
#define SCHEMA__Wifi_Anqp_Config__nai_realm_length "nai_realm_length"
#define SCHEMA__Wifi_Anqp_Config__nai_realm_element "nai_realm_element"
#define SCHEMA__Wifi_Anqp_Config__gpp_cellular_length "gpp_cellular_length"
#define SCHEMA__Wifi_Anqp_Config__gpp_cellular_element "gpp_cellular_element"
#define SCHEMA__Wifi_Anqp_Config__venue_name_length "venue_name_length"
#define SCHEMA__Wifi_Anqp_Config__venue_name_element "venue_name_element"
#define SCHEMA__Wifi_Anqp_Config__vap_name "vap_name"

#define SCHEMA__Wifi_Passpoint_Config__enable "enable"
#define SCHEMA__Wifi_Passpoint_Config__group_addressed_forwarding_disable "group_addressed_forwarding_disable"
#define SCHEMA__Wifi_Passpoint_Config__p2p_cross_connect_disable "p2p_cross_connect_disable"
#define SCHEMA__Wifi_Passpoint_Config__capability_length "capability_length"
#define SCHEMA__Wifi_Passpoint_Config__capability_element "capability_element"
#define SCHEMA__Wifi_Passpoint_Config__nai_home_realm_length "nai_home_realm_length"
#define SCHEMA__Wifi_Passpoint_Config__nai_home_realm_element "nai_home_realm_element"
#define SCHEMA__Wifi_Passpoint_Config__operator_friendly_name_length "operator_friendly_name_length"
#define SCHEMA__Wifi_Passpoint_Config__operator_friendly_name_element "operator_friendly_name_element"
#define SCHEMA__Wifi_Passpoint_Config__connection_capability_length "connection_capability_length"
#define SCHEMA__Wifi_Passpoint_Config__connection_capability_element "connection_capability_element"
#define SCHEMA__Wifi_Passpoint_Config__vap_name "vap_name"

#define SCHEMA__Wifi_Radio_Config__radio_name "radio_name"
#define SCHEMA__Wifi_Radio_Config__enabled "enabled"
#define SCHEMA__Wifi_Radio_Config__freq_band "freq_band"
#define SCHEMA__Wifi_Radio_Config__auto_channel_enabled "auto_channel_enabled"
#define SCHEMA__Wifi_Radio_Config__channel "channel"
#define SCHEMA__Wifi_Radio_Config__num_secondary_channels "num_secondary_channels"
#define SCHEMA__Wifi_Radio_Config__secondary_channels_list "secondary_channels_list"
#define SCHEMA__Wifi_Radio_Config__channel_width "channel_width"
#define SCHEMA__Wifi_Radio_Config__hw_mode "hw_mode"
#define SCHEMA__Wifi_Radio_Config__csa_beacon_count "csa_beacon_count"
#define SCHEMA__Wifi_Radio_Config__country "country"
#define SCHEMA__Wifi_Radio_Config__operating_environment "operating_environment"
#define SCHEMA__Wifi_Radio_Config__dcs_enabled "dcs_enabled"
#define SCHEMA__Wifi_Radio_Config__dfs_enabled "dfs_enabled"
#define SCHEMA__Wifi_Radio_Config__vap_configs "vap_configs"
#define SCHEMA__Wifi_Radio_Config__dtim_period "dtim_period"
#define SCHEMA__Wifi_Radio_Config__beacon_interva  "beacon_interval"
#define SCHEMA__Wifi_Radio_Config__operating_class "operating_class"
#define SCHEMA__Wifi_Radio_Config__basic_data_transmit_rate "basic_data_transmit_rate"
#define SCHEMA__Wifi_Radio_Config__operational_data_transmit_rate "operational_data_transmit_rate"
#define SCHEMA__Wifi_Radio_Config__fragmentation_threshold "fragmentation_threshold"
#define SCHEMA__Wifi_Radio_Config__guard_interval "guard_interval"
#define SCHEMA__Wifi_Radio_Config__transmit_power "transmit_power"
#define SCHEMA__Wifi_Radio_Config__rts_threshold "rts_threshold"
#define SCHEMA__Wifi_Radio_Config__factory_reset_ssid "factory_reset_ssid"
#define SCHEMA__Wifi_Radio_Config__radio_stats_measuring_rate "radio_stats_measuring_rate"
#define SCHEMA__Wifi_Radio_Config__radio_stats_measuring_interval "radio_stats_measuring_interval"
#define SCHEMA__Wifi_Radio_Config__cts_protection "cts_protection"
#define SCHEMA__Wifi_Radio_Config__obss_coex "obss_coex"
#define SCHEMA__Wifi_Radio_Config__stbc_enable "stbc_enable"
#define SCHEMA__Wifi_Radio_Config__greenfield_enable "greenfield_enable"
#define SCHEMA__Wifi_Radio_Config__user_control "user_control"
#define SCHEMA__Wifi_Radio_Config__admin_control "admin_control"
#define SCHEMA__Wifi_Radio_Config__chan_util_threshold "chan_util_threshold"
#define SCHEMA__Wifi_Radio_Config__chan_util_selfheal_enable "chan_util_selfheal_enable"
#define SCHEMA__Wifi_Radio_Config__eco_power_down "eco_power_down"
#define SCHEMA__Wifi_Radio_Config__Tscan "Tscan"
#define SCHEMA__Wifi_Radio_Config__Nscan "Nscan"
#define SCHEMA__Wifi_Radio_Config__Tidle "Tidle"

#define SCHEMA__Wifi_Global_Config__gas_config "gas_config"
#define SCHEMA__Wifi_Global_Config__notify_wifi_changes "notify_wifi_changes"
#define SCHEMA__Wifi_Global_Config__prefer_private "prefer_private"
#define SCHEMA__Wifi_Global_Config__prefer_private_configure "prefer_private_configure"
#define SCHEMA__Wifi_Global_Config__factory_reset "factory_reset"
#define SCHEMA__Wifi_Global_Config__tx_overflow_selfheal "tx_overflow_selfheal"
#define SCHEMA__Wifi_Global_Config__inst_wifi_client_enabled "inst_wifi_client_enabled"
#define SCHEMA__Wifi_Global_Config__inst_wifi_client_reporting_period "inst_wifi_client_reporting_period"
#define SCHEMA__Wifi_Global_Config__inst_wifi_client_mac "inst_wifi_client_mac"
#define SCHEMA__Wifi_Global_Config__inst_wifi_client_def_reporting_period "inst_wifi_client_def_reporting_period"
#define SCHEMA__Wifi_Global_Config__wifi_active_msmt_enabled "wifi_active_msmt_enabled"
#define SCHEMA__Wifi_Global_Config__wifi_active_msmt_pktsize "wifi_active_msmt_pktsize"
#define SCHEMA__Wifi_Global_Config__wifi_active_msmt_num_samples "wifi_active_msmt_num_samples"
#define SCHEMA__Wifi_Global_Config__wifi_active_msmt_sample_duration "wifi_active_msmt_sample_duration"
#define SCHEMA__Wifi_Global_Config__vlan_cfg_version "vlan_cfg_version"
#define SCHEMA__Wifi_Global_Config__wps_pin "wps_pin"
#define SCHEMA__Wifi_Global_Config__bandsteering_enable "bandsteering_enable"
#define SCHEMA__Wifi_Global_Config__good_rssi_threshold "good_rssi_threshold"
#define SCHEMA__Wifi_Global_Config__assoc_count_threshold "assoc_count_threshold"
#define SCHEMA__Wifi_Global_Config__assoc_gate_time "assoc_gate_time"
#define SCHEMA__Wifi_Global_Config__whix_log_interval "whix_log_interval"
#define SCHEMA__Wifi_Global_Config__whix_chutility_loginterval "whix_chutility_loginterval"
#define SCHEMA__Wifi_Global_Config__assoc_monitor_duration "assoc_monitor_duration"
#define SCHEMA__Wifi_Global_Config__rapid_reconnect_enable "rapid_reconnect_enable"
#define SCHEMA__Wifi_Global_Config__vap_stats_feature "vap_stats_feature"
#define SCHEMA__Wifi_Global_Config__mfp_config_feature "mfp_config_feature"
#define SCHEMA__Wifi_Global_Config__force_disable_radio_feature "force_disable_radio_feature"
#define SCHEMA__Wifi_Global_Config__force_disable_radio_status "force_disable_radio_status"
#define SCHEMA__Wifi_Global_Config__fixed_wmm_params "fixed_wmm_params"
#define SCHEMA__Wifi_Global_Config__wifi_region_code "wifi_region_code"
#define SCHEMA__Wifi_Global_Config__diagnostic_enable "diagnostic_enable"
#define SCHEMA__Wifi_Global_Config__validate_ssid "validate_ssid"
#define SCHEMA__Wifi_Global_Config__device_network_mode "device_network_mode"
#define SCHEMA__Wifi_Global_Config__normalized_rssi_list "normalized_rssi_list"
#define SCHEMA__Wifi_Global_Config__snr_list "snr_list"
#define SCHEMA__Wifi_Global_Config__cli_stat_list "cli_stat_list"
#define SCHEMA__Wifi_Global_Config__txrx_rate_list "txrx_rate_list"

#define SCHEMA__Wifi_Preassoc_Control_Config__rssi_up_threshold "rssi_up_threshold"
#define SCHEMA__Wifi_Preassoc_Control_Config__snr_threshold "snr_threshold"
#define SCHEMA__Wifi_Preassoc_Control_Config__cu_threshold "cu_threshold"
#define SCHEMA__Wifi_Preassoc_Control_Config__basic_data_transmit_rates "basic_data_transmit_rates"
#define SCHEMA__Wifi_Preassoc_Control_Config__operational_data_transmit_rates "operational_data_transmit_rates"
#define SCHEMA__Wifi_Preassoc_Control_Config__supported_data_transmit_rates "supported_data_transmit_rates"
#define SCHEMA__Wifi_Preassoc_Control_Config__minimum_advertised_mcs "minimum_advertised_mcs"
#define SCHEMA__Wifi_Preassoc_Control_Config__sixGOpInfoMinRate "sixGOpInfoMinRate"
#define SCHEMA__Wifi_Preassoc_Control_Config__vap_name "vap_name"

#define SCHEMA__Wifi_Postassoc_Control_Config__rssi_up_threshold "rssi_up_threshold"
#define SCHEMA__Wifi_Postassoc_Control_Config__sampling_interval "sampling_interval"
#define SCHEMA__Wifi_Postassoc_Control_Config__snr_threshold "snr_threshold"
#define SCHEMA__Wifi_Postassoc_Control_Config__sampling_count "sampling_count"
#define SCHEMA__Wifi_Postassoc_Control_Config__cu_threshold "cu_threshold"
#define SCHEMA__Wifi_Postassoc_Control_Config__vap_name "vap_name"

#define SCHEMA__Wifi_Connection_Control_Config__vap_name "vap_name"
#define SCHEMA__Wifi_Connection_Control_Config__pre_assoc "pre_assoc"
#define SCHEMA__Wifi_Connection_Control_Config__post_assoc "post_assoc"
