#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bus.h"
#include "wifi_dml_cb.h"
#include "wifi_data_model.h"
#include "wifi_events.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "dml_onewifi_api.h"
#include "wifi_dml_api.h"

extern bool is_radio_config_changed;
extern bool g_update_wifi_region;
static int radio_reset_count;
long long int last_vap_change;
long long int last_radio_change;
static int g_chan_switch_count;

static inline bool is_open_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_none ||
        mode == wifi_security_mode_enhanced_open;
}

static inline bool is_personal_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_wpa_personal ||
        mode == wifi_security_mode_wpa2_personal ||
        mode == wifi_security_mode_wpa_wpa2_personal ||
        mode == wifi_security_mode_wpa3_personal ||
        mode == wifi_security_mode_wpa3_transition;
}

static inline bool is_enterprise_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_wpa_enterprise ||
        mode == wifi_security_mode_wpa2_enterprise ||
        mode == wifi_security_mode_wpa_wpa2_enterprise ||
        mode == wifi_security_mode_wpa3_enterprise;
}

bool wifi_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_dml_wifi_global_param();
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "ApplyRadioSettings")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "ApplyAccessPointSettings")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "X_CISCO_COM_FactoryReset")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "X_CISCO_COM_EnableTelnet")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "X_CISCO_COM_ResetRadios")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "WiFiStuckDetect")) {
        if ((access(WIFI_STUCK_DETECT_FILE_NAME, R_OK)) != 0) {
            *output_value = false;
        } else {
            *output_value = true;
        }
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_WiFiHost_Sync")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "2G80211axEnable")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->twoG80211axEnable_rfc;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_PreferPrivate")) {
        *output_value = pcfg->prefer_private;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_RapidReconnectIndicationEnable")) {
        *output_value = pcfg->rapid_reconnect_enable;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_vAPStatsEnable")) {
        *output_value = pcfg->vap_stats_feature;
    } else if (STR_CMP(param_name, "FeatureMFPConfig")) {
        *output_value = pcfg->mfp_config_feature;
    } else if (STR_CMP(param_name, "TxOverflowSelfheal")) {
        *output_value = pcfg->tx_overflow_selfheal;
    } else if (STR_CMP(param_name, "X_RDK-CENTRAL_COM_ForceDisable")) {
        *output_value = pcfg->force_disable_radio_feature;
    } else if (STR_CMP(param_name, "Managed_WiFi_Enabled")) {
        *output_value = 0;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s param get is not supported\n", __func__,
            __LINE__, param_name);
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_EnableRadiusGreyList")) {
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->radiusgreylist_rfc;
#else
        *output_value = false;
#endif
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_EnableHostapdAuthenticator")) {
        *output_value = true;
    } else if (STR_CMP(param_name, "DFS")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->dfs_rfc;
    } else if (STR_CMP(param_name, "Levl")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->levl_enabled_rfc;
    } else if (STR_CMP(param_name, "DFSatBootUp")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->dfsatbootup_rfc;
    } else if (STR_CMP(param_name, "WiFi-Interworking")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->wifiinterworking_rfc;
    } else if (STR_CMP(param_name, "WiFi-Passpoint")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->wifipasspoint_rfc;
    } else if (STR_CMP(param_name, "WiFi-OffChannelScan")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->wifi_offchannelscan_sm_rfc;
    } else if (STR_CMP(param_name, "WPA3_Personal_Transition")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        *output_value = rfc_params->wpa3_rfc;
    } else if (STR_CMP(param_name, "Log_Upload")) {
        char path[32] = {0};
        int val = 0;
        FILE *fp;

        fp = popen("crontab -l | grep -c copy_wifi_logs.sh","r");
        while(fgets(path, sizeof(path), fp) != NULL) {
            val = atoi(path);
            if(val == 1) {
                *output_value = true;
            }
            else  {
                *output_value = false;
            }
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload got %s and val=%d\n", __func__, __LINE__, path, val);
        }
        fclose(fp);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_dml_wifi_global_param();
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "X_RDKCENTRAL-COM_GoodRssiThreshold")) {
        *output_value = pcfg->good_rssi_threshold;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_AssocCountThreshold")) {
        *output_value = pcfg->assoc_count_threshold;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_AssocMonitorDuration")) {
        *output_value = pcfg->assoc_monitor_duration;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_AssocGateTime")) {
        *output_value = pcfg->assoc_gate_time;
    } else if (STR_CMP(param_name, "WHIX_LogInterval")) {
        *output_value = pcfg->whix_log_interval; //seconds
    } else if (STR_CMP(param_name, "WHIX_ChUtility_LogInterval")) {
        *output_value = pcfg->whix_chutility_loginterval; //seconds
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    if (STR_CMP(param_name, "RadioNumberOfEntries")) {
        *output_value = getNumberRadios();
    } else if (STR_CMP(param_name, "AccessPointNumberOfEntries")) {
        *output_value = getTotalNumberVAPs();
    } else if (STR_CMP(param_name, "SSIDNumberOfEntries")) {
        *output_value = getTotalNumberVAPs();
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }
    return true;
}

bool wifi_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    dml_global_default *p_global_def = (dml_global_default *) get_global_default_obj();
    DM_CHECK_NULL_WITH_RC(p_global_def, false);

    if (STR_CMP(param_name, "X_CISCO_COM_RadioPower")) {
        set_output_string(output_value, p_global_def->RadioPower);
    } else if (STR_CMP(param_name, "X_CISCO_COM_FactoryResetRadioAndAp")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "X_RDK_VapData")) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: This param get:%s is not supported\n",__func__,
            __LINE__, param_name);
        return false;
    } else if (STR_CMP(param_name, "X_RDK_RadioData")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_WiFi_Notification")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_Connected-Client")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_Br0_Sync")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "Status")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_GASConfiguration")) {
        char buff[2048] = { 0 };
        WiFi_GetGasConfig(buff);
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "Log_Enable")) {
        char buff[512] = { 0 };

        if (get_total_dbg_log_enable_str_value(buff) != 0) {
            set_output_string(output_value, buff);
        } else {
            set_output_string(output_value, " ");
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{   
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    if (STR_CMP(param_name, "ApplyRadioSettings")) {
        if (output_value == true) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings push to queue \n",__func__, __LINE__);
            if (push_radio_dml_cache_to_one_wifidb() == RETURN_ERR) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings falied \n",__func__, __LINE__);
                return false;
            }
            radio_reset_count++;
            last_radio_change = get_current_time_in_sec();
            if (g_update_wifi_region) {
                push_global_config_dml_cache_to_one_wifidb();
            }
        }
    } else if (STR_CMP(param_name, "ApplyAccessPointSettings")) {
        if (output_value == true){
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyAccessPointSettings push to queue \n",__func__, __LINE__);
            if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyAccessPointSettings falied \n",__func__, __LINE__);
                return false;
            }
            last_vap_change = get_current_time_in_sec();
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_FactoryReset")) {
        if (wifi_factory_reset(true) != true) {
            return false;
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_EnableTelnet")) {
        if (enable_wifi_telnet(output_value) != RETURN_OK) {
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_ResetRadios")) {
        radio_reset_count++;
    } else if (STR_CMP(param_name, "WiFiStuckDetect")) {
        if (output_value) {
            FILE *fp = fopen(WIFI_STUCK_DETECT_FILE_NAME, "a+");
            if (fp != NULL) {
                fclose(fp);
            }
        } else {
            remove(WIFI_STUCK_DETECT_FILE_NAME);
        }
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_WiFiHost_Sync")) {
        if (push_wifi_host_sync_to_ctrl_queue() == RETURN_ERR) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Failed to push host sync to ctrl queue\n", __func__, __LINE__);
            return false;
        }
    } else if (STR_CMP(param_name, "2G80211axEnable")) {
#ifndef ALWAYS_ENABLE_AX_2G
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->twoG80211axEnable_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_twoG80211axEnable_rfc);
        }
#endif
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_PreferPrivate")) {
        wifi_global_config_t *p_global_wifi_cfg;
        p_global_wifi_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();

        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);
        DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

        if(p_global_wifi_cfg->global_parameters.prefer_private == output_value) {
            return true;
        }

        if (output_value && p_rfc_cfg->radiusgreylist_rfc) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RadiussGreyList enabled=%d hence cannot enable preferPrivate\n",__func__,
                __LINE__, p_rfc_cfg->radiusgreylist_rfc);
            return false;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:prefer_private=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.prefer_private, output_value);
        p_global_wifi_cfg->global_parameters.prefer_private = output_value;
        push_global_config_dml_cache_to_one_wifidb();
        push_prefer_private_ctrl_queue(output_value);
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_RapidReconnectIndicationEnable")) {
        wifi_global_config_t *p_global_wifi_cfg;
        p_global_wifi_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
        DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

        if(p_global_wifi_cfg->global_parameters.rapid_reconnect_enable == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:rapid_reconnect_enable=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.rapid_reconnect_enable,output_value);
        p_global_wifi_cfg->global_parameters.rapid_reconnect_enable = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_vAPStatsEnable")) {
        wifi_global_config_t *p_global_wifi_cfg;
        p_global_wifi_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
        DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

        if(p_global_wifi_cfg->global_parameters.vap_stats_feature == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:vap_stats_feature=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.vap_stats_feature, output_value);
        p_global_wifi_cfg->global_parameters.vap_stats_feature = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "FeatureMFPConfig")) {
        wifi_global_config_t *p_global_wifi_cfg;
        p_global_wifi_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
        DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

        if(p_global_wifi_cfg->global_parameters.mfp_config_feature == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:mfp_config_feature=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.mfp_config_feature, output_value);
        p_global_wifi_cfg->global_parameters.mfp_config_feature = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "TxOverflowSelfheal")) {
        wifi_global_config_t *p_global_wifi_cfg;
        p_global_wifi_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
        DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

        if(p_global_wifi_cfg->global_parameters.tx_overflow_selfheal == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:tx_overflow_selfheal=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.tx_overflow_selfheal, output_value);
        p_global_wifi_cfg->global_parameters.tx_overflow_selfheal = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "X_RDK-CENTRAL_COM_ForceDisable")) {
        wifi_global_config_t *p_global_wifi_cfg;
        p_global_wifi_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
        DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

        if(p_global_wifi_cfg->global_parameters.force_disable_radio_feature == output_value) {
            return true;
        }

        uint32_t instance_number;
        wifi_radio_operationParam_t *dm_wifi_radio_op_param = NULL;
        for (instance_number = 0; instance_number < (uint32_t)getNumberRadios(); instance_number++) {
            dm_wifi_radio_op_param = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(instance_number);
            if (dm_wifi_radio_op_param == NULL) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for instance_number:%d\n", __func__,
                    __LINE__,instance_number);
                return false;
            }
            if(output_value) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d WIFI_FORCE_DISABLE_CHANGED_TO_TRUE\n", __func__, __LINE__);
                if(dm_wifi_radio_op_param->enable) {
                    dm_wifi_radio_op_param->enable = false;
                    is_radio_config_changed = true;
                    if(push_radio_dml_cache_to_one_wifidb() == RETURN_ERR) {
                        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings failed\n", __func__, __LINE__);
                        return false;
                    }
                }
            } else {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d WIFI_FORCE_DISABLE_CHANGED_TO_FALSE\n", __func__, __LINE__);
                dm_wifi_radio_op_param->enable = true;
                is_radio_config_changed = true;
                if(push_radio_dml_cache_to_one_wifidb() == RETURN_ERR) {
                     wifi_util_error_print(WIFI_DMCLI,"%s:%d ApplyRadioSettings failed\n", __func__, __LINE__);
                     return false;
                }
             }
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:force_disable_radio_status=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.force_disable_radio_feature, output_value);
        p_global_wifi_cfg->global_parameters.force_disable_radio_feature = output_value;
        push_global_config_dml_cache_to_one_wifidb();
        if(output_value) {
            wifi_util_info_print(WIFI_DMCLI,"RDK_LOG_WARN, WIFI_FORCE_DISABLE_CHANGED_TO_TRUE\n");
        }
        else {
            wifi_util_info_print(WIFI_DMCLI,"RDK_LOG_WARN, WIFI_FORCE_DISABLE_CHANGED_TO_FALSE\n");
        }
    } else if (STR_CMP(param_name, "Managed_WiFi_Enabled")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d push_managed_wifi_disable_to_ctrl_queue to ctrl queue\n", __func__, __LINE__);
        if (!output_value) {
            if (push_managed_wifi_disable_to_ctrl_queue() == RETURN_ERR) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Failed to push_managed_wifi_disable_to_ctrl_queue to ctrl queue\n", __func__, __LINE__);
                return false;
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI,"Managed-WIFI cannot be enabled through TR-181\n");
            return false;
        }
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_EnableRadiusGreyList")) {
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
        wifi_global_config_t *p_global_wifi_cfg;
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        p_global_wifi_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);
        DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

        if (output_value != p_rfc_cfg->radiusgreylist_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value,wifi_event_type_radius_grey_list_rfc);
        }

        if (output_value && p_global_wifi_cfg->global_parameters.prefer_private) {
            wifi_util_dbg_print(WIFI_DMCLI,"prefer_private is set to false when radiusgreylist is enabled\n");
            p_global_wifi_cfg->global_parameters.prefer_private = false;
            push_global_config_dml_cache_to_one_wifidb();
            push_prefer_private_ctrl_queue(false);
        }
#if 0
        if (ANSC_STATUS_SUCCESS == CosaDmlWiFiSetEnableRadiusGreylist( output_value ))
        {
            return true;
        }
#endif//TBD
#endif
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_EnableHostapdAuthenticator")) {
    } else if (STR_CMP(param_name, "DFS")) {
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->dfs_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_dfs_rfc);
        }
    } else if (STR_CMP(param_name, "Levl")) {
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->levl_enabled_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_levl_rfc);
        }
    } else if (STR_CMP(param_name, "DFSatBootUp")) {
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->dfsatbootup_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_dfs_atbootup_rfc);
        }
    } else if (STR_CMP(param_name, "WiFi-Interworking")) {
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->wifiinterworking_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_wifi_interworking_rfc);
        }
    } else if (STR_CMP(param_name, "WiFi-Passpoint")) {
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->wifipasspoint_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_wifi_passpoint_rfc);
        }
    } else if (STR_CMP(param_name, "WiFi-OffChannelScan")) {
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->wifi_offchannelscan_sm_rfc) {
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_wifi_offchannelscan_sm_rfc);
        }
    } else if (STR_CMP(param_name, "WPA3_Personal_Transition")) {
        wifi_rfc_dml_parameters_t *p_rfc_cfg = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
        DM_CHECK_NULL_WITH_RC(p_rfc_cfg, false);

        if(output_value != p_rfc_cfg->wpa3_rfc){
            push_rfc_dml_cache_to_one_wifidb(output_value, wifi_event_type_wpa3_rfc);
        }
    } else if (STR_CMP(param_name, "Log_Upload")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload set\n", __func__, __LINE__);
        if (output_value) {
            get_stubs_descriptor()->v_secure_system_fn("/usr/ccsp/wifi/wifi_logupload.sh start");
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload started\n", __func__, __LINE__);
        } else {
            get_stubs_descriptor()->v_secure_system_fn("/usr/ccsp/wifi/wifi_logupload.sh stop");
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Log_upload stopped\n", __func__, __LINE__);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{   
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_config_t *p_global_wifi_cfg = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    DM_CHECK_NULL_WITH_RC(p_global_wifi_cfg, false);

    /* check the parameter name and set the corresponding value */
    if (STR_CMP(param_name, "X_RDKCENTRAL-COM_GoodRssiThreshold")) {
        if(p_global_wifi_cfg->global_parameters.good_rssi_threshold == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:good_rssi_threshold=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.good_rssi_threshold, output_value);
        p_global_wifi_cfg->global_parameters.good_rssi_threshold = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_AssocCountThreshold")) {
        if (p_global_wifi_cfg->global_parameters.assoc_count_threshold == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:assoc_count_threshold=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.assoc_count_threshold, output_value);
        p_global_wifi_cfg->global_parameters.assoc_count_threshold = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_AssocMonitorDuration")) {
        if (p_global_wifi_cfg->global_parameters.assoc_monitor_duration == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:assoc_monitor_duration=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.assoc_monitor_duration, output_value);
        p_global_wifi_cfg->global_parameters.assoc_monitor_duration = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_AssocGateTime")) {
        if (p_global_wifi_cfg->global_parameters.assoc_gate_time == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:assoc_gate_time=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.assoc_gate_time, output_value);
        p_global_wifi_cfg->global_parameters.assoc_gate_time = output_value;
        push_global_config_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "WHIX_LogInterval")) {
        if (p_global_wifi_cfg->global_parameters.whix_log_interval == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: WHIX_LogInterval=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.whix_log_interval, output_value);
        p_global_wifi_cfg->global_parameters.whix_log_interval = output_value; //update global structure
        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Failed to push WHIX_LogInterval to onewifi db\n",__func__, __LINE__);
        }
    } else if (STR_CMP(param_name, "WHIX_ChUtility_LogInterval")) {
        if (p_global_wifi_cfg->global_parameters.whix_chutility_loginterval == output_value) {
            return true;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: WHIX_chutility_LogInterval=%d Value=%d\n",__func__, __LINE__,
            p_global_wifi_cfg->global_parameters.whix_chutility_loginterval, output_value);
        p_global_wifi_cfg->global_parameters.whix_chutility_loginterval = output_value; //update global structure
        if (push_global_config_dml_cache_to_one_wifidb() != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Failed to push WHIX_LogInterval to onewifi db\n",__func__, __LINE__);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{   
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    return true;
}

bool wifi_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    DM_CHECK_NULL_WITH_RC(output_value, false);
    DM_CHECK_NULL_WITH_RC(output_value->buff, false);

    dml_global_default *p_global_def = (dml_global_default *) get_global_default_obj();
    if(p_global_def == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Null pointerr get fail\n", __func__, __LINE__);
        return false;
    }

    if (STR_CMP(param_name, "X_CISCO_COM_RadioPower")) {
        STR_COPY(p_global_def->RadioPower, output_value->buff);
    } else if (STR_CMP(param_name, "X_CISCO_COM_FactoryResetRadioAndAp")) {
        fprintf(stderr, "-- %s X_CISCO_COM_FactoryResetRadioAndAp %s\n", __func__, (char *)output_value->buff);
        if (wifi_factory_reset(false) != true) {
            return false;
        }
    } else if (STR_CMP(param_name, "X_RDK_VapData")) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: This param set:%s is not supported\n",__func__,
            __LINE__, param_name);
        return false;
    } else if (STR_CMP(param_name, "X_RDK_RadioData")) {
#if defined (FEATURE_SUPPORT_WEBCONFIG)
        if (dm_wifi_set_webconfig(output_value->buff, output_value->buff_len) == RETURN_OK) {
            wifi_util_info_print(WIFI_DMCLI,"Success in parsing Radio Config\n");
            return true;
        } else {
            wifi_util_error_print(WIFI_DMCLI,"Failed to parse Radio blob\n");
            return false;
        }
#else
        return false;
#endif
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_WiFi_Notification")) {
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_Connected-Client")) {

    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_Br0_Sync")) {
    } else if (STR_CMP(param_name, "Status")) {
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_GASConfiguration")) {
        if(WiFi_SetGasConfig(output_value->buff) == RETURN_OK) {
            return true;
        } else {
            wifi_util_error_print(WIFI_DMCLI,"Failed to Set GAS Configuration\n");
            return false;
        }
    } else if (STR_CMP(param_name, "Log_Enable")) {
        if (disable_dbg_logs(output_value->buff) != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d log disable is failed:%s\n", __func__, __LINE__,
                    output_value->buff);
            return RETURN_ERR;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
    DM_CHECK_NULL_WITH_RC(dm_radio_default, false);

    if (STR_CMP(param_name, "Enable")) {
        *output_value = pcfg->enable;
    } else if (STR_CMP(param_name, "AutoChannelSupported")) {
        *output_value = true;
    } else if (STR_CMP(param_name, "AutoChannelEnable")) {
        *output_value = pcfg->autoChannelEnabled;
    } else if (STR_CMP(param_name, "IEEE80211hSupported")) {
        *output_value = true;
    } else if (STR_CMP(param_name, "IEEE80211hEnabled")) {
        *output_value = dm_radio_default->IEEE80211hEnabled;
    } else if (STR_CMP(param_name, "X_CISCO_COM_FrameBurst")) {
        *output_value = dm_radio_default->FrameBurst;
    } else if (STR_CMP(param_name, "X_CISCO_COM_APIsolation")) {
        *output_value = dm_radio_default->APIsolation;
    } else if (STR_CMP(param_name, "X_CISCO_COM_ApplySetting")) {

    } else if (STR_CMP(param_name, "X_COMCAST_COM_DFSSupport")) {
        wifi_radio_capabilities_t radio_capab = ((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop.radiocap[radio_index];

        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d X_COMCAST_COM_DFSSupport band %d num_channels %d\n", __func__, __LINE__,
            pcfg->band, radio_capab.channel_list[0].num_channels);
        for (int i = 0; i < radio_capab.channel_list[0].num_channels; i++) {
            if ((pcfg->band == WIFI_FREQUENCY_5_BAND || pcfg->band == WIFI_FREQUENCY_5L_BAND || pcfg->band == WIFI_FREQUENCY_5H_BAND)
                && (radio_capab.channel_list[0].channels_list[i] >= 52 && radio_capab.channel_list[0].channels_list[i] <= 144)) {
                *output_value = true;
                return true;
            }
        }
        *output_value = false;
    } else if (STR_CMP(param_name, "X_COMCAST_COM_DFSEnable")) {
        *output_value = pcfg->DfsEnabled;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_RtsThresholdSupported")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "X_RDK_EcoPowerDown")) {
#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        *output_value = pcfg->EcoPowerDown;
#else
        *output_value = false;
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
    DM_CHECK_NULL_WITH_RC(dm_radio_default, false);

    if (STR_CMP(param_name, "MCS")) {
        *output_value = dm_radio_default->MCS;
    } else if (STR_CMP(param_name, "TransmitPower")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: tx_power:%d\n",__func__, __LINE__, pcfg->transmitPower);
        *output_value = pcfg->transmitPower;
    } else if (STR_CMP(param_name, "X_CISCO_COM_MbssUserControl")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: userControl:%d\n",__func__, __LINE__, pcfg->userControl);
        *output_value = pcfg->userControl;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_clientInactivityTimeout")) {
        *output_value = 0;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    if (STR_CMP(param_name, "Channel")) {
        /* collect value */
        *output_value = pcfg->channel;
    } else if (STR_CMP(param_name, "AutoChannelRefreshPeriod")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        *output_value = dm_radio_default->AutoChannelRefreshPeriod;
    } else if (STR_CMP(param_name, "X_CISCO_COM_RTSThreshold")) {
        *output_value = pcfg->rtsThreshold;
    } else if (STR_CMP(param_name, "X_CISCO_COM_FragmentationThreshold")) {
        *output_value = pcfg->fragmentationThreshold;
    } else if (STR_CMP(param_name, "X_CISCO_COM_DTIMInterval")) {
        *output_value = pcfg->dtimPeriod;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_BeaconInterval") ||
        (STR_CMP(param_name, "BeaconPeriod"))) {
        *output_value = pcfg->beaconInterval;
    } else if (STR_CMP(param_name, "X_CISCO_COM_CTSProtectionMode")) {
        *output_value = (false == pcfg->ctsProtection) ? 0 : 1;
    } else if (STR_CMP(param_name, "X_CISCO_COM_TxRate")) {
        *output_value = pcfg->transmitPower;
    } else if (STR_CMP(param_name, "X_CISCO_COM_BasicRate")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        *output_value = dm_radio_default->BasicRate;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_ChannelUtilThreshold")) {
        *output_value = pcfg->chanUtilThreshold;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_ChanUtilSelfHealEnable")) {
        *output_value = pcfg->chanUtilSelfHealEnable;
    } else if (STR_CMP(param_name, "RadioResetCount")) {
        *output_value = radio_reset_count;
    } else if (STR_CMP(param_name, "ExtensionChannel")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        *output_value = dm_radio_default->ExtensionChannel;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;
    wifi_global_config_t        *dm_wifi_global_cfg;

    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);

    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
    DM_CHECK_NULL_WITH_RC(dm_radio_default, false);

    if (STR_CMP(param_name, "Name")) {
        /* collect value */
        wifi_interface_name_t str_ifname;
        wifi_platform_property_t *wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;

        if (convert_radio_index_to_ifname(wifi_prop, radio_index, str_ifname, sizeof(str_ifname) - 1) != RETURN_OK) {
            set_output_string(output_value, "Invalid_Radio");
        }
        set_output_string(output_value, str_ifname);
    } else if (STR_CMP(param_name, "Status")) {
        wifi_platform_property_t *wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;

        if (dm_wifi_global_cfg->global_parameters.force_disable_radio_feature == true) {
            set_output_string(output_value, "Down");
        } else if (get_radio_presence(wifi_prop, radio_index) == false) {
            set_output_string(output_value, "DeepSleep");
        } else if (pcfg->enable == true) {
            set_output_string(output_value, "Up");
        } else {
            set_output_string(output_value, "Down");
        }
    } else if (STR_CMP(param_name, "OperatingFrequencyBand") || STR_CMP(param_name, "SupportedFrequencyBands")) {
        /* collect value */
        char buff[16] = { 0 };

        if (get_radio_band_string_from_int(pcfg->band, buff) != RETURN_OK) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: radio band string convert failed:%d\n",__func__, __LINE__, pcfg->band);
            return false;
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "SupportedStandards")) {
        set_output_string(output_value, dm_radio_default->SupportedStandards);
    } else if (STR_CMP(param_name, "OperatingStandards")) {
        char buff[16] = { 0 };

        if (get_radio_variant_string_from_int(pcfg->variant, buff) == 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: radio variant string convert failed:%d\n",__func__, __LINE__, pcfg->variant);
            return false;
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "PossibleChannels")) {
        wifi_rfc_dml_parameters_t *rfc_params = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        wifi_radio_capabilities_t *radio_cap;
        char buff[256] = { 0 };

        radio_cap = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop.radiocap[radio_index];
        if (get_allowed_channels_str(pcfg->band, radio_cap, buff, sizeof(buff), rfc_params->dfs_rfc) != RETURN_OK) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: get allowed_channels_str is failed:%d\n",__func__, __LINE__, radio_index);
            return false;
        }

        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "ChannelsInUse")) {
        char buff[16] = { 0 };
        snprintf(buff, sizeof(buff), "%d", pcfg->channel);
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "X_CISCO_COM_ApChannelScan")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "OperatingChannelBandwidth")) {
        char buff[16] = { 0 };

        if (get_radio_bandwidth_string_from_int(pcfg->channelWidth, buff) == 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: get radio bw is failed:%d\n",__func__, __LINE__, radio_index);
            return false;
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "GuardInterval")) {
        char buff[8] = { 0 };

        if (get_radio_guard_interval_string_from_int(pcfg->guardInterval, buff) == 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: get radio guardInterval is failed:%d\n",__func__,
                __LINE__, radio_index);
            return false;
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "TransmitPowerSupported")) {
        set_output_string(output_value, dm_radio_default->TransmitPowerSupported);
    } else if (STR_CMP(param_name, "RegulatoryDomain")) {
        char reg_domain_str[4];
        memset(reg_domain_str, 0, sizeof(reg_domain_str));
        if (get_reg_domain_string_from_int(pcfg->countryCode, pcfg->operatingEnvironment, reg_domain_str) == 0) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: get regulatory domain is failed:%d\n",__func__,
                __LINE__, pcfg->countryCode);
            return false;
	}

        set_output_string(output_value, reg_domain_str);
    } else if (STR_CMP(param_name, "BasicDataTransmitRates")) {
        char buff[64] = { 0 };

        if (get_wifi_data_tx_rate_string_from_int(pcfg->basicDataTransmitRates, buff) == 0) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: get basic data tx rates is failed:%d\n",__func__,
                __LINE__, pcfg->basicDataTransmitRates);
            return false;
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "SupportedDataTransmitRates")) {
        set_output_string(output_value, "6,9,12,18,24,36,48,54");
    } else if (STR_CMP(param_name, "OperationalDataTransmitRates")) {
        char buff[64] = { 0 };

        if (get_wifi_data_tx_rate_string_from_int(pcfg->operationalDataTransmitRates, buff) == 0) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: get operational data tx rates is failed:%d\n",__func__,
                __LINE__, pcfg->operationalDataTransmitRates);
            return false;
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "Alias")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        set_output_string(output_value, dm_radio_default->Alias);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;
    wifi_global_config_t *dm_wifi_global_cfg;
    wifi_radio_operationParam_t *dm_radio_param;

    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);

    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    dm_radio_param = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(radio_index);
    if (dm_radio_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for radio_index:%d\n", __func__, __LINE__, radio_index);
        return false;
    }

    if ((radio_index < 0) || (radio_index > (int)get_num_radio_dml())) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Radio index:%d out of range\n", radio_index);
        return false;
    }

    if(STR_CMP(param_name, "Enable")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: enable=%d set value=%d radio_index=%d\n", __func__, __LINE__,
            dm_radio_param->enable, output_value, radio_index);
        if(dm_wifi_global_cfg->global_parameters.force_disable_radio_feature) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __func__, __LINE__);
            return false;
        }
        if (get_radio_presence(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, radio_index) == false) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: Not allowed to change config when radio is not present in CPE \n", __func__, __LINE__);
            return false;
        }
        if (dm_radio_param->enable == output_value) {
            return true;
        }
        /* save update to backup */
        dm_radio_param->enable  = output_value;
        is_radio_config_changed = true;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: RadioEnable : %d\n",__func__, __LINE__, dm_radio_param->enable);
    } else if (STR_CMP(param_name, "AutoChannelEnable")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:autoChannelEnabled=%d set value=%d\n",__func__, __LINE__,
            dm_radio_param->autoChannelEnabled, output_value);
        if (dm_radio_param->autoChannelEnabled == output_value) {
            return true;
        }
        /* save update to backup */
        dm_radio_param->autoChannelEnabled = output_value;
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "IEEE80211hEnabled")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        dm_radio_default->IEEE80211hEnabled = output_value;
    } else if (STR_CMP(param_name, "X_CISCO_COM_FrameBurst")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        dm_radio_default->FrameBurst = output_value;
    } else if (STR_CMP(param_name, "APIsolation")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        dm_radio_default->APIsolation = output_value;
    } else if (STR_CMP(param_name, "X_CISCO_COM_ApplySetting")) {

    } else if (STR_CMP(param_name, "X_COMCAST_COM_DFSEnable")) {
        wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        if (!(rfc_pcfg->dfs_rfc)) {
            wifi_util_info_print(WIFI_DMCLI,"DFS RFC DISABLED\n");
            return false;
        }
        dm_radio_param->DfsEnabled = output_value;
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "X_RDK_EcoPowerDown")) {
#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: EcoPowerDown=%d input=%d\n", __func__, __LINE__,
            dm_radio_param->EcoPowerDown, output_value);
        if (dm_radio_param->EcoPowerDown == output_value) {
            return true;
        }
        /* save update to backup */
        dm_radio_param->EcoPowerDown = output_value;
#ifdef FEATURE_SUPPORT_ECOPOWERDOWN
        dm_radio_param->enable = ((dm_radio_param->EcoPowerDown) ? false : true);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: Updated radio enable status based on EcoPowerDown,=%d, Enable=%d\n", __func__,
            __LINE__, dm_radio_param->EcoPowerDown, dm_radio_param->enable);
#endif // FEATURE_SUPPORT_ECOPOWERDOWN
        is_radio_config_changed = true;
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    wifi_radio_operationParam_t *dm_radio_param;
    dm_radio_param = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(radio_index);
    if (dm_radio_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for radio_index:%d\n", __func__, __LINE__, radio_index);
        return false;
    }

    if ((radio_index < 0) || (radio_index > (int)get_num_radio_dml())) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Radio index:%d out of range\n", radio_index);
        return false;
    }
    dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
    DM_CHECK_NULL_WITH_RC(dm_radio_default, false);

    if (STR_CMP(param_name, "MCS")) {  
        dm_radio_default->MCS = output_value;
    } else if (STR_CMP(param_name, "TransmitPower")) {  
        if (dm_radio_param->transmitPower == (uint32_t)output_value) {
            return  true;
        } else if (is_radio_tx_power_valid(dm_radio_default->TransmitPowerSupported, output_value) != true) {
            return false;
        }
        dm_radio_param->transmitPower = output_value;
        is_radio_config_changed = true;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:transmitPower=%d radio_index=%d\n",__func__, __LINE__,
            dm_radio_param->transmitPower, radio_index);
    } else if (STR_CMP(param_name, "X_CISCO_COM_MbssUserControl")) {
        if (dm_radio_param->userControl == (uint32_t)output_value) {
            return true;
        }

        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:userControl=%d\n",__func__, __LINE__, dm_radio_param->userControl);
        dm_radio_param->userControl = output_value;
        is_radio_config_changed = true;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    wifi_radio_operationParam_t *dm_radio_param;
    dm_radio_param = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(radio_index);
    if (dm_radio_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for radio_index:%d\n", __func__, __LINE__, radio_index);
        return false;
    }

    if ((radio_index < 0) || (radio_index > (int)get_num_radio_dml())) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Radio index:%d out of range\n", radio_index);
        return false;
    }

    if (STR_CMP(param_name, "Channel")) {
        if (radio_wifi_channel_is_valid(radio_index, output_value) != RETURN_OK) {
            return false;
        }
        if (dm_radio_param->channel == output_value) {
            return  true;
        }
        else if ((dm_radio_param->band == WIFI_FREQUENCY_5_BAND) ||
                 (dm_radio_param->band == WIFI_FREQUENCY_5L_BAND) ||
                 (dm_radio_param->band == WIFI_FREQUENCY_5H_BAND)) {
            if (is_dfs_channel_allowed(output_value) == false) {
                return false;
            }
        }

        dm_radio_param->channel = output_value;
        dm_radio_param->autoChannelEnabled = false;
        wifi_util_dbg_print(WIFI_DMCLI,"%s Channel:%d\n", __func__, dm_radio_param->channel);
        g_chan_switch_count++;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:channel=%d output_value=%d\n",__func__, __LINE__,
            dm_radio_param->channel, output_value);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "AutoChannelRefreshPeriod")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        dm_radio_default->AutoChannelRefreshPeriod = output_value;
    } else if (STR_CMP(param_name, "X_CISCO_COM_RTSThreshold")) {
        if (dm_radio_param->rtsThreshold == output_value) {
            return true;
        }
        dm_radio_param->rtsThreshold = output_value;
        wifi_util_dbg_print(WIFI_DMCLI,"%s rtsThreshold:%d\n", __func__, dm_radio_param->rtsThreshold);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "X_CISCO_COM_FragmentationThreshold")) {
        if (dm_radio_param->fragmentationThreshold == output_value) {
            return true;
        }
        dm_radio_param->fragmentationThreshold = output_value;
        wifi_util_dbg_print(WIFI_DMCLI,"%s fragmentationThreshold:%d\n", __func__, dm_radio_param->fragmentationThreshold);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "X_CISCO_COM_DTIMInterval")) {
        if (dm_radio_param->dtimPeriod == output_value) {
            return true;
        }
        dm_radio_param->dtimPeriod = output_value;
        wifi_util_dbg_print(WIFI_DMCLI,"%s dtimPeriod:%d\n", __func__, dm_radio_param->dtimPeriod);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_BeaconInterval") ||
        (STR_CMP(param_name, "BeaconPeriod"))) {
        if (dm_radio_param->beaconInterval == output_value) {
            return true;
        }
        dm_radio_param->beaconInterval = output_value;
        wifi_util_dbg_print(WIFI_DMCLI,"%s beaconInterval:%d\n", __func__, dm_radio_param->beaconInterval);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "X_CISCO_COM_CTSProtectionMode")) {
        if(dm_radio_param->ctsProtection == output_value) {
            return true;
        }

        dm_radio_param->ctsProtection = output_value;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:ctsProtection=%d\n",__func__, __LINE__, dm_radio_param->ctsProtection);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "ExtensionChannel")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);
        if (dm_radio_default->ExtensionChannel != output_value) {
            dm_radio_default->ExtensionChannel = output_value;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radio_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_radio_operationParam_t *pcfg = (wifi_radio_operationParam_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(output_value, false);
    DM_CHECK_NULL_WITH_RC(output_value->buff, false);

    int radio_index = 0;
    if (convert_freq_band_to_radio_index(pcfg->band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Invalid frequency band %X\n", __func__, __LINE__, pcfg->band);
        return false;
    }

    wifi_radio_operationParam_t *dm_radio_param;
    dm_radio_param = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(radio_index);
    if (dm_radio_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get Radio Param for radio_index:%d\n", __func__, __LINE__, radio_index);
        return false;
    }

    if ((radio_index < 0) || (radio_index > (int)get_num_radio_dml())) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Radio index:%d out of range\n", radio_index);
        return false;
    }

    if (STR_CMP(param_name, "OperatingStandards")) {
        wifi_ieee80211Variant_t radio_variant = 0;
        wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

        if ((pcfg->band == WIFI_FREQUENCY_2_4_BAND) &&
                (rfc_pcfg->twoG80211axEnable_rfc == false) &&
                (strstr(output_value->buff, "ax") != NULL)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: wifi hw variant:%s radio_band:%d 80211axEnable rfc:%d\n",
                    __func__, __LINE__, output_value->buff, pcfg->band, rfc_pcfg->twoG80211axEnable_rfc);
            return false;
        }

        if (get_radio_variant_int_from_string(output_value->buff, &radio_variant) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: wrong wifi std String=%s\n",__func__, __LINE__, output_value->buff);
            return false;
        }

        wifi_util_dbg_print(WIFI_DMCLI, "WIFI MODE SET[%d]\n", radio_variant);

        if (validate_wifi_hw_variant(pcfg->band, radio_variant) != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: wifi hw mode validation failure string=%s hw variant:%d\n",__func__,
                __LINE__,output_value->buff, radio_variant);
            return false;
        }

        uint32_t temp_channel_width = sync_bandwidth_and_hw_variant(radio_variant, dm_radio_param->channelWidth);
        if (temp_channel_width != 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d:change bandwidth from %d to %d\r\n",__func__, __LINE__,
                dm_radio_param->channelWidth, temp_channel_width);
            dm_radio_param->channelWidth = temp_channel_width;
        }

        dm_radio_param->variant = radio_variant;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:variant=%d  str_variant=%s\n",__func__, __LINE__, radio_variant, output_value->buff);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "OperatingChannelBandwidth")) {
        wifi_channelBandwidth_t tmp_chan_width = 0;
        wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

        if (get_radio_bandwidth_int_from_string(output_value->buff, &tmp_chan_width) != RETURN_OK) {
            return false;
        } else if (dm_radio_param->channelWidth == tmp_chan_width) {
            return true;
        }

        if ((tmp_chan_width == WIFI_CHANNELBANDWIDTH_160MHZ) && (dm_radio_param->band == WIFI_FREQUENCY_5_BAND)
            && (rfc_pcfg->dfs_rfc != true)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: DFS Disabled!! Cannot set to chan_width=%d\n",__func__,
                __LINE__, tmp_chan_width);
            return false;
        }

        if (dm_radio_param->band == WIFI_FREQUENCY_2_4_BAND) {
            if ((tmp_chan_width != WIFI_CHANNELBANDWIDTH_20MHZ) &&
                (tmp_chan_width != WIFI_CHANNELBANDWIDTH_40MHZ)) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d:Cannot set chan_width=%d for band:%d\n",__func__, __LINE__,
                    tmp_chan_width, dm_radio_param->band);
                return false;
            }
        }

        if (is_bandwidth_and_hw_variant_compatible(dm_radio_param->variant, tmp_chan_width) != true) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d:chan_width=%d variant:%d\n",__func__, __LINE__,
                tmp_chan_width, dm_radio_param->variant);
            return false;
        }

        dm_radio_param->channelWidth = tmp_chan_width;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: New channelWidth=%d\n", __func__, __LINE__, dm_radio_param->channelWidth);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "GuardInterval")) {
        wifi_guard_interval_t tmp_guard_interval = 0;

        if (get_radio_guard_interval_int_from_string(output_value->buff, &tmp_guard_interval) != RETURN_OK) {
            return false;
        } else if(dm_radio_param->guardInterval == tmp_guard_interval) {
            return true;
        }

        dm_radio_param->guardInterval = tmp_guard_interval;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:guardInterval=%d tmpChanWidth=%d\n",__func__, __LINE__,
            dm_radio_param->guardInterval, tmp_guard_interval);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "RegulatoryDomain")) {
        wifi_countrycode_type_t temp_country_code = 0;
        wifi_operating_env_t    temp_oper_env     = 0;
        char partner_id[PARTNER_ID_LEN] = {0};
        char current_time[50] = { 0 };
        char requestor_str[16] = { 0 };

        get_requestor_string(requestor_str);
        get_cur_time_str(current_time, sizeof(current_time));

        if (get_reg_domain_int_from_string(output_value->buff, &temp_country_code, &temp_oper_env) != RETURN_OK) {
            return false;
        } else if ((dm_radio_param->countryCode == temp_country_code) &&
                    (dm_radio_param->operatingEnvironment == temp_oper_env)) {
            return true;
        }

        dm_radio_param->countryCode = temp_country_code;
        dm_radio_param->operatingEnvironment = temp_oper_env;

        if (radio_index == 1) {
            wifi_global_config_t *dm_wifi_global_cfg;
            dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
            DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);
            snprintf(dm_wifi_global_cfg->global_parameters.wifi_region_code,
                sizeof(dm_wifi_global_cfg->global_parameters.wifi_region_code), "%s", (char *)output_value->buff);
            g_update_wifi_region = true;
            if((RETURN_OK == get_partner_id(partner_id)) && (partner_id[ 0 ] != '\0')) {
                if (update_json_param("Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code",partner_id,
                    output_value->buff, requestor_str, current_time) != RETURN_OK) {
                    wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to update WifiRegion to Json file\n", __func__, __LINE__);
                }
            }
            set_wifi_region_update_source(requestor_str);
        }

        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: country code=%d  environment=%d  input=%s\n",__func__,
            __LINE__, dm_radio_param->countryCode, dm_radio_param->operatingEnvironment, output_value->buff);
        is_radio_config_changed = true;
    } else if (STR_CMP(param_name, "BasicDataTransmitRates")) {
        uint32_t tx_rate = 0;

        if (is_valid_transmit_rate(output_value->buff)) {
            if (get_wifi_data_tx_rate_int_from_string(output_value->buff, &tx_rate) != RETURN_OK) {
                return false;
            }

            if(dm_radio_param->basicDataTransmitRates == tx_rate) {
                return true;
            }
            dm_radio_param->basicDataTransmitRates = tx_rate;
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:BasicDataTransmitRates=%d\n",__func__, __LINE__,
                dm_radio_param->basicDataTransmitRates);
            is_radio_config_changed = true;
        }
    } else if (STR_CMP(param_name, "OperationalDataTransmitRates")) {
        uint32_t tx_rate = 0;

        if (is_valid_transmit_rate(output_value->buff)) {
            if (get_wifi_data_tx_rate_int_from_string(output_value->buff, &tx_rate) != RETURN_OK) {
                return false;
            }

            if(dm_radio_param->operationalDataTransmitRates == tx_rate) {
                return true;
            }
            dm_radio_param->operationalDataTransmitRates = tx_rate;
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:operational Data Transmit Rates = %d\n",__func__, __LINE__,
                dm_radio_param->operationalDataTransmitRates);
            is_radio_config_changed = true;
        }
    } else if (STR_CMP(param_name, "Alias")) {
        dml_radio_default *dm_radio_default = get_radio_default_obj(radio_index);
        DM_CHECK_NULL_WITH_RC(dm_radio_default, false);

        if (STR_CMP(dm_radio_default->Alias, output_value->buff)) {
            return true;
        }
        STR_COPY(dm_radio_default->Alias, output_value->buff);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (isVapSTAMesh(pcfg->vap_index) && !STR_CMP(param_name, "Enable")) {
        *output_value = true;
        return true;
    }

    if (STR_CMP(param_name, "Enable")) {
        /* collect value */
        if (isVapSTAMesh(pcfg->vap_index)) {
            *output_value = pcfg->u.sta_info.enabled;
        } else {
            *output_value = pcfg->u.bss_info.enabled;
        }
    } else if(STR_CMP(param_name, "IsolationEnable")) {
        *output_value = pcfg->u.bss_info.isolation;
    } else if(STR_CMP(param_name, "SSIDAdvertisementEnabled")) {
        *output_value = pcfg->u.bss_info.showSsid;
    } else if(STR_CMP(param_name, "WMMCapability")) {
        *output_value = true;
    } else if(STR_CMP(param_name, "UAPSDCapability")) {
        *output_value = true;
    } else if(STR_CMP(param_name, "WMMEnable")) {
        *output_value = pcfg->u.bss_info.wmm_enabled;
    } else if(STR_CMP(param_name, "UAPSDEnable")) {
        *output_value = pcfg->u.bss_info.UAPSDEnabled;
    } else if(STR_CMP(param_name, "X_CISCO_COM_BssCountStaAsCpe")) {
        wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
        int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);

        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->bss_count_sta_as_cpe;
    } else if(STR_CMP(param_name, "X_CISCO_COM_BssHotSpot")) {
        *output_value = pcfg->u.bss_info.bssHotspot;
    } else if(STR_CMP(param_name, "X_CISCO_COM_KickAssocDevices")) {
        wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
        int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);

        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->kick_assoc_devices;
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_InterworkingServiceCapability")) {
#if defined (FEATURE_SUPPORT_INTERWORKING)
        return true;
#else
        *output_value = false;
#endif
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_InterworkingServiceEnable")) {
#if defined (FEATURE_SUPPORT_INTERWORKING)
        *output_value = pcfg->u.bss_info.interworking.interworking.interworkingEnabled;
#else
        *output_value = false;
#endif
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_rapidReconnectCountEnable")) {
        *output_value = pcfg->u.bss_info.rapidReconnectEnable;
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_StatsEnable")) {
        *output_value = pcfg->u.bss_info.vapStatsEnable;
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_BSSTransitionImplemented")) {
        wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
        int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

        if (isVapHotspot(vap_index) || isVapSTAMesh(vap_index) || (vap_index == 3)) {
           *output_value = false;
        } else {
           *output_value = true;
        }
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_BSSTransitionActivated")) {
        *output_value = pcfg->u.bss_info.bssTransitionActivated;
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_NeighborReportActivated")) {
        *output_value = pcfg->u.bss_info.nbrReportActivated;
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_WirelessManagementImplemented")) {
        *output_value = 1;
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_InterworkingApplySettings")) {
        *output_value = true;
    } else if(STR_CMP(param_name, "Connected_Building_Enabled")) {
        wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
        int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

        if(isVapHotspot(vap_index)) {
            *output_value = pcfg->u.bss_info.connected_building_enabled;
        } else {
            *output_value = false;
        }
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_HostapMgtFrameCtrl")) {
        *output_value = pcfg->u.bss_info.hostap_mgt_frame_ctrl;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (STR_CMP(param_name, "X_CISCO_COM_WmmNoAck")) {
        if (isVapSTAMesh(pcfg->vap_index)) {
           *output_value = 0;
        } else {
            *output_value = pcfg->u.bss_info.wmmNoAck;
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_MulticastRate")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->multicast_rate;
    } else if (STR_CMP(param_name, "X_CISCO_COM_BssMaxNumSta")) {
        *output_value = pcfg->u.bss_info.bssMaxSta;
    } else if (STR_CMP(param_name, "X_CISCO_COM_BssUserStatus")) {
        if (isVapSTAMesh(pcfg->vap_index)) {
           *output_value = (pcfg->u.sta_info.enabled == TRUE)? 1 : 2;
        } else {
            *output_value = (pcfg->u.bss_info.enabled == TRUE)? 1 : 2;
        }
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_ManagementFramePowerControl")) {
        if (isVapSTAMesh(pcfg->vap_index)) {
           *output_value = 0;
        } else {
            *output_value = pcfg->u.bss_info.mgmtPowerControl;
            wifi_util_info_print(WIFI_DMCLI,"RDK_LOG_INFO,X_RDKCENTRAL-COM_ManagementFramePowerControl:%d\n", pcfg->u.bss_info.mgmtPowerControl);
            wifi_util_info_print(WIFI_DMCLI,"X_RDKCENTRAL-COM_ManagementFramePowerControl_Get:<%d>\n", pcfg->u.bss_info.mgmtPowerControl);
        }
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_rapidReconnectMaxTime")) {
        if (isVapSTAMesh(pcfg->vap_index)) {
            *output_value = 180;
        } else {
            *output_value = pcfg->u.bss_info.rapidReconnThreshold;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (STR_CMP(param_name, "RetryLimit")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->retry_limit;
    } else if (STR_CMP(param_name, "X_CISCO_COM_LongRetryLimit")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->long_retry_limit;
    } else if (STR_CMP(param_name, "MaxAssociatedDevices")) {
        *output_value =  pcfg->u.bss_info.bssMaxSta;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->associated_devices_highwatermark_threshold;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_AssociatedDevicesHighWatermarkThresholdReached")) {
        *output_value = 3;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_AssociatedDevicesHighWatermark")) {
        *output_value = 3;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_AssociatedDevicesHighWatermarkDate")) {
	//TODO: need cacultion for the time
	*output_value = (uint32_t)get_current_time_in_sec();
    } else if (STR_CMP(param_name, "X_COMCAST-COM_TXOverflow")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->txoverflow;
    } else if (STR_CMP(param_name, "X_CISCO_COM_MacFilterTableNumberOfEntries")) {
        max_macfilter_number_of_entries(pcfg, output_value);
    } else if (STR_CMP(param_name, "AssociatedDeviceNumberOfEntries")) {
        *output_value = (uint32_t)get_associated_devices_count(pcfg);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;

    if (STR_CMP(param_name, "Status")) {
        if (isVapSTAMesh(pcfg->vap_index)) {
            if (pcfg->u.sta_info.enabled == true) {
                set_output_string(output_value, "Enabled");
            } else {
                set_output_string(output_value, "Disabled");
            }
        } else {
            if (pcfg->u.bss_info.enabled == true) {
                set_output_string(output_value, "Enabled");
            } else {
                set_output_string(output_value, "Disabled");
            }
	}
    } else if (STR_CMP(param_name, "Alias")) {
        char buff[16] = { 0 };

        snprintf(buff, sizeof(buff), "AccessPoint%d", instance_number);
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "SSIDReference")) {
        char buff[32] = { 0 };

        snprintf(buff, sizeof(buff), "Device.WiFi.SSID.%d.", instance_number);
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_BeaconRate")) {
        char buff[32] = { 0 };

        if (isVapSTAMesh(pcfg->vap_index)) {
            set_output_string(output_value, "6Mbps");
            return true;
        }

        if (get_beacon_rate_string_from_int(pcfg->u.bss_info.beaconRate, buff) == 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: beacon rate str not found:%d\n",__func__,
                __LINE__, pcfg->u.bss_info.beaconRate);
            set_output_string(output_value, " ");
        } else {
            set_output_string(output_value, buff);
        }
    } else if (STR_CMP(param_name, "X_COMCAST-COM_MAC_FilteringMode")) {
        char buff[32] = { 0 };

        if (isVapHotspot(pcfg->vap_index)) {
           snprintf(buff, sizeof(buff), "%s", "Deny");
        } else {
            if (pcfg->u.bss_info.mac_filter_enable == TRUE) {
                if (pcfg->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                    snprintf(buff, sizeof(buff), "%s", "Deny");
                } else {
                    snprintf(buff, sizeof(buff), "%s", "Allow");
                }
            } else {
                snprintf(buff, sizeof(buff), "%s", "Allow-ALL");
            }
	}
        set_output_string(output_value, buff);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_global_config_t *dm_wifi_global_cfg;
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);

    if (isVapSTAMesh(pcfg->vap_index) && !STR_CMP(param_name, "Enable")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    if(STR_CMP(param_name, "Enable")) {
        if (dm_wifi_global_cfg->global_parameters.force_disable_radio_feature) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __func__, __LINE__);
            return false;
        }
        if (isVapSTAMesh(pcfg->vap_index)) {
            p_dm_vap_info->u.sta_info.enabled = output_value;
        } else {
            p_dm_vap_info->u.bss_info.enabled = output_value;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "IsolationEnable")) {
        if (p_dm_vap_info->u.bss_info.isolation == output_value) {
            return true;
        }

        /* save update to backup */
        p_dm_vap_info->u.bss_info.isolation = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "SSIDAdvertisementEnabled")) {
        if (p_dm_vap_info->u.bss_info.showSsid == output_value) {
            return true;
        }

        /* save update to backup */
        p_dm_vap_info->u.bss_info.showSsid = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "WMMEnable")) {
        if (p_dm_vap_info->u.bss_info.wmm_enabled == output_value) {
            return true;
        }

        /* save update to backup */
        p_dm_vap_info->u.bss_info.wmm_enabled = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "UAPSDEnable")) {
        if (p_dm_vap_info->u.bss_info.UAPSDEnabled == output_value) {
            return true;
        }
        /* save update to backup */
        p_dm_vap_info->u.bss_info.UAPSDEnabled = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "X_CISCO_COM_BssCountStaAsCpe")) {
        wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
        int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);

        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        p_dm_vap_default->bss_count_sta_as_cpe = output_value;
    } else if(STR_CMP(param_name, "X_CISCO_COM_BssHotSpot")) {
        if (p_dm_vap_info->u.bss_info.bssHotspot == output_value) {
            return true;
        }
        /* save update to backup */
        p_dm_vap_info->u.bss_info.bssHotspot = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "X_CISCO_COM_KickAssocDevices")) {
        wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
        int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);

        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        p_dm_vap_default->kick_assoc_devices = output_value;
        if (p_dm_vap_default->kick_assoc_devices) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Pushing Kick assoc to control queue:%d\n", __func__,
                __LINE__, vap_index);
            push_kick_assoc_to_ctrl_queue(vap_index);
            p_dm_vap_default->kick_assoc_devices = false;
        }
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_BSSTransitionActivated")) {
        if (p_dm_vap_info->u.bss_info.bssTransitionActivated == output_value) {
            return true;
        }
        p_dm_vap_info->u.bss_info.bssTransitionActivated = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
        if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Apply BSSTransitionActivated falied\n",__func__, __LINE__);
            return false;
        }
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_rapidReconnectCountEnable")) {
        if (p_dm_vap_info->u.bss_info.rapidReconnectEnable == output_value) {
            return true;
        }
        p_dm_vap_info->u.bss_info.rapidReconnectEnable = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_StatsEnable")) {
        if (p_dm_vap_info->u.bss_info.vapStatsEnable == output_value) {
            return true;
        }
        p_dm_vap_info->u.bss_info.vapStatsEnable = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_NeighborReportActivated")) {
        if (p_dm_vap_info->u.bss_info.nbrReportActivated == output_value) {
            return true;
        }
        p_dm_vap_info->u.bss_info.nbrReportActivated = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
        if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Apply NeighborReportActivated falied\n",__func__, __LINE__);
            return false;
        }
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_InterworkingServiceEnable")) {
        if (p_dm_vap_info->u.bss_info.interworking.interworking.interworkingEnabled == output_value) {
            return true;
        }
        p_dm_vap_info->u.bss_info.interworking.interworking.interworkingEnabled = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_InterworkingApplySettings")) {
        if (output_value == true) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d X_RDKCENTRAL-COM_InterworkingApplySettings push to queue \n",__func__, __LINE__);
            if (push_vap_dml_cache_to_one_wifidb() == RETURN_ERR) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d X_RDKCENTRAL-COM_InterworkingApplySettings falied \n",__func__, __LINE__);
                return false;
            }
            last_vap_change = get_current_time_in_sec();
        }
    } else if(STR_CMP(param_name, "connected_building_enabled")) {
        if (!isVapHotspot(instance_number - 1)) {
            wifi_util_error_print(WIFI_DMCLI,"RDK_LOG_ERROR, %s connected_building_enabled  not supported for vaps other than public vaps\n", __func__);
            return false;
        }
        p_dm_vap_info->u.bss_info.connected_building_enabled = output_value;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: connected_building_enabled Value=%d\n",__func__,
            __LINE__, p_dm_vap_info->u.bss_info.connected_building_enabled);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "X_RDKCENTRAL-COM_HostapMgtFrameCtrl")) {
        p_dm_vap_info->u.bss_info.hostap_mgt_frame_ctrl = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);

        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: hostap_mgt_frame_ctrl value=%d\n", __func__,
            __LINE__, p_dm_vap_info->u.bss_info.hostap_mgt_frame_ctrl);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, pcfg->vap_name);
        return true;
    }

    if (STR_CMP(param_name, "X_CISCO_COM_WmmNoAck")) {
        if (p_dm_vap_info->u.bss_info.wmmNoAck == (uint32_t)output_value) {
            return true;
        }
        /* save update to backup */
        p_dm_vap_info->u.bss_info.wmmNoAck = (uint32_t)output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "X_CISCO_COM_MulticastRate")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(instance_number - 1);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        p_dm_vap_default->multicast_rate = output_value;
    } else if (STR_CMP(param_name, "X_CISCO_COM_BssMaxNumSta")) {
        if (p_dm_vap_info->u.bss_info.bssMaxSta == (uint32_t)output_value) {
            return true;
        }

        /* Allow users to set max station for given VAP */
        p_dm_vap_info->u.bss_info.bssMaxSta = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_ManagementFramePowerControl")) {
        if ((output_value < -20) || (output_value > 0)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Unsupported Value for ManagementFramePowerControl"
                ": Supports in the Range [-20,0]:%d\n", __func__, __LINE__, output_value);
            return false;
        } else if (p_dm_vap_info->u.bss_info.mgmtPowerControl == output_value) {
            return true;
        } else {
            /* save update to backup */
            p_dm_vap_info->u.bss_info.mgmtPowerControl = output_value;
            wifi_util_info_print(WIFI_DMCLI,"RDK_LOG_INFO,X_RDKCENTRAL-COM_ManagementFramePowerControl:%d\n", output_value);
            wifi_util_info_print(WIFI_DMCLI,"X_RDKCENTRAL-COM_ManagementFramePowerControl_Get:<%d>\n", output_value);
            set_dml_cache_vap_config_changed(instance_number - 1);
	}
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_rapidReconnectMaxTime")) {
        if (p_dm_vap_info->u.bss_info.rapidReconnThreshold == (uint32_t)output_value) {
            return true;
        }
        /* save update to backup */
        p_dm_vap_info->u.bss_info.rapidReconnThreshold = output_value;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (STR_CMP(param_name, "RetryLimit")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(instance_number - 1);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        p_dm_vap_default->retry_limit = output_value;
    } else if (STR_CMP(param_name, "X_CISCO_COM_LongRetryLimit")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(instance_number - 1);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        p_dm_vap_default->long_retry_limit = output_value;
    } else if (STR_CMP(param_name, "MaxAssociatedDevices")) {

        if (isVapSTAMesh(p_dm_vap_info->vap_index)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, p_dm_vap_info->vap_name);
            return TRUE;
        } else if (p_dm_vap_info->u.bss_info.bssMaxSta != output_value) {
            p_dm_vap_info->u.bss_info.bssMaxSta = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(instance_number - 1);
        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        p_dm_vap_default->associated_devices_highwatermark_threshold = output_value;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool accesspoint_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    if (STR_CMP(param_name, "X_RDKCENTRAL-COM_BeaconRate")) {
        wifi_bitrate_t beacon_rate_type = 0;

        if (get_beacon_rate_int_from_string((char *)output_value->buff, &beacon_rate_type) != RETURN_OK)
        {
            wifi_util_error_print(WIFI_DMCLI,"%s BeaconRate Parameter Invalid :%s\n", __func__, (char *)output_value->buff);
            return false;
        }
        p_dm_vap_info->u.bss_info.beaconRate = beacon_rate_type;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool ssid_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_global_config_t *dm_wifi_global_cfg;
    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);

    if(STR_CMP(param_name, "Enable")) {
        if (dm_wifi_global_cfg->global_parameters.force_disable_radio_feature == true) {
            *output_value = false;
        } else if (isVapSTAMesh(pcfg->vap_index)) {
            *output_value = pcfg->u.sta_info.enabled;
        } else {
            *output_value = pcfg->u.bss_info.enabled;
        }
    } else if(STR_CMP(param_name, "X_CISCO_COM_EnableOnline")) {
        if (isVapSTAMesh(pcfg->vap_index)) {
            *output_value = pcfg->u.sta_info.enabled;
        } else {
            *output_value = pcfg->u.bss_info.enabled;
        }
    } else if(STR_CMP(param_name, "X_CISCO_COM_RouterEnabled")) {
        wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
        int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);
        dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);

        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        *output_value = p_dm_vap_default->router_enabled;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool ssid_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool ssid_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    if (STR_CMP(param_name, "LastChange")) {
        *output_value = (uint32_t)get_current_time_in_sec();
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool ssid_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_global_config_t *dm_wifi_global_cfg;
    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);
    uint8_t instance_number = (uint8_t)convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;

    if (STR_CMP(param_name, "SSID")) {
        /* collect value */
        if (isVapSTAMesh(pcfg->vap_index)) {
            set_output_string(output_value, pcfg->u.sta_info.ssid);
        } else {
            set_output_string(output_value, pcfg->u.bss_info.ssid);
        }
    } else if (STR_CMP(param_name, "Status")) {
        wifi_radio_operationParam_t *p_dm_radio_param = get_dml_cache_radio_map(pcfg->radio_index);
        DM_CHECK_NULL_WITH_RC(p_dm_radio_param, false);

        if (dm_wifi_global_cfg->global_parameters.force_disable_radio_feature == true ||
            p_dm_radio_param->enable == false) {
            set_output_string(output_value, "Down");
        } else if (isVapSTAMesh(pcfg->vap_index)) {
            if (pcfg->u.sta_info.enabled == true) {
                set_output_string(output_value, "Up");
            } else {
                set_output_string(output_value, "Down");
            }
        } else if(pcfg->u.bss_info.enabled == true) {
            set_output_string(output_value, "Up");
        } else {
            set_output_string(output_value, "Down");
        }
    } else if (STR_CMP(param_name, "Alias")) {
        char buff[32] = { 0 };

        convert_apindex_to_ifname(p_wifi_prop, instance_number - 1, buff, sizeof(buff) - 1);
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "Name")) {
        set_output_string(output_value, pcfg->vap_name);
    } else if (STR_CMP(param_name, "LowerLayers")) {
        char buff[32] = { 0 };
        int radioIndex = convert_vap_name_to_radio_array_index(p_wifi_prop, pcfg->vap_name);

        snprintf(buff, sizeof(buff), "Device.WiFi.Radio.%d.", radioIndex + 1);
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "BSSID")) {
        char buff[24] = {0};

        if (isVapSTAMesh(pcfg->vap_index)) {
            sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.sta_info.bssid[0], pcfg->u.sta_info.bssid[1],
                pcfg->u.sta_info.bssid[2], pcfg->u.sta_info.bssid[3],
                pcfg->u.sta_info.bssid[4], pcfg->u.sta_info.bssid[5]);
        } else {
            sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.bss_info.bssid[0], pcfg->u.bss_info.bssid[1],
                pcfg->u.bss_info.bssid[2], pcfg->u.bss_info.bssid[3],
                pcfg->u.bss_info.bssid[4], pcfg->u.bss_info.bssid[5]);
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "MACAddress")) {
        char buff[24] = {0};

        if (isVapSTAMesh(pcfg->vap_index)) {
            sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.sta_info.mac[0], pcfg->u.sta_info.mac[1],
                pcfg->u.sta_info.mac[2], pcfg->u.sta_info.mac[3],
                pcfg->u.sta_info.mac[4], pcfg->u.sta_info.mac[5]);
        } else {
            sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
                pcfg->u.bss_info.bssid[0], pcfg->u.bss_info.bssid[1],
                pcfg->u.bss_info.bssid[2], pcfg->u.bss_info.bssid[3],
                pcfg->u.bss_info.bssid[4], pcfg->u.bss_info.bssid[5]);
        }
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "X_COMCAST-COM_DefaultSSID")) {
        char temp_ssid[64] = {0};

        if (wifi_hal_get_default_ssid(temp_ssid, pcfg->vap_index) == RETURN_OK) {
            set_output_string(output_value, temp_ssid);
        }
    } else if (STR_CMP(param_name, "Repurposed_VapName")) {
        if (strlen(pcfg->repurposed_vap_name) != 0) {
            set_output_string(output_value, pcfg->repurposed_vap_name);
        } else {
            set_output_string(output_value, " ");
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool ssid_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_global_config_t *dm_wifi_global_cfg;
    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (STR_CMP(param_name, "Enable")) {
        rdk_wifi_vap_info_t *dm_rdk_vap_info;

        dm_rdk_vap_info = (rdk_wifi_vap_info_t *)get_dml_cache_rdk_vap_info(p_dm_vap_info->vap_index);
        DM_CHECK_NULL_WITH_RC(dm_rdk_vap_info, false);

        if (output_value == true) {
            dm_rdk_vap_info->exists = output_value;
        }

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
        if (output_value == false) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d User is Trying to disable SSID for vap_index=%d\n", __func__,
                __LINE__, p_dm_vap_info->vap_index);
        }
#endif
        set_dml_cache_vap_config_changed(instance_number - 1);

        if (isVapSTAMesh(pcfg->vap_index)) {
            if (p_dm_vap_info->u.sta_info.enabled == output_value)
            {
                return  true;
            }

            p_dm_vap_info->u.sta_info.enabled = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
            return true;
        }

        /* SSID Enable object can be modified only when ForceDisableRadio feature is disabled */
        if(!(dm_wifi_global_cfg->global_parameters.force_disable_radio_feature)) {
            if (p_dm_vap_info->u.bss_info.enabled == output_value)
            {
                return  true;
            }

            p_dm_vap_info->u.bss_info.enabled = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        } else {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_EnableOnline")) {
        if (isVapSTAMesh(pcfg->vap_index)) {
            if (p_dm_vap_info->u.sta_info.enabled == output_value) {
                return true;
            }

            p_dm_vap_info->u.sta_info.enabled = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        } else if (!(dm_wifi_global_cfg->global_parameters.force_disable_radio_feature)) {
            if (p_dm_vap_info->u.bss_info.enabled == output_value) {
                return true;
            }

            p_dm_vap_info->u.bss_info.enabled = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d [%s]WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_RouterEnabled")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(instance_number - 1);

        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        /* SSID Enable object can be modified only when ForceDisableRadio feature is disabled */
        if (!(dm_wifi_global_cfg->global_parameters.force_disable_radio_feature)) {
            if (p_dm_vap_default->router_enabled == output_value) {
                return true;
            }
            p_dm_vap_default->router_enabled = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d [%s]WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool ssid_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool ssid_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool ssid_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    DM_CHECK_NULL_WITH_RC(output_value, false);
    DM_CHECK_NULL_WITH_RC(output_value->buff, false);

    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_global_config_t *dm_wifi_global_cfg;
    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);
    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (STR_CMP(param_name, "SSID")) {
        if(dm_wifi_global_cfg->global_parameters.force_disable_radio_feature) {
             wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __func__, __LINE__, pcfg->vap_name);
             return false;
        }
        if (isVapSTAMesh(p_dm_vap_info->vap_index)) {
            if (STR_CMP(p_dm_vap_info->u.sta_info.ssid, output_value->buff)) {
                return true;
            }
            snprintf(p_dm_vap_info->u.sta_info.ssid,sizeof(p_dm_vap_info->u.sta_info.ssid), "%s", (char *)output_value->buff);
            set_dml_cache_vap_config_changed(instance_number - 1);
            return true;
        } else if(STR_CMP(p_dm_vap_info->u.bss_info.ssid, output_value->buff)) {
            return true;
	} else if (p_dm_vap_info->u.bss_info.bssHotspot) {
            if(STR_CMP(output_value->buff, "OutOfService")) {
                p_dm_vap_info->u.bss_info.enabled = false;
                fprintf(stderr, "%s: Disable HHS SSID since it's set to OutOfService\n", __func__);
            }
        }
        snprintf(p_dm_vap_info->u.bss_info.ssid, sizeof(p_dm_vap_info->u.bss_info.ssid), "%s", (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint8_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    }
    wifi_radio_operationParam_t *p_dm_radio_param = (wifi_radio_operationParam_t *)get_dml_cache_radio_map(pcfg->radio_index);
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

    DM_CHECK_NULL_WITH_RC(p_dm_radio_param, false);

    if (STR_CMP(param_name, "X_RDKCENTRAL-COM_TransitionDisable")) {
        if ((p_dm_radio_param->band != WIFI_FREQUENCY_6_BAND) && (rfc_pcfg->wpa3_rfc)) {
            *output_value = p_sec_cfg->wpa3_transition_disable;
        } else {
            *output_value = false;
        }
    } else if (STR_CMP(param_name, "Reset")) {
        *output_value = false;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint8_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "X_CISCO_COM_RadiusReAuthInterval")) {
        *output_value = 0;
    } else if (STR_CMP(param_name, "X_CISCO_COM_DefaultKey")) {
        *output_value = 0;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint8_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "RekeyingInterval")) {
        *output_value = p_sec_cfg->rekey_interval;
    } else if (STR_CMP(param_name, "RadiusServerPort")) {
        *output_value = p_sec_cfg->u.radius.port;
    } else if (STR_CMP(param_name, "SecondaryRadiusServerPort")) {
        *output_value = p_sec_cfg->u.radius.s_port;
    } else if (STR_CMP(param_name, "RadiusDASPort")) {
        *output_value = p_sec_cfg->u.radius.dasport;
    } else if (STR_CMP(param_name, "X_CISCO_COM_WEPKey64BitNumberOfEntries")) {
        *output_value = 0;
    } else if (STR_CMP(param_name, "X_CISCO_COM_WEPKey128BitNumberOfEntries")) {
        *output_value = 0;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint8_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "ModeEnabled")) {
        /* collect value */
        char buff[32]     = {0};
        uint32_t str_len = 0;

        str_len = get_sec_mode_string_from_int(p_sec_cfg->mode, buff);
        if (str_len == 0) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d:hal security mode:%d conversion failure\n",__func__, __LINE__, p_sec_cfg->mode);
            return false;
        }

        set_output_string(output_value, buff);
    } else if((STR_CMP(param_name, "KeyPassphrase")) ||
        (STR_CMP(param_name, "X_COMCAST-COM_KeyPassphrase")) ||
        (STR_CMP(param_name, "SAEPassphrase"))) {
        /* collect value */
        if (strlen(p_sec_cfg->u.key.key) > 0) {
            set_output_string(output_value, p_sec_cfg->u.key.key);
        } else  {
            set_output_string(output_value, " ");
        }
    } else if(STR_CMP(param_name, "ModesSupported")) {
        char buf[512] = {0};
        int mode = 0;

        get_sec_modes_supported(vap_index, &mode);

        if (get_sec_mode_string_from_int((wifi_security_modes_t)mode, buf) != 0) {
            set_output_string(output_value, buf);
        } else {
            return false;
        }
    } else if(STR_CMP(param_name, "MFPConfig")) {
        char buff[16] = {0};
        convert_security_mode_integer_to_string(p_sec_cfg->mfp, buff);
        set_output_string(output_value, buff);
    } else if(STR_CMP(param_name, "X_CISCO_COM_EncryptionMethod")) {
        char buff[16] = {0};
        if(get_sec_encr_string_from_int(p_sec_cfg->encr, buff) == 0) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d:hal sec encr:%d conversion failure\n",__func__, __LINE__, p_sec_cfg->encr);
            return false;
        }
        set_output_string(output_value, buff);
    } else if ((STR_CMP(param_name, "WEPKey")) || (STR_CMP(param_name, "X_CISCO_COM_WEPKey")) ||
        (STR_CMP(param_name, "X_COMCAST-COM_WEPKey"))) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "PreSharedKey")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "X_COMCAST-COM_DefaultKeyPassphrase")) {
        char default_password[64] = { 0 };

        if (wifi_hal_get_default_keypassphrase(default_password, vap_index) == RETURN_OK) {
            set_output_string(output_value, default_password);
	} else {
            set_output_string(output_value, " ");
        }
    } else if (STR_CMP(param_name, "RadiusServerIPAddr")) {
        if (strcmp((char *)&p_sec_cfg->u.radius.ip, "") != 0) {
            set_output_string(output_value, (char *)&p_sec_cfg->u.radius.ip);
        } else {
            set_output_string(output_value, "0.0.0.0");
        }
    } else if (STR_CMP(param_name, "RadiusSecret")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "SecondaryRadiusServerIPAddr")) {
        if (strcmp((char *)&p_sec_cfg->u.radius.s_ip, "") != 0) {
            set_output_string(output_value, (char *)&p_sec_cfg->u.radius.s_ip);
        } else {
            set_output_string(output_value, "0.0.0.0");
        }
    } else if (STR_CMP(param_name, "SecondaryRadiusSecret")) {
        set_output_string(output_value, " ");
    } else if (STR_CMP(param_name, "RadiusDASIPAddr")) {
        char buff[64] = { 0 };
        getIpStringFromAdrress(buff, &p_sec_cfg->u.radius.dasip);
        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "RadiusDASSecret")) {
        set_output_string(output_value, " ");
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_dm_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    uint8_t vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    wifi_radio_operationParam_t *p_dm_radio_param = get_dml_cache_radio_map(pcfg->radio_index);
    DM_CHECK_NULL_WITH_RC(p_dm_radio_param, false);

    if (isVapSTAMesh(vap_index)) {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache sta security parameter\n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache bss security parameter \n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    }
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

    if (STR_CMP(param_name, "X_RDKCENTRAL-COM_TransitionDisable")) {
        if (p_dm_radio_param->band == WIFI_FREQUENCY_6_BAND) {
            wifi_util_error_print(WIFI_DMCLI,"%s Transition Mode not supported for 6GHz radio\n", __func__);
            return false;
        }
        if ((output_value == true) && (!rfc_pcfg->wpa3_rfc)) {
            wifi_util_error_print(WIFI_DMCLI,"%s: WPA3 Transition RFC is not enabled\n",__func__);
            return false;
        }
        if ((p_dm_sec_cfg->mode != wifi_security_mode_wpa3_transition) && (rfc_pcfg->wpa3_rfc)) {
            wifi_util_error_print(WIFI_DMCLI,"%s: Security mode is not WPA3-Personal-Transition\n",__func__);
            return false;
        }
        p_dm_sec_cfg->wpa3_transition_disable = output_value;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:wpa3_transition_disable=%d Value=%d\n",__func__,
            __LINE__, p_dm_sec_cfg->wpa3_transition_disable, output_value);
        set_dml_cache_vap_config_changed(vap_index);
    } else if (STR_CMP(param_name, "Reset")) {
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    if (STR_CMP(param_name, "X_CISCO_COM_RadiusReAuthInterval")) {
        //nothing we need to do
    } else if (STR_CMP(param_name, "X_CISCO_COM_DefaultKey")) {
        //nothing we need to do
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_dm_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    uint8_t vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    uint8_t instance_number = vap_index + 1;
    wifi_radio_operationParam_t *p_dm_radio_param = get_dml_cache_radio_map(pcfg->radio_index);
    DM_CHECK_NULL_WITH_RC(p_dm_radio_param, false);

    if (isVapSTAMesh(vap_index)) {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache sta security parameter\n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache bss security parameter \n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "RekeyingInterval")) {
        if (p_dm_sec_cfg->rekey_interval != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RekeyingInterval=%d Value=%d\n",__func__,
                __LINE__, p_dm_sec_cfg->rekey_interval, output_value);
            /* save update to backup */
            p_dm_sec_cfg->rekey_interval = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "RadiusServerPort")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }
        if (p_dm_sec_cfg->u.radius.port != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RadiusServerPort=%d Value=%d\n", __func__,
                __LINE__, p_dm_sec_cfg->u.radius.port, output_value);
            p_dm_sec_cfg->u.radius.port = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "SecondaryRadiusServerPort")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }
        if (p_dm_sec_cfg->u.radius.s_port != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:s_RadiusServerPort=%d Value=%d\n", __func__,
                __LINE__, p_dm_sec_cfg->u.radius.s_port, output_value);
            p_dm_sec_cfg->u.radius.s_port = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "RadiusDASPort")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n",__func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }
        if (p_dm_sec_cfg->u.radius.dasport != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:RadiusDASPort=%d Value=%d\n", __func__,
                __LINE__, p_dm_sec_cfg->u.radius.dasport, output_value);
            p_dm_sec_cfg->u.radius.dasport   = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool security_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_dm_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(output_value, false);
    DM_CHECK_NULL_WITH_RC(output_value->buff, false);

    uint8_t vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    uint8_t instance_number = vap_index + 1;
    wifi_global_config_t *dm_wifi_global_cfg;
    wifi_radio_operationParam_t *p_dm_radio_param = get_dml_cache_radio_map(pcfg->radio_index);
    DM_CHECK_NULL_WITH_RC(p_dm_radio_param, false);

    dm_wifi_global_cfg = (wifi_global_config_t*) get_dml_cache_global_wifi_config();
    DM_CHECK_NULL_WITH_RC(dm_wifi_global_cfg, false);

    if (isVapSTAMesh(vap_index)) {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache sta security parameter\n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache bss security parameter \n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if(STR_CMP(param_name, "ModeEnabled")) {
        wifi_security_modes_t l_tmp_sec_mode;

        if (!get_sec_mode_int_from_string(output_value->buff, &l_tmp_sec_mode)) {
             wifi_util_error_print(WIFI_DMCLI, "%s:%d failed to parse mode: %s\n", __func__,
                 __LINE__, output_value->buff);
             return false;
        }

        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d old mode: %d new mode: %d\n", __func__, __LINE__,
            p_dm_sec_cfg->mode, l_tmp_sec_mode);

        if (l_tmp_sec_mode == p_dm_sec_cfg->mode) {
            return true;
        }

        if (p_dm_radio_param->band == WIFI_FREQUENCY_6_BAND &&
            l_tmp_sec_mode != wifi_security_mode_wpa3_personal &&
            l_tmp_sec_mode != wifi_security_mode_wpa3_enterprise &&
            l_tmp_sec_mode != wifi_security_mode_enhanced_open) {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d invalid mode %d for 6GHz\n", __func__,
                __LINE__, l_tmp_sec_mode);
            return false;
        }

        /* GET the WPA3 Transition RFC value */
        wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
        if (p_dm_radio_param->band != WIFI_FREQUENCY_6_BAND && rfc_pcfg->wpa3_rfc == false &&
            (l_tmp_sec_mode == wifi_security_mode_wpa3_transition ||
            l_tmp_sec_mode == wifi_security_mode_wpa3_personal)) {
             wifi_util_error_print(WIFI_DMCLI, "%s:%d WPA3 mode is not supported when "
                 "TransitionDisable RFC is false\n", __func__, __LINE__);
             return false;
        }

        // cleanup key/radius for personal-enterprise-open mode change
        if ((is_personal_sec(l_tmp_sec_mode) && !is_personal_sec(p_dm_sec_cfg->mode)) ||
            (is_enterprise_sec(l_tmp_sec_mode) && !is_enterprise_sec(p_dm_sec_cfg->mode)) ||
            (is_open_sec(l_tmp_sec_mode) && !is_open_sec(p_dm_sec_cfg->mode))) {
            memset(&p_dm_sec_cfg->u, 0, sizeof(p_dm_sec_cfg->u));
        }

        p_dm_sec_cfg->mode = l_tmp_sec_mode;
        switch (p_dm_sec_cfg->mode) {
            case wifi_security_mode_none:
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wep_64:
            case wifi_security_mode_wep_128:
                p_dm_sec_cfg->u.key.type = wifi_security_key_type_pass;
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wpa_personal:
            case wifi_security_mode_wpa2_personal:
            case wifi_security_mode_wpa_wpa2_personal:
                p_dm_sec_cfg->u.key.type = wifi_security_key_type_psk;
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wpa_enterprise:
            case wifi_security_mode_wpa2_enterprise:
            case wifi_security_mode_wpa_wpa2_enterprise:
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_disabled;
                break;
            case wifi_security_mode_wpa3_personal:
                p_dm_sec_cfg->u.key.type = wifi_security_key_type_sae;
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_required;
                break;
            case wifi_security_mode_wpa3_enterprise:
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_required;
                break;
            case wifi_security_mode_wpa3_transition:
                p_dm_sec_cfg->u.key.type = wifi_security_key_type_psk_sae;
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_optional;
                break;
            case wifi_security_mode_enhanced_open:
                p_dm_sec_cfg->mfp = wifi_mfp_cfg_required;
                break;
            default:
                break;
        }
        set_dml_cache_vap_config_changed(instance_number - 1);
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Set Value=%d success\n", __func__, __LINE__, l_tmp_sec_mode);

    } else if((STR_CMP(param_name, "KeyPassphrase")) ||
        (STR_CMP(param_name, "X_COMCAST-COM_KeyPassphrase"))) {
        if(dm_wifi_global_cfg->global_parameters.force_disable_radio_feature) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED\n", __func__, __LINE__);
            return false;
        }
        if ((output_value->buff_len < 8 ) || (output_value->buff_len > 63)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Size is too large value=%s\n",__func__, __LINE__,
                output_value->buff, output_value->buff_len);
            return false;
        }

        if(STR_CMP(p_dm_sec_cfg->u.key.key, output_value->buff)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Value remains unchanged\n",__func__, __LINE__);
            return true;
        }
        /* save update to backup */
        if (security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Security mode %d does not support passphrase configuration \n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }

        STR_COPY(p_dm_sec_cfg->u.key.key, output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if(STR_CMP(param_name, "MFPConfig")) {
        wifi_mfp_cfg_t mfp;

        if (get_mfp_type_from_string(output_value->buff, &mfp) != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s invalide mfp string %s\n", __func__, output_value->buff);
            return false;
        } else if (p_dm_sec_cfg->mfp == mfp) {
            return true;
        }

        p_dm_sec_cfg->mfp = mfp;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "X_CISCO_COM_EncryptionMethod")) {
        wifi_encryption_method_t l_sec_encr_type;

        if (get_sec_encr_int_from_string(output_value->buff, &l_sec_encr_type) != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s invalide sec encr string %s\n", __func__, output_value->buff);
            return false;
	}

        if (p_dm_sec_cfg->encr != l_sec_encr_type) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: sec encryption method=%d Value=%d\n", __func__, __LINE__, p_dm_sec_cfg->encr, l_sec_encr_type);
            /* collect value */
            p_dm_sec_cfg->encr = l_sec_encr_type;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if ((STR_CMP(param_name, "WEPKey")) || (STR_CMP(param_name, "X_CISCO_COM_WEPKey")) ||
        (STR_CMP(param_name, "X_COMCAST-COM_WEPKey"))) {
        if((p_dm_sec_cfg->mode == wifi_security_mode_wep_64) ||
              (p_dm_sec_cfg->mode == wifi_security_mode_wep_128)) {
            /* Return an error only if the security mode enabled is WEP - For UI */
            return false;
        }
    } else if (STR_CMP(param_name, "PreSharedKey")) {
        if((strlen((char *)output_value->buff) >= sizeof(p_dm_sec_cfg->u.key.key))) {
            return false;
        }

        if (security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support"
                " passphrase configuration \n",__func__, __LINE__, p_dm_sec_cfg->mode);
            return false;
        }

        STR_COPY(p_dm_sec_cfg->u.key.key, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "SAEPassphrase")) {
        if ((p_dm_sec_cfg->mode != wifi_security_mode_wpa3_transition) &&
             (p_dm_sec_cfg->mode != wifi_security_mode_wpa3_personal)) {
            wifi_util_error_print(WIFI_DMCLI,"WPA3 security mode is not enabled in VAP %d\n", instance_number);
            return false;
        }
        if (security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support passphrase configuration\n",__func__,
                __LINE__,p_dm_sec_cfg->mode);
            return false;
        }
        if (STR_CMP(p_dm_sec_cfg->u.key.key, (char *)output_value->buff)) {
            return true;
        }

        if ((strlen((char *)output_value->buff) < SAE_PASSPHRASE_MIN_LENGTH) ||
            (strlen((char *)output_value->buff) >= SAE_PASSPHRASE_MAX_LENGTH)) {
            return false;
        }
        STR_COPY((char*)p_dm_sec_cfg->u.key.key, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "RadiusServerIPAddr")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__,p_dm_sec_cfg->mode);
            return false;
        }
        if (STR_CMP((char*)p_dm_sec_cfg->u.radius.ip, (char *)output_value->buff)) {
            return true;
        }

        if (strlen((char *)output_value->buff) >= sizeof(p_dm_sec_cfg->u.radius.ip)) {
            return false;
        }

        STR_COPY((char*)p_dm_sec_cfg->u.radius.ip, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "RadiusSecret")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        } else if (STR_CMP(p_dm_sec_cfg->u.radius.key, (char *)output_value->buff)) {
            return true;
        } else if (strlen((char *)output_value->buff) >= sizeof(p_dm_sec_cfg->u.radius.key)) {
            return false;
        }

        STR_COPY(p_dm_sec_cfg->u.radius.key, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "SecondaryRadiusServerIPAddr")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__,p_dm_sec_cfg->mode);
            return false;
        }
        if (STR_CMP((char*)p_dm_sec_cfg->u.radius.s_ip, (char *)output_value->buff)) {
            return true;
        }

        if (strlen((char *)output_value->buff) >= sizeof(p_dm_sec_cfg->u.radius.s_ip)) {
            return false;
        }

        STR_COPY((char*)p_dm_sec_cfg->u.radius.s_ip, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "SecondaryRadiusSecret")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        } else if (STR_CMP(p_dm_sec_cfg->u.radius.s_key, (char *)output_value->buff)) {
            return true;
        } else if (strlen((char *)output_value->buff) >= sizeof(p_dm_sec_cfg->u.radius.s_key)) {
            return false;
        }

        STR_COPY(p_dm_sec_cfg->u.radius.s_key, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "RadiusDASIPAddr")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__,p_dm_sec_cfg->mode);
            return false;
        }
        ip_addr_t parameter_ip;
        if (getIpAddressFromString((char *)output_value->buff, &parameter_ip) != 1) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d getIpAddressFromString failed \n",__func__, __LINE__);
            return false;
        }
        if ((parameter_ip.family == wifi_ip_family_ipv4) && (parameter_ip.u.IPv4addr == p_dm_sec_cfg->u.radius.dasip.u.IPv4addr)) {
            return true;
        }

        if ((parameter_ip.family == wifi_ip_family_ipv6) && (!memcmp(p_dm_sec_cfg->u.radius.dasip.u.IPv6addr,parameter_ip.u.IPv6addr, 16))) {
            return true;
        }

        memcpy(&p_dm_sec_cfg->u.radius.dasip, &parameter_ip, sizeof(ip_addr_t));
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "RadiusDASSecret")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }

        if (STR_CMP(p_dm_sec_cfg->u.radius.daskey, (char *)output_value->buff)) {
            return true;
        }

        if (strlen((char *)output_value->buff) >= sizeof(p_dm_sec_cfg->u.radius.daskey)) {
            return false;
        }

        STR_COPY(p_dm_sec_cfg->u.radius.daskey, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radius_sec_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint8_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "PMKCaching")) {
        *output_value = p_sec_cfg->disable_pmksa_caching;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radius_sec_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint8_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "RadiusServerRetries")) {
        *output_value = p_sec_cfg->u.radius.server_retries;
    } else if (STR_CMP(param_name, "RadiusServerRequestTimeout")) {
        *output_value = 0;
    } else if (STR_CMP(param_name, "PMKLifetime")) {
        *output_value = 0;
    } else if (STR_CMP(param_name, "PMKCacheInterval")) {
        *output_value = 0;
    } else if (STR_CMP(param_name, "MaxAuthenticationAttempts")) {
        *output_value = p_sec_cfg->u.radius.max_auth_attempts;
    } else if (STR_CMP(param_name, "BlacklistTableTimeout")) {
        *output_value = p_sec_cfg->u.radius.blacklist_table_timeout;
    } else if (STR_CMP(param_name, "IdentityRequestRetryInterval")) {
        *output_value = p_sec_cfg->u.radius.identity_req_retry_interval;
    } else if (STR_CMP(param_name, "QuietPeriodAfterFailedAuthentication")) {
        *output_value = 0;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radius_sec_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_dm_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    uint8_t vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    uint8_t instance_number = vap_index + 1;

    if (isVapSTAMesh(vap_index)) {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache sta security parameter\n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache bss security parameter \n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "PMKCaching")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d disable_pmksa_caching=%d Value=%d\n", __func__,
            __LINE__, p_dm_sec_cfg->disable_pmksa_caching, output_value);
        if(p_dm_sec_cfg->disable_pmksa_caching != output_value) {
            p_dm_sec_cfg->disable_pmksa_caching = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool radius_sec_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_dm_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    uint8_t vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    uint8_t instance_number = vap_index + 1;

    if (isVapSTAMesh(vap_index)) {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache sta security parameter\n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache bss security parameter \n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "RadiusServerRetries")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d server_retries=%d Value=%d\n", __func__,
            __LINE__, p_dm_sec_cfg->u.radius.server_retries, output_value);
        if(p_dm_sec_cfg->u.radius.server_retries != ((unsigned int) output_value)) {
            p_dm_sec_cfg->u.radius.server_retries = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "RadiusServerRequestTimeout")) {
    } else if (STR_CMP(param_name, "PMKLifetime")) {
    } else if (STR_CMP(param_name, "PMKCacheInterval")) {
    } else if (STR_CMP(param_name, "MaxAuthenticationAttempts")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d max_auth_attempts=%d Value=%d\n", __func__,
            __LINE__, p_dm_sec_cfg->u.radius.max_auth_attempts, output_value);
        if (p_dm_sec_cfg->u.radius.max_auth_attempts != ((unsigned int) output_value)) {
            p_dm_sec_cfg->u.radius.max_auth_attempts = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "BlacklistTableTimeout")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d blacklist_table_timeout=%d Value=%d\n", __func__,
            __LINE__, p_dm_sec_cfg->u.radius.blacklist_table_timeout, output_value);
        if (p_dm_sec_cfg->u.radius.blacklist_table_timeout != ((unsigned int) output_value)) {
            p_dm_sec_cfg->u.radius.blacklist_table_timeout = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "IdentityRequestRetryInterval")) {
        if (!security_mode_support_radius(p_dm_sec_cfg->mode)) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Security mode %d does not support radius configuration\n", __func__,
                __LINE__, p_dm_sec_cfg->mode);
            return false;
        }
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d identity_req_retry_interval=%d Value=%d\n", __func__,
            __LINE__, p_dm_sec_cfg->u.radius.identity_req_retry_interval, output_value);
        if (p_dm_sec_cfg->u.radius.identity_req_retry_interval != ((unsigned int) output_value)) {
            p_dm_sec_cfg->u.radius.identity_req_retry_interval = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "QuietPeriodAfterFailedAuthentication")) {
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool auth_sec_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint8_t vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);

    if (isVapSTAMesh(vap_index)) {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_sta_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid Get_wifi_object_sta_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_sec_cfg = (wifi_vap_security_t *) Get_wifi_object_bss_security_parameter(pcfg->vap_index);
        if(p_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get_dml_cache_security_parameter\n",__func__,
                __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "EAPOLKeyTimeout")) {
        *output_value = p_sec_cfg->eapol_key_timeout;
    } else if (STR_CMP(param_name, "EAPOLKeyRetries")) {
        *output_value = p_sec_cfg->eapol_key_retries;
    } else if (STR_CMP(param_name, "EAPIdentityRequestTimeout")) {
        *output_value = p_sec_cfg->eap_identity_req_timeout;
    } else if (STR_CMP(param_name, "EAPIdentityRequestRetries")) {
        *output_value = p_sec_cfg->eap_identity_req_retries ;
    } else if (STR_CMP(param_name, "EAPRequestTimeout")) {
        *output_value = p_sec_cfg->eap_req_timeout;
    } else if (STR_CMP(param_name, "EAPRequestRetries")) {
        *output_value = p_sec_cfg->eap_req_retries ;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool auth_sec_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    wifi_vap_security_t *p_dm_sec_cfg = NULL;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    uint8_t vap_index = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name);
    uint8_t instance_number = vap_index + 1;

    if (isVapSTAMesh(vap_index)) {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_sta_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache sta security parameter\n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    } else {
        p_dm_sec_cfg = (wifi_vap_security_t *) get_dml_cache_bss_security_parameter(pcfg->vap_index);
        if(p_dm_sec_cfg == NULL) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: %s invalid get dml cache bss security parameter \n",__func__, __LINE__, pcfg->vap_name);
            return false;
        }
    }

    if (STR_CMP(param_name, "EAPOLKeyTimeout")) {
        if (p_dm_sec_cfg->eapol_key_timeout != output_value) {
            p_dm_sec_cfg->eapol_key_timeout = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "EAPOLKeyRetries")) {
        if (p_dm_sec_cfg->eapol_key_retries != output_value) {
            p_dm_sec_cfg->eapol_key_retries = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "EAPIdentityRequestTimeout")) {
        if (p_dm_sec_cfg->eap_identity_req_timeout != output_value) {
            p_dm_sec_cfg->eap_identity_req_timeout = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "EAPIdentityRequestRetries")) {
        if (p_dm_sec_cfg->eap_identity_req_retries != output_value) {
            p_dm_sec_cfg->eap_identity_req_retries = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "EAPRequestTimeout")) {
        if (p_dm_sec_cfg->eap_req_timeout != output_value) {
            p_dm_sec_cfg->eap_req_timeout = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "EAPRequestRetries")) {
        if (p_dm_sec_cfg->eap_req_retries != output_value) {
            p_dm_sec_cfg->eap_req_retries  = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool macfilter_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool macfilter_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool macfilter_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool macfilter_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    acl_entry_t *p_acl_entry = (acl_entry_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(p_acl_entry, false);

    /* check the parameter name and return the corresponding value */
    if (STR_CMP(param_name, "MACAddress")) {
        char buff[24] = {0};

        sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X", p_acl_entry->mac[0],
                p_acl_entry->mac[1],
                p_acl_entry->mac[2],
                p_acl_entry->mac[3],
                p_acl_entry->mac[4],
                p_acl_entry->mac[5]);

        set_output_string(output_value, buff);
    } else if (STR_CMP(param_name, "DeviceName")) {
        set_output_string(output_value, p_acl_entry->device_name);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool macfilter_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool macfilter_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool macfilter_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool macfilter_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    mac_filter_set_param_arg_t *p_mac_filter_set_arg = (mac_filter_set_param_arg_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(p_mac_filter_set_arg, false);

    acl_entry_t *acl_entry = p_mac_filter_set_arg->acl_param;
    wifi_vap_info_t *vap_info = p_mac_filter_set_arg->vap_info_param;
    mac_address_t new_mac;
    unsigned int count = 0, itr;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    acl_entry_t *mac_acl_entry;
    int mac_length = -1;
    char formatted_mac[MAX_STR_MAC_ADDR_LEN + 1] = {0};

    DM_CHECK_NULL_WITH_RC(acl_entry, false);
    DM_CHECK_NULL_WITH_RC(vap_info, false);

    hash_map_t **acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    queue_t **acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);
    if (*acl_new_entry_queue == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unexpected ERROR!!! acl_new_entry_queue"
            " should not be NULL\n", __func__,__LINE__);
        *acl_new_entry_queue = queue_create();
    }

    if (STR_CMP(param_name, "MACAddress")) {
        str_tolower(output_value->buff);
        mac_length = strlen(output_value->buff);
        if (mac_length != MAX_STR_MAC_ADDR_LEN && mac_length != MIN_STR_MAC_ADDR_LEN) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid mac:%s\n", __func__,
                __LINE__, (char *)output_value->buff);
            return false;
        }

        if (mac_length == MIN_STR_MAC_ADDR_LEN) {
            itr = 0;
            for (count = 0; count < MIN_STR_MAC_ADDR_LEN; count++) {
                formatted_mac[itr++] = (char)*(char *)(output_value->buff + count);
                if (((count % 2) == 1) && (count != MIN_STR_MAC_ADDR_LEN - 1)) {
                    formatted_mac[itr++] = ':';
                }
            }
            formatted_mac[itr++] = '\0';

            if (is_valid_mac_address(formatted_mac) == false) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid mac:%s\n", __func__,
                    __LINE__, formatted_mac);
                return false;
            }
        } else {
            if (is_valid_mac_address(output_value->buff) == false) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid mac:%s\n", __func__,
                    __LINE__, (char *)output_value->buff);
                return false;
            }
        }

        str_to_mac_bytes(output_value->buff, new_mac);
        if (memcmp(new_mac, zero_mac, sizeof(mac_address_t)) == 0) {
            //Invalid value returning false
            return false;
        }

        if (memcmp(acl_entry->mac, zero_mac, sizeof(mac_address_t)) == 0) {
            memcpy(acl_entry->mac, new_mac, sizeof(mac_address_t));
            if (*acl_device_map == NULL) {
                *acl_device_map = hash_map_create();
            }

            if (*acl_device_map == NULL) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
                return false;
            }
            hash_map_put(*acl_device_map, strdup(output_value->buff), acl_entry);

            if (*acl_new_entry_queue == NULL) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
                return false;
            }
            count = queue_count(*acl_new_entry_queue);
            for (itr = 0; itr < count; itr++) {
                mac_acl_entry = (acl_entry_t *)queue_peek(*acl_new_entry_queue, itr);
                if (mac_acl_entry == NULL) {
                    wifi_util_error_print(WIFI_DMCLI,"%s:%d NULL Pointer\n", __func__, __LINE__);
                    return false;
                }

                if (mac_acl_entry == acl_entry) {
                    mac_acl_entry = queue_remove(*acl_new_entry_queue, itr);
                    break;
                }
            }
        } else if (memcmp(acl_entry->mac, new_mac, sizeof(mac_address_t)) != 0) {
            memcpy(acl_entry->mac, new_mac, sizeof(mac_address_t));
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: mac filter same entry found:%s\n", __func__,
                __LINE__, (char *)output_value->buff);
            return true;
        }

        //macfilter commit
        if (push_acl_list_dml_cache_to_one_wifidb(vap_info) == RETURN_ERR) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Mac_Filter failed \n",__func__, __LINE__);
            return false;
        }
    } else if (STR_CMP(param_name, "DeviceName")) {
        strncpy(acl_entry->device_name, output_value->buff, sizeof(acl_entry->device_name)-1);
        //macfilter commit
        if (push_acl_list_dml_cache_to_one_wifidb(vap_info) == RETURN_ERR) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Mac_Filter failed \n",__func__, __LINE__);
            return false;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_interworking_info = &vap_pcfg->u.bss_info.interworking;

    if (STR_CMP(param_name, "Internet")) {
        if(isVapHotspot(vap_pcfg->vap_index)) {
            *output_value = p_interworking_info->interworking.internetAvailable;
        } else {
            *output_value = p_interworking_info->interworking.internetAvailable;
        }
    } else if (STR_CMP(param_name, "ASRA")) {
        *output_value = p_interworking_info->interworking.asra;
    } else if (STR_CMP(param_name, "ESR")) {
        *output_value = p_interworking_info->interworking.esr;
    } else if (STR_CMP(param_name, "UESA")) {
        *output_value = p_interworking_info->interworking.uesa;
    } else if (STR_CMP(param_name, "VenueOptionPresent")) {
        *output_value = p_interworking_info->interworking.venueOptionPresent;
    } else if (STR_CMP(param_name, "HESSOptionPresent")) {
        *output_value = p_interworking_info->interworking.hessOptionPresent;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool interworking_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_interworking_info = &vap_pcfg->u.bss_info.interworking;

    if (STR_CMP(param_name, "AccessNetworkType")) {
        *output_value = p_interworking_info->interworking.accessNetworkType;
    } else if (STR_CMP(param_name, "VenueInfo.Group")) {
        *output_value = p_interworking_info->interworking.venueGroup;
    } else if (STR_CMP(param_name, "VenueInfo.Type")) {
        *output_value = p_interworking_info->interworking.venueType;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_interworking_info = &vap_pcfg->u.bss_info.interworking;

    if (STR_CMP(param_name, "HESSID")) {
        set_output_string(output_value, p_interworking_info->interworking.hessid);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_dm_interworking_info = &p_dm_vap_info->u.bss_info.interworking;

    if (STR_CMP(param_name, "Internet")) {
        if (p_dm_interworking_info->interworking.internetAvailable != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d internet=%d output_value=%d\n",__func__,
                __LINE__, p_dm_interworking_info->interworking.internetAvailable, output_value);
            p_dm_interworking_info->interworking.internetAvailable = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "ASRA")) {
        if (p_dm_interworking_info->interworking.asra != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d asra=%d output_value=%d\n",__func__,
                __LINE__, p_dm_interworking_info->interworking.asra, output_value);
            p_dm_interworking_info->interworking.asra = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "ESR")) {
        if (p_dm_interworking_info->interworking.esr != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d esr=%d output_value=%d\n",__func__,
                __LINE__, p_dm_interworking_info->interworking.esr, output_value);
            p_dm_interworking_info->interworking.esr = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "UESA")) {
        if (p_dm_interworking_info->interworking.uesa != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d uesa=%d output_value=%d\n",__func__,
                __LINE__, p_dm_interworking_info->interworking.uesa, output_value);
            p_dm_interworking_info->interworking.uesa = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "VenueOptionPresent")) {
        if (p_dm_interworking_info->interworking.venueOptionPresent != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d venue=%d output_value=%d\n",__func__,
                __LINE__, p_dm_interworking_info->interworking.venueOptionPresent, output_value);
            p_dm_interworking_info->interworking.venueOptionPresent = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "HESSOptionPresent")) {
        if (p_dm_interworking_info->interworking.hessOptionPresent != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d hessOptionPresent=%d output_value=%d\n",__func__,
                __LINE__, p_dm_interworking_info->interworking.hessOptionPresent, output_value);
            p_dm_interworking_info->interworking.hessOptionPresent = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool interworking_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_dm_interworking_info = &p_dm_vap_info->u.bss_info.interworking;

    if (STR_CMP(param_name, "AccessNetworkType")) {
        if ((output_value < 6) || ((output_value < 16) && (output_value > 13))) {
            if(p_dm_interworking_info->interworking.accessNetworkType != output_value) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d accessNetworkType=%d Value=%d\n", __func__,
                    __LINE__, p_dm_interworking_info->interworking.accessNetworkType, output_value);
                p_dm_interworking_info->interworking.accessNetworkType = output_value;
                set_dml_cache_vap_config_changed(instance_number - 1);
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d invalid AccessNetworkType cfg:%d\n", __func__,
                __LINE__, output_value);
            return false;
        }
    } else if (STR_CMP(param_name, "VenueInfo.Type")) {
        bool update_invalid_type = false;
        if (output_value < 256) {
            switch (p_dm_interworking_info->interworking.venueGroup) {
                case 0:
                    if (output_value != 0) {
                        update_invalid_type = true;
                    }
                    break;
                case 1:
                    if (!(output_value < 16)) {
                        update_invalid_type = true;
                    }
                    break;
                case 2:
                    if (!(output_value < 10)) {
                        update_invalid_type = true;
                    }
                    break;
                case 3:
                    if (!(output_value < 4)) {
                        update_invalid_type = true;
                    }
                    break;
                case 4:
                    if (!(output_value < 2)) {
                        update_invalid_type = true;
                    }
                    break;

                case 5:
                    if (!(output_value < 6)) {
                        update_invalid_type = true;
                    }
                    break;
                case 6:
                    if (!(output_value < 6)) {
                        update_invalid_type = true;
                    }
                    break;
                case 7:
                    if (!(output_value < 5)) {
                        update_invalid_type = true;
                    }
                    break;
                case 8:
                    if (output_value != 0) {
                        update_invalid_type = true;
                    }
                    break;
                case 9:
                    if (output_value != 0) {
                        update_invalid_type = true;
                    }
                    break;
                case 10:
                    if (!(output_value < 8)) {
                        update_invalid_type = true;
                    }
                    break;
                case 11:
                    if (!(output_value < 7)) {
                        update_invalid_type = true;
                    }
                    break;
            }
        } else {
            update_invalid_type = true;
        }

        if (update_invalid_type == false) {
            if(p_dm_interworking_info->interworking.venueType  != output_value) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d venueType=%d Value=%d\n",__func__,
                    __LINE__, p_dm_interworking_info->interworking.venueType, output_value);
                p_dm_interworking_info->interworking.venueType = output_value;
                set_dml_cache_vap_config_changed(instance_number - 1);
            }
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: invalid config:%d for param name:%s\n",__func__,
                __LINE__, output_value, param_name);
            return false;
        }
    } else if (STR_CMP(param_name, "VenueInfo.Group")) {
        if (output_value < 12) {
            if(p_dm_interworking_info->interworking.venueGroup  != output_value) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d venueGroup=%d Value=%d\n",__func__,
                    __LINE__, p_dm_interworking_info->interworking.venueGroup, output_value);
                p_dm_interworking_info->interworking.venueGroup = output_value;
                set_dml_cache_vap_config_changed(instance_number - 1);
            }
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: invalid VenueInfo.Group config param:%d\n",__func__,
                __LINE__, output_value);
            return false;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_dm_interworking_info = &p_dm_vap_info->u.bss_info.interworking;

    if (STR_CMP(param_name, "HESSID")) {
        if (is_valid_mac_address((char *)output_value->buff) == false) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d HESSID is not valid:%s\n", __func__,
                __LINE__, (char *)output_value->buff);
            return false;
        }
        STR_COPY(p_dm_interworking_info->interworking.hessid, (char *)output_value->buff);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

void *macfilter_tab_add_entry(void *obj_ins_context, uint32_t *p_ins_number)
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside AddEntry \n",__func__, __LINE__);
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)obj_ins_context;
    acl_entry_t *acl_entry;
    unsigned int count = 0;

    if (vap_info->vap_index > MAX_VAP) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d vap_index:%d is out of range\n",__func__,
            __LINE__, vap_info->vap_index);
        return NULL;
    }

    hash_map_t **acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    queue_t **acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);

    acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
    DM_CHECK_NULL_WITH_RC(acl_entry, NULL);

    if (*acl_new_entry_queue == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unexpected ERROR!!! acl_new_entry_queue"
            " should not be NULL\n", __func__, __LINE__);
        *acl_new_entry_queue = queue_create();
    }

    memset(acl_entry, 0, sizeof(acl_entry_t));

    if (*acl_new_entry_queue != NULL) {
        queue_push(*acl_new_entry_queue, acl_entry);
        count  = count + queue_count(*acl_new_entry_queue);
    }

    if (*acl_device_map != NULL) {
        count  = count  + hash_map_count(*acl_device_map);
    }

    //new entry index
    *p_ins_number = count;

    //dont send the blob now because there is no valid mac entry. waits the update

    return acl_entry;
}

int macfilter_tab_del_entry(void *obj_ins_context, void *p_instance)
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Inside DelEntry \n",__func__, __LINE__);
    wifi_vap_info_t *vap_info = (wifi_vap_info_t *)obj_ins_context;
    acl_entry_t *acl_entry = (acl_entry_t *) p_instance;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    acl_entry_t *map_acl_entry, *tmp_acl_entry;
    unsigned int count, itr;
    mac_addr_str_t mac_str;
    if (vap_info->vap_index > MAX_VAP) {
        return RETURN_ERR;
    }

    DM_CHECK_NULL_WITH_RC(acl_entry, RETURN_ERR);

    queue_t **acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);
    hash_map_t **acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    if (*acl_new_entry_queue ==  NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unexpected ERROR!!! acl_new_entry_queue"
            " should not be NULL\n", __func__,__LINE__);
        *acl_new_entry_queue = queue_create();
    }

    if (memcmp(acl_entry->mac, zero_mac, sizeof(mac_address_t)) == 0) {
        if (*acl_new_entry_queue != NULL) {
            count  = queue_count(*acl_new_entry_queue);
            for (itr = 0; itr < count; itr++) {
                map_acl_entry = (acl_entry_t *)queue_peek(*acl_new_entry_queue, itr);
                if (map_acl_entry == acl_entry) {
                    map_acl_entry = queue_remove(*acl_new_entry_queue, itr);
                    if (map_acl_entry) {
                        free(map_acl_entry);
                    }
                    break;
                }
            }
            return RETURN_OK;
        }
    } else {
        to_mac_str(acl_entry->mac, mac_str);
        tmp_acl_entry = hash_map_remove(*acl_device_map, mac_str);
        if (tmp_acl_entry != NULL) {
            free(tmp_acl_entry);
        }

        // Send blob
        if(push_acl_list_dml_cache_to_one_wifidb(vap_info) == RETURN_ERR) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d Mac_Filter falied \n",__func__, __LINE__);
            return RETURN_ERR;
        }
        return RETURN_OK;
    }

    return RETURN_ERR;
}

bool associated_sta_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    assoc_dev_data_t *assoc_dev_data = (assoc_dev_data_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(assoc_dev_data, false);

    /* check the parameter name and return the corresponding value */
    if (STR_CMP(param_name, "AuthenticationState")) {
        *output_value = assoc_dev_data->dev_stats.cli_AuthenticationState;
    } else if (STR_CMP(param_name, "Active")) {
        *output_value = assoc_dev_data->dev_stats.cli_Active;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool associated_sta_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    assoc_dev_data_t *assoc_dev_data = (assoc_dev_data_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(assoc_dev_data, false);

    if (STR_CMP(param_name, "SignalStrength")) {
       *output_value = assoc_dev_data->dev_stats.cli_SignalStrength;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_SNR")) {
       *output_value = assoc_dev_data->dev_stats.cli_SNR;
    } else if (STR_CMP(param_name, "X_RDKCENTRAL-COM_SNR")) {
       *output_value = assoc_dev_data->dev_stats.cli_SNR;
    } else if(STR_CMP(param_name, "X_COMCAST-COM_RSSI")) {
       *output_value = assoc_dev_data->dev_stats.cli_RSSI;
    } else if(STR_CMP(param_name, "X_COMCAST-COM_MinRSSI")) {
       *output_value = assoc_dev_data->dev_stats.cli_MinRSSI;
    } else if(STR_CMP(param_name, "X_COMCAST-COM_MaxRSSI")) {
       *output_value = assoc_dev_data->dev_stats.cli_MaxRSSI;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool associated_sta_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    assoc_dev_data_t *assoc_dev_data = (assoc_dev_data_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(assoc_dev_data, false);

    if (STR_CMP(param_name, "LastDataDownlinkRate")) {
        *output_value = assoc_dev_data->dev_stats.cli_LastDataDownlinkRate;
    } else if (STR_CMP(param_name, "LastDataUplinkRate")) {
        *output_value = assoc_dev_data->dev_stats.cli_LastDataUplinkRate;
    } else if (STR_CMP(param_name, "Retransmissions")) {
        *output_value = assoc_dev_data->dev_stats.cli_Retransmissions;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_DataFramesSentAck")) {
        *output_value = assoc_dev_data->dev_stats.cli_DataFramesSentAck;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_DataFramesSentNoAck")) {
        *output_value = assoc_dev_data->dev_stats.cli_DataFramesSentNoAck;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_BytesSent")) {
        *output_value = assoc_dev_data->dev_stats.cli_BytesSent;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_BytesReceived")) {
        *output_value = assoc_dev_data->dev_stats.cli_BytesReceived;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_Disassociations")) {
        *output_value = assoc_dev_data->dev_stats.cli_Disassociations;
    } else if( STR_CMP(param_name, "X_COMCAST-COM_AuthenticationFailures")) {
        *output_value = assoc_dev_data->dev_stats.cli_AuthenticationFailures;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool associated_sta_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    assoc_dev_data_t *assoc_dev_data = (assoc_dev_data_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(assoc_dev_data, false);

    if (STR_CMP(param_name, "MACAddress")) {
        char p_mac[18];
        snprintf(p_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", assoc_dev_data->dev_stats.cli_MACAddress[0], assoc_dev_data->dev_stats.cli_MACAddress[1], assoc_dev_data->dev_stats.cli_MACAddress[2],
                   assoc_dev_data->dev_stats.cli_MACAddress[3], assoc_dev_data->dev_stats.cli_MACAddress[4], assoc_dev_data->dev_stats.cli_MACAddress[5]);
        set_output_string(output_value, p_mac);
    } else if (STR_CMP(param_name, "X_COMCAST-COM_OperatingStandard")) {
        set_output_string(output_value, assoc_dev_data->dev_stats.cli_OperatingStandard);
    } else if (STR_CMP(param_name, "X_COMCAST-COM_OperatingChannelBandwidth")) {
        set_output_string(output_value, assoc_dev_data->dev_stats.cli_OperatingChannelBandwidth);
    } else if (STR_CMP(param_name, "X_COMCAST-COM_InterferenceSources")) {
        set_output_string(output_value, assoc_dev_data->dev_stats.cli_InterferenceSources);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool ap_macfilter_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (isVapSTAMesh(pcfg->vap_index)) {
        return true;
    }

    if (STR_CMP(param_name, "Enable")) {
        if (isVapHotspot(pcfg->vap_index)) {
            *output_value = true;
        } else {
            *output_value = pcfg->u.bss_info.mac_filter_enable;
        }
    } else if (STR_CMP(param_name, "FilterAsBlackList")) {
        if ((pcfg->u.bss_info.mac_filter_enable == true) &&
            (pcfg->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list)) {
            *output_value = true;
        } else {
            *output_value = false;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool ap_macfilter_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }
    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, pcfg->vap_name);
        return true;
    }

    if (STR_CMP(param_name, "Enable")) {
        if (p_dm_vap_info->u.bss_info.mac_filter_enable != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d mac_filter_enable=%d Value=%d\n", __func__,
                __LINE__, p_dm_vap_info->u.bss_info.mac_filter_enable, output_value);
            p_dm_vap_info->u.bss_info.mac_filter_enable = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "FilterAsBlackList")) {
        if (p_dm_vap_info->u.bss_info.mac_filter_mode != !output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d mac_filter_mode=%d Value=%d\n", __func__,
                __LINE__, p_dm_vap_info->u.bss_info.mac_filter_mode, !output_value);
            p_dm_vap_info->u.bss_info.mac_filter_mode = !output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wps_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, pcfg->vap_name);
        return true;
    }

    if (STR_CMP(param_name, "Enable")) {
        *output_value = pcfg->u.bss_info.wps.enable;
    } else if (STR_CMP(param_name, "X_CISCO_COM_ActivatePushButton")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "X_CISCO_COM_CancelSession")) {
        *output_value = false;
    } else if (STR_CMP(param_name, "X_Comcast_com_Configured")) {
        *output_value = false;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wps_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, pcfg->vap_name);
        return true;
    }

    if (STR_CMP(param_name, "X_CISCO_COM_WpsPushButton")) {
        *output_value = pcfg->u.bss_info.wpsPushButton;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wps_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool wps_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    int vap_index = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name);
    dml_vap_default *p_dm_vap_default = get_vap_default(vap_index);

    DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, pcfg->vap_name);
        return true;
    }

    if (STR_CMP(param_name, "ConfigMethodsSupported")) {
        char buff[128] = {0};

        if (get_wifi_wps_method_string_from_int(p_dm_vap_default->wps_methods, buff) != 0) {
            set_output_string(output_value, buff);
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d wps method:%d str value not found\n", __func__,
                __LINE__, p_dm_vap_default->wps_methods);
            return false;
        }
    } else if (STR_CMP(param_name, "ConfigMethodsEnabled")) {
        char buff[128] = {0};

        if (get_wifi_wps_method_string_from_int(pcfg->u.bss_info.wps.methods, buff) != 0) {
            set_output_string(output_value, buff);
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d wps method:%d str value not found\n", __func__,
                __LINE__, p_dm_vap_default->wps_methods);
            return false;
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_Pin")) {
        set_output_string(output_value, p_dm_vap_default->wps_pin);
    } else if (STR_CMP(param_name, "X_CISCO_COM_ClientPin")) {
        set_output_string(output_value, " ");
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wps_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    } else if (is_sec_mode_open_for_private_ap(pcfg->vap_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d [%s] does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return false;
    }

    if (STR_CMP(param_name, "Enable")) {
        if (p_dm_vap_info->u.bss_info.wps.enable != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:key=%d output_value=%d\n", __func__,
                __LINE__, p_dm_vap_info->u.bss_info.wps.enable, output_value);
            p_dm_vap_info->u.bss_info.wps.enable = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_ActivatePushButton")) {
        dml_vap_default *p_dm_vap_default = get_vap_default(instance_number - 1);

        DM_CHECK_NULL_WITH_RC(p_dm_vap_default, false);

        if (p_dm_vap_info->u.bss_info.wpsPushButton != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:key=%d output_value=%d\n",__func__,
                __LINE__, p_dm_vap_info->u.bss_info.wpsPushButton, output_value);
            //WPS validation
	    if (output_value == true) {
                if (p_dm_vap_info->u.bss_info.wps.enable == false) {
                    wifi_util_error_print(WIFI_DMCLI,"(%s) WPS is not enabled for vap %d\n", __func__, instance_number - 1);
                    p_dm_vap_info->u.bss_info.wpsPushButton = false;
                    return false;
                }

                if ((p_dm_vap_default->wps_methods & WIFI_ONBOARDINGMETHODS_PUSHBUTTON) == 0) {
                    wifi_util_error_print(WIFI_DMCLI,"(%s) WPS PBC:%d is not configured for vap:%d\n", __func__,
                        p_dm_vap_default->wps_methods, instance_number - 1);

                    p_dm_vap_info->u.bss_info.wpsPushButton = false;
                    return false;
                }
            }
            p_dm_vap_info->u.bss_info.wpsPushButton = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
            //WPS commit
            if (output_value == true) {
                int32_t temp_vap_index = instance_number - 1;
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:Activate push button for vap %d\n", __func__,
                    __LINE__, temp_vap_index);
                push_event_to_ctrl_queue(&temp_vap_index, sizeof(temp_vap_index), wifi_event_type_command,
                    wifi_event_type_command_wps, NULL);
                p_dm_vap_info->u.bss_info.wpsPushButton = false;
            }
        }
    } else if (STR_CMP(param_name, "X_CISCO_COM_CancelSession")) {
        instance_number -= 1;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: WPS cancel for vap %d\n",__func__, __LINE__, instance_number);
        push_event_to_ctrl_queue(&instance_number, sizeof(instance_number), wifi_event_type_command, wifi_event_type_command_wps_cancel, NULL);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wps_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    } else if (is_sec_mode_open_for_private_ap(pcfg->vap_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d [%s] does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return false;
    }

    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    if (STR_CMP(param_name, "X_CISCO_COM_WpsPushButton")) {
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wps_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    } else if (is_sec_mode_open_for_private_ap(pcfg->vap_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d [%s] does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return false;
    }

    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool wps_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    uint8_t instance_number = convert_vap_name_to_index(&((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop, pcfg->vap_name)+1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    } else if (is_sec_mode_open_for_private_ap(pcfg->vap_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d [%s] does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return false;
    }

    if (STR_CMP(param_name, "ConfigMethodsEnabled")) {
        wifi_onboarding_methods_t l_wps_method = 0;

        if (get_wifi_wps_method_int_from_string((char *)output_value->buff, &l_wps_method) != RETURN_OK) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: unsupported wps method:%s\n",__func__,
                __LINE__, (char *)output_value->buff);
            return false;
        }
        p_dm_vap_info->u.bss_info.wps.methods = l_wps_method;
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "X_CISCO_COM_ClientPin")) {
        if ((strlen((char *)output_value->buff) >= 4) && (strlen((char *)output_value->buff) <= 8)) {
            push_wps_pin_dml_to_ctrl_queue((instance_number - 1), (char *)output_value->buff);
        } else {
            return false;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_serv_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_interworking_info = &vap_pcfg->u.bss_info.interworking;

    if (STR_CMP(param_name, "Parameters")) {
        if (p_interworking_info->anqp.anqpParameters) {
            set_output_string(output_value, (char *)p_interworking_info->anqp.anqpParameters);
        } else {
            set_output_string(output_value, " ");
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool interworking_serv_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_dm_interworking_info = &p_dm_vap_info->u.bss_info.interworking;

    if (STR_CMP(param_name, "Parameters")) {
        if (STR_CMP((char *)p_dm_interworking_info->anqp.anqpParameters, (char *)output_value->buff)) {
            return true;
        } else {
            cJSON *p_root = cJSON_Parse((char *)output_value->buff);
            if (p_root == NULL) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid json for vap %s\n", __func__,
                    __LINE__,pcfg->vap_name);
                return false;
            }
            STR_COPY((char*)p_dm_interworking_info->anqp.anqpParameters, (char *)output_value->buff);
            set_dml_cache_vap_config_changed(instance_number - 1);
            cJSON_Delete(p_root);
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: interwoking serv param set success\n",__func__, __LINE__);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool passpoint_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_interworking_info = &vap_pcfg->u.bss_info.interworking;

    if (STR_CMP(param_name, "Capability")) {
    } else if (STR_CMP(param_name, "Enable")) {
        *output_value = p_interworking_info->passpoint.enable;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool passpoint_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_interworking_info = &vap_pcfg->u.bss_info.interworking;

    if (STR_CMP(param_name, "Parameters")) {
        if (p_interworking_info->passpoint.hs2Parameters) {
            set_output_string(output_value, (char *)p_interworking_info->passpoint.hs2Parameters);
        } else {
            set_output_string(output_value, " ");
        }
    } else if (STR_CMP(param_name, "WANMetrics")) {
        WiFi_GetWANMetrics((vap_pcfg->vap_index + 1), (char *)&p_interworking_info->passpoint.wanMetricsInfo,
                sizeof(p_interworking_info->passpoint.wanMetricsInfo));
        set_output_string(output_value, (char *)&p_interworking_info->passpoint.wanMetricsInfo);
    } else if (STR_CMP(param_name, "Stats")) {
        WiFi_GetHS2Stats((vap_pcfg->vap_index + 1));
        set_output_string(output_value, (char *)p_interworking_info->anqp.passpointStats);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool passpoint_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_dm_interworking_info = &p_dm_vap_info->u.bss_info.interworking;

    if (STR_CMP(param_name, "Enable")) {
        if (p_dm_interworking_info->interworking.interworkingEnabled == false) {
            wifi_util_info_print(WIFI_DMCLI,"Cannot Enable Passpoint. Interworking Disabled\n");
            return false;
        } else if (p_dm_interworking_info->passpoint.enable != output_value) {
            p_dm_interworking_info->passpoint.enable = output_value;
            set_dml_cache_vap_config_changed(instance_number - 1);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool passpoint_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *pcfg = (wifi_vap_info_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);
    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if (isVapSTAMesh(pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__, __LINE__, pcfg->vap_name);
        return true;
    }

    wifi_interworking_t *p_dm_interworking_info = &p_dm_vap_info->u.bss_info.interworking;

    if (STR_CMP(param_name, "Parameters")) {
        if (STR_CMP((char *)p_dm_interworking_info->passpoint.hs2Parameters, (char *)output_value->buff)) {
            return true;
        } else {
            cJSON *p_root = cJSON_Parse((char *)output_value->buff);
            if (p_root == NULL) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid json for vap %s\n", __func__,
                    __LINE__,pcfg->vap_name);
                return false;
            }
            STR_COPY((char*)p_dm_interworking_info->passpoint.hs2Parameters, (char *)output_value->buff);
            set_dml_cache_vap_config_changed(instance_number - 1);
            cJSON_Delete(p_root);
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: passpoint param set success\n",__func__, __LINE__);
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool conn_ctrl_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    if (STR_CMP(param_name, "ClientForceDisassociation")) {
        set_output_string(output_value, vap_pcfg->u.bss_info.postassoc.client_force_disassoc_info);
    } else if (STR_CMP(param_name, "ClientDenyAssociation")) {
        set_output_string(output_value, vap_pcfg->u.bss_info.preassoc.client_deny_assoc_info);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool conn_ctrl_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    if (STR_CMP(param_name, "ClientForceDisassociation")) {
    } else if (STR_CMP(param_name, "ClientDenyAssociation")) {
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool pre_conn_ctrl_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_preassoc_control_t *p_pre_assoc = &vap_pcfg->u.bss_info.preassoc;

    if (STR_CMP(param_name, "RssiUpThresholdSupported")) {
        set_output_string(output_value, "disabled, 10 to 100");
    } else if (STR_CMP(param_name, "SnrThresholdSupported")) {
        set_output_string(output_value, "disabled, 1 to 100");
    } else if (STR_CMP(param_name, "RssiUpThreshold")) {
        set_output_string(output_value, p_pre_assoc->rssi_up_threshold);
    } else if (STR_CMP(param_name, "SnrThreshold")) {
        set_output_string(output_value, p_pre_assoc->snr_threshold);
    } else if (STR_CMP(param_name, "CuThresholdSupported")) {
        set_output_string(output_value, "disabled, 0 to 100 (%% in integer)");
    } else if (STR_CMP(param_name, "CuThreshold")) {
        set_output_string(output_value, p_pre_assoc->cu_threshold);
    } else if (STR_CMP(param_name, "BasicDataTransmitRates")) {
        set_output_string(output_value, p_pre_assoc->basic_data_transmit_rates);
    } else if (STR_CMP(param_name, "OperationalDataTransmitRates")) {
        set_output_string(output_value, p_pre_assoc->operational_data_transmit_rates);
    } else if (STR_CMP(param_name, "SupportedDataTransmitRates")) {
        set_output_string(output_value, p_pre_assoc->supported_data_transmit_rates);
    } else if (STR_CMP(param_name, "MinimumAdvertisedMCS")) {
        set_output_string(output_value, p_pre_assoc->minimum_advertised_mcs);
    } else if (STR_CMP(param_name, "6GOpInfoMinRate")) {
        set_output_string(output_value, p_pre_assoc->sixGOpInfoMinRate);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool pre_conn_ctrl_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    int val, ret;
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, vap_pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if ((isVapSTAMesh(vap_pcfg->vap_index)) ||
        (!isVapHotspot(vap_pcfg->vap_index))) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_preassoc_control_t *p_dm_pre_assoc = &p_dm_vap_info->u.bss_info.preassoc;
    char *p_input_str = (char *)output_value->buff;

    if (STR_CMP(param_name, "RssiUpThreshold")) {
        if (STR_CMP(p_input_str, p_dm_pre_assoc->rssi_up_threshold)) {
            return true;
        } else if (STR_CMP(p_input_str, "disabled")) {
            STR_COPY(p_dm_pre_assoc->rssi_up_threshold, "disabled");
        } else {
            ret = sscanf(p_input_str, "%d", &val);
            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: -90 to -50\n", __func__, __LINE__);
                return false;
            }

            if (val > -50 || val < -95) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __func__, __LINE__);
                return false;
            }

            STR_COPY(p_dm_pre_assoc->rssi_up_threshold, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "SnrThreshold")) {
        if (STR_CMP(p_input_str, p_dm_pre_assoc->snr_threshold)) {
            return true;
        } else if (STR_CMP(p_input_str, "disabled")) {
            STR_COPY(p_dm_pre_assoc->snr_threshold, "disabled");
        } else {
            ret = sscanf(p_input_str, "%d", &val);
            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __func__, __LINE__);
                return false;
            }

            if (val < 1 || val > 100) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __func__, __LINE__);
                return false;
            }

            STR_COPY(p_dm_pre_assoc->snr_threshold, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "CuThreshold")) {
        if (STR_CMP(p_input_str, p_dm_pre_assoc->cu_threshold)) {
            return true;
        } else if (STR_CMP(p_input_str, "disabled")) {
            STR_COPY(p_dm_pre_assoc->cu_threshold, "disabled");
        } else {
            ret = sscanf(p_input_str, "%d", &val);

            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __func__, __LINE__);
                return false;
            }

            if (val < 0 || val > 100) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __func__, __LINE__);
                return false;
            }

            STR_COPY(p_dm_pre_assoc->cu_threshold, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "BasicDataTransmitRates")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Rate to set for preassoc\n", __func__, __LINE__, p_input_str);

        if (STR_CMP(p_input_str, p_dm_pre_assoc->basic_data_transmit_rates)) {
            return true;
        } else if (strcmp(p_input_str, "disabled") == 0) {
            STR_COPY(p_dm_pre_assoc->basic_data_transmit_rates, "disabled");
        } else if (is_valid_transmit_rate(p_input_str)) {
            wifi_bitrate_t temp_bit_rate = 0;

            if (get_wifi_data_tx_rate_int_from_string(p_input_str, &temp_bit_rate) != RETURN_OK) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Invalid value:%s:%d\n", __func__,
                    __LINE__, p_input_str, temp_bit_rate);
                return false;
            }

            STR_COPY(p_dm_pre_assoc->basic_data_transmit_rates, p_input_str);
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d %s Not a valid format\n", __func__, __LINE__, p_input_str);
            return false;
        }
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "OperationalDataTransmitRates")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s operational Rate to set for preassoc\n", __func__, __LINE__, p_input_str);

        if (STR_CMP(p_input_str, p_dm_pre_assoc->operational_data_transmit_rates)) {
            return true;
        } else if (strcmp(p_input_str, "disabled") == 0) {
            STR_COPY(p_dm_pre_assoc->operational_data_transmit_rates, "disabled");
        } else if (is_valid_transmit_rate(p_input_str)) {
            wifi_bitrate_t temp_bit_rate = 0;

            if (get_wifi_data_tx_rate_int_from_string(p_input_str, &temp_bit_rate) != RETURN_OK) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Invalid value:%s:%d\n", __func__,
                    __LINE__, p_input_str, temp_bit_rate);
                return false;
            }

            STR_COPY(p_dm_pre_assoc->operational_data_transmit_rates, p_input_str);
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d %s Not a valid format\n", __func__, __LINE__, p_input_str);
            return false;
        }
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "SupportedDataTransmitRates")) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d %s Supported Rate to set for preassoc\n", __func__, __LINE__, p_input_str);

        if (STR_CMP(p_input_str, p_dm_pre_assoc->supported_data_transmit_rates)) {
            return true;
        } else if (strcmp(p_input_str, "disabled") == 0) {
            STR_COPY(p_dm_pre_assoc->supported_data_transmit_rates, "disabled");
        } else if (is_valid_transmit_rate(p_input_str)) {
            wifi_bitrate_t temp_bit_rate = 0;

            if (get_wifi_data_tx_rate_int_from_string(p_input_str, &temp_bit_rate) != RETURN_OK) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Invalid value:%s:%d\n", __func__,
                    __LINE__, p_input_str, temp_bit_rate);
                return false;
            }

            STR_COPY(p_dm_pre_assoc->supported_data_transmit_rates, p_input_str);
        } else {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d %s Not a valid format\n", __func__, __LINE__, p_input_str);
            return false;
        }
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "MinimumAdvertisedMCS")) {
        if (STR_CMP(p_input_str, p_dm_pre_assoc->minimum_advertised_mcs)) {
            return true;
        } else if (STR_CMP(p_input_str, "disabled")) {
            STR_COPY(p_dm_pre_assoc->minimum_advertised_mcs, "disabled");
        } else {
            ret = sscanf(p_input_str, "%d", &val);

            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format: value should be"
                    " single integer number between 0 to 7\n", __func__, __LINE__);
                return false;
            }
            if (val < 0 || val > 7) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect value, value should be"
                    " within 0 to 7\n", __func__, __LINE__);
                return false;
            }

            STR_COPY(p_dm_pre_assoc->minimum_advertised_mcs, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "6GOpInfoMinRate")) {
        if (STR_CMP(p_input_str, p_dm_pre_assoc->sixGOpInfoMinRate)) {
            return true;
        } else if (STR_CMP(p_input_str, "disabled")) {
            STR_COPY(p_dm_pre_assoc->sixGOpInfoMinRate, "disabled");
        } else {
	    STR_COPY(p_dm_pre_assoc->sixGOpInfoMinRate, p_input_str);
	}
        set_cac_cache_changed(instance_number - 1);
        set_dml_cache_vap_config_changed(instance_number - 1);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool post_conn_ctrl_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    if (isVapSTAMesh(vap_pcfg->vap_index)) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_postassoc_control_t *p_post_assoc = &vap_pcfg->u.bss_info.postassoc;

    if (STR_CMP(param_name, "RssiUpThresholdSupported")) {
        set_output_string(output_value, "disabled, -50 to -95");
    } else if (STR_CMP(param_name, "RssiUpThreshold")) {
        set_output_string(output_value, p_post_assoc->rssi_up_threshold);
    } else if (STR_CMP(param_name, "SamplingIntervalSupported")) {
        set_output_string(output_value, "1 to 10");
    } else if (STR_CMP(param_name, "SamplingInterval")) {
        set_output_string(output_value, p_post_assoc->sampling_interval);
    } else if (STR_CMP(param_name, "SnrThresholdSupported")) {
        set_output_string(output_value, "disabled, 1 to 100");
    } else if (STR_CMP(param_name, "SnrThreshold")) {
        set_output_string(output_value, p_post_assoc->snr_threshold);
    } else if (STR_CMP(param_name, "SamplingCountSupported")) {
        set_output_string(output_value, "1 to 10");
    } else if (STR_CMP(param_name, "SamplingCount")) {
        set_output_string(output_value, p_post_assoc->sampling_count);
    } else if (STR_CMP(param_name, "CuThresholdSupported")) {
        set_output_string(output_value, "disabled, 0 to 100");
    } else if (STR_CMP(param_name, "CuThreshold")) {
        set_output_string(output_value, p_post_assoc->cu_threshold);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool post_conn_ctrl_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    int val, ret;
    wifi_vap_info_t *vap_pcfg = (wifi_vap_info_t *)obj_ins_context;

    DM_CHECK_NULL_WITH_RC(vap_pcfg, false);

    wifi_platform_property_t *p_wifi_prop = &((webconfig_dml_t *)get_webconfig_dml())->hal_cap.wifi_prop;
    uint32_t instance_number = convert_vap_name_to_index(p_wifi_prop, vap_pcfg->vap_name) + 1;
    wifi_vap_info_t *p_dm_vap_info = (wifi_vap_info_t *) get_dml_cache_vap_info(instance_number - 1);

    if (p_dm_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get VAP info for instance_number:%d\n", __func__, __LINE__, instance_number);
        return false;
    }

    if ((isVapSTAMesh(vap_pcfg->vap_index)) ||
        (!isVapHotspot(vap_pcfg->vap_index))) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d %s does not support configuration\n", __func__,
            __LINE__, vap_pcfg->vap_name);
        return true;
    }

    wifi_postassoc_control_t *p_dm_post_assoc = &p_dm_vap_info->u.bss_info.postassoc;
    char *p_input_str = (char *)output_value->buff;

    if (STR_CMP(param_name, "RssiUpThreshold")) {
        if (STR_CMP(p_input_str, p_dm_post_assoc->rssi_up_threshold)) {
            return true;
        } else if (STR_CMP(p_input_str, "disabled")) {
            STR_COPY(p_dm_post_assoc->rssi_up_threshold, "disabled");
        } else {
            ret = sscanf(p_input_str, "%d", &val);

            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format."
                    " Example: 10 to 100\n", __func__, __LINE__);
                return false;
            }

            if (val > -50 || val < -95) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __func__, __LINE__);
                return false;
            }

            STR_COPY(p_dm_post_assoc->rssi_up_threshold, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "SamplingInterval")) {
        if (STR_CMP(p_input_str, p_dm_post_assoc->sampling_interval)) {
            return true;
        } else {
            ret = sscanf(p_input_str, "%d", &val);
            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __func__, __LINE__);
                return false;
            }

            if (val < 1 || val > 10) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __func__, __LINE__);
                return false;
            }

            STR_COPY(p_dm_post_assoc->sampling_interval, p_input_str);
            set_cac_cache_changed(instance_number - 1);
        }
    } else if (STR_CMP(param_name, "SnrThreshold")) {
        if (STR_CMP(p_input_str, p_dm_post_assoc->snr_threshold)) {
            return true;
        } else if (strcmp(p_input_str, "disabled") == 0) {
            STR_COPY(p_dm_post_assoc->snr_threshold, "disabled");
        } else {
            ret = sscanf(p_input_str, "%d", &val);

            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format. Example: 10 to 100\n", __func__,
                    __LINE__);
                return false;
            }

            if (val < 1 || val > 100) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Value is out of supported range\n", __func__,
                    __LINE__);
                return false;
            }

            STR_COPY(p_dm_post_assoc->snr_threshold, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "SamplingCount")) {
        if (STR_CMP(p_input_str, p_dm_post_assoc->sampling_count) == 0) {
            return true;
        } else {
            ret = sscanf(p_input_str, "%d", &val);

            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format."
                    " Example: 10 to 100\n", __func__, __LINE__);
                return false;
            }

            if (val < 1 || val > 10) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d  Value is out of supported range\n", __func__,
                    __LINE__);
                return false;
            }

            STR_COPY(p_dm_post_assoc->sampling_count, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
    } else if (STR_CMP(param_name, "CuThreshold")) {
        if (STR_CMP(p_input_str, p_dm_post_assoc->cu_threshold)) {
            return true;
        } else if (STR_CMP(p_input_str, "disabled")) {
            STR_COPY(p_dm_post_assoc->cu_threshold, "disabled");
        } else {
            ret = sscanf(p_input_str, "%d", &val);

            /* String should be in format of range between two integers */
            if (ret != 1) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Incorrect format."
                    " Example: 10 to 100\n", __func__, __LINE__);
                return false;
            }

            if (val < 10 || val > 100) {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Value is out of"
                    " supported range\n", __func__, __LINE__);
                return false;
            }

            STR_COPY(p_dm_post_assoc->cu_threshold, p_input_str);
        }
        set_cac_cache_changed(instance_number - 1);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_wifi_diag_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_config_t *p_global_wifi_config;
    p_global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    DM_CHECK_NULL_WITH_RC(p_global_wifi_config, false);

    if (STR_CMP(param_name, "Enable")) {
        *output_value = p_global_wifi_config->global_parameters.diagnostic_enable;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_wifi_diag_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool neig_wifi_diag_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();

    if (STR_CMP(param_name, "ResultNumberOfEntries")) {
        *output_value = (uint32_t)monitor_param->neighbor_scan_cfg.ResultCount;
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: neighbor_scan_cfg ResultCount:%d\n",__func__,
            __LINE__, monitor_param->neighbor_scan_cfg.ResultCount);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_wifi_diag_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();

    if (STR_CMP(param_name, "DiagnosticsState")) {
        set_output_string(output_value, monitor_param->neighbor_scan_cfg.DiagnosticsState);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_wifi_diag_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_config_t *p_global_wifi_config;
    p_global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();

    DM_CHECK_NULL_WITH_RC(p_global_wifi_config, false);

    if (STR_CMP(param_name, "Enable")) {
        if (p_global_wifi_config->global_parameters.diagnostic_enable != output_value) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d:diagnostic_enable=%d Value:%d\n",__func__,
                __LINE__, p_global_wifi_config->global_parameters.diagnostic_enable, output_value);
            p_global_wifi_config->global_parameters.diagnostic_enable = output_value;
            push_global_config_dml_cache_to_one_wifidb();
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_wifi_diag_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool neig_wifi_diag_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool neig_wifi_diag_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_config_t *p_global_wifi_config;
    p_global_wifi_config = (wifi_global_config_t *) get_dml_cache_global_wifi_config();
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();

    DM_CHECK_NULL_WITH_RC(p_global_wifi_config, false);

    if (STR_CMP(param_name, "DiagnosticsState")) {
        if ((STR_CMP((char *)output_value->buff, "Requested")) &&
            (p_global_wifi_config->global_parameters.diagnostic_enable)) {
            if (STR_CMP(monitor_param->neighbor_scan_cfg.DiagnosticsState, "Requested")) {
                return true;
            }

            process_neighbor_scan_dml();
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_diag_result_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_neighbor_ap2_t *  p_neighbor_cfg = (wifi_neighbor_ap2_t *)obj_ins_context;

    if (STR_CMP(param_name, "SignalStrength")) {
        *output_value = p_neighbor_cfg->ap_SignalStrength;
    } else if (STR_CMP(param_name, "Noise")) {
        *output_value = p_neighbor_cfg->ap_Noise;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_diag_result_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_neighbor_ap2_t *  p_neighbor_cfg = (wifi_neighbor_ap2_t *)obj_ins_context;

    if (STR_CMP(param_name, "DTIMPeriod")) {
        *output_value = p_neighbor_cfg->ap_DTIMPeriod;
    } else if (STR_CMP(param_name, "X_COMCAST-COM_ChannelUtilization")) {
        *output_value = p_neighbor_cfg->ap_ChannelUtilization;
    } else if (STR_CMP(param_name, "Channel")) {
        *output_value = p_neighbor_cfg->ap_Channel;
    } else if (STR_CMP(param_name, "BeaconPeriod")) {
       *output_value = p_neighbor_cfg->ap_BeaconPeriod;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool neig_diag_result_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_neighbor_ap2_t *  p_neighbor_cfg = (wifi_neighbor_ap2_t *)obj_ins_context;

    if (STR_CMP(param_name, "Radio")) {
        wifi_freq_bands_t l_freq_band;

        if (get_radio_band_int_from_string(p_neighbor_cfg->ap_OperatingFrequencyBand, &l_freq_band) != RETURN_ERR) {
            return false;
        }

        wifi_radio_operationParam_t *radio_oper_param = NULL;
        char buff[32] = { 0 };

	for (uint32_t index = 0; index < (uint32_t)get_num_radio_dml(); index++) {
            radio_oper_param = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(index);
            if (radio_oper_param != NULL && radio_oper_param->band == l_freq_band) {
                snprintf(buff, sizeof(buff), "Device.WiFi.Radio.%u", index + 1);
                set_output_string(output_value, buff);
                return true;
            }
        }
        return false;
    } else if (STR_CMP(param_name, "EncryptionMode")) {
        set_output_string(output_value, p_neighbor_cfg->ap_EncryptionMode);
    } else if (STR_CMP(param_name, "Mode")) {
        set_output_string(output_value, p_neighbor_cfg->ap_Mode);
    } else if (STR_CMP(param_name, "SecurityModeEnabled")) {
        set_output_string(output_value, p_neighbor_cfg->ap_SecurityModeEnabled);
    } else if (STR_CMP(param_name, "BasicDataTransferRates")) {
        set_output_string(output_value, p_neighbor_cfg->ap_BasicDataTransferRates);
    } else if (STR_CMP(param_name, "SupportedDataTransferRates")) {
        set_output_string(output_value, p_neighbor_cfg->ap_SupportedDataTransferRates);
    } else if (STR_CMP(param_name, "OperatingChannelBandwidth")) {
        set_output_string(output_value, p_neighbor_cfg->ap_OperatingChannelBandwidth);
    } else if (STR_CMP(param_name, "OperatingStandards")) {
        set_output_string(output_value, p_neighbor_cfg->ap_OperatingStandards);
    } else if (STR_CMP(param_name, "SupportedStandards")) {
        set_output_string(output_value, p_neighbor_cfg->ap_SupportedStandards);
    } else if (STR_CMP(param_name, "BSSID")) {
        set_output_string(output_value, p_neighbor_cfg->ap_BSSID);
    } else if( STR_CMP(param_name, "SSID")) {
        set_output_string(output_value, p_neighbor_cfg->ap_SSID);
    } else if (STR_CMP(param_name, "OperatingFrequencyBand")) {
        set_output_string(output_value, p_neighbor_cfg->ap_OperatingFrequencyBand);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_report_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "Enabled")) {
        *output_value = pcfg->b_inst_client_enabled;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_report_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "ReportingPeriod")) {
        *output_value = pcfg->u_inst_client_reporting_period;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_report_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "MacAddress")) {
        set_output_string(output_value, pcfg->mac_address);
    } else if (STR_CMP(param_name, "Schema")) {
        set_output_string(output_value, "WifiSingleClient.avsc");
    } else if (STR_CMP(param_name, "SchemaID")) {
        set_output_string(output_value, INST_SCHEMA_ID_BUFFER);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_report_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *p_dml_harvester = (instant_measurement_config_t *) get_dml_cache_harvester();

    DM_CHECK_NULL_WITH_RC(p_dml_harvester, false);

    if (STR_CMP(param_name, "Enabled")) {
        if ((output_value == true) &&
            (p_dml_harvester->u_inst_client_reporting_period > p_dml_harvester->u_inst_client_def_override_ttl)) {
             wifi_util_error_print(WIFI_DMCLI,"Can not start report when PollingPeriod > TTL\n");
             return false;
        }

        p_dml_harvester->b_inst_client_enabled = output_value;
        push_harvester_dml_cache_to_one_wifidb();
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_report_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) obj_ins_context;
    instant_measurement_config_t *p_dml_harvester = (instant_measurement_config_t *) get_dml_cache_harvester();

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(p_dml_harvester, false);

    if (STR_CMP(param_name, "ReportingPeriod")) {
        if (validate_def_reporting_period_value(output_value)) {
            if (pcfg->b_inst_client_enabled && (output_value != 0) &&
                (output_value > p_dml_harvester->u_inst_client_def_override_ttl)) {
                wifi_util_error_print(WIFI_DMCLI,"%s:%d Unsupported parameter value:%d"
                    " def override ttl value:%d\n", __func__, __LINE__, output_value,
                    p_dml_harvester->u_inst_client_def_override_ttl);
                return false;
            } else {
                p_dml_harvester->u_inst_client_reporting_period = output_value;
                push_harvester_dml_cache_to_one_wifidb();
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Unsupported parameter value:'%d'"
                " for ReportingPeriod\n", __func__, __LINE__, output_value);
            return false;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_report_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *p_dml_harvester = (instant_measurement_config_t *) get_dml_cache_harvester();

    DM_CHECK_NULL_WITH_RC(p_dml_harvester, false);

    if (STR_CMP(param_name, "MacAddress")) {
        if (validate_inst_client_mac_value((char *)output_value->buff)){
            STR_COPY(p_dml_harvester->mac_address, (char *)output_value->buff);
            push_harvester_dml_cache_to_one_wifidb();
        } else {
            return false;
        }
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_def_report_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) obj_ins_context;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "OverrideTTL")) {
        *output_value = pcfg->u_inst_client_def_override_ttl;
    } else if (STR_CMP(param_name, "ReportingPeriod")) {
        *output_value = pcfg->u_inst_client_def_reporting_period;
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_client_def_report_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *) obj_ins_context;
    instant_measurement_config_t *p_dml_harvester = (instant_measurement_config_t *) get_dml_cache_harvester();

    DM_CHECK_NULL_WITH_RC(pcfg, false);
    DM_CHECK_NULL_WITH_RC(p_dml_harvester, false);

    if (STR_CMP(param_name, "OverrideTTL")) {
        if (pcfg->b_inst_client_enabled && (output_value != 0) &&
              (output_value > p_dml_harvester->u_inst_client_reporting_period)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Unsupported parameter value:'%d'"
                " > inst client reporting period:%d\n", __func__, __LINE__, output_value,
                p_dml_harvester->u_inst_client_reporting_period);
            return false;
        } else if (output_value > 900) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Unsupported parameter value:'%d'\n", __func__,
                __LINE__, output_value);
            return false;
        }
        p_dml_harvester->u_inst_client_def_override_ttl = output_value;
        push_harvester_dml_cache_to_one_wifidb();
    } else if (STR_CMP(param_name, "ReportingPeriod")) {
        if (validate_def_reporting_period_value(output_value) != true) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: Unsupported parameter value:'%d'"
                " for Defualt ReportingPeriod\n", __func__, __LINE__, output_value);
            return false;
        }
        p_dml_harvester->u_inst_client_def_reporting_period = output_value;
        push_harvester_dml_cache_to_one_wifidb();
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_region_code_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_param_t *pcfg = (wifi_global_param_t *)obj_ins_context;
    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "Code")) {
        set_output_string(output_value, pcfg->wifi_region_code);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool wifi_region_code_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    wifi_global_param_t *pcfg = (wifi_global_param_t *)obj_ins_context;
    uint32_t radio_index = 0;
    char partner_id[PARTNER_ID_LEN] = {0};
    char current_time[50] = { 0 };
    char requestor_str[16] = { 0 };
    char str_wifi_region_update_src[16] = { 0 };
    wifi_radio_operationParam_t *p_dm_wifi_radio_param;
    wifi_global_config_t *p_dm_global_wifi_cfg;
    p_dm_global_wifi_cfg = (wifi_global_config_t *) get_dml_cache_global_wifi_config();
    wifi_countrycode_type_t l_country_code;
    wifi_operating_env_t l_oper_env;

    DM_CHECK_NULL_WITH_RC(pcfg, false);

    if (STR_CMP(param_name, "Code")) {
        get_requestor_string(requestor_str);
        get_wifi_region_update_source(str_wifi_region_update_src);
        if (strcmp(requestor_str, BS_SOURCE_RFC_STR) == 0 &&
            strcmp(str_wifi_region_update_src, BS_SOURCE_WEBPA_STR) == 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d Do NOT allow override\n", __func__, __LINE__);
            return false;
        }

        for (radio_index = 0; radio_index < get_num_radio_dml(); radio_index++) {
            p_dm_wifi_radio_param = (wifi_radio_operationParam_t *) get_dml_cache_radio_map(radio_index);
            if (p_dm_wifi_radio_param == NULL) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to fetch Operating params for radio index:%d\n", __func__,
                    __LINE__, radio_index);
                continue;
            }

            if (get_reg_domain_int_from_string((char *)output_value->buff, &l_country_code,
                &l_oper_env) == RETURN_OK) {
                is_radio_config_changed = true;
                p_dm_wifi_radio_param->countryCode = l_country_code;
                p_dm_wifi_radio_param->operatingEnvironment = l_oper_env;
            } else {
                wifi_util_info_print(WIFI_DMCLI,"%s:%d Unable to convert country code for radio_index %d\n", __func__,
                    __LINE__, radio_index);
                return false;
            }
        }

        strcpy(p_dm_global_wifi_cfg->global_parameters.wifi_region_code, (char *)output_value->buff);
        push_global_config_dml_cache_to_one_wifidb();
        push_radio_dml_cache_to_one_wifidb();
        last_radio_change = get_current_time_in_sec();

        if((RETURN_OK == get_partner_id(partner_id) ) && (partner_id[ 0 ] != '\0') ) {
            get_cur_time_str(current_time, sizeof(current_time));
            if (update_json_param("Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code", partner_id,
                (char *)output_value->buff, requestor_str, current_time) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Unable to update WifiRegion to Json file\n", __func__, __LINE__);
            }
        }
        set_wifi_region_update_source(requestor_str);
    } else {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: unsupported param name:%s\n",__func__, __LINE__, param_name);
        return false;
    }

    return true;
}

bool default_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool default_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool default_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool default_get_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool default_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool default_set_param_int_value(void *obj_ins_context, char *param_name, int output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool default_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}

bool default_set_param_string_value(void *obj_ins_context, char *param_name, scratch_data_buff_t *output_value)
{
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: param name:%s\n",__func__, __LINE__, param_name);
    return true;
}
