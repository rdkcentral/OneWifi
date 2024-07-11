#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_db.h"

#ifdef ONEWIFI_DB_SUPPORT
extern void init_wifidb(void);
extern void init_wifidb_data(void);
extern int update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config);
extern int start_wifidb();
extern void wifidb_print(char *format, ...);
extern int wifidb_get_wifi_vap_info(char *vap_name, wifi_vap_info_t *config, rdk_wifi_vap_info_t *rdk_config);
extern int wifidb_update_wifi_macfilter_config(char *macfilter_key, acl_entry_t *config, bool add);
extern void wifidb_cleanup();
extern int init_wifidb_tables();
extern void wifidb_init_default_value();
extern int start_wifidb_monitor();
extern int wifidb_update_rfc_config(UINT rfc_id, wifi_rfc_dml_parameters_t *rfc_param);
extern int wifidb_init_global_config_default(wifi_global_param_t *config);
extern int wifidb_init_radio_config_default(int radio_index,wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config);
extern int wifidb_init_vap_config_default(int vap_index, wifi_vap_info_t *config, rdk_wifi_vap_info_t *rdk_config);
extern int wifidb_update_wifi_security_config(char *vap_name, wifi_vap_security_t *sec);
extern int wifidb_get_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info);
extern int wifidb_update_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info);
extern int update_wifi_vap_info(char *vap_name,wifi_vap_info_t *config,rdk_wifi_vap_info_t *rdk_config);
extern int update_wifi_interworking_config(char *vap_name, wifi_interworking_t *config);
extern int update_wifi_global_config(wifi_global_param_t *config);
extern int wifidb_update_wifi_passpoint_config(char *vap_name, wifi_interworking_t *config);
extern int wifidb_update_wifi_anqp_config(char *vap_name, wifi_interworking_t *config);
#else
void init_wifidb(void)
{

}

void init_wifidb_data(void)
{

}

int update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    return 0;
}

int start_wifidb()
{
    return 0;
}

void wifidb_print(char *format, ...)
{

}

int wifidb_get_wifi_vap_info(char *vap_name, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    return 0;
}

int wifidb_update_wifi_macfilter_config(char *macfilter_key, acl_entry_t *config, bool add)
{
    return 0;
}

void wifidb_cleanup()
{

}

int init_wifidb_tables()
{
    return 0;
}

void wifidb_init_default_value()
{

}

int start_wifidb_monitor()
{
    return 0;
}

int wifidb_update_rfc_config(UINT rfc_id, wifi_rfc_dml_parameters_t *rfc_param)
{
    return 0;
}

int wifidb_init_global_config_default(wifi_global_param_t *config)
{
    return 0;
}

int wifidb_init_radio_config_default(int radio_index,wifi_radio_operationParam_t *config, wifi_radio_feature_param_t *feat_config)
{
    return 0;
}

int wifidb_init_vap_config_default(int vap_index, wifi_vap_info_t *config,
    rdk_wifi_vap_info_t *rdk_config)
{
    return 0;
}

int wifidb_update_wifi_security_config(char *vap_name, wifi_vap_security_t *sec)
{
    return 0;
}

int wifidb_get_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    return 0;
}

int wifidb_update_gas_config(UINT advertisement_id, wifi_GASConfiguration_t *gas_info)
{
    return 0;
}

    return;
}
 
int update_wifi_vap_info(char *vap_name,wifi_vap_info_t *config,rdk_wifi_vap_info_t *rdk_config)
{
    return 0;
}

int update_wifi_interworking_config(char *vap_name, wifi_InterworkingElement_t *config)
{
    return 0;
}

int update_wifi_global_config(wifi_global_param_t *config)
{
    return 0;
}

int wifidb_update_wifi_passpoint_config(char *vap_name, wifi_interworking_t *config)
{
    return 0;
}

int wifidb_update_wifi_anqp_config(char *vap_name, wifi_interworking_t *config)
{
    return 0;
}
{
#endif

void wifidb_init(wifi_db_t *db)
{
    db->desc.init_fn = init_wifidb;
    db->desc.init_data_fn = init_wifidb_data;
    db->desc.update_radio_cfg_fn = update_wifi_radio_config;
    db->desc.update_wifi_vap_info_fn = update_wifi_vap_info;
    db->desc.start_wifidb_fn = start_wifidb;
    db->desc.print_fn = wifidb_print;
    db->desc.get_wifi_vpa_info_fn = wifidb_get_wifi_vap_info;
    db->desc.update_wifi_macfilter_config_fn = wifidb_update_wifi_macfilter_config;
    db->desc.cleanup_fn = wifidb_cleanup;
    db->desc.init_tables_fn = init_wifidb_tables;
    db->desc.init_default_value_fn = wifidb_init_default_value;
    db->desc.start_monitor_fn = start_wifidb_monitor;
    db->desc.update_rfc_config_fn = wifidb_update_rfc_config;
    db->desc.init_global_config_default_fn = wifidb_init_global_config_default;
    db->desc.init_radio_config_default_fn = wifidb_init_radio_config_default;
    db->desc.init_vap_config_default_fn = wifidb_init_vap_config_default;
    db->desc.update_wifi_security_config_fn = wifidb_update_wifi_security_config;
    db->desc.get_gas_config_fn = wifidb_get_gas_config;
    db->desc.update_gas_config_fn = wifidb_update_gas_config;
    db->desc.update_wifi_interworking_cfg_fn = update_wifi_interworking_config;
    db->desc.update_wifi_global_cfg_fn = update_wifi_global_config;
    db->desc.update_wifi_passpoint_cfg_fn = wifidb_update_wifi_passpoint_config;
    db->desc.update_wifi_anqp_cfg_fn = wifidb_update_wifi_anqp_config;
}
