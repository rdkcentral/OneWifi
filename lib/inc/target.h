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

/**************************************************************************
  Some material is:
  Copyright (c) 2015, Plume Design Inc. All rights reserved.
  Licensed under the BSD-3 License
**************************************************************************/

#ifndef TARGET_H_INCLUDED
#define TARGET_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ev.h>

#include "os.h"
#include "os_types.h"
#include "schema.h"
#include "os_backtrace.h"
//#include "target_common.h"

#define TARGET_NAME	"abcd"
#define TARGET_OVSDB_SOCK_PATH      "/var/run/db.sock"
#define TARGET_BUFF_SZ              256
#define TARGET_ID_SZ                OS_MACSTR_PLAIN_SZ

/* Target init options */
typedef enum {
    TARGET_INIT_COMMON              =  0,
    TARGET_INIT_MGR_DM              =  1,
    TARGET_INIT_MGR_CM              =  2,
    TARGET_INIT_MGR_WM              =  3,
    TARGET_INIT_MGR_SM              =  4,
    TARGET_INIT_MGR_NM              =  5,
    TARGET_INIT_MGR_BM              =  6,
    TARGET_INIT_MGR_FM              =  7,
    TARGET_INIT_MGR_LM              =  8,
    TARGET_INIT_MGR_LEDM            =  9,
    TARGET_INIT_MGR_OM              = 10,
    TARGET_INIT_MGR_BLEM            = 11,
    TARGET_INIT_MGR_QM              = 12,
    TARGET_INIT_MGR_PM              = 13,
    TARGET_INIT_MGR_FSM             = 14,
    TARGET_INIT_MGR_TM              = 15,
    TARGET_INIT_MGR_HELLO_WORLD     = 16,
    TARGET_INIT_MGR_FCM             = 17,
    TARGET_INIT_MGR_PPM             = 18,
    TARGET_INIT_MGR_NFM             = 19
} target_init_opt_t;


#ifdef RDKB_EMCTRL_TARGET
class target_t {
	public:
		// identity
		virtual bool target_serial_get(void *buff, size_t buffsz);
		virtual bool target_id_get(void *buff, size_t buffsz);
		virtual bool target_sku_get(void *buff, size_t buffsz);
		virtual bool target_model_get(void *buff, size_t buffsz);
		virtual bool target_is_interface_ready(char *if_name);
		virtual bool target_sw_version_get(void *buff, size_t buffsz);
		virtual bool target_hw_revision_get(void *buff, size_t buffsz);
		virtual bool target_platform_version_get(void *buff, size_t buffsz);
		virtual bool target_log_open(char *name, int flags);
		virtual bool target_close(target_init_opt_t opt, struct ev_loop *loop);
		virtual bool target_init(target_init_opt_t opt, struct ev_loop *loop);
		virtual bool target_is_radio_interface_ready(char *phy_name);
		virtual const char *target_tls_cacert_filename(void);
		virtual const char *target_tls_mycert_filename(void);
		virtual const char *target_tls_privkey_filename(void);
		virtual bool target_ready(struct ev_loop *loop);
		virtual void target_managers_restart(void);
		virtual bool target_device_execute(const char *cmd);
		virtual int target_device_capabilities_get();
		virtual bool target_device_connectivity_check(const char *ifname,
                                      target_connectivity_check_t *cstate,
                                      target_connectivity_check_option_t opts);
		virtual bool target_device_restart_managers();
		virtual bool target_device_wdt_ping();
		virtual bool target_device_config_register(void *awlan_cb);
		virtual bool target_device_config_set(struct schema_AWLAN_Node *awlan);
		virtual bool target_stats_clients_get(radio_entry_t *radio_cfg, radio_essid_t *essid,
		     target_stats_clients_cb_t *client_cb, ds_dlist_t *client_list, void *client_ctx);
		 virtual bool target_stats_survey_convert(radio_entry_t *radio_cfg, radio_scan_type_t scan_type,
		     target_survey_record_t *data_new, target_survey_record_t *data_old,
		     dpp_survey_record_t *survey_record);
		 virtual bool target_stats_survey_get(radio_entry_t *radio_cfg, uint32_t *chan_list,
		     uint32_t chan_num, radio_scan_type_t scan_type, target_stats_survey_cb_t *survey_cb,
		     ds_dlist_t *survey_list, void *survey_ctx);
		 virtual bool target_stats_device_get(dpp_device_record_t *device_entry);
		 virtual bool target_stats_device_temp_get(radio_entry_t *radio_cfg, dpp_device_temp_t *device_entry);
		 virtual bool target_stats_device_txchainmask_get(radio_entry_t *radio_cfg, dpp_device_txchainmask_t *txchainmask_entry);
		 virtual bool target_stats_device_fanrpm_get(uint32_t *fan_rpm);
		 virtual bool target_stats_scan_start (radio_entry_t *radio_cfg, uint32_t *chan_list, uint32_t chan_num,
		     radio_scan_type_t scan_type, int32_t dwell_time, target_scan_cb_t  *scan_cb, void *scan_ctx);
		 virtual bool target_stats_scan_stop(radio_entry_t *radio_cfg, radio_scan_type_t scan_type);
		 virtual bool target_stats_scan_get(radio_entry_t *radio_cfg, uint32_t *chan_list, uint32_t chan_num,
		     radio_scan_type_t scan_type, dpp_neighbor_report_data_t *scan_results);
		 virtual bool target_stats_capacity_get(radio_entry_t *radio_cfg, target_capacity_data_t *capacity_new);
		 virtual bool target_stats_capacity_convert(target_capacity_data_t *capacity_new, target_capacity_data_t *capacity_old,
		     dpp_capacity_record_t *capacity_entry);
		 virtual bool target_stats_capacity_enable(radio_entry_t *radio_cfg, bool enabled);
		 virtual void target_client_record_free(target_client_record_t *record);
		 virtual bool target_t::target_stats_clients_convert(radio_entry_t *radio_cfg, target_client_record_t *client_list_new,
		     target_client_record_t *client_list_old, dpp_client_record_t *client_record);
		 virtual void target_survey_record_free(target_survey_record_t *record);
		 virtual bool target_radio_tx_stats_enable(radio_entry_t *radio_cfg, bool status);
		 virtual bool target_radio_fast_scan_enable(radio_entry_t *radio_cfg, ifname_t if_name);

		virtual const char* target_bin_dir(void);	

		// radio and vif (virtual access points)

		/** target calls this whenever middleware (if exists) wants to
     		*  update vif configuration */
		virtual void target_radio_vconf(const struct schema_Wifi_VIF_Config *vconf,
                     const char *phy);
    	/** target calls this whenever middleware (if exists) wants to
     		*  update radio configuration */
		virtual void target_radio_rconf(const struct schema_Wifi_Radio_Config *rconf);

    	/** target calls this whenever system vif state has changed,
     		*  e.g. channel changed, target_vif_config_set2() was called */
		virtual void target_radio_vstate(const struct schema_Wifi_VIF_State *vstate,
                      const char *phy);

	    /** target calls this whenever system radio state has changed,
     		*  e.g. channel changed, target_radio_config_set2() was called */
		virtual void target_radio_rstate(const struct schema_Wifi_Radio_State *rstate);	

    	/** target calls this whenever a client connects or disconnects */
    	virtual void target_radio_client(const struct schema_Wifi_Associated_Clients *client,
                      const char *vif,
                      bool associated);

    	/** target calls this whenever it wants to re-sync all clients due
     		*  to, e.g. internal event buffer overrun. */
    	virtual void target_radio_clients(const struct schema_Wifi_Associated_Clients *clients,
                       int num,
                       const char *vif);

    	/** target calls this whenever it wants to clear out
     	*  all clients on a given vif; intended to use when target wants to
     	*  fully re-sync connects clients (i.e. the call will be followed
     	*  by op_client() calls) or when a vif is deconfigured abruptly */
    	virtual void target_radio_flush_clients(const char *vif);

		virtual bool target_radio_config_init(ds_dlist_t *init_cfg);
		virtual bool target_radio_config_init2(void);
		virtual bool target_radio_config_need_reset(void);
		virtual bool target_radio_config_set (char *ifname, struct schema_Wifi_Radio_Config *rconf);
		virtual bool target_radio_config_set2(const struct schema_Wifi_Radio_Config *rconf,
                              const struct schema_Wifi_Radio_Config_flags *changed);
		virtual bool target_radio_state_get(char *ifname, struct schema_Wifi_Radio_State *rstate);
		virtual void target_radio_state_cb(struct schema_Wifi_Radio_State *rstate, schema_filter_t *filter);
		virtual void target_radio_config_cb(struct schema_Wifi_Radio_Config *rconf, schema_filter_t *filter);
		virtual bool target_vif_config_set (char *ifname, struct schema_Wifi_VIF_Config *vconf);
		virtual bool target_vif_config_set2(const struct schema_Wifi_VIF_Config *vconf,
                            const struct schema_Wifi_Radio_Config *rconf,
                            const struct schema_Wifi_Credential_Config *cconfs,
                            const struct schema_Wifi_VIF_Config_flags *changed,
                            int num_cconfs);

		virtual bool target_vif_state_get(char *ifname, struct schema_Wifi_VIF_State *vstate);
		virtual void target_vif_state_cb(struct schema_Wifi_VIF_State *rstate, schema_filter_t *filter);
		virtual void target_vif_config_cb(struct schema_Wifi_VIF_Config *vconf, schema_filter_t *filter);
		virtual bool target_clients_cb(struct schema_Wifi_Associated_Clients *schema, char *ifname, bool status);
		virtual bool target_vif_config_register(char *ifname, target_vif_config_cb_t *vconfig_cb);
		virtual bool target_vif_state_register(char *ifname, target_vif_state_cb_t *vstate_cb);

		target_t();
		~target_t();

};
#endif

#ifdef __cplusplus
}
#endif

#endif
