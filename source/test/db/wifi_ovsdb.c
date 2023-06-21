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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/prctl.h>
#include "cJSON.h"
#include "wifi_hal.h"
#include "os.h"
#include "util.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"
#include "schema.h"
#include "log.h"
#include "ds.h"
#include "json_util.h"
#include "target.h"
#include <ev.h>
#include <assert.h>
#include "collection.h"
#include "wifi_ovsdb.h"
#include "ccsp_base_api.h"

ovsdb_table_t 	table_Wifi_VAP_Config;
ovsdb_table_t 	table_Wifi_Security_Config;
ovsdb_table_t 	table_Wifi_Device_Config;
ovsdb_table_t 	table_Wifi_Config;

//extern void* bus_handle;
//extern char g_Subsystem[32];
#if 0
void callback_Wifi_Device_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Device_Config *old_rec,
        struct schema_Wifi_Device_Config *new_rec)
{
	if (mon->mon_type == OVSDB_UPDATE_DEL) {
		printf("%s:%d:Delete\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_NEW) {
		printf("%s:%d:New\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_MODIFY) {
		printf("%s:%d:Modify\n", __func__, __LINE__); 
	} else {
		printf("%s:%d:Unknown\n", __func__, __LINE__);
	}
}

void callback_Wifi_Security_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Security_Config *old_rec,
        struct schema_Wifi_Security_Config *new_rec)
{
	if (mon->mon_type == OVSDB_UPDATE_DEL) {
		printf("%s:%d:Delete\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_NEW) {
		printf("%s:%d:New\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_MODIFY) {
		printf("%s:%d:Modify\n", __func__, __LINE__); 
	} else {
		printf("%s:%d:Unknown\n", __func__, __LINE__);
	}
}

void callback_Wifi_VAP_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_VAP_Config *old_rec,
        struct schema_Wifi_VAP_Config *new_rec)
{
	if (mon->mon_type == OVSDB_UPDATE_DEL) {
		printf("%s:%d:Delete\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_NEW) {
		printf("%s:%d:New\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_MODIFY) {
		printf("%s:%d:Modify\n", __func__, __LINE__); 
	} else {
		printf("%s:%d:Unknown\n", __func__, __LINE__);
	}
}

void callback_Wifi_Config(ovsdb_update_monitor_t *mon,
        struct schema_Wifi_Config *old_rec,
        struct schema_Wifi_Config *new_rec)
{
	if (mon->mon_type == OVSDB_UPDATE_DEL) {
		printf("%s:%d:Delete\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_NEW) {
		printf("%s:%d:New\n", __func__, __LINE__); 
	} else if (mon->mon_type == OVSDB_UPDATE_MODIFY) {
		printf("%s:%d:Modify\n", __func__, __LINE__); 
	} else {
		printf("%s:%d:Unknown\n", __func__, __LINE__);
	}
}
#endif
int update_wifi_ovsdb_security(wifi_ovsdb_t *ovsdb, wifi_vap_info_t *vap_info, struct schema_Wifi_Security_Config *cfg, bool update)
{
#if 0
    struct schema_Wifi_Security_Config *pcfg;
    json_t *where;
	unsigned int count;
	struct in_addr addr;
	int ret;

	if (update == true) {
		where = onewifi_ovsdb_tran_cond(OCLM_UUID, "_uuid", OFUNC_EQ, cfg->_uuid.uuid);
    pcfg = onewifi_ovsdb_table_select_where(ovsdb->ovsdb_sock_path, &table_Wifi_Security_Config, where, &count);
		if ((count != 0) && (pcfg != NULL)) {
			assert(count == 1);
			memcpy(cfg, pcfg, sizeof(struct schema_Wifi_Security_Config));
			free(pcfg);
		}
	}

	printf("%s:%d: Found %d records with key: %s in Wifi Device table\n", 
    	__func__, __LINE__, count, vap_info->vap_name);

	strcpy(cfg->onboard_type, "manual");
	sprintf(cfg->security_mode, "%d", vap_info->u.bss_info.security.mode);
	sprintf(cfg->encryption_method, "%d", vap_info->u.bss_info.security.encr);

	if (vap_info->u.bss_info.security.mode < WIFI_SECURITY_WPA_ENTERPRISE) {
		strcpy(cfg->passphrase, vap_info->u.bss_info.security.u.key.key);
		strcpy(cfg->radius_server_ip, "");
		strcpy(cfg->radius_server_port, "");
		strcpy(cfg->radius_server_key, "");
		strcpy(cfg->secondary_radius_server_ip, "");
		strcpy(cfg->secondary_radius_server_port, "");
		strcpy(cfg->secondary_radius_server_key, "");
	} else {
		strcpy(cfg->passphrase, "");
		addr.s_addr = vap_info->u.bss_info.security.u.radius.ip.u.IPv4addr;
		strcpy(cfg->radius_server_ip, inet_ntoa(addr));
		sprintf(cfg->radius_server_port, "%d", vap_info->u.bss_info.security.u.radius.port);
		strcpy(cfg->radius_server_key, vap_info->u.bss_info.security.u.radius.key);
		addr.s_addr = vap_info->u.bss_info.security.u.radius.s_ip.u.IPv4addr;
		strcpy(cfg->secondary_radius_server_ip, inet_ntoa(addr));
		sprintf(cfg->secondary_radius_server_port, "%d", vap_info->u.bss_info.security.u.radius.s_port);
		strcpy(cfg->secondary_radius_server_key, vap_info->u.bss_info.security.u.radius.s_key);
	}

	if (update == true) {
		where = onewifi_ovsdb_tran_cond(OCLM_UUID, "_uuid", OFUNC_EQ, cfg->_uuid.uuid);
    	ret = onewifi_ovsdb_table_update_where(ovsdb->ovsdb_sock_path, &table_Wifi_Security_Config, where, cfg);
		if (ret == -1) {
			printf("%s:%d: failed to update to table_Wifi_Security_Config table\n", 
				__func__, __LINE__);
			return -1;
		} else if (ret == 0) {
			printf("%s:%d: nothing to update to table_Wifi_Security_Config table\n", 
				__func__, __LINE__);
		} else {
			printf("%s:%d: update to table_Wifi_Security_Config table successful\n", 
				__func__, __LINE__);
		}

	} else {
    	if (onewifi_ovsdb_table_insert(ovsdb->ovsdb_sock_path, &table_Wifi_Security_Config, cfg) 
				== false) {
			printf("%s:%d: failed to insert in table_Wifi_Security_Config table\n", 
				__func__, __LINE__);
			return -1;
		} else {
			printf("%s:%d: insert in table_Wifi_Security_Config table successful\n", 
				__func__, __LINE__);
		}
	}
#endif
	return 0;
}
	
int update_wifi_ovsdb_mac_filter(wifi_ovsdb_t *ovsdb, wifi_vap_info_t *vap_info, hash_map_t *mac_filter_map)
{
#if 0
	int ret;
	unsigned int count;
    struct schema_Wifi_Device_Config cfg;
	mac_filter_data_t *filter_data, *tmp;
	json_t *where;

	// remove all filters from the table and insert
	where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_info->vap_name);
	ret = onewifi_ovsdb_table_delete_where(ovsdb->ovsdb_sock_path, &table_Wifi_Device_Config, where);
	if (ret == -1) {
		printf("%s:%d: failed to delete from table_Wifi_Device_Config table\n", 
			__func__, __LINE__);
		return -1;
	} else if (ret == 0) {
		printf("%s:%d: nothing to delete from table_Wifi_Device_Config table\n", 
			__func__, __LINE__);
	} else {
		printf("%s:%d: delete from table_Wifi_Device_Config table successful\n", 
			__func__, __LINE__);
	}

	filter_data = hash_map_get_first(mac_filter_map);
	while (filter_data != NULL) {
		strcpy(cfg.vap_name, vap_info->vap_name);
		strcpy(cfg.device_name, filter_data->dev_name);
		strcpy(cfg.device_mac, filter_data->mac);
    	if (onewifi_ovsdb_table_insert(ovsdb->ovsdb_sock_path, &table_Wifi_Device_Config, &cfg) == false) {
			printf("%s:%d: failed to insert in table_Wifi_Device_Config table\n", 
				__func__, __LINE__);
			return -1;
		} else {
			printf("%s:%d: insert in table_Wifi_Device_Config table successful\n", 
				__func__, __LINE__);
		}
		tmp = filter_data;
		filter_data = hash_map_get_next(mac_filter_map, filter_data);
		free(tmp);
	}
	where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_info->vap_name);
    onewifi_ovsdb_table_select_where(ovsdb->ovsdb_sock_path, &table_Wifi_Device_Config, where, &count);
	printf("%s:%d: mac filter count in table_Wifi_Device_Config table:%d \n", 
		__func__, __LINE__, count);
#endif
	return 0;
}

int update_wifi_ovsdb_vap(wifi_ovsdb_t *ovsdb, wifi_vap_info_t *vap_info, hash_map_t *mac_filter_map)
{
#if 0
    struct schema_Wifi_Security_Config cfg_sec;
    struct schema_Wifi_VAP_Config cfg, *pcfg;
    json_t *where;
	bool update = false;
	unsigned int count;
	int ret;

	where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_info->vap_name);
    pcfg = onewifi_ovsdb_table_select_where(ovsdb->ovsdb_sock_path, &table_Wifi_VAP_Config, where, &count);
	if ((count != 0) && (pcfg != NULL)) {
		assert(count == 1);
		memcpy(&cfg, pcfg, sizeof(struct schema_Wifi_VAP_Config));
		update = true;
		free(pcfg);
	}
	printf("%s:%d: Found %d records with key: %s in Wifi VAP table\n", 
    	__func__, __LINE__, count, vap_info->vap_name);

	memcpy(&cfg_sec._uuid, &cfg.Security, sizeof(cfg.Security));

	if (update_wifi_ovsdb_security(ovsdb, vap_info, &cfg_sec, update) != 0) {
		printf("%s:%d: Update to VAP table failed because security can not be updated\n",
			__func__, __LINE__);
		return -1;
	}

	update_wifi_ovsdb_mac_filter(ovsdb, vap_info, mac_filter_map);

	strcpy(cfg.vap_name, vap_info->vap_name);	
	strcpy(cfg.ssid, vap_info->u.bss_info.ssid);
	cfg.enabled = (vap_info->u.bss_info.enabled == true)?true:false;;
	cfg.SSIDAdvertisementEnabled = vap_info->u.bss_info.showSsid;
	cfg.isolation_enabled = (vap_info->u.bss_info.isolation == true)?true:false;
	cfg.MacFilterEnable = vap_info->u.bss_info.mac_filter_enable;
	if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
		strcpy(cfg.MacFilterMode, "BlackList");
	} else {
		strcpy(cfg.MacFilterMode, "WhiteList");
	}

	memcpy(&cfg.Security, &cfg_sec._uuid, sizeof(cfg_sec._uuid));

	if (update == true) {
		where = onewifi_ovsdb_tran_cond(OCLM_STR, "vap_name", OFUNC_EQ, vap_info->vap_name);
    	ret = onewifi_ovsdb_table_update_where(ovsdb->ovsdb_sock_path, &table_Wifi_VAP_Config, where, &cfg);
		if (ret == -1) {
			printf("%s:%d: failed to update to table_Wifi_VAP_Config table\n", 
				__func__, __LINE__);
			return -1;
		} else if (ret == 0) {
			printf("%s:%d: nothing to update to table_Wifi_VAP_Config table\n", 
				__func__, __LINE__);
		} else {
			printf("%s:%d: update to table_Wifi_VAP_Config table successful\n", 
				__func__, __LINE__);
		}

	} else {
    	if (onewifi_ovsdb_table_insert(ovsdb->ovsdb_sock_path, &table_Wifi_VAP_Config, &cfg) == false) {
			printf("%s:%d: failed to insert in table_Wifi_VAP_Config table\n", 
				__func__, __LINE__);
			return -1;
		} else {
			printf("%s:%d: insert in table_Wifi_VAP_Config table successful\n", 
				__func__, __LINE__);
		}
	}
#endif
	return 0;
}

int update_wifi_ovsdb_vap_map(wifi_ovsdb_t *ovsdb, wifi_vap_info_map_t *vap_map, hash_map_t **mac_filter_maps)
{
#if 0
	wifi_vap_info_t *vap_info;
    unsigned int i;


	for (i = 0; i < vap_map->num_vaps; i++) {
		vap_info = &vap_map->vap_array[i];

		printf("%s:%d:updating ovsdb of vap:%s\n", __func__, __LINE__, vap_info->vap_name);
		if (update_wifi_ovsdb_vap(ovsdb, vap_info, mac_filter_maps[vap_info->vap_index]) != 0) {
			return -1;
		}		
	}
#endif
    return 0;
}

void *evloop_func(void *arg)
{
	wifi_ovsdb_t *ovsdb = (wifi_ovsdb_t *)arg;

	prctl(PR_SET_NAME,  __func__, 0, 0, 0);

	ev_run(ovsdb->ovs_ev_loop, 0);
	return NULL;
}

int init_ovsdb_tables(wifi_ovsdb_t *ovsdb)
{
#if 0
    unsigned int attempts = 0;

    ovsdb->ovs_ev_loop = ev_loop_new(0);
    if (!ovsdb->ovs_ev_loop) {
        printf("%s:%d: Could not find default target_loop\n", __func__, __LINE__);
        return -1;
    }

	pthread_create(&ovsdb->evloop_thr_id, NULL, evloop_func, ovsdb);
    if (onewifi_ovsdb_init_loop(ovsdb->ovsdb_fd, &ovsdb->wovsdb, ovsdb->ovs_ev_loop) == false) {
        printf("%s:%d: Could not find default target_loop\n", __func__, __LINE__);
        return -1;

    }

	ONEWIFI_OVSDB_TABLE_INIT(Wifi_Device_Config, device_mac);
	ONEWIFI_OVSDB_TABLE_INIT_NO_KEY(Wifi_Security_Config);
	ONEWIFI_OVSDB_TABLE_INIT(Wifi_VAP_Config, vap_name);
	ONEWIFI_OVSDB_TABLE_INIT_NO_KEY(Wifi_Config);

    snprintf(ovsdb->ovsdb_sock_path, sizeof(ovsdb->ovsdb_sock_path), "%s/ovs.ctl", ovsdb->ovsdb_run_dir);

    while (attempts < 3) {
        if ((ovsdb->ovsdb_fd = onewifi_ovsdb_conn(ovsdb->ovsdb_sock_path)) < 0) {
            printf("%s:%d:Failed to connect to ovsdb at %s\n",
                __func__, __LINE__, ovsdb->ovsdb_sock_path);
            attempts++;
            sleep(1);
            if (attempts == 3) {
                return -1;
            }
        } else {
            break;
        }
    }


    printf("%s:%d:Connection to ovsdb at %s successful\n",
            __func__, __LINE__, ovsdb->ovsdb_sock_path);

	ONEWIFI_OVSDB_TABLE_MONITOR(ovsdb->ovsdb_fd, Wifi_Device_Config, true);
	ONEWIFI_OVSDB_TABLE_MONITOR(ovsdb->ovsdb_fd, Wifi_Security_Config, true);
	ONEWIFI_OVSDB_TABLE_MONITOR(ovsdb->ovsdb_fd, Wifi_VAP_Config, true);
	ONEWIFI_OVSDB_TABLE_MONITOR(ovsdb->ovsdb_fd, Wifi_Config, true);
#endif
	return 0;
}

void *start_ovsdb_func(void *arg)
{
    char cmd[1024];
	char db_file[128];
	struct stat sb;
	wifi_ovsdb_t *ovsdb = (wifi_ovsdb_t *)arg;

	prctl(PR_SET_NAME,  __func__, 0, 0, 0);

	sprintf(db_file, "%s/rdkb.db", ovsdb->ovsdb_run_dir);	
	if (stat(db_file, &sb) != 0) {
		printf("%s:%d: Could not find rdkb database, ..creating\n", __func__, __LINE__);

    	sprintf(cmd, "%s/ovsdb-tool create %s %s/rdkb.ovsschema", ovsdb->ovsdb_bin_dir, db_file, ovsdb->ovsdb_schema_dir);
        printf("%s\n", cmd);
    	system(cmd);
	} else {
		printf("%s:%d: rdkb database already present\n", __func__, __LINE__);
	}
    
    sprintf(cmd, "%s/ovsdb-server %s/rdkb.db --remote punix:%s/ovs.ctl %s --unixctl=%s/ovsdb.sock", ovsdb->ovsdb_bin_dir, ovsdb->ovsdb_run_dir, ovsdb->ovsdb_run_dir, (ovsdb->debug == true)?"--verbose=dbg":"", ovsdb->ovsdb_run_dir);
    
    system(cmd); 
    
    return NULL;
}

int start_ovsdb(wifi_ovsdb_t *ovsdb)
{
    char curwd[128], *tmp;

    getcwd(curwd, sizeof(curwd));
    strcpy(ovsdb->ovsdb_bin_dir, curwd);

    tmp = strstr(curwd, "/bin");
    if (tmp != NULL) {
        *tmp = 0;
    }
    sprintf(ovsdb->ovsdb_run_dir, "%s/config/nvram", curwd);
    sprintf(ovsdb->ovsdb_schema_dir, "%s/config/schema", curwd);

	if (pthread_create(&ovsdb->ovsdb_thr_id, NULL, start_ovsdb_func, ovsdb) != 0) {
		printf("%s:%d:ssp_main create failed\n", __func__, __LINE__);
		return -1;
	}

	printf("%s:%d:ovsdb thread started, \nrun_dir:%s \nbin_dir:%s \nschema_dir:%s\n", __func__, __LINE__,
        ovsdb->ovsdb_run_dir, ovsdb->ovsdb_bin_dir, ovsdb->ovsdb_schema_dir);
	
    return 0;
}

int del_record(const char *rec_name)
{
#ifndef FEATURE_ONE_WIFI
	//PSM_Del_Record(bus_handle, g_Subsystem, rec_name);
#endif

	return 0;
}

int set_record_value(const char *rec_name, enum dataType_e rec_type, unsigned char *value)
{
	int ret = 0;

#ifndef FEATURE_ONE_WIFI

	//ret = PSM_Set_Record_Value2(bus_handle, g_Subsystem, rec_name, ccsp_string, value);
#endif
	return (ret == CCSP_SUCCESS) ? 0:-1;
}

int get_record_value(const char *rec_name, enum dataType_e rec_type, unsigned char *value, unsigned int len)
{
#if 0
	int ret = 0;
#ifndef FEATURE_ONE_WIFI
	char *str_val = NULL;

	switch (rec_type) {
		case ccsp_int:
		case ccsp_unsignedInt:
			if (len < sizeof(int)) {
				return -1;
			}
			break;

		default:
			break;
	}

	ret = PSM_Get_Record_Value2(bus_handle, g_Subsystem, rec_name, NULL, &str_val);
	if (ret != CCSP_SUCCESS) {
		return -1;
	}

	if ((str_val == NULL) || (strlen(str_val) == 0)) {
		return -1;
	}

	if (len < strlen(str_val)) {
		return -1;
	}

	switch (rec_type) {
		case ccsp_string:
			strcpy((char *)value, str_val);
			break;

		case ccsp_int:
			break;

		default:
			break;
	}

	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(str_val);
#endif
#endif
	return 0;
}

int device_config_update_test(wifi_ovsdb_t *ovsdb)
{
#if 0
    struct schema_Wifi_Device_Config cfg;
    int ret;

    memset(&cfg, 0, sizeof(cfg));

	strcpy(cfg.vap_name, "private_ssid_2g");
	strcpy(cfg.device_name, "test_dev");
	strcpy(cfg.device_mac, "00:11:22:33:44:55");

    ret = onewifi_ovsdb_table_upsert_simple(ovsdb->ovsdb_sock_path, &table_Wifi_Device_Config,
                                   SCHEMA_COLUMN(Wifi_Device_Config, device_mac),
                                   cfg.device_mac,
                                   &cfg,
                                   NULL);
    if (!ret) {
        printf("%s:%d:Insert new row failed for %s", __func__, __LINE__, cfg.vap_name);
	}
#endif
	return 0;
}

int vap_config_update_test(wifi_ovsdb_t *ovsdb)
{
#if 0
    struct schema_Wifi_VAP_Config cfg;
    int ret;

    memset(&cfg, 0, sizeof(cfg));

	strcpy(cfg.vap_name, "private_ssid_2g");
	strcpy(cfg.ssid, "sams_home_2g");

    ret = onewifi_ovsdb_table_upsert_simple(ovsdb->ovsdb_sock_path, &table_Wifi_VAP_Config,
                                   SCHEMA_COLUMN(Wifi_VAP_Config, vap_name),
                                   cfg.vap_name,
                                   &cfg,
                                   NULL);
    if (!ret) {
        printf("%s:%d:Insert new row failed for %s", __func__, __LINE__, cfg.vap_name);
	}

    return ret;
#endif
    return 0;
}
