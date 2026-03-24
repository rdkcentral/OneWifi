/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

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
#include <string.h>
#include <stdlib.h>
#include "bus.h"
#include "wifi_data_model.h"
#include "wifi_dml_api.h"
#include "wfa_data_model.h"
#include "wfa_dml_cb.h"
#include "wifi_ctrl.h"
#include "dml_onewifi_api.h"

wfa_dml_data_model_t g_wfa_dml_data_model;

wfa_dml_data_model_t *get_wfa_dml_data_model_param(void)
{
    return &g_wfa_dml_data_model;
}

bus_error_t wfa_elem_num_of_table_row(char *event_name, uint32_t *table_row_size)
{
    if (!strncmp(event_name, DE_DEVICE_TABLE, strlen(DE_DEVICE_TABLE) + 1)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: WFA DataElements table [%s], using default size\n", __func__, __LINE__, event_name);
        *table_row_size = 1;
    } else if (strstr(event_name, DE_SSID_TABLE) != NULL) {
        *table_row_size = getTotalNumberVAPs();
    } else {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Table is not found for [%s]\n", __func__, __LINE__, event_name);
        return bus_error_invalid_input;
    }
    return bus_error_success;
}

static bus_error_t wfa_network_get(char *event_name, raw_data_t *p_data,struct bus_user_data * user_data )
{
    char     extension[64]    = {0};
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    
    sscanf(event_name, DATAELEMS_NETWORK_OBJ ".%s", extension);

    wifi_util_info_print(WIFI_DMCLI,"%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name, extension);

    bus_error_t status = wfa_network_get_param_value(pcfg, extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wifi param get failed for:[%s][%s]\r\n", __func__, __LINE__, event_name, extension);
    }

    return status;
}

static bus_error_t wfa_network_ssid_get(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
{
    bus_error_t status = bus_error_invalid_input;
    uint32_t index = 0;
    char     extension[64]    = {0};

    sscanf(event_name, DATAELEMS_NETWORK "SSID.%d.%s", &index, extension);
    wifi_util_info_print(WIFI_DMCLI,"%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name, extension);

    wifi_vap_info_t *vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return status;
    }

    if ((status = wfa_network_ssid_get_param_value(vap_param, extension, p_data)) != bus_error_success)
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wifi param get failed for:[%s][%s]\r\n", __func__, __LINE__, event_name, extension);

    return status;
}

static bus_error_t wfa_apmld_get(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
{
    bus_error_t status = bus_error_invalid_input;
    uint32_t device_index = 0;
    uint32_t index = 0;
    char     extension[64]    = {0};

    (void) device_index;
    sscanf(event_name, DATAELEMS_NETWORK "Device.%d.APMLD.%d.%s", &device_index, &index, extension);
    wifi_util_info_print(WIFI_DMCLI,"%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name, extension);

    mld_group_t *mld_grp = get_dml_apmld_group(index - 1);
    if (mld_grp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wrong MLDAP index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return status;
    }

    if ((status = wfa_apmld_get_param_value(mld_grp, extension, p_data)) != bus_error_success)
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wifi param get failed for:[%s][%s]\r\n", __func__, __LINE__, event_name, extension);

    return status;
}

bus_error_t de_ssid_table_add_row_handler(char const* tableName, char const* aliasName, uint32_t* instNum)
{
    (void)instNum;
    (void)aliasName;
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter\r\n", __func__, __LINE__);
    p_dml_param->table_de_ssid_index++;
    *instNum = p_dml_param->table_de_ssid_index;
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Added table:%s table_de_ssid_index:%d-%d\r\n", __func__,
        __LINE__, tableName, p_dml_param->table_de_ssid_index, *instNum);
    return bus_error_success;
}

bus_error_t de_ssid_table_remove_row_handler(char const* rowName)
{
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();
    (void)p_dml_param;
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    return bus_error_success;
}

bus_error_t de_device_table_add_row_handler(char const* tableName, char const* aliasName, uint32_t* instNum)
{
    (void)instNum;
    (void)aliasName;
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter\r\n", __func__, __LINE__);
    p_dml_param->table_de_device_index++;
    *instNum = p_dml_param->table_de_device_index;
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Added table:%s table_de_device_index:%d-%d\r\n", __func__,
        __LINE__, tableName, p_dml_param->table_de_device_index, *instNum);
    return bus_error_success;
}

bus_error_t de_device_table_remove_row_handler(char const* rowName)
{
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    p_dml_param->table_de_device_index--;
    return bus_error_success;
}

bus_error_t de_apmld_table_add_row_handler(char const* tableName, char const* aliasName, uint32_t* instNum)
{
    (void)instNum;
    (void)aliasName;
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter %d\r\n", __func__, __LINE__, *instNum);
    p_dml_param->table_de_apmld_index++;
    *instNum = p_dml_param->table_de_apmld_index;
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Added table:%s table_de_ssid_index:%d-%d\r\n", __func__,
        __LINE__, tableName, *instNum, *instNum);
    return bus_error_success;
}

bus_error_t de_apmld_table_remove_row_handler(char const* rowName)
{
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();
    if(p_dml_param->table_de_apmld_index > 0)
        p_dml_param->table_de_apmld_index--;
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    return bus_error_success;
}

static void de_sync_rows(char const* tableName, uint32_t old_cnt, uint32_t new_cnt, uint32_t *index, bool force)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_bus_desc_t *p_bus_desc = get_bus_descriptor();

    if (!force && (old_cnt == new_cnt))
        return;

    char *rowPath = malloc(strlen(tableName) + 5);
    for (UINT i = 1; i <= old_cnt; i++) {
        sprintf(rowPath, "%s.%d.", tableName, i);
        if (p_bus_desc->bus_unreg_table_row_fn(&ctrl->handle, rowPath) != bus_error_success) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d remove %s failed\r\n", __func__, __LINE__, rowPath);
        } else if (index) {
            (*index)--;
        }
    }
    sprintf(rowPath, "%s.", tableName);
    for (UINT i = 1; i <= new_cnt; i++) {
        if (p_bus_desc->bus_reg_table_row_fn(&ctrl->handle, rowPath, i, NULL) != bus_error_success) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d add %s row failed\r\n", __func__, __LINE__, rowPath);
        } else if (index) {
            (*index)++;
        }
    }
    free(rowPath);
}

bus_error_t de_apmld_sync_handler(char const* tableName, raw_data_t *inParams, raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();

    update_apmld_map();
    UINT num_apmld = get_num_apmld_dml();
    UINT num_row = p_dml_param->table_de_apmld_index;
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter %s, numrow %d, numapmld %d\r\n", __func__, __LINE__, tableName, num_row, num_apmld);

    de_sync_rows(tableName, num_row, num_apmld, &p_dml_param->table_de_apmld_index, false);
    return bus_error_success;
}

bus_error_t de_affap_sync_handler(char const* tableName, raw_data_t *inParams, raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    uint32_t device_index = 0;
    uint32_t index = 0;
    char     extension[64]    = {0};

    sscanf(tableName, DATAELEMS_NETWORK "Device.%d.APMLD.%d.%s", &device_index, &index, extension);
    mld_group_t *mld_grp = get_dml_apmld_group(index - 1);
    if (mld_grp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wrong MLDAP index:%d for:[%s]\r\n", __func__,
            __LINE__, index, tableName);
        return bus_error_invalid_input;
    }

    de_sync_rows(tableName, mld_grp->mld_vap_count, mld_grp->mld_vap_count, NULL, true);
    return bus_error_success;
}

static bus_error_t de_stamld_get(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
{
    bus_error_t status = bus_error_invalid_input;
    uint32_t device_index = 0;
    uint32_t apmld_index = 0;
    uint32_t stamld_index = 0;
    char extension[64] = {0};

    (void)user_data;

    sscanf(event_name, DATAELEMS_NETWORK "Device.%d.APMLD.%d.STAMLD.%d.%s", 
           &device_index, &apmld_index, &stamld_index, extension);
    wifi_util_info_print(WIFI_DMCLI,"%s:%d get event:[%s] apmld:%d stamld:%d ext:[%s]\n", 
                         __func__, __LINE__, event_name, apmld_index, stamld_index, extension);

    stamld_data_t *stamld_entry = get_stamld_entry(apmld_index - 1, stamld_index - 1);
    if (stamld_entry == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wrong STAMLD entry index:%d for:[%s]\r\n", __func__,
            __LINE__, stamld_index, event_name);
        return status;
    }

    if ((status = wfa_stamld_get_param_value(stamld_entry, extension, p_data)) != bus_error_success)
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wifi param get failed for:[%s][%s]\r\n", __func__, __LINE__, event_name, extension);

    return status;
}

bus_error_t de_stamld_sync_handler(char const* tableName, raw_data_t *inParams, raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    uint32_t device_index = 0;
    uint8_t apmld_index = 0;
    wfa_dml_data_model_t *p_dml_param = get_wfa_dml_data_model_param();

    sscanf(tableName, DATAELEMS_NETWORK "Device.%d.APMLD.%hhd.STAMLD", &device_index, &apmld_index);

    if (apmld_index < 1 || apmld_index > MLD_UNIT_COUNT) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid APMLD index:%d\r\n", __func__, __LINE__, apmld_index);
        return bus_error_invalid_input;
    }
    uint32_t apmld_array_index = apmld_index - 1;

    update_dml_stamld_list(apmld_array_index);

    UINT num_stamld = get_total_num_stamld_dml(apmld_array_index);
    UINT num_row = p_dml_param->table_de_stamld_index[apmld_array_index];
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter %s, apmld_idx:%d, numrow:%d, numstamld:%d\r\n", 
                        __func__, __LINE__, tableName, apmld_index, num_row, num_stamld);

    de_sync_rows(tableName, num_row, num_stamld, &(p_dml_param->table_de_stamld_index[apmld_array_index]), false);
    return bus_error_success;
}

static bus_error_t de_affsta_get(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data)
{
    bus_error_t status = bus_error_invalid_input;
    uint32_t device_index = 0;
    uint32_t apmld_index = 0;
    uint32_t stamld_index = 0;
    uint32_t affiliated_sta_index = 0;
    char extension[64] = {0};
    int sscanf_result = 0;

    (void)user_data;
    (void)device_index;
    
    sscanf_result = sscanf(event_name, DATAELEMS_NETWORK "Device.%d.APMLD.%d.STAMLD.%d.AffiliatedSTA.%d.%s", 
           &device_index, &apmld_index, &stamld_index, &affiliated_sta_index, extension);
    
    if (sscanf_result < 4) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d sscanf parse failed, result:%d for:[%s]\r\n", __func__,
            __LINE__, sscanf_result, event_name);
        return status;
    }
    
    wifi_util_info_print(WIFI_DMCLI,"%s:%d get event:[%s] apmld:%d stamld:%d affsta:%d ext:[%s]\n", 
                         __func__, __LINE__, event_name, apmld_index, stamld_index, affiliated_sta_index, extension);

    assoc_dev_data_t *assoc_dev = get_dml_apmld_stamld_affiliated_sta(apmld_index - 1, stamld_index - 1, affiliated_sta_index - 1);
    if (assoc_dev == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d no AffiliatedSTA device at index:%d for:[%s]\r\n", __func__,
            __LINE__, affiliated_sta_index, event_name);
        return status;
    }

    if ((status = wfa_affiliatedsta_get_param_value(assoc_dev, extension, p_data)) != bus_error_success)
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wifi param get failed for:[%s][%s]\r\n", __func__, __LINE__, event_name, extension);

    return status;
}

bus_error_t de_affsta_sync_handler(char const* tableName, raw_data_t *inParams, raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;

    uint32_t device_index = 0;
    uint8_t apmld_index = 0;
    uint32_t stamld_index = 0;
    sscanf(tableName, DATAELEMS_NETWORK "Device.%d.APMLD.%hhd.STAMLD.%d.AffiliatedSTA", &device_index, &apmld_index, &stamld_index);

    if (apmld_index < 1 || apmld_index > MLD_UNIT_COUNT) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid APMLD index:%d\r\n", __func__, __LINE__, apmld_index);
        return bus_error_invalid_input;
    }

    stamld_data_t *stamld_entry = get_stamld_entry(apmld_index - 1, stamld_index - 1);
    if (stamld_entry == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Failed to get STAMLD entry at apmld:%d stamld:%d\r\n", __func__, __LINE__, apmld_index, stamld_index);
        return bus_error_invalid_input;
    }

    UINT num_affsta = stamld_entry->affiliated_sta_count;
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d enter %s, apmld_idx:%d, stamld_idx:%d, numaffsta:%d\r\n", 
                        __func__, __LINE__, tableName, apmld_index, stamld_index, num_affsta);

    de_sync_rows(tableName, MAX_NUM_RADIOS, num_affsta, NULL, true);
    return bus_error_success;
}

/* WFA DataElements callback function pointer mapping */
int wfa_set_bus_callbackfunc_pointers(const char *full_namespace, bus_callback_table_t *cb_table)
{
    static const bus_data_cb_func_t bus_wfa_data_cb[] = {
        /* TR-181 Path
            get                             set
            add_row                         rm_row
            event_sub                       method / sync for tables */

        /* Device.WiFi.DataElements.Network */
        { DATAELEMS_NETWORK_OBJ, {
            wfa_network_get,                 NULL,
            NULL,                            NULL,
            NULL,                            NULL }
        },

        /* Device.WiFi.DataElements.Network.Device.{i} */
        { DE_DEVICE_TABLE, {
            default_get_param_value,         default_set_param_value,
            de_device_table_add_row_handler, de_device_table_remove_row_handler,
            default_event_sub_handler,       NULL }
        },

        /* Device.WiFi.DataElements.Network.SSID.{i} */
        { DE_SSID_TABLE, {
            wfa_network_ssid_get,            default_set_param_value,
            de_ssid_table_add_row_handler,   de_ssid_table_remove_row_handler,
            default_event_sub_handler,       NULL }
        },

        /* Device.WiFi.DataElements.Network.Device.{i}.APMLD */
        { DE_APMLD_TABLE, {
            wfa_apmld_get,                   default_set_param_value,
            de_apmld_table_add_row_handler,  de_apmld_table_remove_row_handler,
            default_event_sub_handler,       de_apmld_sync_handler }
        },

        /* Device.WiFi.DataElements.Network.Device.{i}.APMLD.{i}.APMLDConfig */
        { DE_APMLD_CONFIG, {
            wfa_apmld_get,                   default_set_param_value,
            NULL,                            NULL,
            NULL,                            NULL }
        },

        /* Device.WiFi.DataElements.Network.Device.{i}.APMLD.{i}.AffiliatedAP */
        { DE_AFFAP_TABLE, {
            wfa_apmld_get,                   default_set_param_value,
            NULL,                            NULL,
            NULL,                            de_affap_sync_handler }
        },

        /* Device.WiFi.DataElements.Network.Device.{i}.APMLD.{i}.STAMLD */
        { DE_STAMLD_TABLE, {
            de_stamld_get,                   NULL,
            NULL,                            NULL,
            NULL,                            de_stamld_sync_handler }
        },

        /* Device.WiFi.DataElements.Network.Device.{i}.APMLD.{i}.STAMLD.WiFi7Capabilities */
        { DE_STAMLD_WIFI7CAPS, {
            default_get_param_value,            default_set_param_value,
            NULL,                            NULL,
            default_event_sub_handler,       NULL }
        },

        /* Device.WiFi.DataElements.Network.Device.{i}.APMLD.{i}.STAMLD.STAMLDConfig */
        { DE_STAMLD_CONFIG, {
            default_get_param_value,            default_set_param_value,
            NULL,                            NULL,
            default_event_sub_handler,       NULL }
        },

        /* Device.WiFi.DataElements.Network.Device.{i}.APMLD.{i}.STAMLD.{i}.AffiliatedSTA */
        { DE_AFFSTA_TABLE, {
            de_affsta_get,                   NULL,
            NULL,                            NULL,
            NULL,                            de_affsta_sync_handler }
        },
    };

    return set_bus_callbackfunc_pointers(full_namespace, cb_table, bus_wfa_data_cb, ARRAY_SZ(bus_wfa_data_cb));
}
