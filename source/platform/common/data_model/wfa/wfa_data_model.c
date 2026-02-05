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
    dml_callback_table_t dml_data_cb = {
        NULL, NULL, wfa_network_get_param_uint_value, wfa_network_get_param_string_value,
        NULL, NULL, NULL, NULL
    };
    
    sscanf(event_name, DATAELEMS_NETWORK_OBJ ".%s", extension);

    wifi_util_info_print(WIFI_DMCLI,"%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name, extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)pcfg, extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wifi param get failed for:[%s][%s]\r\n", __func__, __LINE__, event_name, extension);
    }

    return status;
}

static bus_error_t wfa_network_ssid_get(char *event_name, raw_data_t *p_data, struct bus_user_data * user_data )
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
    };

    return set_bus_callbackfunc_pointers(full_namespace, cb_table, bus_wfa_data_cb, ARRAY_SZ(bus_wfa_data_cb));
}
