/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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
#include "wifi_data_model.h"
#include "bus.h"
#include "wifi_data_model_parse.h"
#include "wifi_dml_api.h"
#include "wifi_dml_cb.h"
#include "wifi_mgr.h"
#include "wifi_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

wifi_dml_data_model_t g_dml_data_model;

wifi_dml_data_model_t *get_dml_data_model_param(void)
{
    return &g_dml_data_model;
}

bus_error_t wifi_elem_num_of_table_row(char *event_name, uint32_t *table_row_size)
{
    if (!strncmp(event_name, RADIO_OBJ_TREE_NAME, strlen(RADIO_OBJ_TREE_NAME) + 1)) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Number of radio:%d\n", __func__, __LINE__,
            getNumberRadios());
        *table_row_size = getNumberRadios();
    } else if (!strncmp(event_name, ACCESSPOINT_OBJ_TREE_NAME,
                   strlen(ACCESSPOINT_OBJ_TREE_NAME) + 1)) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Total number of vaps:%d getTotalNumberVAPs():%d\n",
            __func__, __LINE__, getNumberRadios() * MAX_NUM_VAP_PER_RADIO, getTotalNumberVAPs());
        *table_row_size = getTotalNumberVAPs();
    } else if (!strncmp(event_name, SSID_OBJ_TREE_NAME, strlen(SSID_OBJ_TREE_NAME) + 1)) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Total number of vaps:%d get total num vap dml:%d\n",
            __func__, __LINE__, getNumberRadios() * MAX_NUM_VAP_PER_RADIO, getTotalNumberVAPs());
        *table_row_size = getTotalNumberVAPs();
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d Table is not found for [%s]\n", __func__, __LINE__,
            event_name);
        return bus_error_invalid_input;
    }

    return bus_error_success;
}

uint32_t convert_vap_index_from_inst(uint32_t vap_instance_cnt)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();
    unsigned int vap_index;

    vap_index = VAP_INDEX(mgr->hal_cap, vap_instance_cnt) + 1;

    return vap_index;
}

bus_error_t dml_get_set_param_value(dml_callback_table_t *p_dml_cb, uint8_t cb_table_type,
    void *obj_ins_context, char *param_name, raw_data_t *p_data)
{
    bus_error_t status = bus_error_success;

    DM_CHECK_NULL_WITH_RC(obj_ins_context, bus_error_invalid_input);
    DM_CHECK_NULL_WITH_RC(param_name, bus_error_invalid_input);
    DM_CHECK_NULL_WITH_RC(p_data, bus_error_invalid_input);
    DM_CHECK_NULL_WITH_RC(p_dml_cb, bus_error_invalid_input);

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d [%d] param:%s type:%d\n", __func__, __LINE__,
        cb_table_type, param_name, p_data->data_type);
    switch (p_data->data_type) {
    case bus_data_type_boolean:
        if ((cb_table_type == DML_GET_CB) && (p_dml_cb->get_bool_value != NULL)) {
            if (p_dml_cb->get_bool_value(obj_ins_context, param_name, &p_data->raw_data.b) ==
                false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d get bool param:%d failed for [%s]\n",
                    __func__, __LINE__, p_data->raw_data.b, param_name);
                status = bus_error_invalid_input;
            }
        } else if ((cb_table_type == DML_SET_CB) && (p_dml_cb->set_bool_value != NULL)) {
            if (p_dml_cb->set_bool_value(obj_ins_context, param_name, p_data->raw_data.b) ==
                false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d set bool param:%d failed for [%s]\n",
                    __func__, __LINE__, p_data->raw_data.b, param_name);
                status = bus_error_invalid_input;
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cb is not found:%d for [%s]\n", __func__,
                __LINE__, cb_table_type, param_name);
            status = bus_error_invalid_input;
        }
        break;
    case bus_data_type_int32:
        if ((cb_table_type == DML_GET_CB) && (p_dml_cb->get_int_value != NULL)) {
            if (p_dml_cb->get_int_value(obj_ins_context, param_name, &p_data->raw_data.i32) ==
                false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d get int param:%d failed for [%s]\n",
                    __func__, __LINE__, p_data->raw_data.i32, param_name);
                status = bus_error_invalid_input;
            }
        } else if ((cb_table_type == DML_SET_CB) && (p_dml_cb->set_int_value != NULL)) {
            if (p_dml_cb->set_int_value(obj_ins_context, param_name, p_data->raw_data.i32) ==
                false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d set int param:%d failed for [%s]\n",
                    __func__, __LINE__, p_data->raw_data.i32, param_name);
                status = bus_error_invalid_input;
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cb is not found:%d for [%s]\n", __func__,
                __LINE__, cb_table_type, param_name);
            status = bus_error_invalid_input;
        }
        break;
    case bus_data_type_uint32:
        if ((cb_table_type == DML_GET_CB) && (p_dml_cb->get_uint_value != NULL)) {
            if (p_dml_cb->get_uint_value(obj_ins_context, param_name, &p_data->raw_data.u32) ==
                false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d get uint param:%d failed for [%s]\n",
                    __func__, __LINE__, p_data->raw_data.u32, param_name);
                status = bus_error_invalid_input;
            }
        } else if ((cb_table_type == DML_SET_CB) && (p_dml_cb->set_uint_value != NULL)) {
            if (p_dml_cb->set_uint_value(obj_ins_context, param_name, p_data->raw_data.u32) ==
                false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d set uint param:%d failed for [%s]\n",
                    __func__, __LINE__, p_data->raw_data.u32, param_name);
                status = bus_error_invalid_input;
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cb is not found:%d for [%s]\n", __func__,
                __LINE__, cb_table_type, param_name);
            status = bus_error_invalid_input;
        }
        break;
    case bus_data_type_string:
        scratch_data_buff_t temp_buff = { 0 };
        if ((cb_table_type == DML_GET_CB) && (p_dml_cb->get_string_value != NULL)) {

            if (p_dml_cb->get_string_value(obj_ins_context, param_name, &temp_buff) == false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d get string param:%s:%d failed for [%s]\n",
                    __func__, __LINE__, temp_buff.buff, temp_buff.buff_len, param_name);
                status = bus_error_invalid_input;
            } else {
                p_data->raw_data.bytes = temp_buff.buff;
                p_data->raw_data_len = temp_buff.buff_len;
                p_data->data_type = bus_data_type_string;
            }
        } else if ((cb_table_type == DML_SET_CB) && (p_dml_cb->set_string_value != NULL)) {
            temp_buff.buff = (char *)p_data->raw_data.bytes;
            temp_buff.buff_len = p_data->raw_data_len;
            if (p_dml_cb->set_string_value(obj_ins_context, param_name, &temp_buff) == false) {
                wifi_util_error_print(WIFI_DMCLI, "%s:%d set string param:%s:%d failed for [%s]\n",
                    __func__, __LINE__, p_data->raw_data.bytes, p_data->raw_data_len, param_name);
                status = bus_error_invalid_input;
            }
        } else {
            wifi_util_error_print(WIFI_DMCLI, "%s:%d cb is not found:%d for [%s]\n", __func__,
                __LINE__, cb_table_type, param_name);
            status = bus_error_invalid_input;
        }
        break;
    case bus_data_type_none:
        wifi_util_error_print(WIFI_DMCLI, "%s:%d unsupported param failed for [%s]\n", __func__,
            __LINE__, param_name);
        status = bus_error_invalid_input;
        break;
    default:
        wifi_util_error_print(WIFI_DMCLI, "%s:%d unsupported param:%x failed for [%s]\n", __func__,
            __LINE__, p_data->data_type, param_name);
        status = bus_error_invalid_input;
        break;
    }

    return status;
}

bus_error_t wifi_get_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_wifidb_wifi_global_param();
    dml_callback_table_t dml_data_cb = { wifi_get_param_bool_value, wifi_get_param_int_value,
        wifi_get_param_uint_value, wifi_get_param_string_value, wifi_set_param_bool_value,
        wifi_set_param_int_value, wifi_set_param_uint_value, wifi_set_param_string_value };

    sscanf(event_name, "Device.WiFi.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wifi param get failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t wifi_set_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_wifidb_wifi_global_param();
    dml_callback_table_t dml_data_cb = { wifi_get_param_bool_value, wifi_get_param_int_value,
        wifi_get_param_uint_value, wifi_get_param_string_value, wifi_set_param_bool_value,
        wifi_set_param_int_value, wifi_set_param_uint_value, wifi_set_param_string_value };

    sscanf(event_name, "Device.WiFi.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wifi param set failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t wifi_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval,
    bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t neig_wifi_diag_get_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_wifidb_wifi_global_param();
    dml_callback_table_t dml_data_cb = { neig_wifi_diag_get_param_bool_value,
        neig_wifi_diag_get_param_int_value, neig_wifi_diag_get_param_uint_value,
        neig_wifi_diag_get_param_string_value, neig_wifi_diag_set_param_bool_value,
        neig_wifi_diag_set_param_int_value, neig_wifi_diag_set_param_uint_value,
        neig_wifi_diag_set_param_string_value };

    sscanf(event_name, "Device.WiFi.NeighboringWiFiDiagnostic.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d neig wifi diag param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t neig_wifi_diag_set_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_wifidb_wifi_global_param();
    dml_callback_table_t dml_data_cb = { neig_wifi_diag_get_param_bool_value,
        neig_wifi_diag_get_param_int_value, neig_wifi_diag_get_param_uint_value,
        neig_wifi_diag_get_param_string_value, neig_wifi_diag_set_param_bool_value,
        neig_wifi_diag_set_param_int_value, neig_wifi_diag_set_param_uint_value,
        neig_wifi_diag_set_param_string_value };

    sscanf(event_name, "Device.WiFi.NeighboringWiFiDiagnostic.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d neig wifi diag param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t neig_wifi_diag_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

wifi_neighbor_ap2_t *get_neig_diag_result_obj(uint32_t ap_instance)
{
    uint32_t index = 0;
    uint32_t count = 0;
    uint32_t array_index = ap_instance - 1;

    wifi_monitor_t *p_monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    if (p_monitor_param->neighbor_scan_cfg.ResultCount <= 0) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d neig_diag result not valid:%d\r\n", __func__,
            __LINE__, p_monitor_param->neighbor_scan_cfg.ResultCount);
        return NULL;
    }

    for (index = 0; index < (uint32_t)get_num_radio_dml(); index++) {
        if (array_index < (p_monitor_param->neighbor_scan_cfg.resultCountPerRadio[index] + count)) {
            return &p_monitor_param->neighbor_scan_cfg.pResult[index][array_index];
        }
        count += p_monitor_param->neighbor_scan_cfg.resultCountPerRadio[index];
        array_index -= count;
    }

    return NULL;
}

bus_error_t neig_diag_result_get_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    uint32_t index = 0;
    dml_callback_table_t dml_data_cb = { NULL, neig_diag_result_get_param_int_value,
        neig_diag_result_get_param_uint_value, neig_diag_result_get_param_string_value, NULL, NULL,
        NULL, NULL };

    sscanf(event_name, "Device.WiFi.NeighboringWiFiDiagnostic.Result.%d.%s", &index, extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);
    wifi_neighbor_ap2_t *pcfg = get_neig_diag_result_obj(index);
    DM_CHECK_NULL_WITH_RC(pcfg, bus_error_invalid_input);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d neig wifi diag param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t neig_diag_result_table_add_row_cb(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)aliasName;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter\r\n", __func__, __LINE__);
    p_dml_param->table_neig_diag_result_index++;
    *instNum = p_dml_param->table_neig_diag_result_index;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Added table:%s, index:%d\r\n", __func__, __LINE__,
        tableName, *instNum);
    return bus_error_success;
}

bus_error_t neig_diag_result_table_remove_row_cb(char const *rowName)
{
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    p_dml_param->table_neig_diag_result_index--;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s:index:%d\r\n", __func__, __LINE__, rowName,
        p_dml_param->table_neig_diag_result_index);
    return bus_error_success;
}

bus_error_t neig_diag_result_event_sub_cb(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t radio_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_radio_operationParam_t *radio_param;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    dml_callback_table_t dml_data_cb = { radio_get_param_bool_value, radio_get_param_int_value,
        radio_get_param_uint_value, radio_get_param_string_value, radio_set_param_bool_value,
        radio_set_param_int_value, radio_set_param_uint_value, radio_set_param_string_value };

    sscanf(event_name, "Device.WiFi.Radio.%d.%s", &index, extension);
    if (p_dml_param->table_radio_index < index) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong radio get index for:[%s]:%d\r\n", __func__,
            __LINE__, event_name, index);
        return bus_error_invalid_input;
    }
    radio_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index - 1);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d radio enable:%d event:[%s][%s]\n", __func__, __LINE__,
        radio_param->enable, event_name, extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)radio_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d radio param get failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t radio_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_radio_operationParam_t *radio_param;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    dml_callback_table_t dml_data_cb = { radio_get_param_bool_value, radio_get_param_int_value,
        radio_get_param_uint_value, radio_get_param_string_value, radio_set_param_bool_value,
        radio_set_param_int_value, radio_set_param_uint_value, radio_set_param_string_value };

    sscanf(event_name, "Device.WiFi.Radio.%d.%s", &index, extension);
    if (p_dml_param->table_radio_index < index) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong radio set index for:[%s]:%d\r\n", __func__,
            __LINE__, event_name, index);
        return bus_error_invalid_input;
    }
    radio_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index - 1);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d radio enable:%d event:[%s][%s]\n", __func__, __LINE__,
        radio_param->enable, event_name, extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)radio_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d radio param set failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t radio_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)aliasName;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter\r\n", __func__, __LINE__);
    p_dml_param->table_radio_index++;
    *instNum = p_dml_param->table_radio_index;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Added table:%s table_radio_index:%d\r\n", __func__,
        __LINE__, tableName, p_dml_param->table_radio_index);
    return bus_error_success;
}

bus_error_t radio_table_remove_row_handler(char const *rowName)
{
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    p_dml_param->table_radio_index--;
    return bus_error_success;
}

bus_error_t radio_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t accesspoint_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { accesspoint_get_param_bool_value,
        accesspoint_get_param_int_value, accesspoint_get_param_uint_value,
        accesspoint_get_param_string_value, accesspoint_set_param_bool_value,
        accesspoint_set_param_int_value, accesspoint_set_param_uint_value,
        accesspoint_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d AccessPoint get event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d accesspoint param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t accesspoint_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { accesspoint_get_param_bool_value,
        accesspoint_get_param_int_value, accesspoint_get_param_uint_value,
        accesspoint_get_param_string_value, accesspoint_set_param_bool_value,
        accesspoint_set_param_int_value, accesspoint_set_param_uint_value,
        accesspoint_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d AccessPoint set event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d accesspoint param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t accesspoint_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter\r\n", __func__, __LINE__);
    *instNum = convert_vap_index_from_inst(p_dml_param->table_ap_index);
    p_dml_param->table_ap_index++;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Added table:%s table_ap_index:%d-%d\r\n", __func__,
        __LINE__, tableName, p_dml_param->table_ap_index, *instNum);
    return bus_error_success;
}

bus_error_t accesspoint_table_remove_row_handler(char const *rowName)
{
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    p_dml_param->table_ap_index--;
    return bus_error_success;
}

bus_error_t accesspoint_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t security_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { security_get_param_bool_value,
        security_get_param_int_value, security_get_param_uint_value,
        security_get_param_string_value, security_set_param_bool_value,
        security_set_param_int_value, security_set_param_uint_value,
        security_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.Security.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Security Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d security param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t security_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { security_get_param_bool_value,
        security_get_param_int_value, security_get_param_uint_value,
        security_get_param_string_value, security_set_param_bool_value,
        security_set_param_int_value, security_set_param_uint_value,
        security_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.Security.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Security Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d security param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t security_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t ssid_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    dml_callback_table_t dml_data_cb = { ssid_get_param_bool_value, ssid_get_param_int_value,
        ssid_get_param_uint_value, ssid_get_param_string_value, ssid_set_param_bool_value,
        ssid_set_param_int_value, ssid_set_param_uint_value, ssid_set_param_string_value };

    sscanf(event_name, "Device.WiFi.SSID.%d.%s", &index, extension);
    if (p_dml_param->table_ssid_index < index) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong ssid get index for:[%s]:%d\r\n", __func__,
            __LINE__, event_name, index);
        return bus_error_invalid_input;
    }

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d SSID Event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d ssid param get failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t ssid_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    dml_callback_table_t dml_data_cb = { ssid_get_param_bool_value, ssid_get_param_int_value,
        ssid_get_param_uint_value, ssid_get_param_string_value, ssid_set_param_bool_value,
        ssid_set_param_int_value, ssid_set_param_uint_value, ssid_set_param_string_value };

    sscanf(event_name, "Device.WiFi.SSID.%d.%s", &index, extension);
    if (p_dml_param->table_ssid_index < index) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong ssid set index for:[%s]:%d\r\n", __func__,
            __LINE__, event_name, index);
        return bus_error_invalid_input;
    }

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d SSID Event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d ssid param set failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t ssid_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter\r\n", __func__, __LINE__);
    *instNum = convert_vap_index_from_inst(p_dml_param->table_ssid_index);
    p_dml_param->table_ssid_index++;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Added table:%s table_ssid_index:%d-%d\r\n", __func__,
        __LINE__, tableName, p_dml_param->table_ssid_index, *instNum);
    return bus_error_success;
}

bus_error_t ssid_table_remove_row_handler(char const *rowName)
{
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    p_dml_param->table_ssid_index--;
    return bus_error_success;
}

bus_error_t ssid_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval,
    bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t macfilter_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0, acl_index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    bus_error_t status = bus_error_general;
    acl_entry_t *acl_entry;
    dml_callback_table_t dml_data_cb = { macfilter_get_param_bool_value,
        macfilter_get_param_int_value, macfilter_get_param_uint_value,
        macfilter_get_param_string_value, macfilter_set_param_bool_value,
        macfilter_set_param_int_value, macfilter_set_param_uint_value,
        macfilter_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MacFilterTable.%d.%s", &index,
        &acl_index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d vap map not found for:[%s][%d]\r\n", __func__,
            __LINE__, event_name, index);
        return status;
    }

    acl_entry = get_macfilter_entry(vap_param, acl_index - 1);
    if (acl_entry == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d macfilter entry not found index::%d\r\n", __func__,
            __LINE__, acl_index);
        return status;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);
    status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)acl_entry, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d macfilter param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t macfilter_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0, acl_index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    bus_error_t status = bus_error_general;
    acl_entry_t *acl_entry;
    mac_filter_set_param_arg_t l_mac_filter_args;
    dml_callback_table_t dml_data_cb = { macfilter_get_param_bool_value,
        macfilter_get_param_int_value, macfilter_get_param_uint_value,
        macfilter_get_param_string_value, macfilter_set_param_bool_value,
        macfilter_set_param_int_value, macfilter_set_param_uint_value,
        macfilter_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MacFilterTable.%d.%s", &index,
        &acl_index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d vap map not found for:[%s][%d]\r\n", __func__,
            __LINE__, event_name, index);
        return status;
    }

    acl_entry = get_macfilter_entry(vap_param, acl_index - 1);
    if (acl_entry == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d macfilter entry not found index::%d\r\n", __func__,
            __LINE__, acl_index);
        return status;
    }

    l_mac_filter_args.acl_param = acl_entry;
    l_mac_filter_args.vap_info_param = vap_param;
    wifi_util_info_print(WIFI_DMCLI, "%s:%d Event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);
    status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)&l_mac_filter_args,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d macfilter param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t macfilter_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)aliasName;
    wifi_vap_info_t *vap_param;
    int vap_index = 0;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter tableName:%s\r\n", __func__, __LINE__, tableName);
    sscanf(tableName, "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MacFilterTable.", &vap_index);

    vap_param = (wifi_vap_info_t *)getVapInfo(vap_index - 1);
    DM_CHECK_NULL_WITH_RC(vap_param, bus_error_general);

    macfilter_tab_add_entry(vap_param, instNum);
    p_dml_param->table_macfilter_index[vap_param->vap_index]++;

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Added table:%s vap:%d macfilter table index:%d-%d\r\n",
        __func__, __LINE__, tableName, vap_index, *instNum,
        p_dml_param->table_macfilter_index[vap_param->vap_index]);

    return bus_error_success;
}

bus_error_t macfilter_table_remove_row_handler(char const *rowName)
{
    wifi_vap_info_t *vap_param;
    int vap_index = 0, macfilter_entry_index = 0;
    acl_entry_t *acl_entry;
    bus_error_t ret = bus_error_general;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter rowName:%s\r\n", __func__, __LINE__, rowName);
    sscanf(rowName, "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MacFilterTable.%d", &vap_index,
        &macfilter_entry_index);

    vap_param = (wifi_vap_info_t *)getVapInfo(vap_index - 1);
    DM_CHECK_NULL_WITH_RC(vap_param, ret);

    acl_entry = get_macfilter_entry(vap_param, macfilter_entry_index - 1);
    if (acl_entry == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d macfilter entry is not found index:%d\r\n",
            __func__, __LINE__, macfilter_entry_index);
        return ret;
    }

    int status = macfilter_tab_del_entry(vap_param, acl_entry);
    if (status != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d macfilter acl entry del failure for vap:%d index:%d\r\n", __func__, __LINE__,
            vap_index, macfilter_entry_index);
        return ret;
    }
    uint32_t *cur_macfilter_index = &p_dml_param->table_macfilter_index[vap_param->vap_index];

    if (*cur_macfilter_index > 0) {
        if (*cur_macfilter_index == (uint32_t)macfilter_entry_index) {
            (*cur_macfilter_index)--;
        } else {
            sync_dml_macfilter_table(vap_param->vap_index, (char *)rowName);
        }
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d rowName:%s removed for vap_index:%d index:%d\r\n",
        __func__, __LINE__, rowName, vap_index,
        p_dml_param->table_macfilter_index[vap_param->vap_index]);
    return bus_error_success;
}

bus_error_t macfilter_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t associated_sta_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0, sta_index = 0;
    char extension[64] = { 0 };
    bus_error_t status = bus_error_general;
    assoc_dev_data_t *p_assoc_sta_entry;
    dml_callback_table_t dml_data_cb = { associated_sta_get_param_bool_value,
        associated_sta_get_param_int_value, associated_sta_get_param_uint_value,
        associated_sta_get_param_string_value, NULL, NULL, NULL, NULL };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d.%s", &index, &sta_index,
        extension);

    p_assoc_sta_entry = get_sta_assoc_data_map(index, sta_index);
    wifi_util_info_print(WIFI_DMCLI, "%s:%d Event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);
    status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)p_assoc_sta_entry, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d associated sta param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t associated_sta_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter\r\n", __func__, __LINE__);
    uint32_t index;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    wifi_vap_info_t *vap_param;

    sscanf(tableName, "Device.WiFi.AccessPoint.%d.AssociatedDevice.", &index);
    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    DM_CHECK_NULL_WITH_RC(vap_param, bus_error_general);

    p_dml_param->table_sta_assoc_index[vap_param->vap_index]++;
    *instNum = p_dml_param->table_sta_assoc_index[vap_param->vap_index];
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Added table:%s index:%d vap_index:%d\r\n", __func__,
        __LINE__, tableName, *instNum, vap_param->vap_index);
    return bus_error_success;
}

bus_error_t associated_sta_table_remove_row_handler(char const *rowName)
{
    uint32_t index, sta_index;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    wifi_vap_info_t *vap_param;

    sscanf(rowName, "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d", &index, &sta_index);
    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    DM_CHECK_NULL_WITH_RC(vap_param, bus_error_general);

    if (p_dml_param->table_sta_assoc_index[vap_param->vap_index] > 0) {
        p_dml_param->table_sta_assoc_index[vap_param->vap_index]--;
    }
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s vap_index:%d sta_cnt:%d sta_index:%d\r\n",
        __func__, __LINE__, rowName, vap_param->vap_index,
        p_dml_param->table_sta_assoc_index[vap_param->vap_index], sta_index);
    return bus_error_success;
}

bus_error_t associated_sta_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t interworking_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { interworking_get_param_bool_value,
        interworking_get_param_int_value, interworking_get_param_uint_value,
        interworking_get_param_string_value, interworking_set_param_bool_value,
        interworking_set_param_int_value, interworking_set_param_uint_value,
        interworking_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_InterworkingElement.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Get interworking Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d interworking param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t interworking_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { interworking_get_param_bool_value,
        interworking_get_param_int_value, interworking_get_param_uint_value,
        interworking_get_param_string_value, interworking_set_param_bool_value,
        interworking_set_param_int_value, interworking_set_param_uint_value,
        interworking_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_InterworkingElement.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Set interworking Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d interworking param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t interworking_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t wps_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { wps_get_param_bool_value, wps_get_param_int_value,
        wps_get_param_uint_value, wps_get_param_string_value, wps_set_param_bool_value,
        wps_set_param_int_value, wps_set_param_uint_value, wps_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.WPS.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Get wps Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wps param get failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t wps_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { wps_get_param_bool_value, wps_get_param_int_value,
        wps_get_param_uint_value, wps_get_param_string_value, wps_set_param_bool_value,
        wps_set_param_int_value, wps_set_param_uint_value, wps_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.WPS.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Set wps Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wps param set failed for:[%s][%s]\r\n", __func__,
            __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t wps_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval,
    bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t ap_macfilter_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { ap_macfilter_get_param_bool_value, NULL, NULL, NULL,
        ap_macfilter_set_param_bool_value, NULL, NULL, NULL };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MACFilter.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Get ap macfilter Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d ap macfilter param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t ap_macfilter_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { ap_macfilter_get_param_bool_value, NULL, NULL, NULL,
        ap_macfilter_set_param_bool_value, NULL, NULL, NULL };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MACFilter.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Set ap macfilter Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d ap macfilter param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t ap_macfilter_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t radius_sec_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { radius_sec_get_param_bool_value,
        radius_sec_get_param_int_value, NULL, NULL, radius_sec_set_param_bool_value,
        radius_sec_set_param_int_value, NULL, NULL };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.Security.X_COMCAST-COM_RadiusSettings.%s",
        &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Radius sec Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d radius sec param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t radius_sec_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { radius_sec_get_param_bool_value,
        radius_sec_get_param_int_value, NULL, NULL, radius_sec_set_param_bool_value,
        radius_sec_set_param_int_value, NULL, NULL };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.Security.X_COMCAST-COM_RadiusSettings.%s",
        &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d Set Radius sec Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d radius sec param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t radius_sec_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t auth_sec_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, auth_sec_get_param_uint_value, NULL, NULL,
        NULL, auth_sec_set_param_uint_value, NULL };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.Security.X_RDKCENTRAL-COM_Authenticator.%s",
        &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d auth sec Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d auth sec param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t auth_sec_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, auth_sec_get_param_uint_value, NULL, NULL,
        NULL, auth_sec_set_param_uint_value, NULL };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.Security.X_RDKCENTRAL-COM_Authenticator.%s",
        &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set auth sec Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d auth sec param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t auth_sec_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t conn_ctrl_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, conn_ctrl_get_param_string_value, NULL,
        NULL, NULL, conn_ctrl_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.ConnectionControl.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get connection control Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d connection control param get failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t conn_ctrl_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, conn_ctrl_get_param_string_value, NULL,
        NULL, NULL, conn_ctrl_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.ConnectionControl.%s", &index, extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set connection control Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d connection control param set failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t conn_ctrl_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t pre_conn_ctrl_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, pre_conn_ctrl_get_param_string_value,
        NULL, NULL, NULL, pre_conn_ctrl_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.ConnectionControl.PreAssocDeny.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get pre connection control Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d pre connection control param get failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t pre_conn_ctrl_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, pre_conn_ctrl_get_param_string_value,
        NULL, NULL, NULL, pre_conn_ctrl_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.ConnectionControl.PreAssocDeny.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set pre connection control Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d pre connection control param set failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t pre_conn_ctrl_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t post_conn_ctrl_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, post_conn_ctrl_get_param_string_value,
        NULL, NULL, NULL, post_conn_ctrl_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.ConnectionControl.PostAssocDisc.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get post connection control Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d post connection control param get failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t post_conn_ctrl_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, post_conn_ctrl_get_param_string_value,
        NULL, NULL, NULL, post_conn_ctrl_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.ConnectionControl.PostAssocDisc.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set post connection control Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d post connection control param set failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t post_conn_ctrl_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t interworking_serv_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, interworking_serv_get_param_string_value,
        NULL, NULL, NULL, interworking_serv_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_InterworkingService.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get interwoking serv Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d interwoking serv param get failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t interworking_serv_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, interworking_serv_get_param_string_value,
        NULL, NULL, NULL, interworking_serv_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_InterworkingService.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set interwoking serv Event:[%s][%s]\n", __func__,
        __LINE__, event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d interwoking serv param set failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t interworking_serv_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t passpoint_get_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { passpoint_get_param_bool_value, NULL, NULL,
        passpoint_get_param_string_value, passpoint_set_param_bool_value, NULL, NULL,
        passpoint_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_Passpoint.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get passpoint Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d passpoint param get failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t passpoint_set_param_value(char *event_name, raw_data_t *p_data)
{
    uint32_t index = 0;
    char extension[64] = { 0 };
    wifi_vap_info_t *vap_param;
    dml_callback_table_t dml_data_cb = { passpoint_get_param_bool_value, NULL, NULL,
        passpoint_get_param_string_value, passpoint_set_param_bool_value, NULL, NULL,
        passpoint_set_param_string_value };

    sscanf(event_name, "Device.WiFi.AccessPoint.%d.X_RDKCENTRAL-COM_Passpoint.%s", &index,
        extension);

    vap_param = (wifi_vap_info_t *)getVapInfo(index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d wrong vap index:%d for:[%s]\r\n", __func__,
            __LINE__, index, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set passpoint Event:[%s][%s]\n", __func__, __LINE__,
        event_name, extension);
    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)vap_param,
        extension, p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d passpoint param set failed for:[%s][%s]\r\n",
            __func__, __LINE__, event_name, extension);
    }

    return status;
}

bus_error_t passpoint_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t wifi_client_report_get_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *)get_dml_harvester();
    dml_callback_table_t dml_data_cb = { wifi_client_report_get_param_bool_value, NULL,
        wifi_client_report_get_param_uint_value, wifi_client_report_get_param_string_value,
        wifi_client_report_set_param_bool_value, NULL, wifi_client_report_set_param_uint_value,
        wifi_client_report_set_param_string_value };

    sscanf(event_name, "Device.WiFi.X_RDKCENTRAL-COM_Report.WifiClient.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d wifi client report param get failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t wifi_client_report_set_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *)get_dml_harvester();
    dml_callback_table_t dml_data_cb = { wifi_client_report_get_param_bool_value, NULL,
        wifi_client_report_get_param_uint_value, wifi_client_report_get_param_string_value,
        wifi_client_report_set_param_bool_value, NULL, wifi_client_report_set_param_uint_value,
        wifi_client_report_set_param_string_value };

    sscanf(event_name, "Device.WiFi.X_RDKCENTRAL-COM_Report.WifiClient.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d wifi client report param set failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t wifi_client_report_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t wifi_client_def_report_get_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *)get_dml_harvester();
    dml_callback_table_t dml_data_cb = { NULL, NULL, wifi_client_def_report_get_param_uint_value,
        NULL, NULL, NULL, wifi_client_def_report_set_param_uint_value, NULL };

    sscanf(event_name, "Device.WiFi.X_RDKCENTRAL-COM_Report.WifiClient.Default.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d wifi client report param get failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t wifi_client_def_report_set_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    instant_measurement_config_t *pcfg = (instant_measurement_config_t *)get_dml_harvester();
    dml_callback_table_t dml_data_cb = { NULL, NULL, wifi_client_def_report_get_param_uint_value,
        NULL, NULL, NULL, wifi_client_def_report_set_param_uint_value, NULL };

    sscanf(event_name, "Device.WiFi.X_RDKCENTRAL-COM_Report.WifiClient.Default.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d set event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d wifi client report param set failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t wifi_client_def_report_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}

bus_error_t wifi_region_code_get_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_dml_wifi_global_param();
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, wifi_region_code_get_param_string_value,
        NULL, NULL, NULL, wifi_region_code_set_param_string_value };

    sscanf(event_name, "Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_GET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d wifi region code param get failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t wifi_region_code_set_param_value(char *event_name, raw_data_t *p_data)
{
    char extension[64] = { 0 };
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_dml_wifi_global_param();
    dml_callback_table_t dml_data_cb = { NULL, NULL, NULL, wifi_region_code_get_param_string_value,
        NULL, NULL, NULL, wifi_region_code_set_param_string_value };

    sscanf(event_name, "Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.%s", extension);

    wifi_util_info_print(WIFI_DMCLI, "%s:%d get event:[%s][%s]\n", __func__, __LINE__, event_name,
        extension);

    bus_error_t status = dml_get_set_param_value(&dml_data_cb, DML_SET_CB, (void *)pcfg, extension,
        p_data);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,
            "%s:%d wifi region code param set failed for:[%s][%s]\r\n", __func__, __LINE__,
            event_name, extension);
    }

    return status;
}

bus_error_t default_get_param_value(char *event_name, raw_data_t *p_data)
{
    (void)p_data;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return bus_error_success;
}

bus_error_t default_set_param_value(char *event_name, raw_data_t *p_data)
{
    (void)p_data;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return bus_error_success;
}

bus_error_t default_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter\r\n", __func__, __LINE__);
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Added table:%s\r\n", __func__, __LINE__, tableName);
    return bus_error_success;
}

bus_error_t default_table_remove_row_handler(char const *rowName)
{
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    return bus_error_success;
}

bus_error_t default_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__,
        eventName, action, interval);
    return bus_error_success;
}
