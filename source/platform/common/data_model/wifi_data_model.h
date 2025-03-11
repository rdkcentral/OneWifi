#ifndef WIFI_DATA_MODEL_H
#define WIFI_DATA_MODEL_H

#include "bus.h"
#include "wifi_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DM_CHECK_NULL_WITH_RC(ptr, rc)                                                    \
    do {                                                                                  \
        if ((ptr) == NULL) {                                                              \
            wifi_util_error_print(WIFI_DMCLI, "%s:%d Parameter '%s' is NULL\n", __func__, \
                __LINE__, #ptr);                                                          \
            return (rc);                                                                  \
        }                                                                                 \
    } while (0)

typedef struct scratch_data_buff {
    void *buff;
    uint32_t buff_len;
} scratch_data_buff_t;

typedef struct wifi_dml_data_model {
    uint32_t table_radio_index;
    uint32_t table_ap_index;
    uint32_t table_ssid_index;
    uint32_t table_macfilter_index[MAX_VAP];
    uint32_t table_sta_assoc_index[MAX_VAP];
    uint32_t table_neig_diag_result_index;
    char str_wifi_region_update_source[16];
} wifi_dml_data_model_t;

typedef bool (*dml_get_bool_cb_t)(void *obj_ins_context, char *param_name, bool *value);
typedef bool (*dml_set_bool_cb_t)(void *obj_ins_context, char *param_name, bool value);
typedef bool (*dml_get_int_cb_t)(void *obj_ins_context, char *param_name, int *value);
typedef bool (*dml_set_int_cb_t)(void *obj_ins_context, char *param_name, int value);
typedef bool (*dml_get_uint_cb_t)(void *obj_ins_context, char *param_name, uint32_t *value);
typedef bool (*dml_set_uint_cb_t)(void *obj_ins_context, char *param_name, uint32_t value);
typedef bool (
    *dml_get_string_cb_t)(void *obj_ins_context, char *param_name, scratch_data_buff_t *value);
typedef bool (
    *dml_set_string_cb_t)(void *obj_ins_context, char *param_name, scratch_data_buff_t *value);

typedef struct dml_callback_table {
    dml_get_bool_cb_t get_bool_value;
    dml_get_int_cb_t get_int_value;
    dml_get_uint_cb_t get_uint_value;
    dml_get_string_cb_t get_string_value;
    dml_set_bool_cb_t set_bool_value;
    dml_set_int_cb_t set_int_value;
    dml_set_uint_cb_t set_uint_value;
    dml_set_string_cb_t set_string_value;
} dml_callback_table_t;

bus_error_t wifi_elem_num_of_table_row(char *event_name, uint32_t *table_row_size);

bus_error_t wifi_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wifi_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wifi_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval,
    bool *autoPublish);

bus_error_t neig_wifi_diag_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t neig_wifi_diag_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t neig_wifi_diag_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t neig_diag_result_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t neig_diag_result_table_add_row_cb(char const *tableName, char const *aliasName,
    uint32_t *instNum);
bus_error_t neig_diag_result_table_remove_row_cb(char const *rowName);
bus_error_t neig_diag_result_event_sub_cb(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t radio_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t radio_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t radio_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
bus_error_t radio_table_remove_row_handler(char const *rowName);
bus_error_t radio_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t accesspoint_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t accesspoint_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t accesspoint_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
bus_error_t accesspoint_table_remove_row_handler(char const *rowName);
bus_error_t accesspoint_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t ssid_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t ssid_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t ssid_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
bus_error_t ssid_table_remove_row_handler(char const *rowName);
bus_error_t ssid_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval,
    bool *autoPublish);

bus_error_t security_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t security_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t security_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t macfilter_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t macfilter_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t macfilter_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
bus_error_t macfilter_table_remove_row_handler(char const *rowName);
bus_error_t macfilter_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t associated_sta_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t associated_sta_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
bus_error_t associated_sta_table_remove_row_handler(char const *rowName);
bus_error_t associated_sta_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t interworking_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t interworking_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t interworking_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t ap_macfilter_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t ap_macfilter_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t ap_macfilter_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t radius_sec_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t radius_sec_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t radius_sec_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t auth_sec_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t auth_sec_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t auth_sec_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t conn_ctrl_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t conn_ctrl_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t conn_ctrl_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t pre_conn_ctrl_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t pre_conn_ctrl_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t pre_conn_ctrl_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t post_conn_ctrl_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t post_conn_ctrl_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t post_conn_ctrl_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t wps_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wps_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wps_event_sub_handler(char *eventName, bus_event_sub_action_t action, int32_t interval,
    bool *autoPublish);

bus_error_t interworking_serv_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t interworking_serv_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t interworking_serv_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t passpoint_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t passpoint_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t passpoint_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t wifi_client_report_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wifi_client_report_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wifi_client_report_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t wifi_client_def_report_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wifi_client_def_report_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wifi_client_def_report_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t default_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t default_set_param_value(char *event_name, raw_data_t *p_data);
bus_error_t default_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
bus_error_t default_table_remove_row_handler(char const *rowName);
bus_error_t default_event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

bus_error_t wifi_region_code_get_param_value(char *event_name, raw_data_t *p_data);
bus_error_t wifi_region_code_set_param_value(char *event_name, raw_data_t *p_data);

wifi_dml_data_model_t *get_dml_data_model_param(void);
#endif // WIFI_DATA_MODEL_H
