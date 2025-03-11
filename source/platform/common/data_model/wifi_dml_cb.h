#ifndef WIFI_DML_CB_H
#define WIFI_DML_CB_H

#include "wifi_data_model.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SAE_PASSPHRASE_MIN_LENGTH 8
#define SAE_PASSPHRASE_MAX_LENGTH 64

#define INST_SCHEMA_ID_BUFFER \
    "8b27dafc-0c4d-40a1-b62c-f24a34074914/4388e585dd7c0d32ac47e71f634b579b"

typedef struct mac_filter_set_param_arg {
    acl_entry_t *acl_param;
    wifi_vap_info_t *vap_info_param;
} mac_filter_set_param_arg_t;

bool wifi_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool wifi_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool wifi_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);
bool wifi_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool wifi_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool wifi_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool wifi_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);
bool wifi_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool radio_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool radio_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool radio_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);
bool radio_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool radio_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool radio_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool radio_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);
bool radio_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool accesspoint_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool accesspoint_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool accesspoint_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool accesspoint_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool accesspoint_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool accesspoint_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool accesspoint_set_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t output_value);
bool accesspoint_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool ssid_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool ssid_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool ssid_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);
bool ssid_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool ssid_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool ssid_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool ssid_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);
bool ssid_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool security_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool security_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool security_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);
bool security_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool security_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool security_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool security_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);
bool security_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool radius_sec_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool radius_sec_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool radius_sec_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool radius_sec_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);

bool auth_sec_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);
bool auth_sec_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);

bool interworking_serv_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool interworking_serv_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool passpoint_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool passpoint_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool passpoint_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool passpoint_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool wps_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool wps_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool wps_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);
bool wps_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool wps_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool wps_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool wps_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);
bool wps_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool conn_ctrl_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool conn_ctrl_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool pre_conn_ctrl_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool pre_conn_ctrl_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool post_conn_ctrl_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool post_conn_ctrl_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

void *macfilter_tab_add_entry(void *obj_ins_context, uint32_t *p_ins_number);
int macfilter_tab_del_entry(void *obj_ins_context, void *p_instance);
bool macfilter_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool macfilter_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool macfilter_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool macfilter_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool macfilter_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool macfilter_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool macfilter_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);
bool macfilter_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool associated_sta_get_param_bool_value(void *obj_ins_context, char *param_name,
    bool *output_value);
bool associated_sta_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool associated_sta_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool associated_sta_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool interworking_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool interworking_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool interworking_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool interworking_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool interworking_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool interworking_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool interworking_set_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t output_value);
bool interworking_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool ap_macfilter_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool ap_macfilter_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);

bool neig_wifi_diag_get_param_bool_value(void *obj_ins_context, char *param_name,
    bool *output_value);
bool neig_wifi_diag_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool neig_wifi_diag_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool neig_wifi_diag_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool neig_wifi_diag_set_param_bool_value(void *obj_ins_context, char *param_name,
    bool output_value);
bool neig_wifi_diag_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool neig_wifi_diag_set_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t output_value);
bool neig_wifi_diag_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool neig_diag_result_get_param_int_value(void *obj_ins_context, char *param_name,
    int *output_value);
bool neig_diag_result_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool neig_diag_result_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool wifi_client_report_get_param_bool_value(void *obj_ins_context, char *param_name,
    bool *output_value);
bool wifi_client_report_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool wifi_client_report_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool wifi_client_report_set_param_bool_value(void *obj_ins_context, char *param_name,
    bool output_value);
bool wifi_client_report_set_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t output_value);
bool wifi_client_report_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool wifi_client_def_report_get_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t *output_value);
bool wifi_client_def_report_set_param_uint_value(void *obj_ins_context, char *param_name,
    uint32_t output_value);

bool wifi_region_code_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool wifi_region_code_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

bool default_get_param_bool_value(void *obj_ins_context, char *param_name, bool *output_value);
bool default_get_param_int_value(void *obj_ins_context, char *param_name, int *output_value);
bool default_get_param_uint_value(void *obj_ins_context, char *param_name, uint32_t *output_value);
bool default_get_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);
bool default_set_param_bool_value(void *obj_ins_context, char *param_name, bool output_value);
bool default_set_param_int_value(void *obj_ins_context, char *param_name, int output_value);
bool default_set_param_uint_value(void *obj_ins_context, char *param_name, uint32_t output_value);
bool default_set_param_string_value(void *obj_ins_context, char *param_name,
    scratch_data_buff_t *output_value);

#endif // WIFI_DML_CB_H
