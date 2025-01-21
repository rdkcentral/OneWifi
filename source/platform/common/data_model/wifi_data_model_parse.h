#ifndef WIFI_DATA_MODEL_PARSE_H
#define WIFI_DATA_MODEL_PARSE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "bus_common.h"

#define WIFI_OBJ_DEFINITIONS_NAME  "definitions"
#define RADIO_OBJ_NAME             "Radio"
#define ACCESSPOINT_OBJ_NAME       "AccessPoint"

#define LIST_OF_DEFINITION_NAME    "List_Of_Def"
#define MAX_NUM_OF_OBJECTS_NAME    "Num_Of_Objects"

#define WIFI_OBJ_TREE_NAME         "Device.WiFi"
#define NEIG_WIFI_DIAG_OBJ_NAME    "Device.WiFi.NeighboringWiFiDiagnostic"
#define NEIG_DIAG_RESULT_OBJ_NAME  "Device.WiFi.NeighboringWiFiDiagnostic.Result"
#define WIFI_REGION_OBJ_NAME       "Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion"
#define WIFI_CLIENT_REPORT_OBJ_NAME     "Device.WiFi.X_RDKCENTRAL-COM_Report.WifiClient"
#define WIFI_CLIENT_DEF_REPORT_OBJ_NAME "Device.WiFi.X_RDKCENTRAL-COM_Report.WifiClient.Default"
#define RADIO_OBJ_TREE_NAME        "Device.WiFi.Radio.{i}"
#define ACCESSPOINT_OBJ_TREE_NAME  "Device.WiFi.AccessPoint.{i}"
#define SECURITY_OBJ_TREE_NAME     "Device.WiFi.AccessPoint.{i}.Security"
#define RADIUS_SEC_OBJ_TREE_NAME   "Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings"
#define AUTH_SEC_OBJ_TREE_NAME     "Device.WiFi.AccessPoint.{i}.Security.X_RDKCENTRAL-COM_Authenticator"
#define AP_MACFILTER_TREE_NAME     "Device.WiFi.AccessPoint.{i}.X_CISCO_COM_MACFilter"
#define MACFILTER_OBJ_TREE_NAME    "Device.WiFi.AccessPoint.{i}.X_CISCO_COM_MacFilterTable.{i}"
#define ASSOCIATED_STA_OBJ_TREE_NAME "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}"
#define INTERWORKING_OBJ_TREE_NAME "Device.WiFi.AccessPoint.{i}.X_RDKCENTRAL-COM_InterworkingElement"
#define CONN_CTRL_OBJ_TREE_NAME    "Device.WiFi.AccessPoint.{i}.ConnectionControl"
#define PRE_CONN_CTRL_OBJ_TREE_NAME  "Device.WiFi.AccessPoint.{i}.ConnectionControl.PreAssocDeny"
#define POST_CONN_CTRL_OBJ_TREE_NAME "Device.WiFi.AccessPoint.{i}.ConnectionControl.PostAssocDisc"
#define WPS_OBJ_TREE_NAME          "Device.WiFi.AccessPoint.{i}.WPS"
#define INTERWORKING_SERV_OBJ_NAME "Device.WiFi.AccessPoint.{i}.X_RDKCENTRAL-COM_InterworkingService"
#define PASSPOINT_OBJ_TREE_NAME    "Device.WiFi.AccessPoint.{i}.X_RDKCENTRAL-COM_Passpoint"
#define SSID_OBJ_TREE_NAME         "Device.WiFi.SSID.{i}"

#define DML_GET_CB                 1
#define DML_SET_CB                 2

#define decode_json_param_object(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsObject(value) == false)) {  \
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define decode_json_param_string(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) || (strcmp(value->valuestring, "") == 0)) {    \
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define decode_json_param_integer(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsNumber(value) == false)) {  \
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define validate_current_json_obj_param_name(json) \
{   \
    if (json == NULL || json->string == NULL) {  \
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: current json obj param name not found\n", __func__, __LINE__);   \
        return RETURN_ERR;  \
    }   \
}   \

#define decode_json_param_bool(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsBool(value) == false)) {    \
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define  get_func_address    dlsym

typedef struct bus_data_cb_func {
    char                  *cb_table_name;
    bus_callback_table_t  cb_func;
} bus_data_cb_func_t;

int decode_json_obj(bus_handle_t *handle, const char *json_name);

#endif //WIFI_DATA_MODEL_PARSE_H
