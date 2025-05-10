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

#ifdef ONEWIFI_RDKB_APP_SUPPORT
#define  WBCFG_MULTI_COMP_SUPPORT 1
#include "webconfig_framework.h"
#include <msgpack.h>
#endif

#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "bus.h"
#include "wifi_util.h"
#include "wifi_webconfig.h"

uint32_t get_wifi_blob_version(char* subdoc)
{
    // TODO: implementation
    return 0;
}

int set_wifi_blob_version(char* subdoc,uint32_t version)
{
    // TODO: implementation
    return 0;
}

size_t wifi_vap_cfg_timeout_handler()
{
    wifi_util_info_print(WIFI_CTRL, "%s: Enter\n", __func__);
    return 100;
}

int wifi_vap_cfg_rollback_handler()
{
    wifi_util_info_print(WIFI_CTRL, "%s: Enter\n", __func__);
    return RETURN_OK;
}

size_t webconf_timeout_handler(size_t numOfEntries)
{
    return (numOfEntries * 90);
}

static int webconf_rollback_handler(void)
{
    //TODO: what should rollback handler do in the context of OneWifi

    wifi_util_dbg_print(WIFI_CTRL, "%s: Enter\n", __func__);
    return RETURN_OK;
}


#ifdef ONEWIFI_RDKB_APP_SUPPORT
/* local functions */
static int decode_ssid_blob(wifi_vap_info_t *vap_info, cJSON *ssid,char *bridge_name,bool managed_wifi, pErr execRetVal);
static int decode_security_blob(wifi_vap_info_t *vap_info, cJSON *security, pErr execRetVal);
static int update_vap_info(void *data, wifi_vap_info_t *vap_info, pErr execRetVal);
static int update_vap_info_managed_guest(void *data, wifi_vap_info_t *vap_info, char *bridge_name,bool connected_building_enabled, pErr execRetVal);
static int update_vap_info_managed_xfinity(void *data, wifi_vap_info_t *vap_info,pErr execRetVal);
static int update_vap_info_with_blob_info(void *blob, webconfig_subdoc_data_t *data, const char *vap_prefix, bool managed_wifi, pErr execRetVal);
static int push_blob_data(webconfig_subdoc_data_t *data, webconfig_subdoc_type_t subdoc_type);
static pErr create_execRetVal(void);
static pErr private_home_exec_common_handler(void *blob, const char *vap_prefix, webconfig_subdoc_type_t subdoc_type);
static int validate_private_home_ssid_param(char *str, pErr execRetVal);
static int validate_private_home_security_param(char *mode_enabled, char*encryption_method, pErr execRetVal);

void webconf_free_resources(void *arg)
{
    wifi_util_dbg_print(WIFI_CTRL, "%s: Enter\n", __func__);
    if(arg == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null Input Data\n", __func__);
        return;
    }

    execData *blob_exec_data  = (execData*) arg;
    char *blob_data = (char*)blob_exec_data->user_data;
    if(blob_data != NULL) {
        free(blob_data);
        blob_data = NULL;
    }

    free(blob_exec_data);
}

pErr webconf_config_handler(void *blob)
{
    pErr exec_ret_val = NULL;

    if(blob == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return exec_ret_val;
    }

    exec_ret_val = (pErr ) malloc (sizeof(Err));
    if (exec_ret_val == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return exec_ret_val;
    }

    memset(exec_ret_val,0,(sizeof(Err)));
    exec_ret_val->ErrorCode = BLOB_EXEC_SUCCESS;

    // push blob to ctrl queue
    push_event_to_ctrl_queue(blob, strlen(blob), wifi_event_type_webconfig, wifi_event_webconfig_set_data_webconfig, NULL);

    wifi_util_dbg_print(WIFI_CTRL, "%s: return success\n", __func__);
    return exec_ret_val;
}

static int validate_private_home_security_param(char *mode_enabled, char *encryption_method, pErr execRetVal)
{
     wifi_util_info_print(WIFI_CTRL,"Enter %s mode_enabled=%s,encryption_method=%s\n",__func__,mode_enabled,encryption_method);
     wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();

    if (strcmp(mode_enabled, "None") != 0 &&
        (strcmp(encryption_method, "TKIP") != 0 && strcmp(encryption_method, "AES") != 0 &&
        strcmp(encryption_method, "AES+TKIP") != 0 && strcmp(encryption_method, "AES+GCMP"))) {
         wifi_util_error_print(WIFI_CTRL,"%s: Invalid Encryption Method \n",__FUNCTION__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Encryption Method",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }

    if ((strcmp(mode_enabled, "WPA-WPA2-Enterprise") == 0 || 
        strcmp(mode_enabled, "WPA-WPA2-Personal") == 0) &&
        (strcmp(encryption_method, "AES+TKIP") != 0 && strcmp(encryption_method, "AES") != 0 &&
        strcmp(encryption_method, "AES+GCMP") != 0)) {
         wifi_util_error_print(WIFI_CTRL,"%s: Invalid Encryption Security Combination\n",__FUNCTION__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Encryption Security Combination",sizeof(execRetVal->ErrorMsg)-1);
        }
     return RETURN_ERR;
    }

    if( (strcmp(mode_enabled, "WPA3-Personal-Compatibility") == 0) && !rfc_param->wpa3_compatibility_enable) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d RFC for WPA3-Personal-Compatibility is not enabled \n",
            __func__, __LINE__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Security Mode, RFC for WPA3-Personal-Compatibility is not enabled\n",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }

     wifi_util_info_print(WIFI_CTRL,"%s: securityparam validation passed \n",__FUNCTION__);
    return RETURN_OK;

}
static int validate_private_home_ssid_param(char *ssid_name, pErr execRetVal)
{
    int ssid_len = 0;
    int i = 0;
    wifi_util_info_print(WIFI_CTRL,"Enter %s and ssid_name=%s\n",__func__,ssid_name);
    ssid_len = strlen(ssid_name);
    if ((ssid_len == 0) || (ssid_len > MAX_SSID_NAME_LEN)) {
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid SSID string size",sizeof(execRetVal->ErrorMsg)-1);
        }
        wifi_util_error_print(WIFI_CTRL,"%s: Invalid SSID size for ssid_name %s \n",__FUNCTION__, ssid_name);
        return RETURN_ERR;
    }

    for (i = 0; i < ssid_len; i++) {
        if (!((ssid_name[i] >= ' ') && (ssid_name[i] <= '~'))) {
            wifi_util_error_print(WIFI_CTRL,"%s: Invalid character present in SSID \n",__FUNCTION__);
            if (execRetVal) {
                strncpy(execRetVal->ErrorMsg,"Invalid character in SSID",sizeof(execRetVal->ErrorMsg)-1);
            }
            return RETURN_ERR;
        }
    }

   wifi_util_info_print(WIFI_CTRL,"%s: ssidparam validation passed \n",__FUNCTION__);
  return RETURN_OK;
} 
static int decode_ssid_blob(wifi_vap_info_t *vap_info, cJSON *ssid, char *bridge_name, bool managed_wifi, pErr execRetVal)
{ 
    char *value;
    cJSON *param;

    wifi_util_info_print(WIFI_CTRL, "SSID blob:\n");
    param = cJSON_GetObjectItem(ssid, "SSID");
    if (param) {
        value = cJSON_GetStringValue(param);
        wifi_util_info_print(WIFI_CTRL, "   \"SSID\": %s\n", value);
        if (validate_private_home_ssid_param(value,execRetVal) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "SSID validation failed\n");
            return -1;
        }
        snprintf(vap_info->u.bss_info.ssid, sizeof(vap_info->u.bss_info.ssid), "%s", value);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"SSID\"\n", __func__);
        return -1;
    }

    param = cJSON_GetObjectItem(ssid, "Enable");
    if (!param) {
       param = cJSON_GetObjectItem(ssid, "Enabled");
    }
    if (param) {
        if (cJSON_IsBool(param)) {
            vap_info->u.bss_info.enabled = cJSON_IsTrue(param) ? true : false;
            wifi_util_info_print(WIFI_CTRL, "   \"Enable\": %s\n", (vap_info->u.bss_info.enabled) ? "true" : "false");
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: \"Enable\" is not boolean\n", __func__);
            return -1;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"Enable\"\n", __func__);
        return -1;
    }
    param = cJSON_GetObjectItem(ssid, "SSIDAdvertisementEnabled");
    if (param) {
        if (cJSON_IsBool(param)) {
            vap_info->u.bss_info.showSsid = cJSON_IsTrue(param) ? true : false;
            wifi_util_info_print(WIFI_CTRL, "   \"SSIDAdvertisementEnabled\": %s\n", (vap_info->u.bss_info.showSsid) ? "true" : "false");
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: \"SSIDAdvertisementEnabled\" is not boolean\n", __func__);
            return -1;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"SSIDAdvertisementEnabled\"\n", __func__);
        return -1;
    }
    if (managed_wifi) {
        if (strlen(bridge_name) == 0) {
            wifi_util_dbg_print(WIFI_CTRL,"BridgeName is empty\n");
            snprintf(vap_info->bridge_name, sizeof(vap_info->bridge_name), "brlan15");
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"BridgeName is %s\n",bridge_name);
            snprintf(vap_info->bridge_name, sizeof(vap_info->bridge_name), "%s", bridge_name);
        }
        param = cJSON_GetObjectItem(ssid, "BssMaxNumSta");
        if (param) {
            vap_info->u.bss_info.bssMaxSta = param->valuedouble;
            wifi_util_info_print(WIFI_CTRL, "   \"BssMax\": %d\n", vap_info->u.bss_info.bssMaxSta);
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: missing \"BssMax\"\n", __func__);
            return -1;
        }
    }

    return 0;
}
static int decode_security_blob(wifi_vap_info_t *vap_info, cJSON *security,pErr execRetVal)
{
    char *value;
    cJSON *param;
    int pass_len =0;
    char encryption_method[128] = "";

    wifi_util_info_print(WIFI_CTRL, "Security blob:\n");
    param = cJSON_GetObjectItem(security, "Passphrase");
    if (param) {
        value = cJSON_GetStringValue(param);
        snprintf(vap_info->u.bss_info.security.u.key.key, sizeof(vap_info->u.bss_info.security.u.key.key), "%s", value);
        wifi_util_info_print(WIFI_CTRL, "   \"Passphrase\": <Masked>\n");
        pass_len = strlen(value);

    if ((pass_len < MIN_PWD_LEN) || (pass_len > MAX_PWD_LEN)) {
         wifi_util_error_print(WIFI_CTRL,"%s: Invalid Key passphrase length \n",__FUNCTION__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Passphrase length",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;

    }
    if (pass_len == 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"Passphrase\"\n", __func__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Passphrase length",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
    }
    param = cJSON_GetObjectItem(security, "EncryptionMethod");
    if (param) {
        value = cJSON_GetStringValue(param);
        wifi_util_info_print(WIFI_CTRL, "   \"EncryptionMethod\": %s\n", value);
        if (!strcmp(value, "AES")) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes;
        } else if (!strcmp(value, "AES+TKIP")) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        } else if (!strcmp(value, "TKIP")) {
            vap_info->u.bss_info.security.encr = wifi_encryption_tkip;
        } else if (!strcmp(value, "AES+GCMP")) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes_gcmp256;
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: unknown \"EncryptionMethod\n: %s\n", __func__, value);
            if (execRetVal) {
                strncpy(execRetVal->ErrorMsg,"Invalid Encryption Method",sizeof(execRetVal->ErrorMsg)-1);
            }
            return RETURN_ERR;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"EncryptionMethod\"\n", __func__);
         if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Encryption Method",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
    strcpy(encryption_method,value);

    param = cJSON_GetObjectItem(security, "ModeEnabled");
    if (!param) {
       param = cJSON_GetObjectItem(security, "Mode");
    }
    if (param) {
        value = cJSON_GetStringValue(param);
        wifi_util_info_print(WIFI_CTRL, "   \"ModeEnabled\": %s\n", value);
        if (!strcmp(value, "None")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_none;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA2-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA-WPA2-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_wpa2_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;

            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA3-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_sae;
        } else if (!strcmp(value, "WPA3-Personal-Transition")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
        } else if (!strcmp(value, "WPA3-Personal-Compatibility")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_compatibility;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        } else {
            if (execRetVal) {
                strncpy(execRetVal->ErrorMsg,"Invalid Security Mode",sizeof(execRetVal->ErrorMsg)-1);
            }

            wifi_util_error_print(WIFI_CTRL, "%s: unknown \"ModeEnabled\": %s\n", __func__, value);
            return RETURN_ERR;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"ModeEnabled\"\n", __func__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Security Mode",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
    if (validate_private_home_security_param(value,encryption_method,execRetVal) != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid Encryption Security Combination \n", __func__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}
static int update_vap_info(void *data, wifi_vap_info_t *vap_info,pErr execRetVal)
{
    int status = RETURN_OK;
    char *suffix;
    char band[8];
    cJSON *root = NULL;
    cJSON *ssid_obj = NULL;
    cJSON *security_obj = NULL;
    wifi_vap_name_t ssid;
    wifi_vap_name_t security;

    root = cJSON_Parse((char *)data);
    if(root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return RETURN_ERR;
    }

    suffix = strrchr(vap_info->vap_name, (int)'_');
    if (suffix == NULL) {
        goto done;
    }
    /*
    For products with 5GHz lower and upper band radios like XLE,
    the webconfig will support only the VAP names append with '_5gl'. '_5gh' and '_5gu'.
    The blob is using '_5gl' and '_5gu'. VAP names with '_5gh' will be changed to use '_5gu'.
    */
    if (!strcmp(suffix, "_5gh")) {
        snprintf(band, sizeof(band), "_5gu");
    } else {
        snprintf(band, sizeof(band), "%s", suffix);
    }
    if (!strncmp(vap_info->vap_name, VAP_PREFIX_PRIVATE, strlen(VAP_PREFIX_PRIVATE))) {
        snprintf(ssid, sizeof(wifi_vap_name_t), "private_ssid%s", band);
        snprintf(security, sizeof(wifi_vap_name_t), "private_security%s", band);
    } else if (!strncmp(vap_info->vap_name, VAP_PREFIX_IOT, strlen(VAP_PREFIX_IOT))) {
        snprintf(ssid, sizeof(wifi_vap_name_t), "home_ssid%s", band);
        snprintf(security, sizeof(wifi_vap_name_t), "home_security%s", band);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: No SSID and security info\n", __func__);
        status = RETURN_ERR;
        goto done;
   }

    wifi_util_dbg_print(WIFI_CTRL, "%s: parsing %s and %s blob\n", __func__, ssid, security);
    ssid_obj = cJSON_GetObjectItem(root, ssid);
    if (ssid_obj == NULL) {
        status = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s: Failed to get %s SSID\n", __func__, vap_info->vap_name);
        goto done;
    }

    security_obj = cJSON_GetObjectItem(root, security);
    if (security_obj == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get %s security\n", __func__, vap_info->vap_name);
        status = RETURN_ERR;
        goto done;
    }

    /* get SSID */
    if (decode_ssid_blob(vap_info, ssid_obj, NULL, false, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode SSID blob\n", __func__);
        status = RETURN_ERR;
        goto done;
    }

    /* decode security blob */
    if (decode_security_blob(vap_info, security_obj, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode security blob\n", __func__);
        status = RETURN_ERR;
        goto done;
    }

done:
    if (root) {
        cJSON_Delete(root);
    }
    return status;
}

static int update_vap_info_managed_guest(void *data, wifi_vap_info_t *vap_info, char * bridge_name,bool connected_building_enabled,pErr execRetVal)
{
    int status = RETURN_OK;
    cJSON *root = NULL;
    cJSON *security_obj = NULL;
    cJSON *vb_entry = NULL;
    char repurposed_vap_name[64];
    char ssid[128] = {0};
    char password[128] = {0};
    memset(repurposed_vap_name,0,sizeof(repurposed_vap_name));
    char *saveptr = NULL;
    char *blob = NULL;

    if (connected_building_enabled) {
        wifi_util_info_print(WIFI_CTRL, "%s: %d connected_building_enabled %d \n", __func__,__LINE__,connected_building_enabled);
        blob = cJSON_Print((cJSON *)data);
        wifi_util_dbg_print(WIFI_CTRL,"Managed guest  blob is %s\n",blob);
        root = cJSON_Parse(blob);
        if(root == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:Managed guest json  parse failure\n", __func__);
            return RETURN_ERR;
        }

        cJSON_ArrayForEach(vb_entry, root) {

            cJSON *blob_vap_name = cJSON_GetObjectItem(vb_entry, "VapName");
            if((blob_vap_name == NULL) || (cJSON_IsString(blob_vap_name) == false)) {
                wifi_util_info_print(WIFI_CTRL, "%s: Missing VapName\n", __func__);
                continue;
            }

            char *blob_vap_name_str = cJSON_GetStringValue(blob_vap_name);
            strncpy(repurposed_vap_name,blob_vap_name_str,sizeof(repurposed_vap_name)-1);
            wifi_util_info_print(WIFI_CTRL, "repurposed_vap_name:%s %s: %d \n",repurposed_vap_name, __func__,__LINE__ );

            if (strstr(blob_vap_name_str,"managed_guest_")) {
                saveptr = strrchr(blob_vap_name_str, (int)'_');
                if (saveptr == NULL) {
                    wifi_util_error_print(WIFI_CTRL, "%s: %d vapname is not proper \n", __func__,__LINE__);
                    goto done;
                }
                snprintf(blob_vap_name_str,strlen(blob_vap_name_str)-1,"lnf_psk%s",saveptr);
            } else {
                wifi_util_error_print(WIFI_CTRL, "%s: %d vapname is not proper \n", __func__,__LINE__);
                goto done;
            }
            if (!strcmp(vap_info->vap_name,blob_vap_name_str)) {
                wifi_util_error_print(WIFI_CTRL, "%s: %d connected_building_enabled %d \n", __func__,__LINE__,connected_building_enabled);
                if (decode_ssid_blob(vap_info, vb_entry, bridge_name, true, execRetVal) != 0) {
                    wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode SSID blob\n", __func__);
                    status = RETURN_ERR;
                    goto done;
                 }

                security_obj = cJSON_GetObjectItem(vb_entry, "Security");
                if (security_obj == NULL) {
                    wifi_util_error_print(WIFI_CTRL, "%s: Failed to get %s security\n", __func__, vap_info->vap_name);
                    status = RETURN_ERR;
                    goto done;
                }


                /* decode security blob */
                if (decode_security_blob(vap_info, security_obj, execRetVal) != 0) {
                    wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode security blob\n", __func__);
                    status = RETURN_ERR;
                    goto done;
                }
                if (strlen(repurposed_vap_name) != 0) {
                    strncpy(vap_info->repurposed_vap_name, repurposed_vap_name, (strlen(repurposed_vap_name) + 1));
                }
            }
        }
    } else {
        wifi_util_info_print(WIFI_CTRL, "%s: %d connected_building_enabled %d \n", __func__,__LINE__,connected_building_enabled);
        snprintf(vap_info->bridge_name, sizeof(vap_info->bridge_name), "br106");
        vap_info->u.bss_info.showSsid = false;
        vap_info->u.bss_info.enabled = true;
        vap_info->u.bss_info.bssMaxSta = 75;
        wifi_hal_get_default_ssid(ssid, vap_info->vap_index);
        wifi_hal_get_default_keypassphrase(password, vap_info->vap_index);
        snprintf(vap_info->u.bss_info.ssid, sizeof(vap_info->u.bss_info.ssid), "%s", ssid);
        snprintf(vap_info->u.bss_info.security.u.key.key, sizeof(vap_info->u.bss_info.security.u.key.key), "%s", password);
        strncpy(vap_info->repurposed_vap_name,"",(strlen(repurposed_vap_name) + 1));
    }
done:
    if (root) {
        cJSON_free(blob);
        cJSON_Delete(root);
    }
    return status;
}
static int update_vap_info_managed_xfinity(void *data, wifi_vap_info_t *vap_info, pErr execRetVal)
{
    int status = RETURN_OK;
    cJSON *root = NULL;
    cJSON *param = NULL;
    bool connected_building_enabled = false;
    char *blob = cJSON_Print((cJSON *)data);

    root = cJSON_Parse(blob);

    if (root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:Managed xfinity json parse failure\n", __func__);
        return RETURN_ERR;
    }
    param = cJSON_GetObjectItem(root, "connected_building_enabled");

    if (param) {
        if (cJSON_IsBool(param)) {
            connected_building_enabled = cJSON_IsTrue(param) ? true : false;
            wifi_util_dbg_print(WIFI_CTRL, "   \"connected_building_enabled\": %s\n", (connected_building_enabled) ? "true" : "false");
        } else {
            wifi_util_dbg_print(WIFI_CTRL, "%s: \"connected_building_enabled\" is not boolean\n", __func__);
            cJSON_Delete(root);
            return RETURN_ERR;
        }
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s: \"connected_building_enabled\" is not present\n", __func__);
    }
    vap_info->u.bss_info.connected_building_enabled = connected_building_enabled;
    wifi_util_info_print(WIFI_CTRL, "  LINE %d \"connected_building_enabled\": %s and vap_name=%s\n", __LINE__,(vap_info->u.bss_info.connected_building_enabled) ? "true" : "false",vap_info->vap_name);
    cJSON_Delete(root);
    return status;
}

static int update_vap_info_with_blob_info(void *blob, webconfig_subdoc_data_t *data, const char *vap_prefix, bool managed_wifi_enabled,pErr execRetVal)
{
    int status = RETURN_OK;
    int num_vaps = 0;
    int vap_index;
    int radio_index = 0, rc = -1;
    int vap_array_index = 0;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS];
    wifi_vap_name_t vap_names_xfinity[MAX_NUM_RADIOS * 2];
    char brval[32];


    memset(brval,0,sizeof(brval));
    if (!strcmp(vap_prefix,"lnf_psk")) {
        rc = get_managed_guest_bridge(&brval, sizeof(brval));
        if ( rc != 0) {
            wifi_util_dbg_print(WIFI_CTRL,"Managed wifi bridge not found\n");
            strncpy(brval,"brlan15",sizeof(brval)-1);
        }
    }

    if (!strcmp(vap_prefix,"hotspot")){
        /* get a list of VAP names */
        num_vaps= get_list_of_hotspot_open(&data->u.decoded.hal_cap.wifi_prop, MAX_NUM_RADIOS, vap_names_xfinity);
        /* get list of hotspot_secure SSID */
        num_vaps += get_list_of_hotspot_secure(&data->u.decoded.hal_cap.wifi_prop, MAX_NUM_RADIOS, &vap_names_xfinity[num_vaps]);
    }
    else {
        num_vaps = get_list_of_vap_names(&data->u.decoded.hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS, 1, vap_prefix);
    }

    for (int index = 0; index < num_vaps; index++) {
        if (!strcmp(vap_prefix,"hotspot")) {
            /* from VAP name, obtain radio index and array index within the radio */
            vap_index = convert_vap_name_to_index(&data->u.decoded.hal_cap.wifi_prop, vap_names_xfinity[index]);
        } else {
            /* from VAP name, obtain radio index and array index within the radio */
            vap_index = convert_vap_name_to_index(&data->u.decoded.hal_cap.wifi_prop, vap_names[index]);
        }
        status = get_vap_and_radio_index_from_vap_instance(&data->u.decoded.hal_cap.wifi_prop, vap_index, (uint8_t *)&radio_index, (uint8_t *)&vap_array_index);
        if (status == RETURN_ERR) {
            break;
        }
        /* fill the VAP info with current settings */
        if (!strcmp(vap_prefix,"hotspot")) {
            if (update_vap_info_managed_xfinity(blob, &data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index], execRetVal) == RETURN_ERR) {
                status = RETURN_ERR;
                break;
            }
        } else if (!strcmp(vap_prefix,"lnf_psk")) {
            if(update_vap_info_managed_guest(blob, &data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index], brval,managed_wifi_enabled, execRetVal) == RETURN_ERR) {
                status = RETURN_ERR;
                break;
            }
         } else {
            if (update_vap_info(blob, &data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index], execRetVal) == RETURN_ERR) {
                status = RETURN_ERR;
                break;
            }
        }
    }

    return status;
}
static int push_blob_data(webconfig_subdoc_data_t *data, webconfig_subdoc_type_t subdoc_type)
{
    char *str;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (webconfig_encode(&ctrl->webconfig, data, subdoc_type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode for subdoc type %d\n", __FUNCTION__, __LINE__, subdoc_type);
        return RETURN_ERR;
    }

    str = data->u.encoded.raw;
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Encoded blob:\n%s\n", __func__, __LINE__, str);
    push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data_webconfig, NULL);

    webconfig_data_free(data);

    return RETURN_OK;
}

static pErr private_home_exec_common_handler(void *blob, const char *vap_prefix, webconfig_subdoc_type_t subdoc_type)
{
    pErr execRetVal = NULL;
    webconfig_subdoc_data_t *data = NULL;
    if (blob == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return NULL;
    }
    wifi_util_error_print(WIFI_CTRL, "%s: %d\n", __func__,__LINE__);

    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                              __func__, sizeof(webconfig_subdoc_data_t));
        goto done;
    }

    execRetVal = create_execRetVal();
    if (execRetVal == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        goto done;
    }
    webconfig_init_subdoc_data(data);

    if (update_vap_info_with_blob_info(blob, data, vap_prefix, false, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        goto done;
    }

    if (push_blob_data(data, subdoc_type) != RETURN_OK) {
        execRetVal->ErrorCode = WIFI_HAL_FAILURE;
        strncpy(execRetVal->ErrorMsg, "push_blob_to_ctrl_queue failed", sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_error_print(WIFI_CTRL, "%s: failed to encode %s subdoc\n", \
                              __func__, (subdoc_type == webconfig_subdoc_type_private) ? "private" : "home");
        goto done;
    }

done:
    if (data) {
        free(data);
    }
    return execRetVal;
}

static int connected_subdoc_handler(void *blob, char *vap_prefix, webconfig_subdoc_type_t subdoc_type,bool  managed_wifi_enabled, pErr execRetVal)
{
    int ret = RETURN_ERR;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS];
    int num_vaps = 0,i = 0, vap_index = 0;
    webconfig_subdoc_data_t *data = NULL;
    wifi_interface_name_t *lnf_psk_ifname = NULL;
    char managed_interfaces[128];

    memset(managed_interfaces,0,sizeof(managed_interfaces));

    if (blob == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return ret;
    }

    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                              __func__, sizeof(webconfig_subdoc_data_t));
        goto done;
    }

    webconfig_init_subdoc_data(data);

    if (update_vap_info_with_blob_info(blob, data, vap_prefix, managed_wifi_enabled, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        goto done;
    }
    if (push_blob_data(data, subdoc_type) != RETURN_OK) {
        execRetVal->ErrorCode = WIFI_HAL_FAILURE;
        strncpy(execRetVal->ErrorMsg, "push_blob_to_ctrl_queue failed", sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_error_print(WIFI_CTRL, "%s: failed to encode %s subdoc\n", \
                              __func__, (subdoc_type == webconfig_subdoc_type_lnf) ? "lnf_psk" : "xfinity");
        goto done;
    }

    if (strcmp(vap_prefix,"lnf_psk")== 0) {
        num_vaps = get_list_of_vap_names(&data->u.decoded.hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS, 1, VAP_PREFIX_LNF_PSK);

        wifi_util_error_print(WIFI_CTRL, "%s: num_vaps =%d \n", __func__,num_vaps);
        for (i =0; i < num_vaps; i++) {
            vap_index = convert_vap_name_to_index(&data->u.decoded.hal_cap.wifi_prop, vap_names[i]);
            lnf_psk_ifname = get_interface_name_for_vap_index(vap_index,(&data->u.decoded.hal_cap.wifi_prop));

            if ((lnf_psk_ifname != NULL) &&(strlen(managed_interfaces) == 0) && managed_wifi_enabled) {
                snprintf(managed_interfaces,sizeof(managed_interfaces),"ManagedWifi:%s",*lnf_psk_ifname);
            } else if ((lnf_psk_ifname != NULL) && managed_wifi_enabled) {
               strncat(managed_interfaces,",",2);
               strncat(managed_interfaces,*lnf_psk_ifname,strlen(*lnf_psk_ifname));
            } else {
                wifi_util_error_print(WIFI_CTRL, "%s: managed_wifi_enabled is false \n", __func__);
                strncpy(managed_interfaces,"ManagedWifi:",sizeof(managed_interfaces)-1);
            }
        }
        wifi_util_info_print(WIFI_CTRL, "managed_interfaces = %s and lnf_psk_ifname=%s\n",managed_interfaces,(char *)lnf_psk_ifname);
        set_managed_guest_interfaces(managed_interfaces);
    }
    ret = RETURN_OK;
done:
    if (data) {
        free(data);
    }
   return ret;
}

pErr wifi_private_vap_exec_handler(void *blob)
{
    return private_home_exec_common_handler(blob, VAP_PREFIX_PRIVATE, webconfig_subdoc_type_private);
}

pErr wifi_home_vap_exec_handler(void *blob)
{
    return private_home_exec_common_handler(blob, VAP_PREFIX_IOT, webconfig_subdoc_type_home);

}

#define MAX_JSON_BUFSIZE 21240

char *unpackDecode(const char* enb)
{
    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;

    msg_size = b64_get_decoded_buffer_size(strlen((char *)enb));
    msg = (unsigned char *) calloc(sizeof(unsigned char), msg_size);
    if (!msg) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory.\n",__FUNCTION__);
        return NULL;
    }

    msg_size = 0;
    msg_size = b64_decode((unsigned char *)enb, strlen((char *)enb),msg );

    if (msg_size == 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        free(msg);
        return NULL;
    }

    msgpack_zone msg_z;
    msgpack_object msg_obj;

    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    if(msgpack_unpack((const char*)msg, (size_t)msg_size, NULL, &msg_z, &msg_obj) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_zone_destroy(&msg_z);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to unpack blob\n", __func__);
        return NULL;
    }

    char *dej = (char*)malloc(MAX_JSON_BUFSIZE);
    if(dej == NULL) {
        msgpack_zone_destroy(&msg_z);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return NULL;
    }

    memset(dej, 0, MAX_JSON_BUFSIZE);
    int json_len = msgpack_object_print_jsonstr(dej, MAX_JSON_BUFSIZE, msg_obj);
    if(json_len <= 0) {
        msgpack_zone_destroy(&msg_z);
        free(dej);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: json conversion failure\n", __func__);
        return NULL;
    }

    msgpack_zone_destroy(&msg_z);
//    wifi_util_dbg_print(WIFI_CTRL, "%s, blob\n%s\n", __func__, dej);
    return dej; // decoded, unpacked json - caller should free memory
}

bool webconf_ver_txn(const char* bb, uint32_t *ver, uint16_t *txn)
{
    cJSON *root = cJSON_Parse(bb);
    if(root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return false;
    }

    cJSON *c_ver = cJSON_GetObjectItemCaseSensitive(root, "version");
    if(c_ver == NULL) {
       cJSON_Delete(root);       wifi_util_error_print(WIFI_CTRL, "%s, Failed to get version\n", __func__ );
       return false;
    }
    cJSON *c_txn = cJSON_GetObjectItem(root, "transaction_id");
    if(c_txn == NULL) {
       cJSON_Delete(root);
       wifi_util_error_print(WIFI_CTRL, "%s, Failed to get transaction_id\n", __func__ );
       return false;
    }

    *ver = (uint32_t)c_ver->valuedouble;
    *txn = (uint16_t)c_txn->valuedouble;
    wifi_util_dbg_print(WIFI_CTRL, "%s, ver: %u, txn: %u\n", __func__, *ver, *txn);

    cJSON_Delete(root);

    return true;
}
bool webconfig_to_wifi_update_params(const char* raw)
{
    webconfig_t *config;
    webconfig_subdoc_data_t data = {0};
    wifi_ctrl_t *ctrl = (wifi_ctrl_t*)get_wifictrl_obj();
    wifi_mgr_t *mgr = (wifi_mgr_t*)get_wifimgr_obj();

    config = &ctrl->webconfig;
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
    if (webconfig_decode(config, &data, raw) == webconfig_error_none && webconfig_data_free(&data) == webconfig_error_none)
    {
        wifi_util_info_print(WIFI_CTRL,"%s:%d: WebConfig blob has been successfully applied\n",__FUNCTION__,__LINE__);
        return true;
    }
    wifi_util_error_print(WIFI_CTRL,"%s:%d: WebConfig blob apply has failed\n",__FUNCTION__,__LINE__);
    return false;
}

pErr wifi_vap_cfg_subdoc_handler(void *data)
{
    pErr execRetVal = NULL;
    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    execRetVal = create_execRetVal();
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return NULL;
    }
    memset(execRetVal,0,(sizeof(Err)));
    if(data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        if (execRetVal) {
            execRetVal->ErrorCode = VALIDATION_FALIED;
            strncpy(execRetVal->ErrorMsg, "Empty subdoc", sizeof(execRetVal->ErrorMsg)-1);
        }
        return execRetVal;
    }

    msg_size = b64_get_decoded_buffer_size(strlen((char *)data));
    msg = (unsigned char *) calloc(sizeof(unsigned char), msg_size);
    if (!msg) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory.\n",__FUNCTION__);
        strncpy(execRetVal->ErrorMsg, "Failed to allocate memory", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        return execRetVal;
    }

    msg_size = 0;
    msg_size = b64_decode((unsigned char *)data, strlen((char *)data), msg );
    if (msg_size == 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        free(msg);
        strncpy(execRetVal->ErrorMsg, "Failed  in Decoding multicomp blob", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        return execRetVal;
    }

    wifidb_print("%s:%d [Start] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());

    msgpack_zone msg_z;
    msgpack_object msg_obj;

    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    if(msgpack_unpack((const char*)msg, (size_t)msg_size, NULL, &msg_z, &msg_obj) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Msg unpack failed", sizeof(execRetVal->ErrorMsg)-1);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to unpack blob\n", __func__);
        return execRetVal;
    }

    char *blob_buf = (char*)malloc(MAX_JSON_BUFSIZE);
    if(blob_buf == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "blob mem alloc failure", sizeof(execRetVal->ErrorMsg)-1);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return execRetVal;
    }
    memset(blob_buf, 0, MAX_JSON_BUFSIZE);
    int json_len = msgpack_object_print_jsonstr(blob_buf, MAX_JSON_BUFSIZE, msg_obj);
    if(json_len <= 0) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "json conversion failure", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        wifi_util_error_print(WIFI_CTRL, "%s: json conversion failure\n", __func__);
        return execRetVal;
    }

    //wifi_util_dbg_print(WIFI_CTRL, "%s, blob\n%s\n", __func__, blob_buf);

    cJSON *root = cJSON_Parse(blob_buf);
    if(root == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "json parse failure", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return execRetVal;
    }

    cJSON *vap_blob = cJSON_DetachItemFromObject(root, "WifiVapConfig");
    if(vap_blob == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Failed to detach WifiVapConfig", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to detach WifiVapConfig\n", __func__);
        return execRetVal;
    }

    cJSON_Delete(root); // don't need this anymore

    // wifi_util_dbg_print(WIFI_CTRL, "%s, vap_blob arr sz: %d\n", __func__, cJSON_GetArraySize(vap_blob));
    wifi_mgr_t *mgr = get_wifimgr_obj();

    int status = RETURN_OK;
    cJSON *vb_entry = NULL;
    cJSON_ArrayForEach(vb_entry, vap_blob) {
        cJSON *nm_o = cJSON_GetObjectItem(vb_entry, "VapName");
        if((nm_o == NULL) || (cJSON_IsString(nm_o) == false)) {
            wifi_util_error_print(WIFI_CTRL, "%s: Missing VapName\n", __func__);

          continue;
        }
        char *nm_s = cJSON_GetStringValue(nm_o);

        int rindx = convert_vap_name_to_radio_array_index(&mgr->hal_cap.wifi_prop, nm_s);
        if(rindx == -1) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get radio_index for %s\n", __func__, nm_s);
            continue;
        }
        unsigned int vindx;
        int vapArrayIndex = 0;
        if(getVAPIndexFromName(nm_s, &vindx) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get vap_index for %s\n", __func__, nm_s);
            continue;
        }
        vapArrayIndex = convert_vap_name_to_array_index(&mgr->hal_cap.wifi_prop, nm_s);
        if (vapArrayIndex == -1) {
            wifi_util_dbg_print(WIFI_CTRL, "%s: Failed to get vap_array_index for %s\n", __func__, nm_s);
            continue;
        }
        char br_name[32];
        memset(br_name, 0, sizeof(br_name));
        if(get_vap_interface_bridge_name(vindx, br_name) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get bridge name for vap_index %d\n", __func__, vindx);
            continue;
        }
        wifi_vap_info_map_t *wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(rindx);
        if(wifi_vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get vap map for radio_index %d\n", __func__, rindx);
            continue;
        }
        rdk_vap_info = get_wifidb_rdk_vap_info(wifi_vap_map->vap_array[vapArrayIndex].vap_index);
        if(rdk_vap_info == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get rdk_vap_info from vap)index %d\n", __func__, rindx);
            continue;
        }

        cJSON_AddNumberToObject(vb_entry, "RadioIndex", rindx);
        cJSON_AddNumberToObject(vb_entry, "VapMode", 0);
        cJSON_AddItemToObject(vb_entry, "BridgeName", cJSON_CreateString(br_name));
        cJSON_AddItemToObject(vb_entry, "BSSID", cJSON_CreateString("00:00:00:00:00:00"));
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
       if(rdk_vap_info->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
           if(wifi_vap_map->vap_array[vapArrayIndex].vap_index != 2 && wifi_vap_map->vap_array[vapArrayIndex].vap_index != 3) {
               wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,wifi_vap_map->vap_array[vapArrayIndex].vap_index);
               rdk_vap_info->exists = true;
           }
#else
           wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,wifi_vap_map->vap_array[vapArrayIndex].vap_index);
           rdk_vap_info->exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
       }
#endif /* !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_) */
        cJSON_AddBoolToObject(vb_entry, "Exists", rdk_vap_info->exists);

        cJSON_AddBoolToObject(vb_entry, "MacFilterEnable", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.mac_filter_enable);
        cJSON_AddNumberToObject(vb_entry, "MacFilterMode", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.mac_filter_mode);
        cJSON_AddBoolToObject(vb_entry, "WmmEnabled", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wmm_enabled);
        cJSON_AddBoolToObject(vb_entry, "UapsdEnabled", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.UAPSDEnabled);
        cJSON_AddNumberToObject(vb_entry, "BeaconRate", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRate);
        cJSON_AddNumberToObject(vb_entry, "WmmNoAck", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wmmNoAck);
        cJSON_AddNumberToObject(vb_entry, "WepKeyLength", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wepKeyLength);
        cJSON_AddBoolToObject(vb_entry, "BssHotspot", true);
        cJSON_AddNumberToObject(vb_entry, "WpsPushButton", 0);
        cJSON_AddBoolToObject(vb_entry, "WpsEnable", false);
        if(strstr(nm_s, "private") != NULL) {
            cJSON_AddNumberToObject(vb_entry, "WpsConfigMethodsEnabled", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wps.methods);
            cJSON_AddItemToObject(vb_entry, "WpsConfigPin", cJSON_CreateString(wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wps.pin));
        }
        if(wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRateCtl[0] != 0) {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRateCtl);
        }
        else {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", "6Mbps");
        }
       cJSON *connected_building_enabled_o = cJSON_GetObjectItem(vb_entry, "Connected_building_enabled");
        if (connected_building_enabled_o == NULL) {
            wifi_util_dbg_print(WIFI_CTRL, "connected_building_enabled param is not present\n");
            cJSON_AddBoolToObject(vb_entry,"Connected_building_enabled",wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.connected_building_enabled);
        }

        cJSON_AddStringToObject(vb_entry, "RepurposedVapName", wifi_vap_map->vap_array[vapArrayIndex].repurposed_vap_name);

        cJSON_AddBoolToObject(vb_entry, "HostapMgtFrameCtrl", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.hostap_mgt_frame_ctrl);
        cJSON_AddBoolToObject(vb_entry, "MboEnabled",
            wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.mbo_enabled);

        char* extra_vendor_ies_hex_str = ( char* )malloc(sizeof(char) * ((wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.vendor_elements_len * 2) + 1));
        if (extra_vendor_ies_hex_str != NULL) {
            memset(extra_vendor_ies_hex_str, 0, sizeof(char) * ((wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.vendor_elements_len * 2) + 1));
            for (unsigned int i = 0; i < wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.vendor_elements_len; i++) {
                sprintf(extra_vendor_ies_hex_str + (i * 2), "%02x", (unsigned int) wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.vendor_elements[i]);
            }
            cJSON_AddStringToObject(vb_entry, "ExtraVendorIEs", extra_vendor_ies_hex_str);

            free(extra_vendor_ies_hex_str);
            extra_vendor_ies_hex_str = NULL;
        }
        else {
            cJSON_AddStringToObject(vb_entry, "ExtraVendorIEs", "");
        }

        cJSON *vapConnectionControl_o = cJSON_GetObjectItem(vb_entry, "VapConnectionControl");
        if (vapConnectionControl_o == NULL) {
            wifi_util_info_print(WIFI_CTRL, "vapConnectionContro param is not present\n");
            vapConnectionControl_o = cJSON_AddObjectToObject(vb_entry,"VapConnectionControl");

            cJSON *PreAssocDeny =  cJSON_AddObjectToObject(vapConnectionControl_o,"PreAssociationDeny");
            cJSON_AddStringToObject(PreAssocDeny, "RssiUpThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.rssi_up_threshold);
            cJSON_AddStringToObject(PreAssocDeny, "SnrThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.snr_threshold);
            cJSON_AddStringToObject(PreAssocDeny, "CuThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.cu_threshold);
            cJSON_AddStringToObject(PreAssocDeny, "BasicDataTransmitRates", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.basic_data_transmit_rates);
            cJSON_AddStringToObject(PreAssocDeny, "OperationalDataTransmitRates", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.operational_data_transmit_rates);
            cJSON_AddStringToObject(PreAssocDeny, "SupportedDataTransmitRates", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.supported_data_transmit_rates);
            cJSON_AddStringToObject(PreAssocDeny, "MinimumAdvertisedMCS", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.minimum_advertised_mcs);
            cJSON_AddStringToObject(PreAssocDeny, "6GOpInfoMinRate", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.sixGOpInfoMinRate);

            cJSON *PostAssocDeny =  cJSON_AddObjectToObject(vapConnectionControl_o,"PostAssociationDeny");
            cJSON_AddStringToObject(PostAssocDeny, "RssiUpThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.rssi_up_threshold);
            cJSON_AddStringToObject(PostAssocDeny, "SnrThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.snr_threshold);
            cJSON_AddStringToObject(PostAssocDeny, "CuThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.cu_threshold);
            cJSON_AddStringToObject(PostAssocDeny, "SamplingInterval", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.sampling_interval);
            cJSON_AddStringToObject(PostAssocDeny, "SamplingCount", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.sampling_count);
      }
        else {
            wifi_util_info_print(WIFI_CTRL, "vapConnectionContro param is present in blob\n");
        }

        const cJSON *value = cJSON_GetObjectItem(vapConnectionControl_o, "TcmPreAssociationDeny");     
        if ((value == NULL) || (cJSON_IsObject(value) == false))
        {
            cJSON *TcmPreAssocDeny =  cJSON_AddObjectToObject(vapConnectionControl_o,"TcmPreAssociationDeny");
            cJSON_AddNumberToObject(TcmPreAssocDeny, "TcmWaitTime", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.time_ms);
            cJSON_AddNumberToObject(TcmPreAssocDeny, "TcmMinMgmtFrames", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.min_num_mgmt_frames);
            cJSON_AddStringToObject(TcmPreAssocDeny, "TcmExpWeightage", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.tcm_exp_weightage);
            cJSON_AddStringToObject(TcmPreAssocDeny, "TcmGradientThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.tcm_gradient_threshold);
        }

        /*
        Correct integrity of interworking field in the VAP object is very important. Let's check it here to avoid
        reporting code 300 (SUCCESS) for webconfig agent even if it's not correct.
        */
        cJSON *interworking_o = cJSON_GetObjectItem(vb_entry, "Interworking");
        if(interworking_o == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get Interworking obj for %s\n", __func__, nm_s);
            continue;
        }

        if ((status = early_validate_interworking(interworking_o,  execRetVal)) != RETURN_OK) {
            break;
        }

        if(strstr(nm_s, "hotspot_secure") == NULL) { continue; }

        cJSON *sec_o = cJSON_GetObjectItem(vb_entry, "Security");
        if(sec_o == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get Security obj for %s\n", __func__, nm_s);
            continue;
        }

        cJSON_AddBoolToObject(sec_o, "Wpa3_transition_disable", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.wpa3_transition_disable);
        cJSON_AddNumberToObject(sec_o, "RekeyInterval", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.rekey_interval);
        cJSON_AddBoolToObject(sec_o, "StrictRekey", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.strict_rekey);
        cJSON_AddNumberToObject(sec_o, "EapolKeyTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eapol_key_timeout);
        cJSON_AddNumberToObject(sec_o, "EapolKeyRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eapol_key_retries);
        cJSON_AddNumberToObject(sec_o, "EapIdentityReqTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_identity_req_timeout);
        cJSON_AddNumberToObject(sec_o, "EapIdentityReqRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_identity_req_retries);
        cJSON_AddNumberToObject(sec_o, "EapReqTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_req_timeout);
        cJSON_AddNumberToObject(sec_o, "EapReqRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_req_retries);
        cJSON_AddBoolToObject(sec_o, "DisablePmksaCaching", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.disable_pmksa_caching);

      cJSON *rad_o = cJSON_GetObjectItem(sec_o, "RadiusSettings");
        if(rad_o == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get RadiusSettings obj for %s\n", __func__, nm_s);
            continue;
        }

        char dasIpAddr[32];
        memset(dasIpAddr, 0, sizeof(dasIpAddr));
        int das_ip_r = getIpStringFromAdrress(dasIpAddr, &wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.dasip);
        if(das_ip_r == 1) {
            cJSON_AddItemToObject(rad_o, "DasServerIPAddr", cJSON_CreateString(dasIpAddr));
        }
        else {
            cJSON_AddItemToObject(rad_o, "DasServerIPAddr", cJSON_CreateString("0.0.0.0"));
        }
        cJSON_AddNumberToObject(rad_o, "DasServerPort", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.dasport);
        if(wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.daskey[0] != 0) {
            cJSON_AddStringToObject(rad_o, "DasSecret", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.daskey);
        }
        else {
            cJSON_AddStringToObject(rad_o, "DasSecret", INVALID_KEY);
        }
        cJSON_AddNumberToObject(rad_o, "MaxAuthAttempts", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.max_auth_attempts);
        cJSON_AddNumberToObject(rad_o, "BlacklistTableTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.blacklist_table_timeout);
        cJSON_AddNumberToObject(rad_o, "IdentityReqRetryInterval", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.identity_req_retry_interval);
        cJSON_AddNumberToObject(rad_o, "ServerRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.server_retries);
    }

    if (status == RETURN_OK) {
        cJSON *n_blob = cJSON_CreateObject();
        cJSON_AddItemToObject(n_blob, "Version", cJSON_CreateString("1.0"));
        cJSON_AddItemToObject(n_blob, "SubDocName", cJSON_CreateString("xfinity"));
        cJSON_AddItemToObject(n_blob, "WifiVapConfig", vap_blob);

        char *vap_blob_str = cJSON_Print(n_blob);
        wifi_util_dbg_print(WIFI_CTRL,"WebConfig blob is %s\n",vap_blob_str);
        if (webconfig_to_wifi_update_params(vap_blob_str))
        {
            execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
        }
        else
        {
            execRetVal->ErrorCode = VALIDATION_FALIED;
            wifi_util_error_print(WIFI_CTRL, "%s(): Validation failed: %s\n", __FUNCTION__, execRetVal->ErrorMsg);
        }

        cJSON_free(vap_blob_str);
        cJSON_Delete(n_blob);
        execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    }
    else {
        execRetVal->ErrorCode = VALIDATION_FALIED;
        wifi_util_error_print(WIFI_CTRL, "%s(): Validation failed: %s\n", __FUNCTION__, execRetVal->ErrorMsg);
    }

    free(blob_buf);
    msgpack_zone_destroy(&msg_z);
    free(msg);

    return execRetVal;
}
static pErr create_execRetVal(void)
{
    pErr execRetVal;

    execRetVal = (pErr) malloc(sizeof(Err));
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return execRetVal;
    }

    memset(execRetVal,0,(sizeof(Err)));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;

    return execRetVal;
}

pErr webconf_process_managed_subdoc(void* data)
{
    pErr execRetVal = NULL;
    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;
    int ret = RETURN_ERR;
    bool connected_wifi_enabled = false;

    execRetVal = create_execRetVal();
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return NULL;
    }
    memset(execRetVal,0,(sizeof(Err)));
    if(data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        if (execRetVal) {
            execRetVal->ErrorCode = VALIDATION_FALIED;
            strncpy(execRetVal->ErrorMsg, "Empty subdoc", sizeof(execRetVal->ErrorMsg)-1);
        }
        return execRetVal;
    }


    msg_size = b64_get_decoded_buffer_size(strlen((char *)data));
    msg = (unsigned char *) calloc(sizeof(unsigned char), msg_size);
    if (!msg) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory.\n",__FUNCTION__);
        strncpy(execRetVal->ErrorMsg, "Failed to allocate memory", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        return execRetVal;
    }

    msg_size = 0;
    msg_size = b64_decode((unsigned char *)data, strlen((char *)data), msg );
    if (msg_size == 0) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        free(msg);
        strncpy(execRetVal->ErrorMsg, "Failed in Decoding multicomp blob", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;

        return execRetVal;
    }

    wifidb_print("%s:%d [Start] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());

    msgpack_zone msg_z;
    msgpack_object msg_obj;

    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    if(msgpack_unpack((const char*)msg, (size_t)msg_size, NULL, &msg_z, &msg_obj) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Msg unpack failed", sizeof(execRetVal->ErrorMsg)-1);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to unpack blob\n", __func__);
        return execRetVal;
    }

    char *blob_buf = (char*)malloc(MAX_JSON_BUFSIZE);
    if(blob_buf == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "blob mem alloc failure", sizeof(execRetVal->ErrorMsg)-1);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return execRetVal;
    }
    memset(blob_buf, 0, MAX_JSON_BUFSIZE);
    int json_len = msgpack_object_print_jsonstr(blob_buf, MAX_JSON_BUFSIZE, msg_obj);
    if(json_len <= 0) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "json conversion failure", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: json conversion failure\n", __func__);
        return execRetVal;
    }

    wifi_util_info_print(WIFI_CTRL, "%s, Managed wifi blob\n%s\n", __func__, blob_buf);


  cJSON *root = cJSON_Parse(blob_buf);
    if(root == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "json parse failure", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return execRetVal;
    }
    cJSON *managed_wifi_enabled = cJSON_GetObjectItem(root, "ManagedWifiEnabled");
    if (managed_wifi_enabled == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Failed to Get ManagedWifiEnabled", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to Get ManagedWifiEnabled\n", __func__);
        return execRetVal;
    }
    connected_wifi_enabled = cJSON_IsTrue(managed_wifi_enabled)? true : false;
    wifi_util_dbg_print(WIFI_CTRL,"managed_wifi_enabled is %d\n",connected_wifi_enabled);

    cJSON *vap_blob = cJSON_DetachItemFromObject(root, "WifiVapConfig");
    if(vap_blob == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Failed to detach WifiVapConfig", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to detach WifiVapConfig\n", __func__);
        return execRetVal;
    }
    ret = connected_subdoc_handler(vap_blob, VAP_PREFIX_LNF_PSK, webconfig_subdoc_type_lnf, connected_wifi_enabled,  execRetVal);
    if (ret != RETURN_OK) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        free(blob_buf);
    free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to detach xfinity_blob\n", __func__);
        return execRetVal;
    }
    cJSON *xfinity_blob = cJSON_DetachItemFromObject(root, "xfinityWifiVapConfig");
    if(xfinity_blob == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Failed to detach xfinity_blob", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to detach xfinity_blob\n", __func__);
        return execRetVal;
    }

    ret = connected_subdoc_handler(xfinity_blob, VAP_PREFIX_HOTSPOT, webconfig_subdoc_type_xfinity, connected_wifi_enabled, execRetVal);
    if (ret != RETURN_OK) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to update connectedbuilding AVPs in  Xfinity vaps \n", __func__);
        return execRetVal;
    }
    if (connected_wifi_enabled) {
        wifi_util_info_print(WIFI_CTRL,"lnf_psk vaps are repurposed to managed_guest\n");
    } else {
        wifi_util_info_print(WIFI_CTRL,"managed_guest vaps are reverted back to lnf_psk\n");
    }


    wifi_util_info_print(WIFI_CTRL,"Managed guest blob is applied successfuly \n");
    cJSON_Delete(root); // don't need this anymore

    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    return execRetVal;
}


#endif

int register_multicomp_subdocs()
{
#ifdef ONEWIFI_RDKB_APP_SUPPORT
    // PAM delivers xfinity blob  and connectedbuilding blobs as hotspot,connectedbuilding - so OneWifi will register for both blobs
    char *multi_sub_docs[MULTI_COMP_SUPPORTED_SUBDOC_COUNT+1]= {"hotspot","connectedbuilding",(char *) 0 };
    multiCompSubDocReg *multiCompData = NULL ;
    multiCompData = (multiCompSubDocReg*) malloc(MULTI_COMP_SUPPORTED_SUBDOC_COUNT * sizeof(multiCompSubDocReg));
    memset(multiCompData, 0, MULTI_COMP_SUPPORTED_SUBDOC_COUNT * sizeof(multiCompSubDocReg));
    multiCompSubDocReg *multiCompDataPointer = multiCompData ;
    int j ;

    for (j=0; j < MULTI_COMP_SUPPORTED_SUBDOC_COUNT ; j++ )
    {
        strncpy(multiCompDataPointer->multi_comp_subdoc , multi_sub_docs[j], sizeof(multiCompDataPointer->multi_comp_subdoc)-1) ;
        if ( strcmp(multiCompDataPointer->multi_comp_subdoc,"hotspot") == 0 )
        {
            multiCompDataPointer->executeBlobRequest = wifi_vap_cfg_subdoc_handler;
        }
        else if ( strcmp(multiCompDataPointer->multi_comp_subdoc,"connectedbuilding") == 0 )
        {
            multiCompDataPointer->executeBlobRequest = webconf_process_managed_subdoc;
        }

        multiCompDataPointer->calcTimeout = wifi_vap_cfg_timeout_handler;
        multiCompDataPointer->rollbackFunc = wifi_vap_cfg_rollback_handler;
        multiCompDataPointer->freeResources = NULL;
        multiCompDataPointer++ ;
    }
    multiCompDataPointer = multiCompData ;
    register_MultiComp_subdoc_handler(multiCompData,MULTI_COMP_SUPPORTED_SUBDOC_COUNT);
#endif
    return RETURN_OK;
}

static char *sub_docs[] = { "privatessid", "homessid", (char *)0 };
int register_single_subdocs()
{
#ifdef ONEWIFI_RDKB_APP_SUPPORT
    int sd_sz = sizeof(sub_docs)/sizeof(char*) - 1; // not counting 0 in array

    blobRegInfo *blob_data = (blobRegInfo*) malloc(sd_sz * sizeof(blobRegInfo));
    if (blob_data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Malloc error\n", __func__);
        return RETURN_ERR;
    }
    memset(blob_data, 0, sd_sz * sizeof(blobRegInfo));

    blobRegInfo *blob_data_pointer = blob_data;
    for (int i=0 ;i < sd_sz; i++)
    {
        strncpy(blob_data_pointer->subdoc_name, sub_docs[i], sizeof(blob_data_pointer->subdoc_name)-1);
        blob_data_pointer++;
    }
    blob_data_pointer = blob_data;

    getVersion version_get = get_wifi_blob_version;
    setVersion version_set = set_wifi_blob_version;

    register_sub_docs(blob_data, sd_sz, version_get, version_set);

#endif
    return RETURN_OK;

}
void process_managed_wifi_disable ()
{
#ifdef ONEWIFI_RDKB_APP_SUPPORT
    int ret = RETURN_ERR;
    pErr execRetVal = NULL;

    wifi_util_info_print(WIFI_CTRL,"Enter %s:%d\n", __func__, __LINE__);
    execRetVal = create_execRetVal();
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return ;
    }

    cJSON *managed_blob = cJSON_CreateObject();
    cJSON_AddBoolToObject(managed_blob, "connected_building_enabled", false);


    ret = connected_subdoc_handler(managed_blob, VAP_PREFIX_LNF_PSK, webconfig_subdoc_type_lnf, false,  execRetVal);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:Managed LNF vaps were not disabled \n", __func__);
    }
    ret = connected_subdoc_handler(managed_blob, VAP_PREFIX_HOTSPOT, webconfig_subdoc_type_xfinity, false, execRetVal);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:Managed xfinity vaps were not disabled \n", __func__);
    }

    wifi_util_info_print(WIFI_CTRL,"managed_guest vaps are reverted back to lnf_psk\n");
    free(execRetVal);
    cJSON_Delete(managed_blob);
#endif
}

void webconf_process_private_vap(const char* enb)
{
#ifdef ONEWIFI_RDKB_APP_SUPPORT
    char *blob_buf = unpackDecode(enb);
    if(blob_buf == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s, Invalid Json\n", __func__ );
        return;
    }

    uint32_t t_version = 0;
    uint16_t tx_id = 0;
    if(!webconf_ver_txn(blob_buf, &t_version, &tx_id)) {
        free(blob_buf);
        wifi_util_error_print(WIFI_CTRL, "%s, Invalid json, no version or transaction Id\n", __func__ );
        return;
    }

    execData *execDataPf = (execData*) malloc (sizeof(execData));
    if (execDataPf != NULL) {
        memset(execDataPf, 0, sizeof(execData));
        execDataPf->txid = tx_id;
        execDataPf->version = t_version;
        execDataPf->numOfEntries = 1;
        strncpy(execDataPf->subdoc_name, "privatessid", sizeof(execDataPf->subdoc_name)-1);
        execDataPf->user_data = (void*) blob_buf;
        execDataPf->calcTimeout = webconf_timeout_handler;
        execDataPf->executeBlobRequest = wifi_private_vap_exec_handler;
        execDataPf->rollbackFunc = webconf_rollback_handler;
        execDataPf->freeResources = webconf_free_resources;
        PushBlobRequest(execDataPf);
        wifi_util_info_print(WIFI_CTRL, "%s:%d: PushBlobRequest Complete\n", __func__, __LINE__ );
    }
#endif
}
void webconf_process_home_vap(const char* enb)
{
#ifdef ONEWIFI_RDKB_APP_SUPPORT
    char *blob_buf = unpackDecode(enb);
    if(blob_buf == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s, Invalid Json\n", __func__ );
        return;
    }

    uint32_t t_version = 0;
    uint16_t tx_id = 0;
    if(!webconf_ver_txn(blob_buf, &t_version, &tx_id)) {
        free(blob_buf);
        wifi_util_error_print(WIFI_CTRL, "%s, Invalid json, no version or transaction Id\n", __func__ );
        return;
    }

    execData *execDataPf = (execData*) malloc (sizeof(execData));
    if (execDataPf != NULL) {
        memset(execDataPf, 0, sizeof(execData));
        execDataPf->txid = tx_id;
        execDataPf->version = t_version;
        execDataPf->numOfEntries = 1;
        strncpy(execDataPf->subdoc_name, "homessid", sizeof(execDataPf->subdoc_name)-1);
        execDataPf->user_data = (void*) blob_buf;
        execDataPf->calcTimeout = webconf_timeout_handler;
        execDataPf->executeBlobRequest = wifi_home_vap_exec_handler;
        execDataPf->rollbackFunc = webconf_rollback_handler;
        execDataPf->freeResources = webconf_free_resources;
        PushBlobRequest(execDataPf);
        wifi_util_info_print(WIFI_CTRL, "%s:%d: PushBlobRequest Complete\n", __func__, __LINE__ );
    }
#endif
}

extern wifi_mgr_t g_wifi_mgr;

webconfig_error_t webconfig_multi_doc_init()
{
    webconfig_multi_doc_t *desc;
    webconfig_t *config;

    //config  = get_webconfig_obj();
    config = &g_wifi_mgr.ctrl.webconfig;

    desc = &config->multi_doc_desc;

    desc->register_func = register_multicomp_subdocs;
    register_multicomp_subdocs();
    wifi_util_info_print(WIFI_CTRL, "%s:%d: register_multicomp_subdocs\n", __func__, __LINE__ );

    return webconfig_error_none;
}


webconfig_error_t webconfig_single_doc_init()
{
    webconfig_single_doc_t *desc;
    webconfig_t *config;

    //config  = get_webconfig_obj();
    config = &g_wifi_mgr.ctrl.webconfig;
    desc = &config->single_doc_desc;

    desc->register_func = register_single_subdocs;
    register_single_subdocs();
    wifi_util_info_print(WIFI_CTRL, "%s:%d: register_single_subdocs \n", __func__, __LINE__ );
    return webconfig_error_none;
}

