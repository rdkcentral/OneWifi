/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
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
#if defined (FEATURE_SUPPORT_WEBCONFIG)
#include "cosa_apis.h"
#include "cosa_dbus_api.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_internal.h"
#include "ccsp_psm_helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "wifi_hal.h"
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include <arpa/inet.h>
#include "plugin_main_apis.h"
#include "ctype.h"
#include "ccsp_WifiLog_wrapper.h"
#include "secure_wrapper.h"
#include "collection.h"
#include "msgpack.h"
#include "wifi_webconfig.h"
#include "wifi_webconfig_old.h"
#include "wifi_validator.h"
#include "wifi_passpoint.h"
#include "wifi_monitor.h"

#include "webconfig_framework.h"

#include "wifi_util.h"
#include "wifi_ctrl.h"

wifi_vap_info_map_t vap_map_per_radio[MAX_NUM_RADIOS];
static bool global_ssid_updated[MAX_NUM_RADIOS] = {FALSE};
static bool global_updated[MAX_NUM_RADIOS] = {FALSE};
const char *mfp_config_options[3] = {"Disabled", "Optional", "Required"};

webconf_apply_t apply_params;

extern ANSC_HANDLE bus_handle;
extern char   g_Subsystem[32];
webconf_wifi_t *curr_config = NULL;

extern void configWifi(BOOLEAN redirect);

wifi_vap_info_map_t vap_curr_cfg[MAX_NUM_RADIOS];
wifi_global_config_t wifi_cfg;
char num_radio;

char notify_wifi_changes_val[16] = {0};

extern UINT g_interworking_RFC;
extern UINT g_passpoint_RFC;

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

/************************************************************************************
 ************************************************************************************
  Function    : webconf_auth_mode_to_str
  Parameter   : auth_mode_str - authentication mode in string
                sec_mode - authentication mode in  wifi_security_modes_t
  Description : Function to convert authentication mode integer to string
 *************************************************************************************
***************************************************************************************/
void webconf_auth_mode_to_str(char *auth_mode_str, wifi_security_modes_t sec_mode) 
{
    switch(sec_mode)
    {
    case wifi_security_mode_wpa2_personal:
        strcpy(auth_mode_str, "WPA2-Personal");
        break;
    case wifi_security_mode_wpa2_enterprise:
        strcpy(auth_mode_str, "WPA2-Enterprise");
        break;
    case wifi_security_mode_wpa3_personal:
        strcpy(auth_mode_str, "WPA3-Personal");
        break;
    case wifi_security_mode_wpa3_transition:
        strcpy(auth_mode_str, "WPA3-Personal-Transition");
        break;
    case wifi_security_mode_wpa3_enterprise:
        strcpy(auth_mode_str, "WPA3-Enterprise");
        break;
    case wifi_security_mode_none:
        default:
        strcpy(auth_mode_str, "None");
        break;
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_enc_mode_to_str
  Parameter   : enc_mode_str - Encryption mode in string
                enc_mode - Encryption mode in  wifi_encryption_method_t
  Description : Function to convert Encryption mode integer to string
 *************************************************************************************
***************************************************************************************/
void webconf_enc_mode_to_str(char *enc_mode_str,wifi_encryption_method_t enc_mode)
{
    switch(enc_mode)
    {
    case wifi_encryption_tkip:
        strcpy(enc_mode_str, "TKIP");
        break;
    case wifi_encryption_aes:
        strcpy(enc_mode_str, "AES");
        break;
    case wifi_encryption_aes_tkip:
        strcpy(enc_mode_str, "AES+TKIP");
        break;
    default:
        strcpy(enc_mode_str, "None");
        break;
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_auth_mode_to_int
  Parameter   : auth_mode_str - authentication mode in string
                auth_mode - athentication mode in  wifi_security_modes_t
  Description : Function to convert Authentication mode string to Integer
 *************************************************************************************
***************************************************************************************/
void webconf_auth_mode_to_int(char *auth_mode_str, wifi_security_modes_t * auth_mode)
{
    if (strcmp(auth_mode_str, "None") == 0 ) {
        *auth_mode = wifi_security_mode_none;
    }
    else if ((strcmp(auth_mode_str, "WPA2-Personal") == 0)) {
        *auth_mode = wifi_security_mode_wpa2_personal;
    }
    else if (strcmp(auth_mode_str, "WPA2-Enterprise") == 0) {
        *auth_mode = wifi_security_mode_wpa2_enterprise;
    }
    else if (strcmp(auth_mode_str, "WPA3-Enterprise") == 0) {
        *auth_mode = wifi_security_mode_wpa3_enterprise;
    }
    else if ((strcmp(auth_mode_str, "WPA3-Personal") == 0)) {
        *auth_mode = wifi_security_mode_wpa3_personal;
    }
    else if ((strcmp(auth_mode_str, "WPA3-Personal-Transition") == 0)) {
        *auth_mode = wifi_security_mode_wpa3_transition;
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_enc_mode_to_int
  Parameter   : enc_mode_str - Encryted string
                enc_mode     - Encryption method
  Description : Function to convert Encryption mode string to integer
 *************************************************************************************
***************************************************************************************/
void webconf_enc_mode_to_int(char *enc_mode_str, wifi_encryption_method_t *enc_mode)
{
    if ((strcmp(enc_mode_str, "TKIP") == 0)) {
        *enc_mode = wifi_encryption_tkip;
    } else if ((strcmp(enc_mode_str, "AES") == 0)) {
        *enc_mode = wifi_encryption_aes;
    } else if ((strcmp(enc_mode_str, "AES+TKIP") == 0)) {
	*enc_mode = wifi_encryption_aes_tkip;
    }
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_populate_initial_config
  Parameter   : current_config - Pointer to current config wifi structure
                ssid - ssid
  Description : Function to populate TR-181 parameters to wifi structure
 *************************************************************************************
***************************************************************************************/
int webconf_populate_initial_config(webconf_wifi_t *current_config, uint8_t ssid)
{
    wifi_vap_info_map_t *p_vap_map;
    wifi_util_dbg_print(WIFI_CTRL, "%s: start init config\n", __FUNCTION__);

    UINT ap_index, radio_index;
    for (ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++) 
    {
        radio_index = getRadioIndexFromAp(ap_index);
        p_vap_map = get_wifidb_vap_map(radio_index);
	    if(p_vap_map == NULL)
	    {
                wifi_util_dbg_print(WIFI_CTRL, "[%s]: wrong radio_index %d\n", __FUNCTION__, radio_index);
	        return RETURN_ERR;
	    }
	    strncpy(current_config->ssid[radio_index].ssid_name, p_vap_map->vap_array[ap_index].u.bss_info.ssid, WIFI_AP_MAX_SSID_LEN);
        current_config->ssid[radio_index].enable = p_vap_map->vap_array[ap_index].u.bss_info.enabled;
        current_config->ssid[radio_index].ssid_advertisement_enabled = p_vap_map->vap_array[ap_index].u.bss_info.showSsid;
        strncpy(current_config->security[radio_index].passphrase, (char*)p_vap_map->vap_array[ap_index].u.bss_info.security.u.key.key,
                    sizeof(current_config->security[radio_index].passphrase)-1);
        webconf_auth_mode_to_str(current_config->security[radio_index].mode_enabled,
                    p_vap_map->vap_array[ap_index].u.bss_info.security.mode);
        webconf_enc_mode_to_str(current_config->security[radio_index].encryption_method,
                    p_vap_map->vap_array[ap_index].u.bss_info.security.encr);
    }

    return 0;
}
 

/**
 *  Allocates memory to store current configuration
 *  to use in case of rollback
 *
 *  returns 0 on success, error otherwise
 */
int webconf_alloc_current_cfg(uint8_t ssid) {
    if (!curr_config) {
        curr_config = (webconf_wifi_t *) malloc(sizeof(webconf_wifi_t));
        if (!curr_config) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Memory allocation error\n", __FUNCTION__);
            return RETURN_ERR;
        }
        memset(curr_config, 0, sizeof(webconf_wifi_t));
    }
    
    if (webconf_populate_initial_config(curr_config, ssid) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to copy initial configs\n", __FUNCTION__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_update_params
  Parameter   : ps   - pointer to webconf_wifi_t
                ssid - ssid
  Description : Update webconfig parameters
 *************************************************************************************
***************************************************************************************/
int webconf_update_params(webconf_wifi_t *ps, uint8_t ssid) 
{
    wifi_vap_info_map_t *p_vap_map;
    wifi_util_dbg_print(WIFI_CTRL, "%s: webconfig param update\n", __FUNCTION__);

    UINT ap_index, radio_index;
    for (ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++) 
    {
        if ( (ssid == WIFI_WEBCONFIG_PRIVATESSID && isVapPrivate(ap_index)) || (ssid == WIFI_WEBCONFIG_HOMESSID && isVapXhs(ap_index)) )
        {
            radio_index = getRadioIndexFromAp(ap_index);
            if (curr_config->ssid[radio_index].ssid_changed) 
            {
                p_vap_map = get_wifidb_vap_map(radio_index);
	            if(p_vap_map == NULL)
                {
                    wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
                    return RETURN_ERR;
                }

                strncpy(p_vap_map->vap_array[ap_index].u.bss_info.ssid, ps->ssid[radio_index].ssid_name, sizeof(p_vap_map->vap_array[ap_index].u.bss_info.ssid)-1);
                p_vap_map->vap_array[ap_index].u.bss_info.enabled = ps->ssid[radio_index].enable;
                p_vap_map->vap_array[ap_index].u.bss_info.showSsid = ps->ssid[radio_index].ssid_advertisement_enabled;                
                curr_config->ssid[radio_index].ssid_changed = false;
            }

            if (curr_config->security[radio_index].sec_changed) 
            {
                p_vap_map = get_wifidb_vap_map(radio_index);
	            if(p_vap_map == NULL)
                {
                    wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
                    return RETURN_ERR;
                }
                webconf_auth_mode_to_int(ps->security[radio_index].mode_enabled, &p_vap_map->vap_array[ap_index].u.bss_info.security.mode); 
                strncpy((char*)p_vap_map->vap_array[ap_index].u.bss_info.security.u.key.key, ps->security[radio_index].passphrase,sizeof(p_vap_map->vap_array[ap_index].u.bss_info.security.u.key.key)-1);
                //strncpy((char*)pWifiAp->SEC.Cfg.PreSharedKey, ps->security[radio_index].passphrase,sizeof(pWifiAp->SEC.Cfg.PreSharedKey)-1);

                //strncpy((char*)pWifiAp->SEC.Cfg.SAEPassphrase, ps->security[radio_index].passphrase,sizeof(pWifiAp->SEC.Cfg.SAEPassphrase)-1);//TBD -A
                webconf_enc_mode_to_int(ps->security[radio_index].encryption_method, &p_vap_map->vap_array[ap_index].u.bss_info.security.encr);                
                curr_config->security[radio_index].sec_changed = false;
             }

        }
    }

    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_apply_wifi_ssid_params
  Parameter   : pssid_entry  - pointer to webconf_wifi_t
                wlan_index   - AP Index
                exec_ret_val - return value
  Description : Applies Wifi SSID Parameters
 *************************************************************************************
***************************************************************************************/ 
int webconf_apply_wifi_ssid_params (webconf_wifi_t *pssid_entry, uint8_t wlan_index,
                                    pErr exec_ret_val)
{
    int ret_val = RETURN_ERR;
    char *ssid = NULL;
    bool enable = false, adv_enable = false;
    webconf_ssid_t *wlan_ssid = NULL, *cur_conf_ssid = NULL;
    BOOLEAN b_force_disable_flag = FALSE;

    UINT radio_index = getRadioIndexFromAp(wlan_index);
    {
        wlan_ssid = &pssid_entry->ssid[radio_index];
        cur_conf_ssid = &curr_config->ssid[radio_index];        
    }

    ssid = wlan_ssid->ssid_name;
    enable = wlan_ssid->enable;
    adv_enable = wlan_ssid->ssid_advertisement_enabled;

    /* Apply SSID values to hal */
    if ((strcmp(cur_conf_ssid->ssid_name, ssid) != 0) && (!b_force_disable_flag)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDKB_WIFI_CONFIG_CHANGED : %s Calling wifi_setSSID to "
                        "change SSID name on interface: %d SSID: %s \n",__FUNCTION__,wlan_index,ssid);
        t2_event_d("WIFI_INFO_XHCofigchanged", 1);
        
	ret_val = wifi_setSSIDName(wlan_index, ssid);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to apply SSID name for wlan %d\n",__FUNCTION__, wlan_index);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Ssid name apply failed",sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return ret_val;
        }

        ret_val = wifi_pushSSID(wlan_index, ssid);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to push SSID name for wlan %d\n",__FUNCTION__, wlan_index);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Ssid name apply failed",sizeof(exec_ret_val->ErrorMsg)-1);
            } 
            return ret_val;
        }
        strncpy(cur_conf_ssid->ssid_name, ssid, COSA_DML_WIFI_MAX_SSID_NAME_LEN);
        cur_conf_ssid->ssid_changed = true;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: SSID name change applied for wlan %d\n",__FUNCTION__, wlan_index);

        wifi_util_dbg_print(WIFI_WEBCONFIG, "RDK_LOG_INFO,WIFI %s : Notify Mesh of SSID change\n",__FUNCTION__);
        v_secure_system("/usr/bin/sysevent set wifi_SSIDName \"RDK|%d|%s\"",wlan_index, ssid);
        
	if (isVapPrivate(wlan_index))
        {
            global_ssid_updated[getRadioIndexFromAp(wlan_index)] = TRUE;
        }
    } else if (b_force_disable_flag == TRUE) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_WARN, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED \n");
    }

    if ((cur_conf_ssid->enable != enable) && (!b_force_disable_flag)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_WARN,RDKB_WIFI_CONFIG_CHANGED : %s Calling wifi_setEnable"
                        " to enable/disable SSID on interface:  %d enable: %d\n",
                         __FUNCTION__, wlan_index, enable);

        ret_val = wifi_setSSIDEnable(wlan_index, enable);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to set AP Enable for wlan %d\n",__FUNCTION__, wlan_index);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Ssid enable failed",sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return ret_val;
        }
        if (wlan_index == 3) {
            char passph[128]={0};
            wifi_getApSecurityKeyPassphrase(2, passph);
            wifi_setApSecurityKeyPassphrase(3, passph);
            wifi_getApSecurityPreSharedKey(2, passph);
            wifi_setApSecurityPreSharedKey(3, passph);
        }
		
	wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_WARN,WIFI %s wifi_setApEnable success  index %d , %d",
                     __FUNCTION__,wlan_index, enable);

       	wifi_security_modes_t auth_mode;
        webconf_auth_mode_to_int(curr_config->security[getRadioIndexFromAp(wlan_index)].mode_enabled, &auth_mode);

        if (enable) {
            BOOL enable_wps = FALSE;
            ret_val = wifi_getApWpsEnable(wlan_index, &enable_wps);
            if (ret_val != RETURN_OK) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to get Ap Wps Enable\n", __FUNCTION__);
                return ret_val;
            }
            BOOL up;
            char status[64]={0};
            if (wifi_getSSIDStatus(wlan_index, status) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to get SSID Status\n", __FUNCTION__);
                return RETURN_ERR;
            }
            up = (strcmp(status,"Enabled")==0);
            wifi_util_dbg_print(WIFI_WEBCONFIG,"SSID status is %s\n",status);
            if (up == FALSE) {
                uint8_t radio_index = getRadioIndexFromAp(wlan_index);
                ret_val = wifi_createAp(wlan_index, radio_index, ssid, (adv_enable == TRUE) ? FALSE : TRUE);
                if (ret_val != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to create AP Interface for wlan %d\n",
                                __FUNCTION__, wlan_index);
                    return ret_val;
                }
                wifi_util_dbg_print(WIFI_WEBCONFIG,"AP Created Successfully %d\n\n",wlan_index);
                apply_params.hostapd_restart = true;
            }

            if (auth_mode >= wifi_security_mode_wpa_personal) {
                ret_val = wifi_removeApSecVaribles(wlan_index);
                if (ret_val != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to remove AP SEC Variable for wlan %d\n",
                                     __FUNCTION__, wlan_index);
                    return ret_val;
                }
                ret_val = wifi_createHostApdConfig(wlan_index, enable_wps);
                if (ret_val != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to create hostapd config for wlan %d\n",
                                 __FUNCTION__, wlan_index);
                    return ret_val;
                }
                apply_params.hostapd_restart = true;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"Created hostapd config successfully wlan_index %d\n", wlan_index);
            }
            wifi_setApEnable(wlan_index, true);
            wifi_pushBridgeInfo(wlan_index);
        } else {
        
            if (auth_mode >= wifi_security_mode_wpa_personal) {
                ret_val = wifi_removeApSecVaribles(wlan_index);
                if (ret_val != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to remove AP SEC Variable for wlan %d\n",
                                     __FUNCTION__, wlan_index);
                    return ret_val;
                }
                apply_params.hostapd_restart = true; 
            }
        }
        cur_conf_ssid->enable = enable;
        cur_conf_ssid->ssid_changed = true;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: SSID Enable change applied for wlan %d\n",__FUNCTION__, wlan_index);
    } else if (b_force_disable_flag == TRUE) {
	    wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_WARN, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED \n");
    }
    
    if (cur_conf_ssid->ssid_advertisement_enabled != adv_enable) {
        ret_val = wifi_setApSsidAdvertisementEnable(wlan_index, adv_enable);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to set SSID Advertisement Status for wlan %d\n",
                                                             __FUNCTION__, wlan_index);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"SSID Advertisement Status apply failed",
                        sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return ret_val;
        }
        ret_val = wifi_pushSsidAdvertisementEnable(wlan_index, adv_enable);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to push SSID Advertisement Status for wlan %d\n",
                                                             __FUNCTION__, wlan_index);
            return ret_val;
        }

        curr_config->security[getRadioIndexFromAp(wlan_index)].sec_changed = true;

        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_INFO,WIFI %s : Notify Mesh of SSID Advertise changes\n",__FUNCTION__);
        v_secure_system("/usr/bin/sysevent set wifi_SSIDAdvertisementEnable \"RDK|%d|%s\"", 
                        wlan_index, adv_enable?"true":"false");
        
	apply_params.hostapd_restart = true;
        cur_conf_ssid->ssid_changed = true;
        cur_conf_ssid->ssid_advertisement_enabled = adv_enable;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Advertisement change applied for wlan index: %d\n", 
                                                    __FUNCTION__, wlan_index);
    }

    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_apply_wifi_security_params
  Parameter   : pssid_entry  - pointer to webconf_wifi_t
                wlan_index   - AP Index
                exec_ret_val - return value
  Description : Applies Wifi Security Parameters
 *************************************************************************************
***************************************************************************************/
int webconf_apply_wifi_security_params(webconf_wifi_t *pssid_entry, uint8_t wlan_index,
                                       pErr exec_ret_val)
{
    int ret_val = RETURN_ERR;
    char security_type[32] = {0};
    char auth_mode[32] = {0};
    char method[32] = {0};
    char *mode = NULL, *encryption = NULL, *passphrase = NULL;
    webconf_security_t *wlan_security = NULL, *cur_sec_cfg = NULL;
    BOOLEAN b_force_disable_flag = FALSE;

    wifi_security_modes_t sec_mode = wifi_security_mode_none;

    UINT radio_index = getRadioIndexFromAp(wlan_index);
    wlan_security = &pssid_entry->security[radio_index];
    cur_sec_cfg = &curr_config->security[radio_index]; 
    
    passphrase = wlan_security->passphrase;
    mode = wlan_security->mode_enabled;
    encryption = wlan_security->encryption_method;

    /* Copy hal specific strings for respective Authentication Mode */
    if (strcmp(mode, "None") == 0 ) {
	    sec_mode = wifi_security_mode_none;
        strcpy(security_type,"None");
        strcpy(auth_mode,"None");
    }
    else if ((strcmp(mode, "WPA2-Personal") == 0)) {
        sec_mode = wifi_security_mode_wpa2_personal;
        strcpy(security_type,"11i");
        strcpy(auth_mode,"SharedAuthentication");
    }
    else if (strcmp(mode, "WPA2-Enterprise") == 0) {
        sec_mode = wifi_security_mode_wpa2_enterprise;
        strcpy(security_type,"11i");
        strcpy(auth_mode,"EAPAuthentication");
    } else if (strcmp(mode, "WPA-WPA2-Enterprise") == 0) {
        strcpy(security_type,"WPAand11i");
        strcpy(auth_mode,"EAPAuthentication");
        sec_mode = wifi_security_mode_wpa_wpa2_enterprise;
    }


    if ((strcmp(encryption, "TKIP") == 0)) {
        strcpy(method,"TKIPEncryption");
    } else if ((strcmp(encryption, "AES") == 0)) {
        strcpy(method,"AESEncryption");
    } 

    /* Apply Security Values to hal */
        if ((isVapPrivate(wlan_index)) && 
            (sec_mode == wifi_security_mode_none)) {

        ret_val = wifi_setApWpsEnable(wlan_index, FALSE);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to set AP Wps Status\n", __FUNCTION__);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Failed to set Wps Status",sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return ret_val;
        }
    }

    if (strcmp(cur_sec_cfg->mode_enabled, mode) != 0) {
        ret_val = wifi_setApBeaconType(wlan_index, security_type);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to set AP Beacon type\n", __FUNCTION__);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Failed to set Ap Beacon type",sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return ret_val;
        }
	wifi_util_dbg_print(WIFI_WEBCONFIG, "RDK_LOG_WARN,%s calling setBasicAuthenticationMode ssid : %d auth_mode : %s \n",
                       __FUNCTION__,wlan_index, mode);
        ret_val = wifi_setApBasicAuthenticationMode(wlan_index, auth_mode);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to set AP Authentication Mode\n", __FUNCTION__);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Failed to set Ap Auth Mode",sizeof(exec_ret_val->ErrorMsg)-1);
            } 
            return ret_val;
        }

        strncpy(cur_sec_cfg->mode_enabled, mode, sizeof(cur_sec_cfg->mode_enabled)-1);
        cur_sec_cfg->sec_changed = true;
        apply_params.hostapd_restart = true;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_NOTICE, Wifi security mode %s is Enabled", mode);
	    wifi_util_dbg_print(WIFI_WEBCONFIG, "RDK_LOG_WARN,RDKB_WIFI_CONFIG_CHANGED : Wifi security mode %s is Enabled\n",mode);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Security Mode Change Applied for wlan index %d\n", __FUNCTION__,wlan_index);
    }

    if (strcmp(cur_sec_cfg->passphrase, passphrase) != 0 && (!b_force_disable_flag)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"KeyPassphrase changed for index = %d\n",wlan_index);
        ret_val = wifi_setApSecurityKeyPassphrase(wlan_index, passphrase);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to set AP Security Passphrase\n", __FUNCTION__);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Failed to set Passphrase",sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return ret_val;
        }
        strncpy(cur_sec_cfg->passphrase, passphrase, sizeof(cur_sec_cfg->passphrase)-1);
        apply_params.hostapd_restart = true;
        cur_sec_cfg->sec_changed = true;

        if (isVapPrivate(wlan_index))
        {
            global_updated[getRadioIndexFromAp(wlan_index)] = TRUE;
        }

        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_NOTICE, KeyPassphrase changed \n ");
        wifi_util_dbg_print(WIFI_WEBCONFIG, "RDK_LOG_WARN,\n RDKB_WIFI_CONFIG_CHANGED : %s KeyPassphrase changed for index = %d\n",
                        __FUNCTION__, wlan_index);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Passpharse change applied for wlan index %d\n", __FUNCTION__, wlan_index);
    } else if (b_force_disable_flag == TRUE) {
	wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_WARN, WIFI_ATTEMPT_TO_CHANGE_CONFIG_WHEN_FORCE_DISABLED \n");
    }

    if ((strcmp(cur_sec_cfg->encryption_method, encryption) != 0) &&
        (sec_mode >= wifi_security_mode_wpa_personal) &&
        (sec_mode <= wifi_security_mode_wpa_wpa2_enterprise)) {

        wifi_util_dbg_print(WIFI_WEBCONFIG, "RDK_LOG_WARN, RDKB_WIFI_CONFIG_CHANGED :%s Encryption method changed , "
                       "calling setWpaEncryptionMode Index : %d mode : %s \n",
                       __FUNCTION__,wlan_index, encryption);

        ret_val = wifi_setApWpaEncryptionMode(wlan_index, method);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to set WPA Encryption Mode\n", __FUNCTION__);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Failed to set Encryption Mode",
                        sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return ret_val;
        }
        strncpy(cur_sec_cfg->encryption_method, encryption, sizeof(cur_sec_cfg->encryption_method)-1);
        cur_sec_cfg->sec_changed = true;
        apply_params.hostapd_restart = true;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Encryption mode change applied for wlan index %d\n", 
                        __FUNCTION__, wlan_index);
    }

    if (cur_sec_cfg->sec_changed) {
	wifi_util_dbg_print(WIFI_WEBCONFIG, "RDK_LOG_INFO,WIFI %s : Notify Mesh of Security changes\n",__FUNCTION__);
        v_secure_system("/usr/bin/sysevent set wifi_ApSecurity \"RDK|%d|%s|%s|%s\"",wlan_index, passphrase, auth_mode, method);
    }
 
    BOOL up;

    up = pssid_entry->ssid[getRadioIndexFromAp(wlan_index)].enable;

    if ((cur_sec_cfg->sec_changed) && (up == TRUE)) {
        BOOL enable_wps = FALSE;
        ret_val = wifi_getApWpsEnable(wlan_index, &enable_wps);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to get Ap Wps Enable\n", __FUNCTION__);
            return ret_val;
        }
        
	ret_val = wifi_removeApSecVaribles(wlan_index);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to remove Ap Sec variables\n", __FUNCTION__);
            return ret_val;
        }

        ret_val = wifi_disableApEncryption(wlan_index);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to disable AP Encryption\n",__FUNCTION__);
            return ret_val;
        }

        if (sec_mode == wifi_security_mode_none) {
            ret_val = wifi_createHostApdConfig(wlan_index, TRUE);
        }
        else {
            ret_val = wifi_createHostApdConfig(wlan_index, enable_wps);
            
        }
        
	if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to create Host Apd Config\n",__FUNCTION__);
            return ret_val;
        }
        if (wifi_setApEnable(wlan_index, TRUE) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: wifi_setApEnable failed  index %d\n",__FUNCTION__,wlan_index);
        }
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Security changes applied for wlan index %d\n",
                       __FUNCTION__, wlan_index);
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_apply_radio_settings
  Parameter   : void
  Description : Applies Radio settings
 *************************************************************************************
***************************************************************************************/
char *wifi_apply_radio_settings()
{
    return NULL;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_validate_wifi_ssid_params
  Parameter   : pssid_entry  - pointer to webconf_wifi_t
                wlan_index   - AP Index
                exec_ret_val - return value
  Description : Validation of WiFi SSID Parameters
 *************************************************************************************
***************************************************************************************/
int webconf_validate_wifi_ssid_params (webconf_wifi_t *pssid_entry, uint8_t wlan_index,
                                       pErr exec_ret_val)
{
    char *ssid_name = NULL;
    int ssid_len = 0;
    int i = 0, j = 0;
    char ssid_char[COSA_DML_WIFI_MAX_SSID_NAME_LEN] = {0};
    char ssid_lower[COSA_DML_WIFI_MAX_SSID_NAME_LEN] = {0};

    ssid_name = pssid_entry->ssid[getRadioIndexFromAp(wlan_index)].ssid_name;

    ssid_len = strlen(ssid_name);
    if ((ssid_len == 0) || (ssid_len > COSA_DML_WIFI_MAX_SSID_NAME_LEN)) {
        if (exec_ret_val) {
            strncpy(exec_ret_val->ErrorMsg,"Invalid SSID string size",sizeof(exec_ret_val->ErrorMsg)-1);
        }
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid SSID size for wlan index %d \n",__FUNCTION__, wlan_index);
        return RETURN_ERR;
    }

 
    while (i < ssid_len) {
        ssid_lower[i] = tolower(ssid_name[i]);
        if (isalnum(ssid_name[i]) != 0) {
            ssid_char[j++] = ssid_lower[i];
        }
        i++;
    }
    ssid_lower[i] = '\0';
    ssid_char[j] = '\0';

    for (i = 0; i < ssid_len; i++) {
        if (!((ssid_name[i] >= ' ') && (ssid_name[i] <= '~'))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid character present in SSID %d\n",__FUNCTION__, wlan_index);
            if (exec_ret_val) {
                strncpy(exec_ret_val->ErrorMsg,"Invalid character in SSID",sizeof(exec_ret_val->ErrorMsg)-1);
            }
            return RETURN_ERR;
        }
    }
 

    /* SSID containing "optimumwifi", "TWCWiFi", "cablewifi" and "xfinitywifi" are reserved */
    if ((strstr(ssid_char, "cablewifi") != NULL) || (strstr(ssid_char, "twcwifi") != NULL) || (strstr(ssid_char, "optimumwifi") != NULL) ||
        (strstr(ssid_char, "xfinitywifi") != NULL) || (strstr(ssid_char, "xfinity") != NULL) || (strstr(ssid_char, "coxwifi") != NULL) ||
        (strstr(ssid_char, "spectrumwifi") != NULL) || (strstr(ssid_char, "shawopen") != NULL) || (strstr(ssid_char, "shawpasspoint") != NULL) ||
        (strstr(ssid_char, "shawguest") != NULL) || (strstr(ssid_char, "shawmobilehotspot") != NULL)) {

        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Reserved SSID format used for ssid %d\n",__FUNCTION__, wlan_index);
        if (exec_ret_val) {
            strncpy(exec_ret_val->ErrorMsg,"Reserved SSID format used",sizeof(exec_ret_val->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
 
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_validate_wifi_security_params
  Parameter   : pssid_entry  - pointer to webconf_wifi_t
                wlan_index   - AP Index
                exec_ret_val - return value
  Description : Validates Wifi Security Paramters
 *************************************************************************************
***************************************************************************************/
int webconf_validate_wifi_security_params (webconf_wifi_t *pssid_entry, uint8_t wlan_index,
                                           pErr exec_ret_val)
{
    char *passphrase = NULL;
    char *mode_enabled = NULL;
    char *encryption_method = NULL;
    int pass_len = 0;

    UINT radio_index = getRadioIndexFromAp(wlan_index);
    passphrase = pssid_entry->security[radio_index].passphrase;
    mode_enabled = pssid_entry->security[radio_index].mode_enabled;
    encryption_method = pssid_entry->security[radio_index].encryption_method;    

    /* Sanity Checks */
    if ((strcmp(mode_enabled, "None") != 0) && (strcmp(mode_enabled, "WEP-64") != 0) && (strcmp(mode_enabled, "WEP-128") !=0) &&
        (strcmp(mode_enabled, "WPA-Personal") != 0) && (strcmp(mode_enabled, "WPA2-Personal") != 0) &&
        (strcmp(mode_enabled, "WPA-WPA2-Personal") != 0) && (strcmp(mode_enabled, "WPA2-Enterprise") != 0) &&
        (strcmp(mode_enabled, "WPA-WPA2-Enterprise") != 0) && (strcmp(mode_enabled, "WPA-Enterprise") !=0)) {
 
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid Security Mode for wlan index %d\n",__FUNCTION__, wlan_index);
        if (exec_ret_val) {
            strncpy(exec_ret_val->ErrorMsg,"Invalid Security Mode",sizeof(exec_ret_val->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }

    if ((strcmp(mode_enabled, "None") != 0) &&
        ((strcmp(encryption_method, "TKIP") != 0) && (strcmp(encryption_method, "AES") != 0) &&
        (strcmp(encryption_method, "AES+TKIP") != 0))) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid Encryption Method for wlan index %d\n",__FUNCTION__, wlan_index);
        if (exec_ret_val) {
            strncpy(exec_ret_val->ErrorMsg,"Invalid Encryption Method",sizeof(exec_ret_val->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }

    if (((strcmp(mode_enabled, "WPA-WPA2-Enterprise") == 0) || (strcmp(mode_enabled, "WPA-WPA2-Personal") == 0)) &&
        ((strcmp(encryption_method, "AES+TKIP") != 0) && (strcmp(encryption_method, "AES") != 0))) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid Encryption Security Combination for wlan index %d\n",__FUNCTION__, wlan_index);
        if (exec_ret_val) {
            strncpy(exec_ret_val->ErrorMsg,"Invalid Encryption Security Combination",sizeof(exec_ret_val->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }

    pass_len = strlen(passphrase);

    if ((pass_len < MIN_PWD_LEN) || (pass_len > MAX_PWD_LEN)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid Key passphrase length index %d\n",__FUNCTION__, wlan_index);
        if (exec_ret_val) {
            strncpy(exec_ret_val->ErrorMsg,"Invalid Passphrase length",sizeof(exec_ret_val->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }


    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Security Params validated Successfully for wlan index %d\n",__FUNCTION__, wlan_index);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_apply_wifi_param_handler
  Parameter   : pssid_entry  - pointer to webconf_wifi_t
                exec_ret_val - return value
                ssid         - ssid
  Description : Function to call WiFi Apply Handlers
 *************************************************************************************
***************************************************************************************/
int webconf_apply_wifi_param_handler (webconf_wifi_t *pssid_entry, pErr exec_ret_val,uint8_t ssid)
{
    int ret_val = RETURN_ERR;
    char *err = NULL;
    uint8_t i = 0, wlan_index = 0;

    for (i = 0; i < getTotalNumberVAPs(); i++) 
    {
        if ( (ssid == WIFI_WEBCONFIG_PRIVATESSID && isVapPrivate(i)) || (ssid == WIFI_WEBCONFIG_HOMESSID && isVapXhs(i)) )
        {
            ret_val  = webconf_apply_wifi_ssid_params(pssid_entry, i, exec_ret_val);
            if (ret_val != RETURN_OK) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to apply ssid params for ap index %d\n",
                            __FUNCTION__, wlan_index);
                return ret_val;
            }

            ret_val = webconf_apply_wifi_security_params(pssid_entry, i, exec_ret_val);
            if (ret_val != RETURN_OK) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to apply security params for ap index %d\n",
                             __FUNCTION__, wlan_index);
                return ret_val;
            }
		}
    } 
    err = wifi_apply_radio_settings();
    if (err != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to Apply Radio settings\n", __FUNCTION__);
        if (exec_ret_val) {
            strncpy(exec_ret_val->ErrorMsg, err,sizeof(exec_ret_val->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_ssid_rollback_handler
  Parameter   : pssid_entry  - pointer to webconf_wifi_t
                exec_ret_val - return value
                ssid         - ssid
  Description : Function to call WiFi Validation handlers
 *************************************************************************************
***************************************************************************************/
int webconf_validate_wifi_param_handler (webconf_wifi_t *pssid_entry, pErr exec_ret_val,uint8_t ssid)
{
    uint8_t i = 0, wlan_index = 0;
    int ret_val = RETURN_ERR;

    for (i = 0; i < getTotalNumberVAPs(); i++) 
    {
        if ( (ssid == WIFI_WEBCONFIG_PRIVATESSID && isVapPrivate(i)) || (ssid == WIFI_WEBCONFIG_HOMESSID && isVapXhs(i)) )
        {
            ret_val = webconf_validate_wifi_ssid_params(pssid_entry, i, exec_ret_val);
            if (ret_val != RETURN_OK) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to validate ssid params for ap index %d\n",
                             __FUNCTION__,wlan_index);
                return ret_val;
            }

            ret_val = webconf_validate_wifi_security_params(pssid_entry, i, exec_ret_val);
            if (ret_val != RETURN_OK) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to validate security params for ap index %d\n",
                             __FUNCTION__, wlan_index);
                return ret_val;
            }
        }
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_ssid_rollback_handler
  Parameter   : void
  Description : Function to rollback to previous configs if apply failed
 *************************************************************************************
***************************************************************************************/
int webconf_ssid_rollback_handler(void)
{

    webconf_wifi_t *prev_config = NULL;
    uint8_t ssid_type = 0;

    prev_config = (webconf_wifi_t *) malloc(sizeof(webconf_wifi_t));
    if (!prev_config) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Memory allocation error\n", __FUNCTION__);
        return RETURN_ERR;
    }
    memset(prev_config, 0, sizeof(webconf_wifi_t));

    if (strncmp(curr_config->subdoc_name, "privatessid",strlen("privatessid")) == 0) {
        ssid_type = WIFI_WEBCONFIG_PRIVATESSID;
    } else if (strncmp(curr_config->subdoc_name,"homessid",strlen("homessid")) == 0) {
        ssid_type = WIFI_WEBCONFIG_HOMESSID;
    }

    if (webconf_populate_initial_config(prev_config, ssid_type) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to copy initial configs\n", __FUNCTION__);
        free(prev_config);
        return RETURN_ERR;
    }

    if (webconf_apply_wifi_param_handler(prev_config, NULL, ssid_type) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Rollback of webconfig params failed!!\n",__FUNCTION__);
        free(prev_config);
        return RETURN_ERR;
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Rollback of webconfig params applied successfully\n",__FUNCTION__);
    free(prev_config);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_ssid_free_resources
  Parameter   : arg - pointer to blob
  Description : API to free the resources after blob apply
 *************************************************************************************
***************************************************************************************/
void webconf_ssid_free_resources(void *arg)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG,"Entering: %s\n",__FUNCTION__);
    if (arg == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Input Data is NULL\n",__FUNCTION__);
        return;
    }
    execData *blob_exec_data  = (execData*) arg;

    webconf_wifi_t *ps_data   = (webconf_wifi_t *) blob_exec_data->user_data;
    free(blob_exec_data);

    if (ps_data != NULL) {
        free(ps_data);
        ps_data = NULL;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Success in Clearing wifi webconfig resources\n",__FUNCTION__);
    }
}

/*
 * Function to deserialize ssid params from msgpack object
 *
 * @param obj  Pointer to msgpack object
 * @param ssid Pointer to wifi ssid structure
 *
 * returns 0 on success, error otherwise
 */
int webconf_copy_wifi_ssid_params(msgpack_object obj, webconf_ssid_t *ssid) {
    unsigned int i;
    msgpack_object_kv* p = obj.via.map.ptr;

    for(i = 0;i < obj.via.map.size;i++) {
        if (strncmp(p->key.via.str.ptr, "SSID",p->key.via.str.size) == 0) {
            if (p->val.type == MSGPACK_OBJECT_STR) { 
                strncpy(ssid->ssid_name,p->val.via.str.ptr, p->val.via.str.size);
                ssid->ssid_name[p->val.via.str.size] = '\0';
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Invalid value type for SSID",__FUNCTION__);
                return RETURN_ERR;
            }
        }
        else if (strncmp(p->key.via.str.ptr, "Enable",p->key.via.str.size) == 0) {
            if (p->val.type == MSGPACK_OBJECT_BOOLEAN) {
                if (p->val.via.boolean) {
                    ssid->enable = true;
                } else {
                    ssid->enable = false;
                }
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Invalid value type for SSID Enable",__FUNCTION__);
                return RETURN_ERR;
            } 
        }
        else if (strncmp(p->key.via.str.ptr, "SSIDAdvertisementEnabled",p->key.via.str.size) == 0) {
            if (p->val.type == MSGPACK_OBJECT_BOOLEAN) {
                if (p->val.via.boolean) {
                    ssid->ssid_advertisement_enabled = true;
                } else {
                    ssid->ssid_advertisement_enabled = false;
                }
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Invalid value type for SSID Advtertisement",__FUNCTION__);
                return RETURN_ERR;
            }
        }
        ++p;
    }
    return RETURN_OK;
}

/*
 * Function to deserialize security params from msgpack object
 *
 * @param obj  Pointer to msgpack object
 * @param ssid Pointer to wifi security structure
 *
 * returns 0 on success, error otherwise
 */
int webconf_copy_wifi_security_params(msgpack_object obj, webconf_security_t *security) {
    unsigned int i;
    msgpack_object_kv* p = obj.via.map.ptr;

    for(i = 0;i < obj.via.map.size;i++) {
        if (strncmp(p->key.via.str.ptr, "Passphrase",p->key.via.str.size) == 0) {
            if (p->val.type == MSGPACK_OBJECT_STR) {
                strncpy(security->passphrase,p->val.via.str.ptr, p->val.via.str.size);
                security->passphrase[p->val.via.str.size] = '\0';
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Invalid value type for Security passphrase",__FUNCTION__);
                return RETURN_ERR;
            }
        }
        else if (strncmp(p->key.via.str.ptr, "EncryptionMethod",p->key.via.str.size) == 0) {
            if (p->val.type == MSGPACK_OBJECT_STR) {
                strncpy(security->encryption_method,p->val.via.str.ptr, p->val.via.str.size);
                security->encryption_method[p->val.via.str.size] = '\0';
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Invalid value type for Encryption method",__FUNCTION__);
                return RETURN_ERR;
            }
        }
        else if (strncmp(p->key.via.str.ptr, "ModeEnabled",p->key.via.str.size) == 0) {
            if (p->val.type == MSGPACK_OBJECT_STR) {
                strncpy(security->mode_enabled,p->val.via.str.ptr, p->val.via.str.size);
                security->mode_enabled[p->val.via.str.size] = '\0';
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Invalid value type for Authentication mode",__FUNCTION__);
                return RETURN_ERR;
            }
        }
        ++p;
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_wifi_ssid_config_handler
  Parameter   : numOfEntries - Number of Entries of blob
  Description : Function to calculate timeout value for executing the blob
 *************************************************************************************
***************************************************************************************/
size_t webconf_ssid_timeout_handler(size_t numOfEntries)
{
    return (numOfEntries * SSID_DEFAULT_TIMEOUT);
}

/************************************************************************************
 ************************************************************************************
  Function    : webconf_wifi_ssid_config_handler
  Parameter   : Data - Pointer to structure holding wifi parameters
  Description : Execute blob request callback handler
 *************************************************************************************
***************************************************************************************/
pErr webconf_wifi_ssid_config_handler(void *Data)
{
    pErr exec_ret_val = NULL;
    int ret_val = RETURN_ERR;
    uint8_t ssid_type = 0;

    if (Data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Input Data is NULL\n",__FUNCTION__);
        return exec_ret_val;
    }

    webconf_wifi_t *ps = (webconf_wifi_t *) Data;
    if(strncmp(ps->subdoc_name,"privatessid",strlen("privatessid")) == 0) {
        ssid_type = WIFI_WEBCONFIG_PRIVATESSID;
    } else if (strncmp(ps->subdoc_name,"homessid",strlen("homessid")) == 0) {
        ssid_type = WIFI_WEBCONFIG_HOMESSID;
    }
 
    /* Copy the initial configs */
    if (webconf_alloc_current_cfg(ssid_type) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to copy the current config\n",__FUNCTION__);
        return exec_ret_val;
    }
    strncpy(curr_config->subdoc_name, ps->subdoc_name, sizeof(curr_config->subdoc_name)-1);

    exec_ret_val = (pErr ) malloc (sizeof(Err));
    if (exec_ret_val == NULL )
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s : Malloc failed\n",__FUNCTION__);
        return exec_ret_val;
    }

    memset(exec_ret_val,0,(sizeof(Err)));

    exec_ret_val->ErrorCode = BLOB_EXEC_SUCCESS;


    /* Validation of Input parameters */
    ret_val = webconf_validate_wifi_param_handler(ps, exec_ret_val, ssid_type);
    if (ret_val != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Validation of msg blob failed\n",__FUNCTION__);
        exec_ret_val->ErrorCode = VALIDATION_FALIED;
        return exec_ret_val;
    } else {
        /* Apply Paramters to hal and update TR-181 cache */
        ret_val = webconf_apply_wifi_param_handler(ps, exec_ret_val, ssid_type);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to Apply WebConfig Params\n",
                             __FUNCTION__);
            exec_ret_val->ErrorCode = WIFI_HAL_FAILURE;
            return exec_ret_val;
        }
    }
 
    if (webconf_update_params(ps, ssid_type) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to Populate TR-181 Params\n",
                             __FUNCTION__);
        exec_ret_val->ErrorCode = WIFI_HAL_FAILURE;
        return exec_ret_val;
    }

    if ( strcmp(notify_wifi_changes_val,"true") == 0 ) 
    {
        char param_name[64] = {0};
        UINT radio_index = 0;
		
        for (UINT ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++)
        {
            if (isVapPrivate(ap_index))
            {
                radio_index = getRadioIndexFromAp(ap_index);
                if (global_ssid_updated[radio_index])
                {
                    snprintf(param_name, sizeof(param_name), "Device.WiFi.SSID.%u.SSID", ap_index + 1);
                    global_ssid_updated[radio_index] = FALSE;
                }

                if (global_updated[radio_index])
                {
                    snprintf(param_name, sizeof(param_name), "Device.WiFi.AccessPoint.%u.Security.X_COMCAST-COM_KeyPassphrase", ap_index + 1);
                    global_updated[radio_index] = FALSE;
                }
            }
        }
    }       


    return exec_ret_val;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_apply_common_config
  Parameter   : buf  - Pointer to the decodedMsg
                len  - Size of the Decoded Message
                ssid -  name of ssid
  Description : Function to apply WiFi Configs from dmcli
 *************************************************************************************
***************************************************************************************/
int web_config_set(const void *buf, size_t len,uint8_t ssid)
{
    size_t offset = 0;
    msgpack_unpacked msg;
    msgpack_unpack_return mp_rv;
    msgpack_object_map *map = NULL;
    msgpack_object_kv* map_ptr  = NULL;
  
    webconf_wifi_t *ps = NULL;  
    unsigned int i = 0;

    char ssid_str[MAX_NUM_RADIOS][20] = {0};
    char sec_str[MAX_NUM_RADIOS][20] = {0};

    msgpack_unpacked_init( &msg );
    len +=  1;
    /* The outermost wrapper MUST be a map. */
    mp_rv = msgpack_unpack_next( &msg, (const char*) buf, len, &offset );
    if (mp_rv != MSGPACK_UNPACK_SUCCESS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to unpack wifi msg blob. Error %d",__FUNCTION__,mp_rv);
        msgpack_unpacked_destroy( &msg );
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Msg unpack success. Offset is %lu\n", __FUNCTION__,offset);
    msgpack_object obj = msg.data;
    
    map = &msg.data.via.map;
    
    map_ptr = obj.via.map.ptr;
    if ((!map) || (!map_ptr)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Failed to get object map\n");
        msgpack_unpacked_destroy( &msg );
        return RETURN_ERR;
    }

    if (msg.data.type != MSGPACK_OBJECT_MAP) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid msgpack type",__FUNCTION__);
        msgpack_unpacked_destroy( &msg );
        return RETURN_ERR;
    }

    /* Allocate memory for wifi structure */
    ps = (webconf_wifi_t *) malloc(sizeof(webconf_wifi_t));
    if (ps == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Wifi Struc malloc error\n",__FUNCTION__);
        return RETURN_ERR;
    }
    memset(ps, 0, sizeof(webconf_wifi_t));
    
    if (ssid == WIFI_WEBCONFIG_PRIVATESSID) {
        for (UINT radio_index = 0; radio_index < getNumberRadios(); ++radio_index)
        {
            UINT band = convert_radio_index_to_frequencyNum(radio_index);
            snprintf(ssid_str[radio_index],sizeof(ssid_str[radio_index]),"private_ssid_%ug", band);
            snprintf(sec_str[radio_index],sizeof(sec_str[radio_index]),"private_security_%ug", band);
        }
    } else if (ssid == WIFI_WEBCONFIG_HOMESSID) {
        for (UINT radio_index = 0; radio_index < getNumberRadios(); ++radio_index)
        {
            UINT band = convert_radio_index_to_frequencyNum(radio_index);
            snprintf(ssid_str[radio_index],sizeof(ssid_str[radio_index]),"home_ssid_%ug",band);
            snprintf(sec_str[radio_index],sizeof(sec_str[radio_index]),"home_security_%ug", band);
        }
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid ssid type\n",__FUNCTION__);
    }
    /* Parsing Config Msg String to Wifi Structure */
    for(i = 0;i < map->size;i++) {
        for (UINT radio_index = 0; radio_index < getNumberRadios(); ++radio_index)
        {
            if (strncmp(map_ptr->key.via.str.ptr, ssid_str[radio_index], map_ptr->key.via.str.size) == 0) {
                if (webconf_copy_wifi_ssid_params(map_ptr->val, &ps->ssid[radio_index]) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Failed to copy wifi ssid params for wlan index 0",__FUNCTION__);
                    msgpack_unpacked_destroy( &msg );
                    if (ps) {  
                        free(ps);
                        ps = NULL;  
                    } 
                    return RETURN_ERR; 
                }  
            } 
            else if (strncmp(map_ptr->key.via.str.ptr, sec_str[radio_index], map_ptr->key.via.str.size) == 0) {
                if (webconf_copy_wifi_security_params(map_ptr->val, &ps->security[radio_index]) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Failed to copy wifi security params for wlan index 0",__FUNCTION__);
                    msgpack_unpacked_destroy( &msg );
                    if (ps) {
                        free(ps);
                        ps = NULL;
                    } 
                    return RETURN_ERR;
                }
            }  
        }
        if (strncmp(map_ptr->key.via.str.ptr, "subdoc_name", map_ptr->key.via.str.size) == 0) {
            if (map_ptr->val.type == MSGPACK_OBJECT_STR) {
                strncpy(ps->subdoc_name, map_ptr->val.via.str.ptr, map_ptr->val.via.str.size);
                wifi_util_dbg_print(WIFI_WEBCONFIG,"subdoc name %s\n", ps->subdoc_name);
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "version", map_ptr->key.via.str.size) == 0) {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                ps->version = (uint64_t) map_ptr->val.via.u64;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"Version type %d version %lu\n",map_ptr->val.type,ps->version);                
                }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "transaction_id", map_ptr->key.via.str.size) == 0) {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                ps->transaction_id = (uint16_t) map_ptr->val.via.u64;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"Tx id type %d tx id %d\n",map_ptr->val.type,ps->transaction_id);
            }
        }

        ++map_ptr;
    }

    msgpack_unpacked_destroy( &msg );

    execData *exec_data_pf = NULL ;
 
    exec_data_pf = (execData*) malloc (sizeof(execData));
    if (exec_data_pf != NULL) {
        memset(exec_data_pf, 0, sizeof(execData));

        exec_data_pf->txid = ps->transaction_id;
        exec_data_pf->version = ps->version;
        exec_data_pf->numOfEntries = 1;

        strncpy(exec_data_pf->subdoc_name,ps->subdoc_name, sizeof(exec_data_pf->subdoc_name)-1);

        exec_data_pf->user_data = (void*) ps;
        exec_data_pf->calcTimeout = webconf_ssid_timeout_handler;
        exec_data_pf->executeBlobRequest = webconf_wifi_ssid_config_handler;
        exec_data_pf->rollbackFunc = webconf_ssid_rollback_handler;
        exec_data_pf->freeResources = webconf_ssid_free_resources;
        PushBlobRequest(exec_data_pf);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"PushBlobRequest Complete\n");

    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_apply_common_config
  Parameter   : wifi_cfg - wifi_global_config_t updated to wifidb
                vap_name - name of vap 
  Description : API to update wifi_GASConfiguration_t to HAL 
 *************************************************************************************
***************************************************************************************/
char *wifi_apply_common_config(wifi_global_config_t *wifi_cfg) 
{
    int ret_val;

    ret_val = wifi_setGASConfiguration(wifi_cfg->gas_config.AdvertisementID,&wifi_cfg->gas_config);
    if (ret_val != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to update HAL with GAS Config\n",__FUNCTION__);
        return "wifi_setGASConfiguration failed";
    }
    return NULL;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_get_initial_common_config
  Parameter   : wifi_cfg - wifi_global_config_t will be updated from wifidb
  Description : API to get wifi_global_config_t from wifidb 
 *************************************************************************************
***************************************************************************************/
int wifi_get_initial_common_config(wifi_global_config_t *curr_cfg) 
{
    wifi_GASConfiguration_t *p_gas_conf = Get_wifi_gas_conf_object();
    curr_cfg->gas_config.AdvertisementID = p_gas_conf->AdvertisementID;
    curr_cfg->gas_config.PauseForServerResponse = p_gas_conf->PauseForServerResponse;
    curr_cfg->gas_config.ResponseTimeout = p_gas_conf->ResponseTimeout;
    curr_cfg->gas_config.ComeBackDelay = p_gas_conf->ComeBackDelay;
    curr_cfg->gas_config.ResponseBufferingTime = p_gas_conf->ResponseBufferingTime;
    curr_cfg->gas_config.QueryResponseLengthLimit = p_gas_conf->QueryResponseLengthLimit;
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Fetched Initial GAS Configs\n",__FUNCTION__);

    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_update_common_config
  Parameter   : wifi_cfg - wifi_global_config_t updated to wifidb
  Description : API to update wifi_GASConfiguration_t to wifidb 
 *************************************************************************************
***************************************************************************************/
int wifi_update_common_config(wifi_global_config_t *wifi_cfg)
{
        wifi_GASConfiguration_t *p_gas_conf = Get_wifi_gas_conf_object();
	p_gas_conf->AdvertisementID = wifi_cfg->gas_config.AdvertisementID;
        p_gas_conf->PauseForServerResponse = wifi_cfg->gas_config.PauseForServerResponse;
        p_gas_conf->ResponseTimeout = wifi_cfg->gas_config.ResponseTimeout;
        p_gas_conf->ComeBackDelay = wifi_cfg->gas_config.ComeBackDelay;
        p_gas_conf->ResponseBufferingTime = wifi_cfg->gas_config.ResponseBufferingTime;
        p_gas_conf->QueryResponseLengthLimit = wifi_cfg->gas_config.QueryResponseLengthLimit;
    //Update WIFIDB
    if(RETURN_OK != wifidb_update_gas_config(wifi_cfg->gas_config.AdvertisementID, &wifi_cfg->gas_config))
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Failed to update WIFIDB with GAS Config\n");
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_vap_cfg_rollback_handler
  Parameter   : void
  Description : Will be implemented
 *************************************************************************************
***************************************************************************************/
int wifi_vap_cfg_rollback_handler() 
{
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_update_captiveportal
  Parameter   : ssid     - Name of SSID
                password - password of SSID
                vap_name - name of vap 
  Description : API to update captive portal
 *************************************************************************************
***************************************************************************************/
int wifi_update_captiveportal (char *ssid, char *password, char *vap_name) {
    char param_name[64] = {0};
    bool *ssid_updated, *pwd_updated;
    uint8_t wlan_index;

    if ( strcmp(notify_wifi_changes_val,"true") != 0 ) {
        return RETURN_OK;
    }
	
    UINT ap_index = 0;
    wlan_index = 2;
    pwd_updated = NULL;
    ssid_updated = NULL;
    if ( (getVAPIndexFromName(vap_name, &ap_index) == RETURN_OK) && (isVapPrivate(ap_index)) )
    {
        ssid_updated = &global_ssid_updated[getRadioIndexFromAp(ap_index)];
        pwd_updated = &global_updated[getRadioIndexFromAp(ap_index)];
        wlan_index  = ap_index + 1;
        return RETURN_ERR;
    }

    if (*ssid_updated) {
        sprintf(param_name, "Device.WiFi.SSID.%d.SSID",wlan_index);
        *ssid_updated = FALSE;
    } 

    if (*pwd_updated) {
        sprintf(param_name, "Device.WiFi.AccessPoint.%d.Security.X_COMCAST-COM_KeyPassphrase",wlan_index);
        *pwd_updated = FALSE;
    }
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : notify_mesh_events
  Parameter   : vap_cfg - wifi_vap_info_t 
  Description : Function to notify mesh changes
 *************************************************************************************
***************************************************************************************/
int notify_mesh_events(wifi_vap_info_t *vap_cfg)
{
    char mode[32] = {0};
    char security_type[32] = {0};
    char auth_mode[32] = {0};
    char method[32] = {0};
    char encryption[32] = {0};
    UINT wlan_index = 0;

    if (vap_cfg == NULL)
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_WARN, WIFI %s : vap_cfg is NULL", __FUNCTION__);
        return RETURN_ERR;
    }

    wlan_index = vap_cfg->vap_index;

    wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_INFO,WIFI %s : Notify Mesh of SSID change\n",__FUNCTION__);
    v_secure_system("/usr/bin/sysevent set wifi_SSIDName \"RDK|%d|%s\"",wlan_index, vap_cfg->u.bss_info.ssid);

    wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_INFO,WIFI %s : Notify Mesh of SSID Advertise changes\n",__FUNCTION__);
    v_secure_system("/usr/bin/sysevent set wifi_SSIDAdvertisementEnable \"RDK|%d|%s\"",
            wlan_index, vap_cfg->u.bss_info.showSsid?"true":"false");

    webconf_auth_mode_to_str(mode, vap_cfg->u.bss_info.security.mode);
    /* Copy hal specific strings for respective Authentication Mode */
    if (strcmp(mode, "None") == 0 ) {
        strcpy(security_type,"None");
        strcpy(auth_mode,"None");
    }
    else if ((strcmp(mode, "WPA2-Personal") == 0)) {
        strcpy(security_type,"11i");
        strcpy(auth_mode,"SharedAuthentication");
    }
    else if (strcmp(mode, "WPA2-Enterprise") == 0) {
        strcpy(security_type,"11i");
        strcpy(auth_mode,"EAPAuthentication");
    } else if (strcmp(mode, "WPA-WPA2-Enterprise") == 0) {
        strcpy(security_type,"WPAand11i");
        strcpy(auth_mode,"EAPAuthentication");
    }

    webconf_enc_mode_to_str(encryption,vap_cfg->u.bss_info.security.encr);
    if ((strcmp(encryption, "TKIP") == 0))
    {
        strcpy(method,"TKIPEncryption");
    }
    else if ((strcmp(encryption, "AES") == 0))
    {
        strcpy(method,"AESEncryption");
    }

    if (vap_cfg->u.bss_info.sec_changed)
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_INFO,WIFI %s : Notify Mesh of Security changes\n",__FUNCTION__);
        v_secure_system("/usr/bin/sysevent set wifi_ApSecurity \"RDK|%d|%s|%s|%s\"",wlan_index, vap_cfg->u.bss_info.security.u.key.key, auth_mode, method);
    }

    vap_cfg->u.bss_info.sec_changed = FALSE;

    return RETURN_OK;

}

/************************************************************************************
 ************************************************************************************
  Function    : radio_config_set
  Parameter   : buf          - Pointer to the decoded strin
                len          - Size of the Decoded Message
                exec_ret_val - return value
  Description : Function to Parse Msg packed Wifi Config
 *************************************************************************************
***************************************************************************************/
int radio_config_set(const char *buf, size_t len, pErr exec_ret_val)
{
/*
#define MAX_JSON_BUFSIZE 10240
    size_t  json_len = 0;
    msgpack_zone msg_z;
    msgpack_object msg_obj;
    msgpack_unpack_return mp_rv = 0;
*/
    wifi_vap_info_map_t vap_map[MAX_NUM_RADIOS];
    wifi_radio_operationParam_t radio_vap_map[MAX_NUM_RADIOS];
    wifi_global_config_t wifi;
    wifi_platform_property_t *wifi_prop;
//    char *buffer = NULL;
    const char *err = NULL;
    int i, ret_val, r_index;
    int radio_index = 0;

    memset(&vap_map,0,sizeof(vap_map));
    memset(&radio_vap_map,0,sizeof(radio_vap_map));
    if (!buf || !exec_ret_val) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Empty input parameters for subdoc set\n",__FUNCTION__);
        if (exec_ret_val) {
            exec_ret_val->ErrorCode = VALIDATION_FALIED;
            strncpy(exec_ret_val->ErrorMsg, "Empty subdoc", sizeof(exec_ret_val->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }

/*
    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    if(MSGPACK_UNPACK_SUCCESS != msgpack_unpack(buf, len, NULL, &msg_z, &msg_obj)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to unpack wifi msg blob. Error %d\n",__FUNCTION__,mp_rv));
        if (exec_ret_val) {
            exec_ret_val->ErrorCode = VALIDATION_FALIED;
            strncpy(exec_ret_val->ErrorMsg, "Msg unpack failed", sizeof(exec_ret_val->ErrorMsg)-1);
        }
        msgpack_zone_destroy(&msg_z);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Msg unpack success.\n", __FUNCTION__));

    buffer = (char*) malloc (MAX_JSON_BUFSIZE);
    if (!buffer) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory\n",__FUNCTION__));
        strncpy(exec_ret_val->ErrorMsg, "Failed to allocate memory", sizeof(exec_ret_val->ErrorMsg)-1);
        exec_ret_val->ErrorCode = VALIDATION_FALIED;
        msgpack_zone_destroy(&msg_z);
        return RETURN_ERR;
    } 
    
    memset(buffer,0,MAX_JSON_BUFSIZE);
    json_len = msgpack_object_print_jsonstr(buffer, MAX_JSON_BUFSIZE, msg_obj);
    if (json_len <= 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Msgpack to json conversion failed\n",__FUNCTION__));
        if (exec_ret_val) {
            exec_ret_val->ErrorCode = VALIDATION_FALIED;
            strncpy(exec_ret_val->ErrorMsg, "Msgpack to json conversion failed", sizeof(exec_ret_val->ErrorMsg)-1);
        }
        free(buffer);
        msgpack_zone_destroy(&msg_z);
        return RETURN_ERR;
    }

    buffer[json_len] = '\0';
    msgpack_zone_destroy(&msg_z);
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Msgpack to JSON success.\n", __FUNCTION__));
*/

    //Fetch RFC values for Interworking and Passpoint
    get_wifi_rfc_parameters(RFC_WIFI_PASSPOINT_STATUS, &g_passpoint_RFC);
    get_wifi_rfc_parameters(RFC_WIFI_INTERWORKING_STATUS, &g_interworking_RFC);

    num_radio = 0;
    memset(radio_vap_map, 0, sizeof(radio_vap_map));
    memset(vap_map, 0, sizeof(vap_map));
    memset(&wifi, 0, sizeof(wifi));

     FILE *fpw = NULL;
    fpw = fopen("/tmp/wifiWebconf", "w+");
    if (fpw != NULL) {
        fputs(buf, fpw);
        fclose(fpw);
    }

    cJSON *root_json = NULL;
    root_json = cJSON_Parse(buf);
    if(root_json == NULL) {
        CcspTraceError(("%s: Json parse fail\n", __FUNCTION__));
        exec_ret_val->ErrorCode = VALIDATION_FALIED;
        strncpy(exec_ret_val->ErrorMsg, "Json parse fail",sizeof(exec_ret_val->ErrorMsg)-1);
        err = cJSON_GetErrorPtr();
        if (err) {
            CcspTraceError(("%s: Json parse error %s\n", __FUNCTION__, err));
        }
        return RETURN_ERR;
    }

    wifi_prop = &((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop;
    if (wifi_validate_config(root_json, &wifi, vap_map, radio_vap_map, &num_radio, wifi_prop, exec_ret_val) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to fetch and validate vaps from json. ErrorMsg: %s\n", __FUNCTION__,exec_ret_val->ErrorMsg);
        exec_ret_val->ErrorCode = VALIDATION_FALIED;
        //free(buffer);
        return RETURN_ERR;
    }

    cJSON_Delete(root_json);

    if(num_radio > getNumberRadios()){
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid number of radios received. num_radio =%d\n",__FUNCTION__,num_radio);
        exec_ret_val->ErrorCode = VALIDATION_FALIED;
        //free(buffer);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Sucessfully Validated Radio and VAP configs num_radio =%d\n",__FUNCTION__,num_radio);
    //free(buffer);
    print_radio_config_data(radio_vap_map);
    print_vap_config_data(vap_map);
    memcpy(vap_map_per_radio, vap_map, sizeof(wifi_vap_info_map_t) * getNumberRadios());
    for (r_index = 0; r_index < num_radio; r_index++)
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG, " %s For radio_index %d num_vaps : %d to be configured\n", __FUNCTION__, r_index, vap_map_per_radio[r_index].num_vaps);

        if(convert_freq_band_to_radio_index(radio_vap_map[r_index].band, &radio_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, " %s %d convert_freq_band_to_radio_index failed for band : %d \n", __FUNCTION__, __LINE__, radio_vap_map[r_index].band);
            return RETURN_ERR;
        }

        ret_val = wifi_hal_setRadioOperatingParameters(radio_index, &radio_vap_map[r_index]);
        if (ret_val != RETURN_OK)
        {
            wifi_util_dbg_print(WIFI_WEBCONFIG," %s wifi_setRadioOperatingParameters returned with error %d\n", __FUNCTION__, ret_val);
            strncpy(exec_ret_val->ErrorMsg, "wifi_setRadioOperatingParameters Failed", sizeof(exec_ret_val->ErrorMsg)-1);
            exec_ret_val->ErrorCode = WIFI_HAL_FAILURE;
            return RETURN_ERR;
        }

        wifi_util_dbg_print(WIFI_CTRL,"%s: wifi radio parameter set\n",__FUNCTION__);
        //For Each Radio call the createVAP
        if (vap_map[r_index].num_vaps != 0)
        {
#if 0
            ret_val =  wifi_createVAP(radio_index, &vap_map[r_index]);
#else
            ret_val =  wifi_hal_createVAP(radio_index, &vap_map[r_index]);
#endif
            if (ret_val != RETURN_OK)
            {
                wifi_util_dbg_print(WIFI_WEBCONFIG," %s wifi_createVAP returned with error %d\n", __FUNCTION__, ret_val);
                strncpy(exec_ret_val->ErrorMsg, "wifi_createVAP Failed", sizeof(exec_ret_val->ErrorMsg)-1);
                exec_ret_val->ErrorCode = WIFI_HAL_FAILURE;
                return RETURN_ERR;
            }

            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s wifi_createVAP Successful for Radio : %d\n", __FUNCTION__, r_index);
        }
    }
    err = wifi_apply_common_config(&wifi);
    if (err != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to apply common WiFi config\n",__FUNCTION__);
        strncpy(exec_ret_val->ErrorMsg,err,sizeof(exec_ret_val->ErrorMsg)-1);
        exec_ret_val->ErrorCode = WIFI_HAL_FAILURE;
        return RETURN_ERR;
    }

    for (r_index = 0; r_index < num_radio; r_index++) {   
        for (i = 0; i < (int)vap_map[r_index].num_vaps; i++) {
            UINT ap_index = 0;
            if ( (getVAPIndexFromName(vap_map[r_index].vap_array[i].vap_name, &ap_index) == RETURN_OK) && (isVapPrivate(ap_index)) )
            {
                /* Update captive portal */
                ret_val = wifi_update_captiveportal(vap_map[r_index].vap_array[i].u.bss_info.ssid, 
                          vap_map[r_index].vap_array[i].u.bss_info.security.u.key.key,
                          vap_map[r_index].vap_array[i].vap_name);
                if (ret_val != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to update captive portal\n", __FUNCTION__);
                    strncpy(exec_ret_val->ErrorMsg,"Failed to update captive portal settings",
                        sizeof(exec_ret_val->ErrorMsg)-1);
                }
            } 
        }
    }

    for (r_index = 0; r_index < num_radio; r_index++)
    {
            /* Update wifidb params */
	    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Update wifidb with radio and VAP configs No of Radios=%d No of Vaps=%d\n",__FUNCTION__,__LINE__,num_radio,vap_map[r_index].num_vaps);
        if (convert_freq_band_to_radio_index(radio_vap_map[r_index].band, &radio_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, " %s %d convert_freq_band_to_radio_index failed for band : %d \n", __FUNCTION__, __LINE__, radio_vap_map[r_index].band);
            return RETURN_ERR;
        }

        ret_val = update_wifi_radio_config(radio_index,&radio_vap_map[r_index]);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to update wifidb :%d\n", __FUNCTION__, __LINE__);
            strncpy(exec_ret_val->ErrorMsg,"Failed to update Wifidb of radio config ",
                    sizeof(exec_ret_val->ErrorMsg)-1);
            return RETURN_ERR;
        }
        ret_val = update_wifi_vap_config(radio_index,&vap_map[r_index]);
        if (ret_val != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to update wifidb :%d\n", __FUNCTION__, __LINE__);
            strncpy(exec_ret_val->ErrorMsg,"Failed to update wifidb of vapconfig",
                    sizeof(exec_ret_val->ErrorMsg)-1);
            return RETURN_ERR;
        }

    }
    ret_val = update_wifi_global_config(&wifi.global_parameters);
    if (ret_val != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to update wifidb :%d\n", __FUNCTION__, __LINE__);
        strncpy(exec_ret_val->ErrorMsg,"Failed to update wifidb of globalconfig",
                sizeof(exec_ret_val->ErrorMsg)-1);
        //return RETURN_ERR;
    }
    ret_val = update_wifi_gas_config(wifi.gas_config.AdvertisementID,&wifi.gas_config);
    if (ret_val != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to update wifidb :%d\n", __FUNCTION__, __LINE__);
        strncpy(exec_ret_val->ErrorMsg,"Failed to update wifidb of gasconfig",
                sizeof(exec_ret_val->ErrorMsg)-1);
        //return RETURN_ERR;
    }

    exec_ret_val->ErrorCode = BLOB_EXEC_SUCCESS;
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_radio_config_get
  Parameter   : void
  Description : Function to get radio and vap config 
 *************************************************************************************
***************************************************************************************/
int wifi_radio_config_get()
{
    wifi_vap_info_map_t vap_map[MAX_NUM_RADIOS];
    wifi_radio_operationParam_t radio_vap_map[MAX_NUM_RADIOS];
    int r_index = 0;
    unsigned int i = 0;
    wifi_global_param_t config;
    wifi_GASConfiguration_t gas;

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: wifidb %d\n", __FUNCTION__,num_radio);
    for (r_index = 0; r_index < (int)getNumberRadios(); r_index++)
    {
            get_wifi_radio_config(r_index,&radio_vap_map[r_index]);
            get_wifi_vap_config(r_index,&vap_map[r_index]);
            wifi_util_dbg_print(WIFI_DB,"%s:%d: Wifi_Radio_Config data enabled=%d freq_band=%d auto_channel_enabled=%d channel=%d  channel_width=%d hw_mode=%d csa_beacon_count=%d country=%d dcs_enabled=%d numSecondaryChannels=%d channelSecondary=%d dtim_period %d beacon_interval %d operating_class %d basic_data_transmit_rate %d operational_data_transmit_rate %d  fragmentation_threshold %d guard_interval %d transmit_power %d rts_threshold %d  factory_reset_ssid = %d, radio_stats_measuring_rate = %d, radio_stats_measuring_interval = %d, cts_protection %d, obss_coex= %d, stbc_enable= %d, greenfield_enable= %d, user_control= %d, admin_control= %d,chan_util_threshold= %d, chan_util_selfheal_enable= %d \n",__func__, __LINE__,radio_vap_map[r_index].enable,radio_vap_map[r_index].band,radio_vap_map[r_index].autoChannelEnabled,radio_vap_map[r_index].channel,radio_vap_map[r_index].channelWidth,radio_vap_map[r_index].variant,radio_vap_map[r_index].csa_beacon_count,radio_vap_map[r_index].countryCode,radio_vap_map[r_index].DCSEnabled,radio_vap_map[r_index].numSecondaryChannels,radio_vap_map[r_index].channelSecondary[0],radio_vap_map[r_index].dtimPeriod,radio_vap_map[r_index].beaconInterval,radio_vap_map[r_index].operatingClass,radio_vap_map[r_index].basicDataTransmitRates,radio_vap_map[r_index].operationalDataTransmitRates,radio_vap_map[r_index].fragmentationThreshold,radio_vap_map[r_index].guardInterval,radio_vap_map[r_index].transmitPower,radio_vap_map[r_index].rtsThreshold,radio_vap_map[r_index].factoryResetSsid,radio_vap_map[r_index].radioStatsMeasuringRate,radio_vap_map[r_index].radioStatsMeasuringInterval,radio_vap_map[r_index].ctsProtection,radio_vap_map[r_index].obssCoex,radio_vap_map[r_index].stbcEnable,radio_vap_map[r_index].greenFieldEnable,radio_vap_map[r_index].userControl,radio_vap_map[r_index].adminControl,radio_vap_map[r_index].chanUtilThreshold,radio_vap_map[r_index].chanUtilSelfHealEnable);

	    for (i=0;i<vap_map[r_index].num_vaps;i++)
            {
                wifi_util_dbg_print(WIFI_DB,"%s:%d:VAP Config Row=%d radioindex=%d vap_name=%s vap_index=%d ssid=%s enabled=%d ssid_advertisement_enable=%d isolation_enabled=%d mgmt_power_control=%d bss_max_sta =%d bss_transition_activated=%d nbr_report_activated=%d  rapid_connect_enabled=%d rapid_connect_threshold=%d vap_stats_enable=%d mac_filter_enabled =%d mac_filter_mode=%d  wmm_enabled=%d anqpParameters=%s hs2Parameters=%s uapsd_enabled =%d beacon_rate=%d bridge_name=%s wmm_noack = %d wep_key_length = %d bss_hotspot = %d wps_push_button = %d beacon_rate_ctl =%s network_initiated_greylist=%d\n",__func__, __LINE__,i,vap_map[r_index].vap_array[i].radio_index,vap_map[r_index].vap_array[i].vap_name,vap_map[r_index].vap_array[i].vap_index,vap_map[r_index].vap_array[i].u.bss_info.ssid,vap_map[r_index].vap_array[i].u.bss_info.enabled,vap_map[r_index].vap_array[i].u.bss_info.showSsid ,vap_map[r_index].vap_array[i].u.bss_info.isolation,vap_map[r_index].vap_array[i].u.bss_info.mgmtPowerControl,vap_map[r_index].vap_array[i].u.bss_info.bssMaxSta,vap_map[r_index].vap_array[i].u.bss_info.bssTransitionActivated,vap_map[r_index].vap_array[i].u.bss_info.nbrReportActivated,vap_map[r_index].vap_array[i].u.bss_info.rapidReconnectEnable,vap_map[r_index].vap_array[i].u.bss_info.rapidReconnThreshold,vap_map[r_index].vap_array[i].u.bss_info.vapStatsEnable,vap_map[r_index].vap_array[i].u.bss_info.mac_filter_enable,vap_map[r_index].vap_array[i].u.bss_info.mac_filter_mode,vap_map[r_index].vap_array[i].u.bss_info.wmm_enabled,vap_map[r_index].vap_array[i].u.bss_info.interworking.anqp.anqpParameters,vap_map[r_index].vap_array[i].u.bss_info.interworking.passpoint.hs2Parameters,vap_map[r_index].vap_array[i].u.bss_info.UAPSDEnabled,vap_map[r_index].vap_array[i].u.bss_info.beaconRate,vap_map[r_index].vap_array[i].bridge_name,vap_map[r_index].vap_array[i].u.bss_info.wmmNoAck,vap_map[r_index].vap_array[i].u.bss_info.wepKeyLength,vap_map[r_index].vap_array[i].u.bss_info.bssHotspot,vap_map[r_index].vap_array[i].u.bss_info.wpsPushButton,vap_map[r_index].vap_array[i].u.bss_info.beaconRateCtl,vap_map[r_index].vap_array[i].u.bss_info.network_initiated_greylist);
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Interworking_Config table vap_name=%s Enable=%d accessNetworkType=%d internetAvailable=%d asra=%d esr=%d uesa=%d hess_present=%d hessid=%s venueGroup=%d venueType=%d \n",__func__, __LINE__,vap_map[r_index].vap_array[i].vap_name,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.interworkingEnabled,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.accessNetworkType,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.internetAvailable,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.asra,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.esr,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.uesa,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.hessOptionPresent,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.hessid,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.venueGroup,vap_map[r_index].vap_array[i].u.bss_info.interworking.interworking.venueType);

                if ((!security_mode_support_radius(vap_map[r_index].vap_array[i].u.bss_info.security.mode))&& (!isVapHotspotOpen(vap_map[r_index].vap_array[i].vap_index)))
                {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table sec type=%d  sec key=%s \n",__func__, __LINE__,vap_map[r_index].vap_array[i].u.bss_info.security.u.key.type,vap_map[r_index].vap_array[i].u.bss_info.security.u.key.key,vap_map[r_index].vap_array[i].u.bss_info.security.u.key.type,vap_map[r_index].vap_array[i].u.bss_info.security.u.key.key);
                }
                else
                {
                    wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table radius server ip =%s  port =%d sec key=%s Secondary radius server ip=%s port=%d key=%s max_auth_attempts=%d blacklist_table_timeout=%d identity_req_retry_interval=%d server_retries=%d das_ip = %s das_port=%d das_key=%s\n",__func__, __LINE__,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.ip,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.port,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.key,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.s_ip,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.s_port,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.s_key,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.max_auth_attempts,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.blacklist_table_timeout,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.identity_req_retry_interval,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.server_retries,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.ip,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.dasport,vap_map[r_index].vap_array[i].u.bss_info.security.u.radius.daskey);
                }
                wifi_util_dbg_print(WIFI_DB,"%s:%d: Get Wifi_Security_Config table vap_name=%s Sec_mode=%d enc_mode=%d mfg_config=%d rekey_interval = %d strict_rekey  = %d eapol_key_timeout  = %d eapol_key_retries  = %d eap_identity_req_timeout  = %d eap_identity_req_retries  = %d eap_req_timeout = %d eap_req_retries = %d disable_pmksa_caching = %d \n",__func__, __LINE__,vap_map[r_index].vap_array[i].vap_name,vap_map[r_index].vap_array[i].u.bss_info.security.mode,vap_map[r_index].vap_array[i].u.bss_info.security.encr,vap_map[r_index].vap_array[i].u.bss_info.security.mfp,vap_map[r_index].vap_array[i].u.bss_info.security.rekey_interval,vap_map[r_index].vap_array[i].u.bss_info.security.strict_rekey,vap_map[r_index].vap_array[i].u.bss_info.security.eapol_key_timeout,vap_map[r_index].vap_array[i].u.bss_info.security.eapol_key_retries,vap_map[r_index].vap_array[i].u.bss_info.security.eap_identity_req_timeout,vap_map[r_index].vap_array[i].u.bss_info.security.eap_identity_req_retries,vap_map[r_index].vap_array[i].u.bss_info.security.eap_req_timeout,vap_map[r_index].vap_array[i].u.bss_info.security.eap_req_retries,vap_map[r_index].vap_array[i].u.bss_info.security.disable_pmksa_caching);

            } 
    }
    get_wifi_global_param(&config);
    wifi_util_dbg_print(WIFI_DB,"%s:%d  notify_wifi_changes %d  prefer_private %d  prefer_private_configure %d  factory_reset %d  tx_overflow_selfheal %d  inst_wifi_client_enabled %d  inst_wifi_client_reporting_period %d  inst_wifi_client_mac = %s inst_wifi_client_def_reporting_period %d  wifi_active_msmt_enabled %d  wifi_active_msmt_pktsize %d  wifi_active_msmt_num_samples %d  wifi_active_msmt_sample_duration %d  vlan_cfg_version %d  wps_pin = %s bandsteering_enable %d  good_rssi_threshold %d  assoc_count_threshold %d  assoc_gate_time %d  assoc_monitor_duration %d  rapid_reconnect_enable %d  vap_stats_feature %d  mfp_config_feature %d  force_disable_radio_feature %d  force_disable_radio_status %d  fixed_wmm_params %d  wifi_region_code %s diagnostic_enable %d  validate_ssid %d \n", __func__, __LINE__, config.notify_wifi_changes,config.prefer_private,config.prefer_private_configure,config.factory_reset,config.tx_overflow_selfheal,config.inst_wifi_client_enabled,config.inst_wifi_client_reporting_period,config.inst_wifi_client_mac, config.inst_wifi_client_def_reporting_period,config.wifi_active_msmt_enabled,config.wifi_active_msmt_pktsize,config.wifi_active_msmt_num_samples,config.wifi_active_msmt_sample_duration,config.vlan_cfg_version,config.wps_pin, config.bandsteering_enable,config.good_rssi_threshold,config.assoc_count_threshold,config.assoc_gate_time,config.assoc_monitor_duration,config.rapid_reconnect_enable,config.vap_stats_feature,config.mfp_config_feature,config.force_disable_radio_feature,config.force_disable_radio_status,config.fixed_wmm_params,config.wifi_region_code,config.diagnostic_enable,config.validate_ssid);
    get_wifi_gas_config(&gas);

    wifi_util_dbg_print(WIFI_DB,"%s:%d advertisement_id=%d pause_for_server_response=%d response_timeout=%d comeback_delay=%d response_buffering_time=%d query_responselength_limit=%d\n", __func__, __LINE__,gas.AdvertisementID,gas.PauseForServerResponse,gas.ResponseTimeout, gas.ComeBackDelay,gas.ResponseBufferingTime,gas.QueryResponseLengthLimit);
    return RETURN_OK;
}


/************************************************************************************
 ************************************************************************************
  Function    : vap_config_set
  Parameter   : buf          - Pointer to the decoded string
                len          - Size of the Decoded Message
                exec_ret_val - return value
  Description : Function to Parse Msg packed Wifi Config
 *************************************************************************************
***************************************************************************************/
int vap_config_set(const char *buf, size_t len, pErr exec_ret_val)
{
    exec_ret_val->ErrorCode = BLOB_EXEC_SUCCESS;
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_multicomp_subdoc_handler
  Parameter   : data - pointer to multicomp blob
  Description : Set Vap config via multicomp blob
 *************************************************************************************
***************************************************************************************/
pErr wifi_multicomp_subdoc_handler(void *data)
{
    unsigned char *msg = NULL; 
    unsigned long msg_size = 0;
    pErr exec_ret_val = NULL;

    if (data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Empty multi component subdoc\n",__FUNCTION__);
        return exec_ret_val;
    }
    msg = AnscBase64Decode((unsigned char *)data, &msg_size);
    
    if (!msg) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        return exec_ret_val;
    }

    exec_ret_val = (pErr ) malloc (sizeof(Err));
    if (exec_ret_val == NULL ) {
        free(msg);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s : Failed in allocating memory for error struct\n",__FUNCTION__);
        return exec_ret_val;
    }
    memset(exec_ret_val,0,(sizeof(Err)));

    if (vap_config_set((char *)msg, msg_size, exec_ret_val) == RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Successfully applied tbe subdoc\n",__FUNCTION__);
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s : Failed to apply the subdoc\n", __FUNCTION__);
    }
    if (msg) {
        free(msg);
    }
    return exec_ret_val;     
} 

/************************************************************************************
 ************************************************************************************
  Function    : wifi_vap_cfg_exec_handler
  Parameter   : data - pointer to vap data
  Description : Set Vap config
 *************************************************************************************
***************************************************************************************/
pErr wifi_vap_cfg_exec_handler(void *data)
{
    pErr exec_ret_val = NULL;

    if (data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Input Data is NULL\n",__FUNCTION__);
        return exec_ret_val;
    }

    wifi_vap_blob_data_t *vap_msg = (wifi_vap_blob_data_t *) data;
 
    exec_ret_val = (pErr ) malloc (sizeof(Err));
    if (exec_ret_val == NULL ) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s : Failed in allocating memory for error struct\n",__FUNCTION__);
        return exec_ret_val;
    }
    memset(exec_ret_val,0,(sizeof(Err)));
    
    if (vap_config_set((const char *)vap_msg->data,vap_msg->msg_size,exec_ret_val) == RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s : Vap config set success\n",__FUNCTION__);
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s : Vap config set Failed\n",__FUNCTION__);
    }

    return exec_ret_val;
}

/************************************************************************************
 ************************************************************************************
  Function    : wifi_vap_cfg_free_resources
  Parameter   : arg - pointer to blob memory
  Description : Release the allocated blob memory
 *************************************************************************************
***************************************************************************************/
void wifi_vap_cfg_free_resources(void *arg)
{

    wifi_util_dbg_print(WIFI_WEBCONFIG,"Entering: %s\n",__FUNCTION__);
    if (arg == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Input Data is NULL\n",__FUNCTION__);
        return;
    }
    
    execData *blob_exec_data  = (execData*) arg;

    wifi_vap_blob_data_t *vap_Data = (wifi_vap_blob_data_t *) blob_exec_data->user_data;
      
    if (vap_Data && vap_Data->data) {
        free(vap_Data->data);
        vap_Data->data = NULL;
    }
  
    if (vap_Data) {   
        free(vap_Data);
        vap_Data = NULL; 
    }

    free(blob_exec_data);
    blob_exec_data = NULL;
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Success in Clearing wifi vapconfig resources\n",__FUNCTION__);
}

/************************************************************************************
 ************************************************************************************
  Function    : vap_blob_set
  Parameter   : data vapconfig blob input
  Description : API to set vapconfig blob 
 *************************************************************************************
***************************************************************************************/
int vap_blob_set(void *data)
{
    char *decoded_data = NULL; 
    unsigned long msg_size = 0;
    size_t offset = 0;
    msgpack_unpacked msg;
    msgpack_unpack_return mp_rv;
    msgpack_object_map *map = NULL;
    msgpack_object_kv* map_ptr  = NULL;
    wifi_vap_blob_data_t *vap_data = NULL;
    int i = 0;

    if (data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Empty Blob Input\n",__FUNCTION__);
        return RETURN_ERR;
    }

    decoded_data = (char *)AnscBase64Decode((unsigned char *)data, &msg_size);

    if (!decoded_data) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed in Decoding vapconfig blob\n",__FUNCTION__);
        return RETURN_ERR;
    }

    msgpack_unpacked_init( &msg );
    /* The outermost wrapper MUST be a map. */
    mp_rv = msgpack_unpack_next( &msg, (const char*) decoded_data, msg_size+1, &offset );
    if (mp_rv != MSGPACK_UNPACK_SUCCESS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to unpack wifi msg blob. Error %d",__FUNCTION__,mp_rv);
        msgpack_unpacked_destroy( &msg );
        free(decoded_data);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:Msg unpack success. Offset is %lu\n", __FUNCTION__,offset);
    msgpack_object obj = msg.data;
    
    map = &msg.data.via.map;
    
    map_ptr = obj.via.map.ptr;
    if ((!map) || (!map_ptr)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Failed to get object map\n");
        msgpack_unpacked_destroy( &msg );
        free(decoded_data);
        return RETURN_ERR;
    }
    if (msg.data.type != MSGPACK_OBJECT_MAP) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Invalid msgpack type",__FUNCTION__);
        msgpack_unpacked_destroy( &msg );
        free(decoded_data);
        return RETURN_ERR;
    }    
   
    vap_data = (wifi_vap_blob_data_t *) malloc(sizeof(wifi_vap_blob_data_t));
    if (vap_data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Wifi vap data malloc error\n",__FUNCTION__);
        free(decoded_data); 
        return RETURN_ERR;
    }
 
    /* Parsing Config Msg String to Wifi Structure */
    for (i = 0;i < (int)map->size;i++) {
        if (strncmp(map_ptr->key.via.str.ptr, "version", map_ptr->key.via.str.size) == 0) {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                vap_data->version = (uint64_t) map_ptr->val.via.u64;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"Version type %d version %lu\n",map_ptr->val.type,vap_data->version);
            }
        }
        else if (strncmp(map_ptr->key.via.str.ptr, "transaction_id", map_ptr->key.via.str.size) == 0) {
            if (map_ptr->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                vap_data->transaction_id = (uint16_t) map_ptr->val.via.u64;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"Tx id type %d tx id %d\n",map_ptr->val.type,vap_data->transaction_id);
            }
        }
        ++map_ptr;
    }

    msgpack_unpacked_destroy( &msg );
    
    vap_data->msg_size = msg_size;
    vap_data->data = decoded_data;

    execData *exec_data_pf = NULL ;
    exec_data_pf = (execData*) malloc (sizeof(execData));
    if (exec_data_pf != NULL) {
        memset(exec_data_pf, 0, sizeof(execData));
        exec_data_pf->txid = vap_data->transaction_id;
        exec_data_pf->version = vap_data->version;
        exec_data_pf->numOfEntries = 2;
        strncpy(exec_data_pf->subdoc_name, "wifiVapData", sizeof(exec_data_pf->subdoc_name)-1);
        exec_data_pf->user_data = (void*) vap_data;
        exec_data_pf->calcTimeout = webconf_ssid_timeout_handler;
        exec_data_pf->executeBlobRequest = wifi_vap_cfg_exec_handler;
        exec_data_pf->rollbackFunc = wifi_vap_cfg_rollback_handler;
        exec_data_pf->freeResources = wifi_vap_cfg_free_resources;
        PushBlobRequest(exec_data_pf);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"PushBlobRequest Complete\n");
    }

    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : get_wifi_blob_version
  Parameter   : subdoc  - Pointer to name of the subdoc
  Description : API to get Blob version from PSM db
 *************************************************************************************
***************************************************************************************/    
uint32_t get_wifi_blob_version(char* subdoc)
{
	//This implemenation part is remaining.
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : set_wifi_blob_version
  Parameter   : subdoc  - Pointer to name of the subdoc
                version - Version of the blob
  Description : API to set Blob version in PSM db
 *************************************************************************************
***************************************************************************************/
int set_wifi_blob_version(char* subdoc,uint32_t version)
{
    //This implemenation part is remaining.
    return 0;
}

/************************************************************************************
 ************************************************************************************
  Function    : tunnel_event_callback
  Parameter   : info , data
  Description : Will be implemented
 *************************************************************************************
***************************************************************************************/
void tunnel_event_callback(char *info, void *data)
{
    //This implemenation part is remaining.
}

/************************************************************************************
 ************************************************************************************
  Function    : register_multicomp_subdocs
  Parameter   : void
  Description : API to register Multicomponent supported subdocs with framework
 *************************************************************************************
***************************************************************************************/
int register_multicomp_subdocs()
{
    int ret;
#ifdef WBCFG_MULTI_COMP_SUPPORT
    multiCompSubDocReg *subdoc_data = NULL;
    char *subdocs[MULTISUBDOC_COUNT+1]= {"hotspot", (char *) 0 };
    uint8_t i;

    subdoc_data = (multiCompSubDocReg *) malloc(MULTISUBDOC_COUNT * sizeof(multiCompSubDocReg));
    if (subdoc_data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to alloc memory for registering multisubdocs\n",__FUNCTION__);
        return RETURN_ERR;
    }
    memset(subdoc_data, 0 , MULTISUBDOC_COUNT * sizeof(multiCompSubDocReg));
    
    for(i = 0; i < MULTISUBDOC_COUNT; i++) {
        strncpy(subdoc_data->multi_comp_subdoc, subdocs[i], sizeof(subdoc_data->multi_comp_subdoc)-1);
        subdoc_data->executeBlobRequest = wifi_multicomp_subdoc_handler;
        subdoc_data->calcTimeout = wifi_vap_cfg_timeout_handler;
        subdoc_data->rollbackFunc = wifi_vap_cfg_rollback_handler;
    }

    register_MultiComp_subdoc_handler(subdoc_data, MULTISUBDOC_COUNT);

#endif
     /* Register ccsp event to receive GRE Tunnel UP/DOWN */
    ret = CcspBaseIf_Register_Event(bus_handle,NULL,"TunnelStatus");
    if (ret != CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s Failed to register for tunnel status notification event",__FUNCTION__);
        return ret;
    }
    CcspBaseIf_SetCallback2(bus_handle, "TunnelStatus", tunnel_event_callback, NULL);
    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
  Function    : init_web_config
  Parameter   : void
  Description : API to register all the supported subdocs , version_get and
               version_set are callback functions to get and set the subdoc versions in db
 *************************************************************************************
***************************************************************************************/
int init_web_config()
{
    char *sub_docs[SUBDOC_COUNT+1]= {"privatessid","homessid","wifiVapData",(char *) 0 };
    blobRegInfo *blob_data = NULL,*blob_data_pointer = NULL;
    int i;

    blob_data = (blobRegInfo*) malloc(SUBDOC_COUNT * sizeof(blobRegInfo));
    if (blob_data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Malloc error\n",__FUNCTION__); 
        return RETURN_ERR;
    }
    memset(blob_data, 0, SUBDOC_COUNT * sizeof(blobRegInfo));

    blob_data_pointer = blob_data;
    for (i=0 ;i < SUBDOC_COUNT; i++)
    {
        strncpy(blob_data_pointer->subdoc_name, sub_docs[i], sizeof(blob_data_pointer->subdoc_name)-1);
        blob_data_pointer++;
    }
    blob_data_pointer = blob_data;
 
    getVersion version_get = get_wifi_blob_version;
    setVersion version_set = set_wifi_blob_version;

    register_sub_docs(blob_data,SUBDOC_COUNT,version_get,version_set);

    if (register_multicomp_subdocs() != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to register multicomp subdocs with framework\n",__FUNCTION__);
        return RETURN_ERR;
    }
    return 0;
}
#endif
