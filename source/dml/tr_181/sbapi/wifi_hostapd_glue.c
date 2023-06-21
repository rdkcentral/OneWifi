/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2021 RDK Management

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

/*************************************************************************
  Some material from
  Copyright (c) 2003-2014, Jouni Malinen <j@w1.fi>
  Licensed under the BSD-3 License

**************************************************************************/

#include "plugin_main_apis.h"
#include "cosa_wifi_apis.h"
#include "wifi_hostap_auth.h"
#include "cosa_wifi_internal.h"
#include <cJSON.h>
#include "wifi_hal_rdk.h"
#include <sys/prctl.h>

#define MAC_LEN 19

/*********************************************
*           GLOBAL VARIABLES                 *
*********************************************/

//Check whether eloop init is already done or not.
static int is_eloop_init_done = 0;

void hapd_reset_ap_interface(int apIndex);
#if !defined (_XB7_PRODUCT_REQ_)
void hapd_wpa_deinit(int ap_index);
#endif
void libhostapd_wpa_deinit(int ap_index);
void convert_apindex_to_interface(int idx, char *iface, int len);

#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
#if !defined (_XB7_PRODUCT_REQ_)
char *cmmac; //Global variable to get the cmmac of the gateway
#endif

/****************************************************
*           FUNCTION DEFINITION(S)                  *
****************************************************/

/* RDKB-30263 Grey List control from RADIUS
This function is to execute the command and retrieve the value
@arg1 - cmd - command to execute on syste,
@arg2 - retBuf - Buffer to hold the data
@ags3 - retBufSize - buffer size
return - success 0 Failue 1
*/
int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    FILE *f;
    char *ptr = retBuf;
    int bufSize=retBufSize, bufbytes=0, readbytes=0;

    if ((f = popen(cmd, "r")) == NULL) {
        wpa_printf(MSG_ERROR, "popen %s error\n", cmd);
        return -1;
    }

    while(!feof(f)) {
        *ptr = 0;
        if(bufSize>=128) {
                bufbytes=128;
        } else {
                bufbytes=bufSize-1;
        }
        fgets(ptr,bufbytes,f);
        readbytes=strlen(ptr);
        if( readbytes== 0)
                break;
        bufSize-=readbytes;
        ptr += readbytes;
    }
    pclose(f);
    return 0;
}
#endif //FEATURE_SUPPORT_RADIUSGREYLIST

#if defined (FEATURE_SUPPORT_RADIUSGREYLIST) && !defined(_XB7_PRODUCT_REQ_)
extern void wifi_del_mac_handler(void *eloop_ctx, void *timeout_ctx);
extern void wifi_add_mac_handler(char *addr, struct hostapd_data *hapd);

/* RDKB-30263 Grey List control from RADIUS
This function is to read the mac from /nvram/greylist_mac.txt when the process starts/restart,
add the client mac to the greylist and run 24hrs timers for those client mac*/

void greylist_cache_timeout (struct hostapd_data *hapd)
{

    FILE *fptr;
    char date[10] = {0}, get_time[10] = {0}, mac[18] = {0};
    char buffer1[26] = {0}, time_buf[26] = {0};
    struct tm time1, time2;
    time_t newtime;
    struct tm *timeinfo;
    time_t t1, t2;
    int index = 0;
    struct greylist_mac *mac_data;
    u32 timeleft=0;
    u32 timeout=TWENTYFOUR_HR_IN_SEC;

    /* Open the file to get the list of greylisted mac*/
    if ((fptr = fopen("/nvram/greylist_mac.txt", "r")) == NULL) {
        wpa_printf(MSG_DEBUG,"No such file, no greylist client\n");
        return;
    }
    /* Read each mac from the file and add the mac to the greylist*/
    while ((fscanf(fptr, "%s %s %s %d", date, get_time, mac, &index)) == 4) {  // Read the time and mac from the file
        mac_data = os_zalloc(sizeof(*mac_data));
        if (mac_data == NULL) {
            wpa_printf(MSG_DEBUG, "unable to allocate memory "
                    "failed");
            fclose(fptr);
            return;
        }
        timeleft = 0;
        timeout = TWENTYFOUR_HR_IN_SEC;
        os_memcpy(mac_data->mac,mac,sizeof(mac));
        snprintf(time_buf,20,"%s %s",date,get_time);
        time ( &newtime );                                       //Get the curent time to calculate the remaining time
        timeinfo = localtime ( &newtime );
        strftime(buffer1, 26, "%Y-%m-%d %H:%M:%S", timeinfo);    // convert the time to this format 2020-11-09 13:17:56
        if (!strptime(buffer1, "%Y-%m-%d %T", &time1))
            printf("\nstrptime failed-1\n");
        if (!strptime(time_buf, "%Y-%m-%d %T", &time2))
            printf("\nstrptime failed-2\n");
        t1 = mktime(&time1);
        t2 = mktime(&time2);

        wifi_add_mac_handler(mac, hapd);                    // Add the mac to the greylist
        timeleft=comparetime(t1,t2,mac);              // calculate the time leftout for the client from the 24 hrs of time
        if (timeleft  > TWENTYFOUR_HR_IN_SEC ) {     // Due to some reason client entry is not removed after 24hrs force the clienttimeout to 0
            wpa_printf(MSG_DEBUG,"Timeout exceeded :%d",timeleft);
            timeout = 0;
        }
        else {
            timeout -= timeleft;
        }
        wpa_printf(MSG_DEBUG, "eloop timeout for greylist :%s :timeout:%d",mac_data->mac,timeout);
        eloop_cancel_timeout(wifi_del_mac_handler, mac_data, hapd); //cancel the timer if the timer is already running for the client mac
        eloop_register_timeout(timeout, 0, wifi_del_mac_handler, mac_data, hapd); //start the timer for the client mac
    }
    fclose(fptr);
    return;
}
#endif //FEATURE_SUPPORT_RADIUSGREYLIST

/* Description:
 *      The API is used set vap(athX) interface up or down.
 * Arguments:
 *      ifname - Interface name(athX) to be updated.
 *      dev_up - Switch up/down the respective interface.
 *         1 - UP 0 - Down.
 */

#if !defined(_XB7_PRODUCT_REQ_)
int linux_set_iface_flags(const char *ifname, int dev_up)
{

    return wifi_setIfaceFlags(ifname, dev_up);
}
#endif

/* Description:
 *      The API is used to receive assoc req frame received from client and forward to
 *      lib hostapd authenticator.
 * Arguments:
 *      ap_index - Index of Vap in which frame is received
 *      sta - client station mac-address.
 *      reason - Reason for disassoc and deauth.
 *      frame - Assoc resp frames.
 *      frame_len - Assoc resp length
 */
#if 0
int hapd_process_assoc_req_frame(unsigned int ap_index, mac_address_t sta, unsigned char *frame, unsigned int frame_len)
{
    struct hostapd_data *hapd;
#if defined (_XB7_PRODUCT_REQ_)
    hapd = g_hapd_glue[ap_index].hapd;
#else
    hapd = &g_hapd_glue[ap_index].hapd;
#endif

    if (!hapd || !hapd->started)
        return -1;

    const struct ieee80211_mgmt *mgmt;
    int len = frame_len;
    u16 fc, stype;
    int ielen = 0;
    const u8 *iebuf = NULL;
    int reassoc = 0;

    mgmt = (const struct ieee80211_mgmt *) frame;

    if (len < (int)IEEE80211_HDRLEN) {
        wpa_printf(MSG_INFO, "%s:%d: ASSOC REQ HEADER is not proper \n", __func__, __LINE__);
        return -1;
    }

    fc = le_to_host16(mgmt->frame_control);

    if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT) {
        wpa_printf(MSG_INFO, "%s:%d: ASSOC REQ HEADER is not ASSOC mgt REQ\n", __func__, __LINE__);
        return -1;
    }

    stype = WLAN_FC_GET_STYPE(fc);

    switch (stype) {
        case WLAN_FC_STYPE_ASSOC_REQ:
            if (len < (int)( IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req)))
                break;
            ielen = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req));
            iebuf = mgmt->u.assoc_req.variable;
            reassoc = 0;
            break;

        case WLAN_FC_STYPE_REASSOC_REQ:
            wpa_printf(MSG_INFO, "%s:%d: REASSOC REQ ieee802_11_mgmt \n", __func__, __LINE__);
            if (len < (int) (IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req)))
                break;
            ielen = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req));
            iebuf = mgmt->u.reassoc_req.variable;
            reassoc = 1;
            break;
    }
    hostapd_notif_assoc(hapd, mgmt->sa,
            iebuf,
            ielen,
            reassoc);
    return 0;
}
#endif//ONE_WIFI

/* Description:
 *      The API is used to receive assoc rsp frame received from client and forward to
 *      lib hostapd authenticator.
 * Arguments:
 *      ap_index - Index of Vap in which frame is received
 *      sta - client station mac-address.
 *      reason - Reason for disassoc and deauth.
 *      frame - Assoc resp frames.
 *      frame_len - Assoc resp length
 * !!Currently not used!!
 */
int hapd_process_assoc_rsp_frame(unsigned int ap_index, mac_address_t sta, unsigned char *frame, unsigned int frame_len)
{
   //	ieee802_11_mgmt_cb(&g_hapd_glue[ap_index].hapd, frame, frame_len, WLAN_FC_STYPE_ASSOC_RESP, 1);
   return 0;
}

/* Description:
 *      The API is used to receive disassoc/deauth frame received from client and forward to
 *      lib hostapd authenticator.
 * Arguments:
 *      ap_index - Index of Vap in which frame is received
 *      sta - client station mac-address.
 *      reason - Reason for disassoc and deauth.
 */
#if 0
int hapd_process_disassoc_frame(unsigned int ap_index, mac_address_t sta, int reason)
{
#if !defined (_XB7_PRODUCT_REQ_)
    struct hostapd_data *hapd;
    hapd = &g_hapd_glue[ap_index].hapd;

    if (!hapd || !hapd->started)
        return -1;

    hostapd_notif_disassoc(hapd, sta);
#endif
    return 0;
}
#endif//ONE_WIFI

/* Description:
 *      The API is used to receive AUTH req/resp frames from data plane and forward to
 *      lib hostapd authenticator.
 * Arguments:
 *      ap_index - Index of Vap in which frame is received
 *      sta - client station mac-address.
 *      frame - Auth req/resp frames.
 *      frame_len - Auth req/resp length
 *      dir - Direction of frame - uplink or downlink.
 *          uplink - From Client to AP
 *          dwonlink - AP to Client
 *
 */
#if 0
int hapd_process_auth_frame(unsigned int ap_index, mac_address_t sta, unsigned char *frame, unsigned int frame_len, wifi_direction_t dir)
{
#if defined (_XB7_PRODUCT_REQ_)
    struct hostapd_data *hapd = g_hapd_glue[ap_index].hapd;
#else
    struct hostapd_data *hapd = &g_hapd_glue[ap_index].hapd;
#endif

    if (!hapd || !hapd->started)
        return -1;

    const struct ieee80211_mgmt *mgmt;
    union wpa_event_data event;
    int len = frame_len;

    mgmt = (const struct ieee80211_mgmt *) frame;

    if (len < (int) (IEEE80211_HDRLEN + sizeof(mgmt->u.auth))) {
        wpa_printf(MSG_ERROR, "%s:%d AUTH HDR LEN is not proper END\n", __func__, __LINE__);
        return -1;
    }
    os_memset(&event, 0, sizeof(event));
    if (le_to_host16(mgmt->u.auth.auth_alg) == WLAN_AUTH_SAE) {
        event.rx_mgmt.frame = frame;
        event.rx_mgmt.frame_len = len;
        return -1;
    }
    os_memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
    os_memcpy(event.auth.bssid, mgmt->bssid, ETH_ALEN);
    event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
    event.auth.status_code = le_to_host16(mgmt->u.auth.status_code);
    event.auth.auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
    event.auth.ies = mgmt->u.auth.variable;
    event.auth.ies_len = len - IEEE80211_HDRLEN - sizeof(mgmt->u.auth);

    if (dir == wifi_direction_uplink) {
        hostapd_notif_auth(hapd, &event.auth);
        //return ieee802_11_mgmt(&g_hapd_glue[ap_index].hapd, frame, frame_len, NULL);
    } else if (dir == wifi_direction_downlink) {
        //ieee802_11_mgmt_cb(&g_hapd_glue[ap_index].hapd, frame, frame_len, WLAN_FC_STYPE_AUTH, 1);
        //return;
    }
    return 0;
}
#endif//ONE_WIFI
/* Description:
 *      The API is used to receive EAPOL frames from data plane and forward to
 *      lib hostapd authenticator.
 * Arguments:
 *      ap_index - Index of Vap in which frame is received
 *      sta - client station mac-address.
 *      data - EAPOL data frames.
 *      data_len - EAPOL data length
 *
 */
#if 0
int hapd_process_eapol_frame(unsigned int ap_index, mac_address_t sta, unsigned char *data, unsigned int data_len)
{
#if defined (_XB7_PRODUCT_REQ_)
    struct hostapd_data *hapd = g_hapd_glue[ap_index].hapd;
#else
    struct hostapd_data *hapd = &g_hapd_glue[ap_index].hapd;
#endif

    ieee802_1x_receive(hapd, sta, data, data_len);
    return 0;
}

//Thread for calling hostap eloop_run_thread
/* Description:
 *      The API is used start the eloop after all the eloop registered timer.
 *      Make sure it is called only once for any number of VAP(s) enabled.
 * Arguments: None
 */
static void* eloop_run_thread(void *data)
{
    prctl(PR_SET_NAME,  __func__, 0, 0, 0);
    eloop_run();
    wpa_printf(MSG_INFO,"%s:%d: Started eloop mechanism\n", __func__, __LINE__);
    pthread_detach(pthread_self());
    pthread_exit(0);
}

/* Description:
 *      The API is used to create thread for starting the eloop after
 *      all the eloop registered timer.
 * Arguments: None
 */
void hapd_wpa_run()
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, eloop_run_thread, NULL))
    {
        wpa_printf(MSG_ERROR,"%s:%d: failing creating eloop run \n", __func__, __LINE__);
    }

}
#endif//ONE_WIFI

void update_default_oem_configs(int apIndex, struct hostapd_bss_config *bss)
{
    cJSON *json = NULL, *jsonObj = NULL, *jsonData = NULL;
    FILE *fp = NULL;
    char *data = NULL;
    int len = 0;

    fp = fopen("/usr/ccsp/wifi/LibHostapdConfigFile.json", "r");
    if (fp != NULL)
    {
        fseek( fp, 0, SEEK_END );
        len = ftell(fp);
        fseek(fp, 0, SEEK_SET );

        data = ( char* )malloc( sizeof(char) * (len + 1) );
        if (!data)
        {
            wpa_printf(MSG_ERROR, "%s:%d Unable to allocate memory of len %d", __func__, __LINE__, len);
            fclose(fp);
            return;
        }
        memset( data, 0, ( sizeof(char) * (len + 1) ));
        fread( data, 1, len, fp);

        fclose(fp);

        if (strlen(data) != 0)
        {
            json = cJSON_Parse(data);
            if (!json)
            {
                wpa_printf(MSG_ERROR, "%s:%d Unable to parse JSON data", __func__, __LINE__);
                free(data);
                return;
            }
            /* WPS Configs */
            jsonObj = cJSON_GetObjectItem(json, "WPS");
            if (jsonObj != NULL)
            {
                jsonData = cJSON_GetObjectItem(jsonObj, "device_name");
                bss->device_name = strdup(jsonData ? jsonData->valuestring : "RDKB");

                jsonData = cJSON_GetObjectItem(jsonObj, "manufacturer");
                bss->manufacturer = strdup(jsonData ? jsonData->valuestring : "RDKB XB Communications, Inc.");

                jsonData = cJSON_GetObjectItem(jsonObj, "model_name");
                bss->model_name = strdup(jsonData ? jsonData->valuestring : "APxx");

                jsonData = cJSON_GetObjectItem(jsonObj, "model_number");
                bss->model_number = strdup(jsonData ? jsonData->valuestring : "APxx-xxx");

                jsonData = cJSON_GetObjectItem(jsonObj, "serial_number");
                bss->serial_number = strdup(jsonData ? jsonData->valuestring : "000000");

                jsonData = cJSON_GetObjectItem(jsonObj, "device_type");
                if (!jsonData || wps_dev_type_str2bin(jsonData->valuestring, bss->device_type))
                {
                    wpa_printf(MSG_ERROR,"Error in device type configs - %d\n", __LINE__);
                    return;
                }

                jsonData = cJSON_GetObjectItem(jsonObj, "friendly_name");
                bss->friendly_name = strdup(jsonData ? jsonData->valuestring : "RDKBxx");

                jsonData = cJSON_GetObjectItem(jsonObj, "manufacturer_url");
                bss->manufacturer_url = strdup(jsonData ? jsonData->valuestring : "http://manufacturer.url.here");

                jsonData = cJSON_GetObjectItem(jsonObj, "model_description");
                bss->model_description = strdup(jsonData ? jsonData->valuestring : "Model description here");

                jsonData = cJSON_GetObjectItem(jsonObj, "model_url");
                bss->model_url = strdup(jsonData ? jsonData->valuestring : "http://model.url.here");
            }

#if !defined(_XB7_PRODUCT_REQ_)
            jsonObj = cJSON_GetObjectItem(json, "BSS");
            if (jsonObj != NULL)
            {
#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
                jsonData = cJSON_GetObjectItem(jsonObj, "ap_vlan");
                if (jsonData != NULL && cJSON_GetArraySize(jsonData))
                    bss->ap_vlan = cJSON_GetArrayItem(jsonData, apIndex)->valueint;
#endif /* FEATURE_SUPPORT_RADIUSGREYLIST */

                jsonData = cJSON_GetObjectItem(jsonObj, "bridge");
                if (jsonData != NULL && cJSON_GetArraySize(jsonData))
                    snprintf(bss->bridge, IFNAMSIZ + 1, "%s", cJSON_GetArrayItem(jsonData, apIndex)->valuestring);
            }
            else
            {
                wpa_printf(MSG_ERROR, "%s:%d Unable to Parse sub object item\n", __func__, __LINE__);
            }
#endif //_XB7_PRODUCT_REQ_
            cJSON_Delete(json);
        }
        free(data);
        data = NULL;

    } else
        wpa_printf(MSG_ERROR, "%s:%d Unable to open config file", __func__, __LINE__);
}

/* Description:
 *      The API is used to init default values for radius params (auth and acct server)
 *      only if iee802_1x is enabled..
 * Arguments:
 *      conf - Allocated bss config struct
 */
void update_radius_config(struct hostapd_bss_config *conf)
{
     if (conf->radius == NULL) {
         //radius configuration call this as radius_init in glue.c
         conf->radius = malloc(sizeof(struct hostapd_radius_servers));

         memset(conf->radius, '\0', sizeof(struct hostapd_radius_servers));
     }

#if !defined(_XB7_PRODUCT_REQ_)
     if (conf->ieee802_1x)
     {
#endif
	conf->radius->num_auth_servers = 1;

	struct hostapd_radius_server *pri_auth_serv = NULL, *sec_auth_serv = NULL;
	char *auth_serv_addr = "127.0.0.1";
	//authentication server
	pri_auth_serv = malloc(sizeof(struct hostapd_radius_server));
	if (inet_aton(auth_serv_addr, &pri_auth_serv->addr.u.v4)) {
	        pri_auth_serv->addr.af = AF_INET;
	}
	pri_auth_serv->port = 1812;
	pri_auth_serv->shared_secret = (u8 *) os_strdup("radius");
	pri_auth_serv->shared_secret_len = os_strlen("radius");
	conf->radius->auth_server = pri_auth_serv;

	sec_auth_serv = malloc(sizeof(struct hostapd_radius_server));
	if (inet_aton(auth_serv_addr, &sec_auth_serv->addr.u.v4)) {
	        sec_auth_serv->addr.af = AF_INET;
	}
	sec_auth_serv->port = 1812;
	sec_auth_serv->shared_secret = (u8 *) os_strdup("radius");
	sec_auth_serv->shared_secret_len = os_strlen("radius");
	conf->radius->auth_servers =sec_auth_serv;

	conf->radius->msg_dumps = 1;

	//accounting server
	conf->radius->num_acct_servers = 0;
/* Account servers not needed as AAA server doesn't handle RADIUS accounting packets */
#if 0
	accnt_serv = malloc(sizeof(struct hostapd_radius_server));
	if (inet_aton(accnt_serv_addr, &accnt_serv->addr.u.v4)) {
	        accnt_serv->addr.af = AF_INET;
	}
	accnt_serv->port = 1813;
	accnt_serv->shared_secret = (u8 *) os_strdup("radius");
	accnt_serv->shared_secret_len = os_strlen("radius");
	conf->radius->acct_server = accnt_serv;
	conf->radius->acct_servers = accnt_serv;
#endif
	conf->radius->force_client_addr =0;
#if !defined(_XB7_PRODUCT_REQ_)
    }
#endif
}

/* Description:
 *      Construct key_mgmt value from TR-181 cache for
 *      saving it in hostap authenticator.
 * Arguments:
 *      encryptionMethod - TR-181 cache value.
 *      Device.WiFi.AccessPoint.{i}.Security.ModeEnabled.
 *
 */
static int hostapd_tr181_config_parse_key_mgmt(int modeEnabled)
{
    char conf_value[16] = {0};
    int val = 0;

    switch(modeEnabled)
    {
        case COSA_DML_WIFI_SECURITY_WPA2_Personal:
        case COSA_DML_WIFI_SECURITY_WPA_WPA2_Personal:
        {
            strcpy(conf_value, "WPA-PSK");
            break;
        }
        case COSA_DML_WIFI_SECURITY_WPA2_Enterprise:
        case COSA_DML_WIFI_SECURITY_WPA_WPA2_Enterprise:
        {
            strcpy(conf_value, "WPA-EAP");
            break;
        }
        case COSA_DML_WIFI_SECURITY_None:
        {
            strcpy(conf_value, "NONE");
            break;
        }
        case COSA_DML_WIFI_SECURITY_WPA3_Personal:
        case COSA_DML_WIFI_SECURITY_WPA3_Personal_Transition:
        {
            strcpy(conf_value, "WPA-PSK SAE");
            break;
        }
        case COSA_DML_WIFI_SECURITY_WPA3_Enterprise:
        {
            strcpy(conf_value, "WPA-EAP SAE");
            break;
        }
    }

    if (os_strcmp(conf_value, "WPA-PSK") == 0)
        val |= WPA_KEY_MGMT_PSK;
    else if (os_strcmp(conf_value, "WPA-EAP") == 0)
        val |= WPA_KEY_MGMT_IEEE8021X;
#ifdef CONFIG_IEEE80211R
//Defined
    else if (os_strcmp(conf_value, "FT-PSK") == 0)
        val |= WPA_KEY_MGMT_FT_PSK;
    else if (os_strcmp(conf_value, "FT-EAP") == 0)
        val |= WPA_KEY_MGMT_FT_IEEE8021X;
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
//Defined
    else if (os_strcmp(conf_value, "WPA-PSK-SHA256") == 0)
        val |= WPA_KEY_MGMT_PSK_SHA256;
    else if (os_strcmp(conf_value, "WPA-EAP-SHA256") == 0)
         val |= WPA_KEY_MGMT_IEEE8021X_SHA256;
#endif /* CONFIG_IEEE80211W */
#if defined (CONFIG_SAE) && defined (WIFI_HAL_VERSION_3)
    else if (os_strcmp(conf_value, "WPA-PSK SAE") == 0) {
         val |= WPA_KEY_MGMT_PSK;
         val |= WPA_KEY_MGMT_SAE;
    }
    else if (os_strcmp(conf_value, "WPA-EAP SAE") == 0) {
        val |= WPA_KEY_MGMT_IEEE8021X;
        val |= WPA_KEY_MGMT_SAE;
    }
    else if (os_strcmp(conf_value, "FT-SAE") == 0)
         val |= WPA_KEY_MGMT_FT_SAE;
#endif /* CONFIG_SAE */
#ifdef CONFIG_SUITEB
//Not Defined
    else if (os_strcmp(conf_value, "WPA-EAP-SUITE-B") == 0)
         val |= WPA_KEY_MGMT_IEEE8021X_SUITE_B;
#endif /* CONFIG_SUITEB */
#ifdef CONFIG_SUITEB192
//Not Defined
    else if (os_strcmp(conf_value, "WPA-EAP-SUITE-B-192") == 0)
         val |= WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
#endif /* CONFIG_SUITEB192 */
    else if (os_strcmp(conf_value, "NONE") == 0)
         val |= WPA_KEY_MGMT_NONE;
    else {
         wpa_printf(MSG_ERROR, "Line %d: invalid key_mgmt '%s'",
                     __LINE__, conf_value);
         return -1;
    }
    return val;
}

/* Description:
 *      Construct cipher value from TR-181 cache for
 *      saving it in hostap authenticator.
 * Arguments:
 *      encryptionMethod - TR-181 cache value.
 *      Device.WiFi.AccessPoint.{i}.Security.X_CISCO_COM_EncryptionMethod
 *
 */
static int hostapd_tr181_config_parse_cipher(int encryptionMethod)
{
    char conf_value[16] = {0};

    switch(encryptionMethod)
    {
        case COSA_DML_WIFI_AP_SEC_TKIP:
            strcpy(conf_value, "TKIP");
            break;
        case COSA_DML_WIFI_AP_SEC_AES:
            strcpy(conf_value, "CCMP");
            break;
        case COSA_DML_WIFI_AP_SEC_AES_TKIP:
            strcpy(conf_value, "TKIP CCMP");
            break;
        default:
            wpa_printf(MSG_ERROR, "Wrong encryption method configured\n");
            return -1;
    }

    int val = wpa_parse_cipher(conf_value);
    if (val < 0) {
        wpa_printf(MSG_ERROR, "Line %d: invalid cipher '%s'.",
                   __LINE__, conf_value);
        return -1;
    }
    if (val == 0) {
        wpa_printf(MSG_ERROR, "Line %d: no cipher values configured.",
                   __LINE__);
        return -1;
    }
    return val;
}

/* Description:
 *      Delete all WPS config allocated sources during config parser of hostapd init.
 *      This API will only deinit hostapd_bss_config WPS configuration,
 * Arguments:
 *      conf - Allocated hostapd_bss_config structure.
 *
 * Note: Init all the source to NULL after freed.
 */
void hostapd_config_free_wps(struct hostapd_bss_config *conf)
{

#ifdef CONFIG_WPS
//Defined
    os_free(conf->device_name);
    conf->device_name = NULL;

    os_free(conf->manufacturer);
    conf->manufacturer = NULL;

    os_free(conf->model_name);
    conf->model_name = NULL;

    os_free(conf->model_number);
    conf->model_number = NULL;

    os_free(conf->serial_number);
    conf->serial_number = NULL;

    os_free(conf->config_methods);
    conf->config_methods = NULL;

    os_free(conf->ap_pin);
    conf->ap_pin = NULL;

    os_free(conf->friendly_name);
    conf->friendly_name = NULL;

    os_free(conf->manufacturer_url);
    conf->manufacturer_url = NULL;

    os_free(conf->model_description);
    conf->model_description = NULL;

    os_free(conf->model_url);
    conf->model_url = NULL;
#endif //CONFIG_WPS
}

/* Description:
 *      Delete all allocated sources during config parser of hostapd init.
 *      This API will only deinit hostapd_bss_config conf structure,
 * Arguments:
 *      conf - Allocated hostapd_bss_config structure.
 *
 * Note: Init all the source to NULL after freed.
 */
void hostapd_config_free_bss(struct hostapd_bss_config *conf)
{
#if 0
    struct hostapd_eap_user *user, *prev_user;
#endif
    if (conf == NULL)
            return;

    wpa_printf(MSG_INFO,"%s - %d Start of Deinit API \n", __func__, __LINE__);
    hostapd_config_clear_wpa_psk(&conf->ssid.wpa_psk);

    if (conf->ssid.wpa_passphrase)
    {
        str_clear_free(conf->ssid.wpa_passphrase);
        conf->ssid.wpa_passphrase = NULL;
        conf->ssid.wpa_passphrase_set = 0;
    }

    if (conf->ssid.wpa_psk_file)
    {
        os_free(conf->ssid.wpa_psk_file);
        conf->ssid.wpa_psk_file = NULL;
    }

    hostapd_config_free_wep(&conf->ssid.wep);

    os_free(conf->ctrl_interface);
    conf->ctrl_interface = NULL;
#if 0
/* We are not currently using it, might be needing it for future purpose */
    user = conf->eap_user;
    while (user) {
            prev_user = user;
            user = user->next;
            hostapd_config_free_eap_user(prev_user);
    }
    os_free(conf->eap_user_sqlite);

    os_free(conf->eap_req_id_text);
    os_free(conf->erp_domain);
    os_free(conf->accept_mac);
    os_free(conf->deny_mac);
    os_free(conf->rsn_preauth_interfaces);
#endif
    if (conf->nas_identifier != NULL)
    {
        os_free(conf->nas_identifier);
        conf->nas_identifier = NULL;
    }

    if (conf->radius) {
        hostapd_config_free_radius(conf->radius->auth_servers,
                                   conf->radius->num_auth_servers);
/* Account servers not needed as AAA server doesn't handle RADIUS accounting packets */
#if 0
        hostapd_config_free_radius(conf->radius->acct_servers,
                                   conf->radius->num_acct_servers);
#endif
        if (conf->radius_auth_req_attr)
            hostapd_config_free_radius_attr(conf->radius_auth_req_attr);
        if (conf->radius_acct_req_attr)
            hostapd_config_free_radius_attr(conf->radius_acct_req_attr);
        conf->radius_auth_req_attr = NULL;
        conf->radius_acct_req_attr = NULL;
        os_free(conf->radius_server_clients);
        os_free(conf->radius);
        conf->radius_server_clients = NULL;
        conf->radius = NULL;
    }

    hostapd_config_free_wps(conf);
    wpa_printf(MSG_INFO,"%s - %d End of Deinit API \n", __func__, __LINE__);
}

/* Description:
 *      The API is used to create the ath%d interface for respective ap_index.
 * Arguments:
 *      ap_index - Index of Vap for which default config and init has to be updated.
 *      hostapd_data - Allocated hostapd_data parent struct for all config.
 *
 * Note: Hapd should have valid address before calling this API. ap_index should be
 *      0 - 15 only
 */
#if !defined(_XB7_PRODUCT_REQ_)
void driver_init(int ap_index, struct hostapd_data *hapd)
{
    struct wpa_init_params params;
    struct hostapd_bss_config *conf = hapd->conf;
    int radio_index = -1;

    u8 *b = conf->bssid;

    os_memset(&params, 0, sizeof(params));
    params.bssid = b;
    params.ifname = hapd->conf->iface;
    params.driver_params = hapd->iconf->driver_params;

    params.own_addr = hapd->own_addr;

    wifi_getApRadioIndex(ap_index, &radio_index);
    wifi_createAp(ap_index, radio_index, (char *)hapd->conf->ssid.ssid, hapd->conf->ignore_broadcast_ssid);
    hapd->drv_priv = hapd->driver->hapd_init(hapd, &params);
    os_free(params.bridge);
}
#endif
/* Description:
 *      The API is used to init default values for interface struct and max bss per vap
 *            hostapd_iface - conf
 * Arguments:
 *      ap_index - Index of Vap for which default config and init has to be updated.
 *      iface - Allocated hostapd_iface struct pointer
 *      hapd - Allocated hostapd_data struct pointer
 *
 * Note: iface should have valid address before calling this API. ap_index should be
 *      0 - 15 only
 */
void update_hostapd_iface(int ap_index, struct hostapd_iface *iface, struct hostapd_data *hapd)
{
    iface->conf = hapd->iconf;
    iface->num_bss = hapd->iconf->num_bss;
    iface->bss = os_calloc(hapd->iconf->num_bss, sizeof(struct hostapd_data *));
    iface->bss[0] = hapd;

    iface->drv_flags |= WPA_DRIVER_FLAGS_INACTIVITY_TIMER;
    iface->drv_flags |= WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS;

    dl_list_init(&iface->sta_seen);
}

/* Description:
 *      The API is used to init default values for hostapd_config
 *            hostapd_config - conf
 *      beacon interval, TX/RX wmm queues, acs related configs
 * Arguments:
 *      ap_index - Index of Vap for which default config and init has to be updated.
 *      conf - Allocated hostapd_config struct pointer
 *
 * Note: conf should have valid address before calling this API. ap_index should be
 *      0 - 15 only
 */
void update_hostapd_iconf(int ap_index, struct hostapd_config *conf)
{
    conf->num_bss = 1;

    conf->beacon_int = 100;
    conf->rts_threshold = -2; /* use driver default: 2347 */
    conf->fragm_threshold = -2; /* user driver default: 2346 */
    /* Set to invalid value means do not add Power Constraint IE */
    conf->local_pwr_constraint = -1;

    conf->spectrum_mgmt_required = 0;
    const int aCWmin = 4, aCWmax = 10;
    const struct hostapd_wmm_ac_params ac_bk =
    { aCWmin, aCWmax, 7, 0, 0 }; /* background traffic */
    const struct hostapd_wmm_ac_params ac_be =
    { aCWmin, aCWmax, 3, 0, 0 }; /* best effort traffic */
    const struct hostapd_wmm_ac_params ac_vi = /* video traffic */
    { aCWmin - 1, aCWmin, 2, 3008 / 32, 0 };
    const struct hostapd_wmm_ac_params ac_vo = /* voice traffic */
    { aCWmin - 2, aCWmin - 1, 2, 1504 / 32, 0 };
    const struct hostapd_tx_queue_params txq_bk =
    { 7, ecw2cw(aCWmin), ecw2cw(aCWmax), 0 };
    const struct hostapd_tx_queue_params txq_be =
    { 3, ecw2cw(aCWmin), 4 * (ecw2cw(aCWmin) + 1) - 1, 0};
    const struct hostapd_tx_queue_params txq_vi =
    { 1, (ecw2cw(aCWmin) + 1) / 2 - 1, ecw2cw(aCWmin), 30};
    const struct hostapd_tx_queue_params txq_vo =
    { 1, (ecw2cw(aCWmin) + 1) / 4 - 1,
        (ecw2cw(aCWmin) + 1) / 2 - 1, 15};

    conf->wmm_ac_params[0] = ac_be;
    conf->wmm_ac_params[1] = ac_bk;
    conf->wmm_ac_params[2] = ac_vi;
    conf->wmm_ac_params[3] = ac_vo;

    conf->tx_queue[0] = txq_vo;
    conf->tx_queue[1] = txq_vi;
    conf->tx_queue[2] = txq_be;
    conf->tx_queue[3] = txq_bk;

    conf->ht_capab = HT_CAP_INFO_SMPS_DISABLED;

    conf->ap_table_max_size = 255;
    conf->ap_table_expiration_time = 60;
    conf->track_sta_max_age = 180;

    conf->acs = 0;
    conf->acs_ch_list.num = 0;
#ifdef CONFIG_ACS
//Not defined
    conf->acs_num_scans = 5;
#endif /* CONFIG_ACS */

#ifdef CONFIG_IEEE80211AX
//Not defined
    conf->he_op.he_rts_threshold = HE_OPERATION_RTS_THRESHOLD_MASK >>
        HE_OPERATION_RTS_THRESHOLD_OFFSET;
    /* Set default basic MCS/NSS set to single stream MCS 0-7 */
    conf->he_op.he_basic_mcs_nss_set = 0xfffc;
#endif /* CONFIG_IEEE80211AX */

    /* The third octet of the country string uses an ASCII space character
     * by default to indicate that the regulations encompass all
     * environments for the current frequency band in the country. */
#if defined (_XB7_PRODUCT_REQ_)
    snprintf(conf->country, sizeof(conf->country), "US");
#else
    wifi_getRadioCountryCode(ap_index, conf->country);
#endif

    conf->rssi_reject_assoc_rssi = 0;
    conf->rssi_reject_assoc_timeout = 30;

#ifdef CONFIG_AIRTIME_POLICY
//Not defined
    conf->airtime_update_interval = AIRTIME_DEFAULT_UPDATE_INTERVAL;
    conf->airtime_mode = AIRTIME_MODE_STATIC;
#endif /* CONFIG_AIRTIME_POLICY */
#if defined (_XB7_PRODUCT_REQ_)
    conf->ieee80211h = 1;
    conf->ieee80211d = 1;
#else
    conf->ieee80211h = 0;
    conf->ieee80211d = 0;
#endif
}

/* Description:
 *      The API is used to init default values for security and bss related configs
 *            hostapd_bss_config - conf
 *      This will also init queue/list for necessary STA connections.
 * Arguments:
 *      ap_index - Index of Vap for which default config and init has to be updated.
 *      bss - Allocated hostapd_bss_config struct pointer
 *
 * Note: bss should have valid address before calling this API. ap_index should be
 *      0 - 15 only
 */
void update_hostapd_bss_config(int ap_index, struct hostapd_bss_config *bss)
{
    //HOSTAPD_MODULE_IEEE80211|HOSTAPD_MODULE_IEEE8021X|HOSTAPD_MODULE_RADIUS|HOSTAPD_MODULE_WPA;

    /* Set to -1 as defaults depends on HT in setup */
    dl_list_init(&bss->anqp_elem);

    bss->logger_syslog_level = HOSTAPD_LEVEL_INFO;
    bss->logger_stdout_level = HOSTAPD_LEVEL_INFO;
    bss->logger_syslog =  -1;
    bss->logger_stdout =  -1;

    bss->auth_algs = WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED;

    bss->wep_rekeying_period = 300;
    /* use key0 in individual key and key1 in broadcast key */
    bss->broadcast_key_idx_min = 1;
    bss->broadcast_key_idx_max = 2;
    bss->eap_reauth_period = 3600;

    bss->wpa_group_rekey = 600;
    bss->wpa_gmk_rekey = 86400;
    bss->wpa_group_update_count = 4;
    bss->wpa_pairwise_update_count = 4;
    bss->wpa_disable_eapol_key_retries =
        DEFAULT_WPA_DISABLE_EAPOL_KEY_RETRIES;
    bss->wpa_key_mgmt = WPA_KEY_MGMT_PSK;
    bss->wpa_pairwise = WPA_CIPHER_TKIP;
    bss->wpa_group = WPA_CIPHER_TKIP;
    bss->rsn_pairwise = 0;

    bss->max_num_sta = MAX_STA_COUNT;

    bss->dtim_period = 2;

    bss->radius_server_auth_port = 1812;
#if !defined(_XB7_PRODUCT_REQ_)        //remove if any radius patch is added for xb7
    bss->radius->radius_server_retries = RADIUS_CLIENT_MAX_RETRIES;
    bss->radius->radius_max_retry_wait = RADIUS_CLIENT_MAX_WAIT;
#endif
    bss->eap_sim_db_timeout = 1;
    bss->eap_sim_id = 3;
    bss->ap_max_inactivity = AP_MAX_INACTIVITY;
    bss->eapol_version = EAPOL_VERSION;

    bss->max_listen_interval = 65535;

    bss->pwd_group = 19; /* ECC: GF(p=256) */

#ifdef CONFIG_IEEE80211W
//Defined
    bss->assoc_sa_query_max_timeout = 1000;
    bss->assoc_sa_query_retry_timeout = 201;
    bss->group_mgmt_cipher = WPA_CIPHER_AES_128_CMAC;
#endif /* CONFIG_IEEE80211W */
#ifdef EAP_SERVER_FAST
//Defined
    /* both anonymous and authenticated provisioning */
    bss->eap_fast_prov = 3;
    bss->pac_key_lifetime = 7 * 24 * 60 * 60;
    bss->pac_key_refresh_time = 1 * 24 * 60 * 60;
#endif /* EAP_SERVER_FAST */

    /* Set to -1 as defaults depends on HT in setup */
    bss->wmm_enabled = -1;

#ifdef CONFIG_IEEE80211R_AP
//Defined
    bss->ft_over_ds = 1;
    bss->rkh_pos_timeout = 86400;
    bss->rkh_neg_timeout = 60;
    bss->rkh_pull_timeout = 1000;
    bss->rkh_pull_retries = 4;
    bss->r0_key_lifetime = 1209600;
#endif /* CONFIG_IEEE80211R_AP */

    bss->radius_das_time_window = 300;

    bss->sae_anti_clogging_threshold = 5;
    bss->sae_sync = 5;

    bss->gas_frag_limit = 1400;

#ifdef CONFIG_FILS
//Not Defined
    dl_list_init(&bss->fils_realms);
    bss->fils_hlp_wait_time = 30;
    bss->dhcp_server_port = DHCP_SERVER_PORT;
    bss->dhcp_relay_port = DHCP_SERVER_PORT;
#endif /* CONFIG_FILS */

    bss->broadcast_deauth = 1;

#ifdef CONFIG_MBO
//Not Defined
    bss->mbo_cell_data_conn_pref = -1;
#endif /* CONFIG_MBO */

    /* Disable TLS v1.3 by default for now to avoid interoperability issue.
     * This can be enabled by default once the implementation has been fully
     * completed and tested with other implementations. */
    bss->tls_flags = TLS_CONN_DISABLE_TLSv1_3;

    bss->send_probe_response = 1;

#ifdef CONFIG_HS20
//Not Defined
    bss->hs20_release = (HS20_VERSION >> 4) + 1;
#endif /* CONFIG_HS20 */

#ifdef CONFIG_MACSEC
//Not Defined
    bss->mka_priority = DEFAULT_PRIO_NOT_KEY_SERVER;
    bss->macsec_port = 1;
#endif /* CONFIG_MACSEC */

    /* Default to strict CRL checking. */
    bss->check_crl_strict = 1;
}

/* Description:
 *      The API is used to init default values for following hostapd stuctures.
 *            hostapd_config - iconf
 *            hostapd_bss_config - conf
 *            hostapd_iface - iface
 *      This will also init queue/list for necessary STA connections.
 * Arguments:
 *      ap_index - Index of Vap for which default config and init has to be updated.
 *      hostapd_data - Allocated hostapd_data parent struct for all config
 *      ModeEnabled - Security mode enabled for respective vap Index.
 *
 * Note: Hapd should have valid address before calling this API. ap_index should be
 *      0 - 15 only
 */
void update_config_defaults(int ap_index, struct hostapd_data *hapd, int ModeEnabled)
{
#if defined (_XB7_PRODUCT_REQ_)
    hapd->iconf = g_hapd_glue[ap_index].conf;
    hapd->iface = g_hapd_glue[ap_index].iface;
    hapd->conf = g_hapd_glue[ap_index].bss_conf;
#else
    hapd->iconf = &g_hapd_glue[ap_index].conf;
    hapd->iface = &g_hapd_glue[ap_index].iface;
    hapd->conf = &g_hapd_glue[ap_index].bss_conf;
#endif

    hapd->new_assoc_sta_cb = hostapd_new_assoc_sta;
    hapd->ctrl_sock = -1;

    dl_list_init(&hapd->ctrl_dst);
    dl_list_init(&hapd->nr_db);
    hapd->dhcp_sock = -1;
#ifdef CONFIG_IEEE80211R_AP
//Defined
    dl_list_init(&hapd->l2_queue);
    dl_list_init(&hapd->l2_oui_queue);
#endif /* CONFIG_IEEE80211R_AP */
#if defined (CONFIG_SAE) && defined (WIFI_HAL_VERSION_3)
//Not Defined
    dl_list_init(&hapd->sae_commit_queue);
#endif /* CONFIG_SAE */

    hapd->iconf->bss = os_calloc(1, sizeof(struct hostapd_bss_config *));
    if (hapd->iconf->bss == NULL) {
        os_free(hapd->iconf);
        os_free(hapd->iconf->bss);
        return;
    }
    hapd->iconf->bss[0] = hapd->conf;

    hapd->conf->wpa_key_mgmt = hostapd_tr181_config_parse_key_mgmt(ModeEnabled);
    if ((hapd->conf->wpa_key_mgmt == WPA_KEY_MGMT_PSK) ||
        (hapd->conf->wpa_key_mgmt == (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_SAE)))
    {
        hapd->conf->ieee802_1x = 0;
    }
    else
        hapd->conf->ieee802_1x = 1;

    //UPDATE radius server
    update_radius_config(hapd->conf);

    update_hostapd_bss_config(ap_index, hapd->conf);

    update_hostapd_iconf(ap_index, hapd->iconf);

    update_hostapd_iface(ap_index, hapd->iface, hapd);

    update_default_oem_configs(ap_index, hapd->conf);

    hapd->driver = (const struct wpa_driver_ops *)&g_hapd_glue[ap_index].driver_ops;
}

/* Description:
 *      The API is used to init lib hostap authenticator log file system.
 * Arguments
 *      None
 */
void hapd_init_log_files()
{
    wpa_debug_open_file(HOSTAPD_LOG_FILE_PATH);
#if !(defined CISCO_XB3_PLATFORM_CHANGES)
#if !defined(_XB7_PRODUCT_REQ_)
    rdk_debug_open_file();
#endif
#endif
#ifndef CONFIG_CTRL_IFACE_UDP
    system("rm -rf /var/run/hostapd");
#endif
}

const char * interfaceVapMap[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO] = {
    "wl0.1", "wl1.1", "wl0.2", "wl1.2", "wl0.3", "wl1.3", "wl0.4", "wl1.4",
    "wl0.5", "wl1.5","wl0.6", "wl1.6", "wl0.7", "wl1.7", "wl0","wl1"
};

void convert_apindex_to_interface(int idx, char *iface, int len)
{
        if (NULL == iface || idx  >= (getNumberRadios() * MAX_NUM_VAP_PER_RADIO) ) {
                wpa_printf(MSG_INFO, "%s:%d: input_string parameter error!!!\n", __func__, __LINE__);
                return;
        }

        memset(iface, 0, len);
        snprintf(iface, len, interfaceVapMap[idx])
}

/* Description:
 *      The API is used to init lib hostap authenticator.
 *      TR181 Radio,SSID,AccessPoint structure cache is used to init hostap
 *      authenticator necessary params.
 *      Additional to TR-181 cache, this will init all other necessary params
 *      with default values.
 * Arguments:
 *      pWifiAp         Device.WiFi.AccessPoint.{i} cache structure.
 *      pWifiSsid       Device.WiFi.SSID.{i} cache structure.
 *      pWifiRadioFull  Device.WiFi.Radio.{i} cache structure.
 */

#if defined (_XB7_PRODUCT_REQ_)
#ifndef HOSTAPD_CLEANUP_INTERVAL
#define HOSTAPD_CLEANUP_INTERVAL 10
#endif /* HOSTAPD_CLEANUP_INTERVAL */

int hostapd_periodic_call(struct hostapd_iface *iface, void *ctx);
void hostapd_periodic(void *eloop_ctx, void *timeout_ctx);
int hostapd_driver_init(struct hostapd_iface *iface);

extern struct hapd_global global;

int libhostapd_global_init()
{
        int i;
        wpa_printf(MSG_ERROR, "%s:%d Start", __func__, __LINE__);
        os_memset(&global, 0, sizeof(global));
     
        if (!is_eloop_init_done)
        {
                if ( eap_server_register_methods() == 0) {
                        wpa_printf(MSG_DEBUG, "%s:%d: EAP methods registered \n", __func__, __LINE__);
                }   else {
                        wpa_printf(MSG_DEBUG, "%s:%d: failed to register EAP methods \n", __func__, __LINE__);
                }

                wpa_printf(MSG_INFO, "%s:%d: Setting up eloop", __func__, __LINE__);
                if (eloop_init() < 0)
                {
                        wpa_printf(MSG_ERROR, "%s:%d: Failed to setup eloop\n", __func__, __LINE__);
                        return -1;
                }
                is_eloop_init_done = 1;
        }   

        random_init(NULL);
        wpa_printf(MSG_ERROR, "%s:%d: random init successful", __func__, __LINE__);

        for (i = 0; wpa_drivers[i]; i++) {
                global.drv_count++;
        }

	wpa_debug_level = MSG_DEBUG;
        wpa_printf(MSG_ERROR, "%s:%d: global.drv_count :%d wpa_debug_level:%d", __func__, __LINE__, global.drv_count, wpa_debug_level);
        if (global.drv_count == 0) {
                wpa_printf(MSG_ERROR, "No drivers enabled");
                return -1;
        }
        global.drv_priv = os_calloc(global.drv_count, sizeof(void *));
        if (global.drv_priv == NULL)
                return -1;

        wpa_printf(MSG_ERROR, "%s:%d: global init successful", __func__, __LINE__);
        return 0;
}

//customized equivalent of hostapd_config_read
struct hostapd_config * libhostapd_config_read(const char *fname, int apIndex)
{
#if defined (_XB7_PRODUCT_REQ_)
    char ifname[8] = {0};
#endif

    g_hapd_glue[apIndex].conf = hostapd_config_defaults();
    if (g_hapd_glue[apIndex].conf == NULL) {
        return NULL;
    }

    /* set default driver based on configuration */
    g_hapd_glue[apIndex].conf->driver = wpa_drivers[0];
    if (g_hapd_glue[apIndex].conf->driver == NULL) {
        wpa_printf(MSG_ERROR, "No driver wrappers registered!");
        hostapd_config_free(g_hapd_glue[apIndex].conf);
        return NULL;
    }

    g_hapd_glue[apIndex].conf->last_bss = g_hapd_glue[apIndex].conf->bss[0];

#if defined (_XB7_PRODUCT_REQ_)
    convert_apindex_to_interface(apIndex, ifname, sizeof(ifname));

    os_strlcpy(g_hapd_glue[apIndex].conf->bss[0]->iface, ifname,sizeof(g_hapd_glue[apIndex].conf->bss[0]->iface));
#endif

    return g_hapd_glue[apIndex].conf;
}

//customized equivalent of hostapd_init
struct hostapd_iface * libhostapd_init(struct hapd_interfaces *interfaces,
                    const char *config_file, int apIndex)
{
    size_t i;

    g_hapd_glue[apIndex].iface = hostapd_alloc_iface();
    if (g_hapd_glue[apIndex].iface == NULL)
        goto fail;

    g_hapd_glue[apIndex].iface->config_fname = (char *)config_file;

    g_hapd_glue[apIndex].conf = libhostapd_config_read(NULL, apIndex);
    if (g_hapd_glue[apIndex].conf == NULL)
        goto fail;

    g_hapd_glue[apIndex].iface->conf = g_hapd_glue[apIndex].conf;

    g_hapd_glue[apIndex].iface->num_bss = g_hapd_glue[apIndex].conf->num_bss;
    g_hapd_glue[apIndex].iface->bss = os_calloc(g_hapd_glue[apIndex].conf->num_bss,
                    sizeof(struct hostapd_data *));

    if (g_hapd_glue[apIndex].iface->bss == NULL)
        goto fail;

    for (i = 0; i < g_hapd_glue[apIndex].conf->num_bss; i++) {
        g_hapd_glue[apIndex].hapd = g_hapd_glue[apIndex].iface->bss[i] = 
            hostapd_alloc_bss_data(g_hapd_glue[apIndex].iface, g_hapd_glue[apIndex].conf,
                           g_hapd_glue[apIndex].conf->bss[i]);
        if (g_hapd_glue[apIndex].hapd == NULL)
            goto fail;
        g_hapd_glue[apIndex].hapd->msg_ctx = g_hapd_glue[apIndex].hapd;
    }

    return g_hapd_glue[apIndex].iface;

fail:
    wpa_printf(MSG_ERROR, "Failed to set up interface with %s",
           config_file);
    if (g_hapd_glue[apIndex].conf)
        hostapd_config_free(g_hapd_glue[apIndex].conf);
    if (g_hapd_glue[apIndex].iface) {
        os_free(g_hapd_glue[apIndex].iface->config_fname);
        os_free(g_hapd_glue[apIndex].iface->bss);
        wpa_printf(MSG_DEBUG, "%s: free iface %p",
               __func__, g_hapd_glue[apIndex].iface);
        os_free(g_hapd_glue[apIndex].iface);
    }
    return NULL;
}

//customized equivalent of hostapd_interface_init
struct hostapd_iface *
libhostapd_interface_init(struct hapd_interfaces *interfaces, const char *if_name,
               const char *config_fname, int debug, int apIndex)
{
    int k;

    wpa_printf(MSG_ERROR, "%s:%d Enter", __func__, __LINE__);

    g_hapd_glue[apIndex].iface = libhostapd_init(interfaces, config_fname, apIndex);
    if (!g_hapd_glue[apIndex].iface)
        return NULL;

    if (if_name) {
        os_strlcpy(g_hapd_glue[apIndex].iface->conf->bss[0]->iface, if_name,
               sizeof(g_hapd_glue[apIndex].iface->conf->bss[0]->iface));
    }

    g_hapd_glue[apIndex].iface->interfaces = interfaces;

    for (k = 0; k < debug; k++) {
        if (g_hapd_glue[apIndex].iface->bss[0]->conf->logger_stdout_level > 0)
            g_hapd_glue[apIndex].iface->bss[0]->conf->logger_stdout_level--;
    }

    if (g_hapd_glue[apIndex].iface->conf->bss[0]->iface[0] == '\0') {
        if(!hostapd_drv_none(g_hapd_glue[apIndex].iface->bss[0])) {
            wpa_printf(MSG_ERROR,
                  "Interface name not specified in %s, nor by '-i' parameter",
                  config_fname);
            hostapd_interface_deinit_free(g_hapd_glue[apIndex].iface);
            return NULL;
        }
    }
    wpa_printf(MSG_ERROR, "%s:%d Exit", __func__, __LINE__);
    return g_hapd_glue[apIndex].iface;
}

//customized equivalent of hostapd_global_deinit
void libhostapd_global_deinit()
{
       int i;
       wpa_printf(MSG_ERROR, "%s:%d Enter", __func__, __LINE__);

       for (i = 0; wpa_drivers[i] && global.drv_priv; i++) {
               if (!global.drv_priv[i])
                       continue;
               wpa_drivers[i]->global_deinit(global.drv_priv[i]);
       }
       os_free(global.drv_priv);
       global.drv_priv = NULL;

#ifdef EAP_SERVER_TNC
       tncs_global_deinit();
#endif /* EAP_SERVER_TNC */

       random_deinit();

       eap_server_unregister_methods();

#ifndef CONFIG_CTRL_IFACE_UDP
    system("rm -rf /var/run/hostapd");
#endif /* !CONFIG_CTRL_IFACE_UDP */

#if !defined(_XB7_PRODUCT_REQ_)
       rdk_debug_close_file();

       wpa_debug_close_file();
#endif

#if !defined (_XB7_PRODUCT_REQ_)
       wifi_callback_deinit();
#endif

       wpa_printf(MSG_ERROR, "%s:%d Exit", __func__, __LINE__);
}

void libupdate_hostapd_iface(int ap_index, struct hostapd_iface *iface, struct hostapd_data *hapd)
{
	iface->conf = hapd->iconf;
    	iface->num_bss = hapd->iconf->num_bss;
    	iface->bss[0] = hapd;

    	iface->drv_flags |= WPA_DRIVER_FLAGS_INACTIVITY_TIMER;
	iface->drv_flags |= WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS;
}

#else

/* Description:
 *      The API is used to de-init lib hostap authenticator per vap index.
 *      Should handle all necessary deinit of hostap API(s) and eloop registered
 *      timeout, if any.
 * Arguments:
 *      ap_index: Index of the VAP to be de-init.
 */
void hapd_wpa_deinit(int ap_index)
{
    struct hostapd_data *hapd;
    struct driver_data *drv;

#if defined (_XB7_PRODUCT_REQ_)
    hapd = g_hapd_glue[ap_index].hapd;
#else
    hapd = &g_hapd_glue[ap_index].hapd;
#endif /*_XB7_PRODUCT_REQ_ */
    drv = hapd->drv_priv;

    wpa_printf(MSG_INFO, "%s:%d: Starting De-init - %p\n", __func__, __LINE__, hapd);
    if (hapd->started == 0)
    {
        wpa_printf(MSG_DEBUG,"%s - %d lib hostapd is not started, no need deinit\n", __func__, __LINE__);
        return;
    }
    hapd->started = 0;
    hapd->beacon_set_done = 0;

#if defined (CONFIG_SAE) && defined (WIFI_HAL_VERSION_3)
/* SAE is not defined now, but will be needed in feature for WPA3 support */
    {
        struct hostapd_sae_commit_queue *q;

        while ((q = dl_list_first(&hapd->sae_commit_queue,
                              struct hostapd_sae_commit_queue,
                              list))) {
            dl_list_del(&q->list);
            os_free(q);
        }
    }
    eloop_cancel_timeout(auth_sae_process_commit, hapd, NULL);
    wpa_printf(MSG_DEBUG, "%s:%d: End eloop_cancel_timeout \n", __func__, __LINE__);
#endif /* CONFIG_SAE */

#if !defined(_XB7_PRODUCT_REQ_)
    wifi_hostApIfaceUpdateSigPselect(ap_index, FALSE);
#endif

    //flush old stations
    hostapd_flush_old_stations(hapd, WLAN_REASON_PREV_AUTH_NOT_VALID);
    hostapd_broadcast_wep_clear(hapd);

#ifndef CONFIG_NO_RADIUS
     if (hapd->radius)
     {
         radius_client_deinit(hapd->radius);
         hapd->radius = NULL;
     }
     if (hapd->radius_das)
     {
         radius_das_deinit(hapd->radius_das);
         hapd->radius_das = NULL;
     }
 #endif /* CONFIG_NO_RADIUS */

    hostapd_deinit_wps(hapd);
    hostapd_deinit_wpa(hapd);
    hostapd_config_free_bss(hapd->conf);
    sta_track_deinit(hapd->iface);
    os_free(hapd->iface->bss);
    os_free(drv);
    hostapd_ctrl_iface_deinit(hapd);
#ifndef CONFIG_CTRL_IFACE_UDP
    char *fname = NULL;
    fname = (char *)hostapd_ctrl_iface_path(hapd);
    if (fname)
            unlink(fname);
    os_free(fname);

    if (hapd->conf->ctrl_interface &&
        rmdir(hapd->conf->ctrl_interface) < 0) {
            if (errno == ENOTEMPTY) {
                    wpa_printf(MSG_INFO, "Control interface "
                               "directory not empty - leaving it "
                               "behind");
            } else {
                    wpa_printf(MSG_ERROR,
                               "rmdir[ctrl_interface=%s]: %s",
                               hapd->conf->ctrl_interface,
                               strerror(errno));
            }
    }
#endif /* !CONFIG_CTRL_IFACE_UDP */
    os_free(hapd->iface->interfaces);

    memset(&g_hapd_glue[ap_index].hapd, 0, sizeof(struct hostapd_data));

    wpa_printf(MSG_DEBUG, "%s:%d: End De-init Successfully \n", __func__, __LINE__);
}
#endif /* _XB7_PRODUCT_REQ_ */

#if defined (_XB7_PRODUCT_REQ_)
void libhostap_eloop_deinit()
{
       if (is_eloop_init_done) {
           eloop_terminate();
           wpa_printf(MSG_ERROR, "%s:%d calling eloop_destroy", __func__, __LINE__);
           eloop_destroy();
	   is_eloop_init_done = 0;
       }

}
#if 0
void libhostapd_wpa_deinit(int ap_index)
{
    wpa_printf(MSG_INFO, "%s:%d: Starting De-init for apIndex:%d\n", __func__, __LINE__, ap_index);

    if (!g_hapd_glue[ap_index].hapd)
    {
        wpa_printf(MSG_INFO, "%s:%d: Return, hapd not started on apIndex:%d\n", __func__, __LINE__, ap_index);
        return;
    }
//    hostapd_global_ctrl_iface_deinit(&g_hapd_glue[ap_index].interfaces);


    unsigned int i = 0;
    for (i = 0; i < g_hapd_glue[ap_index].interfaces.count; i++) {
	    if (!g_hapd_glue[ap_index].interfaces.iface[i])
		    continue;
	    g_hapd_glue[ap_index].interfaces.iface[i]->driver_ap_teardown =
		    !!(g_hapd_glue[ap_index].interfaces.iface[i]->drv_flags &
				    WPA_DRIVER_FLAGS_AP_TEARDOWN_SUPPORT);
	    hostapd_interface_deinit_free(g_hapd_glue[ap_index].interfaces.iface[i]);
    }
    os_free(g_hapd_glue[ap_index].interfaces.iface);

    if (g_hapd_glue[ap_index].interfaces.eloop_initialized)
	    eloop_cancel_timeout(hostapd_periodic, &g_hapd_glue[ap_index].interfaces, NULL);

    if (g_hapd_glue[ap_index].hapd)
    {
        wpa_printf(MSG_ERROR, "%s:%d hapd is not properly deleted, hapd->started %d\n", __func__, __LINE__, g_hapd_glue[ap_index].hapd->started);
        g_hapd_glue[ap_index].hapd = NULL;
    }
    else {
        wpa_printf(MSG_ERROR, "%s:%d hapd is deleted\n", __func__, __LINE__);
    }

    wpa_printf(MSG_DEBUG, "%s:%d: End De-init Successfully \n", __func__, __LINE__);
}
#endif//ONE_WIFI
#endif

/* Description:
 *      The API is used to de-init lib hostap eloop params, close debugs files and
 *      handle all necessary deinit which are common for all VAP(s)
 *      Should be called during RFC switch or complete deinit of lib hostap.
 * Arguments:
 *      None
 */
void deinit_eloop()
{
    if (is_eloop_init_done)
    {
        eloop_terminate();
        eloop_destroy();
        is_eloop_init_done = 0;
        wpa_printf(MSG_DEBUG, "%s:%d: Called deinit_loop\n", __func__, __LINE__);
    }
#ifndef CONFIG_CTRL_IFACE_UDP
    system("rm -rf /var/run/hostapd");
#endif /* !CONFIG_CTRL_IFACE_UDP */
#if !(defined CISCO_XB3_PLATFORM_CHANGES)
#if !defined(_XB7_PRODUCT_REQ_)
    rdk_debug_close_file();
#endif
#endif
    wpa_debug_close_file();
#if !defined (_XB7_PRODUCT_REQ_)
    wifi_callback_deinit();
#endif
}

#if defined (FEATURE_SUPPORT_RADIUSGREYLIST)
void init_lib_hostapd_greylisting()
{
#if !defined (_XB7_PRODUCT_REQ_)
    //RDKB-30263 Grey List control from RADIUS 
    cmmac = (char *) malloc (MAC_LEN*sizeof(char));
    memset(cmmac, '\0', MAC_LEN);
    /* execute the script /usr/sbin/deviceinfo.sh to get the cmmac of the device*/
    _syscmd("sh /usr/sbin/deviceinfo.sh -cmac",cmmac, MAC_LEN);
    wpa_printf(MSG_DEBUG,"CM MAC is :%s\n",cmmac);
    //RDKB-30263 Grey List control from RADIUS END 
#endif
}

void deinit_lib_hostapd_greylisting()
{
#if !defined (_XB7_PRODUCT_REQ_)
        os_free(cmmac);
#endif
}
#endif //FEATURE_SUPPORT_RADIUSGREYLIST

int hapd_reload_ssid(int apIndex, char *ssid)
{
    struct hostapd_data *hapd;
    struct hostapd_bss_config *conf;

#if defined (_XB7_PRODUCT_REQ_)
    hapd = g_hapd_glue[apIndex].hapd;
#else
    hapd = &g_hapd_glue[apIndex].hapd;
#endif /*_XB7_PRODUCT_REQ_ */

    if (!hapd || !hapd->started)
        return -1;

    hostapd_flush_old_stations(hapd, WLAN_REASON_PREV_AUTH_NOT_VALID);

    conf = hapd->conf;
    hostapd_config_clear_wpa_psk(&conf->ssid.wpa_psk);
    conf->ssid.wpa_psk = NULL;

    memset(conf->ssid.ssid, '\0', sizeof(conf->ssid.ssid));
    snprintf((char *)conf->ssid.ssid, sizeof(conf->ssid.ssid), "%s", ssid);

    conf->ssid.ssid_len = strlen(ssid);
    conf->ssid.ssid_set = 1;
    conf->ssid.utf8_ssid = 0;

    if (hostapd_setup_wpa_psk(conf))
    {
        wpa_printf(MSG_ERROR,"%s:%d Unable to set WPA PSK\n", __func__, __LINE__);
        return -1;
    }
    if (hostapd_set_ssid(hapd, conf->ssid.ssid, conf->ssid.ssid_len))
    {
        wpa_printf(MSG_ERROR,"%s:%d Unable to set SSID for kernel driver\n", __func__, __LINE__);
        return -1;
    }
    wifi_setSSIDName(apIndex, (char *)conf->ssid.ssid);
    return 0;
}

int hapd_reload_authentication(int apIndex, char *keyPassphrase)
{
    struct hostapd_data *hapd;
    struct hostapd_bss_config *conf;

#if defined (_XB7_PRODUCT_REQ_)
    hapd = g_hapd_glue[apIndex].hapd;
#else
    hapd = &g_hapd_glue[apIndex].hapd;
#endif /*_XB7_PRODUCT_REQ_ */

    if (!hapd || !hapd->started)
        return -1;

    conf = hapd->conf;
    if (os_strlen(keyPassphrase) > 0)
    {

        if (conf->ssid.wpa_passphrase)
            str_clear_free(conf->ssid.wpa_passphrase);

        hostapd_flush_old_stations(hapd, WLAN_REASON_PREV_AUTH_NOT_VALID);

        hostapd_config_clear_wpa_psk(&conf->ssid.wpa_psk);
        conf->ssid.wpa_psk = NULL;

        conf->ssid.wpa_passphrase = strdup(keyPassphrase);
        conf->ssid.wpa_passphrase_set = 1;
        hostapd_setup_wpa_psk(conf);

        if ((hapd->conf->wpa || hapd->conf->osen) && hapd->wpa_auth == NULL) {
            hostapd_setup_wpa(hapd);
            if (hapd->wpa_auth)
                wpa_init_keys(hapd->wpa_auth);
        } else if (hapd->conf->wpa) {
            const u8 *wpa_ie;
            size_t wpa_ie_len;
            hostapd_reconfig_wpa(hapd);
            wpa_ie = wpa_auth_get_wpa_ie(hapd->wpa_auth, &wpa_ie_len);
            if (hostapd_set_generic_elem(hapd, wpa_ie, wpa_ie_len))
                    wpa_printf(MSG_ERROR,"Failed to configure WPA IE for "
                               "the kernel driver.\n");
        } else if (hapd->wpa_auth) {
            wpa_deinit(hapd->wpa_auth);
            hapd->wpa_auth = NULL;
            hostapd_set_privacy(hapd, 0);
            hostapd_setup_encryption(hapd->conf->iface, hapd);
            hostapd_set_generic_elem(hapd, (u8 *) "", 0);
        }
    }
#if !defined(_XB7_PRODUCT_REQ_)
    wifi_setApSecurityKeyPassphrase(apIndex, conf->ssid.wpa_passphrase);
#endif
    return 0;
}

int hapd_reload_encryption_method(int apIndex, int encryptionMethod)
{
    struct hostapd_data *hapd;
    struct hostapd_bss_config *conf;

#if defined (_XB7_PRODUCT_REQ_)
    hapd = g_hapd_glue[apIndex].hapd;
#else
    hapd = &g_hapd_glue[apIndex].hapd;
#endif /*_XB7_PRODUCT_REQ_ */

    if (!hapd || !hapd->started)
        return -1;

    conf = hapd->conf;
    hostapd_flush_old_stations(hapd, WLAN_REASON_PREV_AUTH_NOT_VALID);

    hostapd_config_clear_wpa_psk(&conf->ssid.wpa_psk);
    conf->ssid.wpa_psk = NULL;
    hostapd_deinit_wpa(hapd);

    conf->wpa_pairwise = hostapd_tr181_config_parse_cipher(encryptionMethod);
    switch(encryptionMethod)
    {
        case COSA_DML_WIFI_AP_SEC_TKIP:
            wifi_setApWpaEncryptionMode(apIndex, "TKIPEncryption");
            break;
        case COSA_DML_WIFI_AP_SEC_AES:
            wifi_setApWpaEncryptionMode(apIndex, "AESEncryption");
            break;
        case COSA_DML_WIFI_AP_SEC_AES_TKIP:
            wifi_setApWpaEncryptionMode(apIndex, "TKIPandAESEncryption");
            break;
        default:
            wpa_printf(MSG_ERROR,"Wrong encryption method configured\n");
            return -1;
    }

    conf->rsn_pairwise = 0; //Re-init back to defaults
    hostapd_set_security_params(hapd->conf, 1);
    if ((hapd->conf->wpa || hapd->conf->osen) && hapd->wpa_auth == NULL)
    {

        hostapd_set_privacy(hapd,0);
        hostapd_broadcast_wep_clear(hapd);
        if (hostapd_setup_encryption(conf->iface, hapd) || hostapd_setup_wpa_psk(conf) ||
             ieee802_1x_init(hapd) || (hostapd_setup_wpa(hapd) < 0))
        {
            wpa_printf(MSG_ERROR, "%s:%d: Failed to change the encryption method\n", __func__, __LINE__);
            return -1;
        }
        if (hapd->wpa_auth)
            wpa_init_keys(hapd->wpa_auth);
    }

    wpa_printf(MSG_INFO,"Reconfigured interface %s\n", hapd->conf->iface);

    hostapd_update_wps(hapd);
    ieee802_11_set_beacon(hapd);

    return 0;
}

void hapd_reload_bss_transition(int apIndex, BOOL bss_transition)
{
   struct hostapd_data *hapd;

#if defined (_XB7_PRODUCT_REQ_)
    hapd = g_hapd_glue[apIndex].hapd;
#else
    hapd = &g_hapd_glue[apIndex].hapd;
#endif /*_XB7_PRODUCT_REQ_ */

   if (!hapd || !hapd->started)
       return;

   hapd->conf->bss_transition = bss_transition;
   hostapd_reload_config(hapd->iface);
}

void hapd_reset_ap_interface(int apIndex)
{
    struct hostapd_data *hapd;
    int radio_index = -1;

    wpa_printf(MSG_INFO,"%s - %d Resetting the ap :%d interface\n", __func__, __LINE__,apIndex);
#if defined (_XB7_PRODUCT_REQ_)
    hapd = g_hapd_glue[apIndex].hapd;
#else
    hapd = &g_hapd_glue[apIndex].hapd;
#endif /*_XB7_PRODUCT_REQ_ */
    //Reset the AP index

    //RDKB-35373 To avoid resetting iface which is not pre-initialized
    if (!hapd || !hapd->started)
        return;

    //Reset the AP index
    wifi_disableApEncryption(apIndex);

    wifi_deleteAp(apIndex);

    wifi_getApRadioIndex(apIndex, &radio_index);
    wifi_createAp(apIndex, radio_index, (char *)hapd->conf->ssid.ssid, 0);
    wifi_ifConfigUp(apIndex);
}
