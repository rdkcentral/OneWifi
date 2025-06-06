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
#include "cosa_apis.h"
#include "cosa_dbus_api.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_internal.h"
#include "plugin_main_apis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_easy_connect.h"
#include "wifi_data_plane_types.h"
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#include "wifi_monitor.h"
#include "wifi_data_plane.h"
#include "wifi_util.h"

static const char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";

extern bool is_device_associated(int ap_index, char *mac);
extern bool wifi_api_is_device_associated(int ap_index, char *mac);
static wifi_easy_connect_t g_easy_connect = {0};

wifi_vap_dpp_sta_t find_dpp_sta_dml_wifi_ap(unsigned int ap_index, mac_address_t sta_mac);
wifi_vap_dpp_t find_dpp_dml_wifi_ap(unsigned int ap_index);
INT wifi_dppProcessAuthResponse(wifi_device_dpp_context_t *dpp_ctx);
INT wifi_dppProcessConfigRequest(wifi_device_dpp_context_t *ctx);
INT wifi_dppProcessConfigResult(wifi_device_dpp_context_t *dpp_ctx);
int wifi_dppReconfigInitiate(wifi_device_dpp_context_t *ctx);
INT wifi_dppProcessReconfigAuthResponse(wifi_device_dpp_context_t *dpp_ctx);
int wifi_dppSendReconfigAuthCnf(wifi_device_dpp_context_t *dpp_ctx);

void end_device_provisioning    (wifi_device_dpp_context_t *ctx)
{

    wifi_dppCancel(ctx);

    free(ctx);
    ctx = NULL;

}

void log_dpp_diagnostics(char *format, ...)
{
#define BUFF_SIZE 512
    char buff[BUFF_SIZE] = {0};
    va_list list;
    get_formatted_time(buff);
    strcat(buff, " ");
  
    va_start(list, format);
    vsprintf(buff, format, list);
    va_end(list);
    write_to_file(wifi_health_log, buff);
}

static char *acti_status[] = {
    "ActStatus_Idle",
    "ActStatus_Config_Error",
    "ActStatus_In_Progress",
    "ActStatus_No_Response",
    "ActStatus_Failed",
    "ActStatus_OK"
};

static char *resp_status[] = {
    "RESPONDER_STATUS_OK", 
    "RESPONDER_STATUS_NOT_COMPATIBLE", 
    "RESPONDER_STATUS_AUTH_FAILURE", 
    "RESPONDER_STATUS_BAD_CODE", 
    "RESPONDER_STATUS_BAD_GROUP", 
    "RESPONDER_STATUS_CONFIGURATION_FAILURE", 
    "RESPONDER_STATUS_RESPONSE_PENDING", 
    "RESPONDER_STATUS_INVALID_CONNECTOR", 
    "RESPONDER_STATUS_NO_MATCH", 
    "RESPONDER_STATUS_CONFIG_REJECTED", 
    "RESPONDER_STATUS_NOT_AVAILABLE"
};

#define SET_DPP_DEVICE_CONTEXT_STATES(ctx, state, status, enrollee_status) \
        set_dpp_device_context_states(ctx, state, status, enrollee_status, pWifiDppSta)

void set_dpp_device_context_states(wifi_device_dpp_context_t *ctx, wifi_dpp_state_t state, 
					wifi_activation_status_t activation_status, wifi_enrollee_responder_status_t enrollee_status, 
					wifi_vap_dpp_sta_t pWifiDppSta)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 1 ... \n", __func__, __LINE__);
    
	ctx->session_data.state = state;
    ctx->activation_status = activation_status;
    ctx->enrollee_status = enrollee_status;
// #if 0
    strcpy((char*)pWifiDppSta.ActivationStatus, acti_status[activation_status]);
    strcpy((char*)pWifiDppSta.EnrolleeResponderStatus, resp_status[enrollee_status]);
// #else
    //This implementation part is remaining
// #endif//ONE_WIFI TBD
}

void process_easy_connect_event(wifi_device_dpp_context_t *ctx, wifi_easy_connect_t *module)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP  ... \n", __func__, __LINE__);
                    
    // UNREFERENCED_PARAMETER(module);
    int rc;
    ssid_t ssid;
    char passphrase[64] = {0x0};
    // wifi_vap_dpp_t pWifiDppCfg;
    wifi_vap_dpp_sta_t pWifiDppSta;
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 2 31... \n", __func__, __LINE__);

            if (ctx->session_data.state == STATE_DPP_UNPROVISIONED) { 
                wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 2 32... \n", __func__, __LINE__);

                if (wifi_dppInitiate(ctx) == RETURN_OK) {
                    wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Authentication Request Frame send success 1 \n", __func__, __LINE__);
                    SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTH_RSP_PENDING,
                            ActStatus_In_Progress, RESPONDER_STATUS_RESPONSE_PENDING);
                    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 2 33... \n", __func__, __LINE__);

                    log_dpp_diagnostics("Wifi DPP: STATE_DPP_AUTH_RSP_PENDING\n");
                } else {
                    wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Authentication Request Frame send failed\n", __func__, __LINE__);
                    ctx->dpp_init_retries++;
                }
                data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
            } else if (ctx->session_data.state == STATE_DPP_AUTH_RSP_PENDING) {
                wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 2 34... \n", __func__, __LINE__);

                if (ctx->type == dpp_context_type_received_frame_auth_rsp) {
                    wifi_util_error_print(WIFI_DPP, "%s:%d: Sending DPP Authentication Cnf ... \n", __func__, __LINE__);
                    rc = wifi_dppProcessAuthResponse(ctx);
                    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 2 35... \n", __func__, __LINE__);

                    ctx->type = dpp_context_type_session_data;
                    free(ctx->received_frame.frame);
                    ctx->received_frame.length = 0;
					if (rc == RETURN_OK) {
                        rc = wifi_dppSendAuthCnf(ctx);
                    if (rc == RETURN_OK) {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTHENTICATED,
                                ActStatus_In_Progress, RESPONDER_STATUS_RESPONSE_PENDING);
                        //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: STATE_DPP_AUTHENTICATED", pWifiDppSta->ClientMac);//ONE_WIFI
                        data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                    } else {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTH_FAILED,
                                ActStatus_No_Response, RESPONDER_STATUS_AUTH_FAILURE);
                        end_device_provisioning(ctx);
                        //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONSE PENDING FAILURE", pWifiDppSta->ClientMac);//ONE_WIFI
                    }
                    } else {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTH_FAILED,
                                ActStatus_No_Response, RESPONDER_STATUS_AUTH_FAILURE);
                        end_device_provisioning(ctx);
                        //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONSE PENDING FAILURE", pWifiDppSta->ClientMac);//ONE_WIFI
                    }
                }
            } else if (ctx->session_data.state == STATE_DPP_AUTHENTICATED) {
                if ((ctx->type == dpp_context_type_received_frame_cfg_req) && (wifi_dppProcessConfigRequest(ctx) == RETURN_OK)) {
                    ctx->config.wifiTech = WIFI_DPP_TECH_INFRA;
		    /*TODO CID: 160007 Out-of-bounds access - Fix in QTN code*/
                    /*CID: 160016 BUFFER_SIZE_WARNING*/
                    ctx->config.discovery[sizeof(ctx->config.discovery)-1] = '\0';
                    wifi_util_error_print(WIFI_DPP, "%s:%d: Sending DPP Config Rsp ... ssid: %s passphrase: %s\n", __func__, __LINE__,
                            ctx->config.discovery, ctx->config.credentials.creds.passPhrase);
                    rc = wifi_dppSendConfigResponse(ctx);
                    ctx->type = dpp_context_type_session_data;
                    free(ctx->received_frame.frame);
                    ctx->received_frame.length = 0;
                    if (rc == RETURN_OK) {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_CFG_RSP_SENT,
                                ActStatus_In_Progress, RESPONDER_STATUS_RESPONSE_PENDING);
                        log_dpp_diagnostics("Wifi DPP: STATE_DPP_CFG_RSP_SENT\n");
                        data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                    } else {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_CFG_FAILED,
                                ActStatus_Config_Error, RESPONDER_STATUS_CONFIGURATION_FAILURE);
                        pWifiDppSta.Activate = FALSE;//ONE_WIFI
                        end_device_provisioning(ctx);
                    }
                }
            } else if (ctx->session_data.state == STATE_DPP_CFG_RSP_SENT) {
                if (ctx->type == dpp_context_type_received_frame_cfg_result) {
                    rc = wifi_dppProcessConfigResult(ctx);
                    ctx->type = dpp_context_type_session_data;
                    free(ctx->received_frame.frame);
                    ctx->received_frame.length = 0;
                    if (rc == RETURN_OK) {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_PROVISIONED,
                                ActStatus_OK, RESPONDER_STATUS_OK);
                        pWifiDppSta.Activate = FALSE;//ONE_WIFI
                        log_dpp_diagnostics("Wifi DPP: RESPONDER_STATUS_OK\n");
                        end_device_provisioning(ctx);
                    } else {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_CFG_FAILED,
                                ActStatus_Config_Error, RESPONDER_STATUS_CONFIG_REJECTED);
                        pWifiDppSta.Activate = FALSE;//ONE_WIFI
                        end_device_provisioning(ctx);
                    }
                }
            } else if (ctx->session_data.state == STATE_DPP_PROVISIONED) {
                if (ctx->type == dpp_context_type_received_frame_recfg_announce) {
                    wifi_util_error_print(WIFI_DPP, "%s:%d: Trying to send DPP Reconfig Authentication Request\n", __func__, __LINE__);
                    if (wifi_dppReconfigInitiate(ctx) == RETURN_OK) {
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Reconfig Authentication Request Frame send success\n", __func__, __LINE__);
                        log_dpp_diagnostics("Wifi DPP: STATE_DPP_RECFG_AUTH_RSP_PENDING\n");
                    } else {
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Authentication Request Frame send failed\n", __func__, __LINE__);
                        ctx->dpp_init_retries++;
                    }
                    SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_RECFG_AUTH_RSP_PENDING,
                            ActStatus_In_Progress, RESPONDER_STATUS_RESPONSE_PENDING);
                    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                }
            } else if (ctx->session_data.state == STATE_DPP_RECFG_AUTH_RSP_PENDING) {
                if (ctx->type == dpp_context_type_received_frame_recfg_auth_rsp) {
                    rc = wifi_dppProcessReconfigAuthResponse(ctx);
                    ctx->type = dpp_context_type_session_data;
                    free(ctx->received_frame.frame);
                    ctx->received_frame.length = 0;
                    if (rc == RETURN_OK) {	
                        wifi_util_error_print(WIFI_DPP, "%s:%d: Sending DPP Authentication Cnf ... \n", __func__, __LINE__);
                        rc = wifi_dppSendReconfigAuthCnf(ctx);
                        if (rc == RETURN_OK) {
                            SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTHENTICATED,
                                    ActStatus_In_Progress, RESPONDER_STATUS_RESPONSE_PENDING);
                            //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: STATE_DPP_AUTHENTICATED", pWifiDppSta->ClientMac);//ONE_WIFI
                            data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                        } else {
                            SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_RECFG_AUTH_FAILED,
                                    ActStatus_No_Response, RESPONDER_STATUS_AUTH_FAILURE);
                            end_device_provisioning(ctx);
                            //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONSE PENDING FAILURE", pWifiDppSta->ClientMac);//ONE_WIFI
                        }
                    } else {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_RECFG_AUTH_FAILED,
                                ActStatus_No_Response, RESPONDER_STATUS_AUTH_FAILURE);
                        end_device_provisioning(ctx);
                        //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONSE PENDING FAILURE", pWifiDppSta->ClientMac);//ONE_WIFI
                    }
                }
            }
}

void process_easy_connect_event_timeout(wifi_device_dpp_context_t *ctx, wifi_easy_connect_t *module)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 3 ... \n", __func__, __LINE__);
    
    UNREFERENCED_PARAMETER(module);
    wifi_vap_dpp_sta_t pWifiDppSta;
    mac_addr_str_t mac_str;
    int next_ch = 0;

    wifi_util_error_print(WIFI_DPP, "%s:%d: Found dpp config in database\n", __func__, __LINE__);
    // check if the STA was provisioned by us
    pWifiDppSta = find_dpp_sta_dml_wifi_ap(ctx->ap_index, ctx->session_data.sta_mac);
            wifi_util_error_print(WIFI_DPP, "%s:%d: DPP context state:%d DPP init retries:%d Max retries:%d\n", __func__, __LINE__,
                    ctx->session_data.state, ctx->dpp_init_retries, ctx->max_retries);
            if ((ctx->session_data.state == STATE_DPP_AUTH_RSP_PENDING) || (ctx->session_data.state == STATE_DPP_UNPROVISIONED)) {
                if (ctx->dpp_init_retries < ctx->max_retries) {
                    wifi_util_error_print(WIFI_DPP, "%s:%d: Trying to send DPP Authentication Request Frame ... \n", __func__, __LINE__);
                    if (wifi_dppInitiate(ctx) == RETURN_OK) {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTH_RSP_PENDING,
                                ActStatus_No_Response, RESPONDER_STATUS_RESPONSE_PENDING);
                        log_dpp_diagnostics("Wifi DPP: STATE_DPP_AUTH_RSP_PENDING\n");
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Authentication Request Frame send success2  \n", __func__, __LINE__);
                        //reached here
                    } else {
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Authentication Request Frame send failed\n", __func__, __LINE__);
                    } 
                    ctx->dpp_init_retries++;
                    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                } else if ((next_ch = find_best_dpp_channel(ctx)) != -1) {
                    ctx->dpp_init_retries = 0;
                    ctx->session_data.channel = next_ch;
                    if (wifi_dppInitiate(ctx) == RETURN_OK) {
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTH_RSP_PENDING,
                                ActStatus_No_Response, RESPONDER_STATUS_RESPONSE_PENDING);
                        log_dpp_diagnostics("Wifi DPP: STATE_DPP_AUTH_RSP_PENDING\n");
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Authentication Request Frame send success 3\n", __func__, __LINE__);
                    } else {
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Authentication Request Frame send failed\n", __func__, __LINE__);
                    }
                    ctx->dpp_init_retries++;
                    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                } else {
                    SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTH_FAILED,
                            ActStatus_Failed, RESPONDER_STATUS_AUTH_FAILURE);
                    //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONDER_STATUS_AUTH_FAILURE", pWifiDppSta.ClientMac);//ONE_WIFI
                    pWifiDppSta.Activate = FALSE;//ONE_WIFI
                    end_device_provisioning(ctx);
                }
            } else if (ctx->session_data.state == STATE_DPP_RECFG_AUTH_RSP_PENDING) {
                if (ctx->dpp_init_retries < ctx->max_retries) {
                    wifi_util_error_print(WIFI_DPP, "%s:%d: Trying to send DPP Reconfig Authentication Request Frame ... \n", __func__, __LINE__);
                    ctx->dpp_init_retries++;
                    if (wifi_dppReconfigInitiate(ctx) == RETURN_OK) {
                        log_dpp_diagnostics("Wifi DPP: STATE_DPP_RECFG_AUTH_RSP_PENDING\n");
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Reconfig Authentication Request Frame send success\n", __func__, __LINE__);
                    } else {
                        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Reconfig Authentication Request Frame send failed\n", __func__, __LINE__);
                    } 
                    SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_RECFG_AUTH_RSP_PENDING,
                            ActStatus_No_Response, RESPONDER_STATUS_RESPONSE_PENDING);
                    ctx->session_data.state = STATE_DPP_RECFG_AUTH_RSP_PENDING;
                    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                } else {
                    SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_RECFG_AUTH_FAILED,
                            ActStatus_Failed, RESPONDER_STATUS_AUTH_FAILURE);
                    //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONDER_STATUS_AUTH_FAILURE", pWifiDppSta.ClientMac);//ONE_WIFI
                    pWifiDppSta.Activate = FALSE;//ONE_WIFI
                    end_device_provisioning(ctx);
                }
            } else if (ctx->session_data.state == STATE_DPP_AUTHENTICATED) {
                // DPP Config Request never arrived
                if (ctx->check_for_config_requested >= ctx->max_retries/*5*/) {
                    SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_UNPROVISIONED,
                            ActStatus_Failed, RESPONDER_STATUS_AUTH_FAILURE);
                    //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONDER_STATUS_AUTH_FAILURE", pWifiDppSta->ClientMac);//ONE_WIFI
                    pWifiDppSta.Activate = FALSE;//ONE_WIFI
                    end_device_provisioning(ctx);
                } else {
                    ctx->check_for_config_requested++;
                    SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_AUTHENTICATED,
                            ActStatus_In_Progress, RESPONDER_STATUS_RESPONSE_PENDING);
                    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, FALSE)); //need to pass NoLock
                }
            } else if (ctx->session_data.state == STATE_DPP_CFG_RSP_SENT) {
                // now start checking for associated state on the vap index
                if ((ctx->enrollee_version == 1)) { /* configurator shall support both 2.0 & 1.0, hence check only enrollee */
                    to_mac_str(ctx->session_data.sta_mac, mac_str);
                        SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_PROVISIONED,
                                ActStatus_OK, RESPONDER_STATUS_OK);
                        pWifiDppSta.Activate = FALSE;//ONE_WIFI
                        log_dpp_diagnostics("Wifi DPP: RESPONDER_STATUS_OK\n");
                        end_device_provisioning(ctx);
                }
            } else if ((ctx->session_data.state == STATE_DPP_AUTH_FAILED) || (ctx->session_data.state == STATE_DPP_RECFG_AUTH_FAILED)) {
                // Authentication Cnf send failure
                SET_DPP_DEVICE_CONTEXT_STATES(ctx, STATE_DPP_UNPROVISIONED,
                        ActStatus_Failed, RESPONDER_STATUS_AUTH_FAILURE);
                pWifiDppSta.Activate = FALSE;//ONE_WIFI
                //log_dpp_diagnostics("%s MAC: %s\n", "Wifi DPP: RESPONDER_STATUS_AUTH_FAILURE", pWifiDppSta->ClientMac);//ONE_WIFI
                end_device_provisioning(ctx);
            }
}

bool is_matching_easy_connect_event(wifi_device_dpp_context_t *ctx, void *ptr)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 4 ... \n", __func__, __LINE__);
    
    wifi_easy_connect_event_match_criteria_t *criteria = (wifi_easy_connect_event_match_criteria_t *) ptr;
    if ((ctx->ap_index != criteria->apIndex) || (memcmp(ctx->session_data.sta_mac, criteria->sta_mac, sizeof(mac_address_t)) != 0)) {
        return false;
        }
    if (ctx->session_data.state != criteria->state) {
        return false;
    }
    return true;
}

void dppAuthResponse_callback(UINT apIndex, mac_address_t sta, unsigned char *frame, unsigned int len)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 5 ... \n", __func__, __LINE__);
    
    wifi_device_dpp_context_t *ctx = NULL;
    wifi_easy_connect_event_match_criteria_t criteria;

    criteria.apIndex = apIndex;
    memcpy(criteria.sta_mac, sta, sizeof(mac_address_t));
    criteria.state = STATE_DPP_AUTH_RSP_PENDING;

    wifi_util_error_print(WIFI_DPP, "%s:%d apIndex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x len=%d\n", __func__, __LINE__, apIndex, sta[0], sta[1], sta[2], sta[3], sta[4], sta[5], len);
    ctx = (wifi_device_dpp_context_t *)data_plane_queue_remove_event(wifi_data_plane_event_type_dpp, &criteria);

    if (ctx == NULL) {
        wifi_util_error_print(WIFI_DPP, "%s:%d ctx NULL\n", __func__, __LINE__);
        return;
    }

    ctx->type = dpp_context_type_received_frame_auth_rsp;
    ctx->received_frame.frame = malloc(len);
    memcpy(ctx->received_frame.frame, frame, len);

    ctx->received_frame.length = len;

    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, TRUE));
}

void dppConfigRequest_callback(UINT apIndex, mac_address_t sta, UCHAR token, UCHAR *configAttributes, UINT len)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 6 ... \n", __func__, __LINE__);
    wifi_device_dpp_context_t *ctx = NULL;
    wifi_easy_connect_event_match_criteria_t criteria;

    criteria.apIndex = apIndex;
    memcpy(criteria.sta_mac, sta, sizeof(mac_address_t));
    criteria.state = STATE_DPP_AUTHENTICATED;

    wifi_util_error_print(WIFI_DPP, "%s:%d apIndex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x len=%d\n", __func__, __LINE__, apIndex, sta[0], sta[1], sta[2], sta[3], sta[4], sta[5], len);
    ctx = (wifi_device_dpp_context_t *)data_plane_queue_remove_event(wifi_data_plane_event_type_dpp, &criteria);

    if (ctx == NULL) {
        wifi_util_error_print(WIFI_DPP, "%s:%d ctx NULL\n", __func__, __LINE__);
        return;
    }

    ctx->type = dpp_context_type_received_frame_cfg_req;
    ctx->received_frame.frame = malloc(len);
    memcpy(ctx->received_frame.frame, configAttributes, len);
    ctx->received_frame.length = len; // add length
    ctx->token = token;

    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, TRUE));
}

void dppConfigResult_callback(UINT apIndex, mac_address_t sta, UCHAR *frame, UINT len)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 7 ... \n", __func__, __LINE__);
    
    wifi_device_dpp_context_t *ctx = NULL;
    wifi_easy_connect_event_match_criteria_t criteria;

    criteria.apIndex = apIndex;
    memcpy(criteria.sta_mac, sta, sizeof(mac_address_t));
    criteria.state = STATE_DPP_CFG_RSP_SENT;

    wifi_util_error_print(WIFI_DPP, "%s:%d apIndex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x len=%d\n", __func__, __LINE__, apIndex, sta[0], sta[1], sta[2], sta[3], sta[4], sta[5], len);
    ctx = (wifi_device_dpp_context_t *)data_plane_queue_remove_event(wifi_data_plane_event_type_dpp, &criteria);

    if (ctx == NULL) {
        wifi_util_error_print(WIFI_DPP, "%s:%d ctx NULL\n", __func__, __LINE__);
        return;
    }

    ctx->type = dpp_context_type_received_frame_cfg_result;
    ctx->received_frame.frame = malloc(len);
    memcpy(ctx->received_frame.frame, frame, len);

    ctx->received_frame.length = len;

    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, TRUE));
}

void dppReconfigAnnounce_callback(UINT apIndex, mac_address_t sta, UCHAR *frame, UINT len)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 8 ... \n", __func__, __LINE__);
    
    wifi_device_dpp_context_t *ctx = NULL;
    wifi_vap_dpp_sta_t pWifiDppSta;
    wifi_vap_dpp_t pWifiDppCfg;
    mac_addr_str_t	mac_str;
    wifi_easy_connect_event_match_criteria_t criteria;
    pWifiDppCfg = find_dpp_dml_wifi_ap(apIndex);


    wifi_util_error_print(WIFI_DPP, "%s:%d: Found dpp config in database\n", __func__, __LINE__);

    // check if the STA was provisioned by us
    pWifiDppSta = find_dpp_sta_dml_wifi_ap(apIndex, sta);

    wifi_util_error_print(WIFI_DPP, "%s:%d: Found dpp station:%s config in database\n", __func__, __LINE__, to_mac_str(sta, mac_str));

    // check the sctivation status
    if (strcmp(pWifiDppSta.ActivationStatus, enum_str(ActStatus_OK)) != 0) {
       wifi_util_error_print(WIFI_DPP, "%s:%d: The station was never activated in database\n", __func__, __LINE__);
    		return;

    }

    // check if the request for reconfiguring is in the queue already
    criteria.apIndex = apIndex;
    memcpy(criteria.sta_mac, sta, sizeof(mac_address_t));
    criteria.state = STATE_DPP_PROVISIONED;

    if (data_plane_queue_check_event(wifi_data_plane_event_type_dpp, &criteria) == true) {
            wifi_util_error_print(WIFI_DPP, "%s:%d: The station is already in queue\n", __func__, __LINE__);	
            return;
        }

    if (wifi_dppProcessReconfigAnnouncement(frame, len, g_easy_connect.csign[apIndex].sign_key_hash) != RETURN_OK) {
        wifi_util_error_print(WIFI_DPP, "%s:%d: C-sign-key hash does not match\n", __func__, __LINE__);
        return;

    }

    wifi_util_error_print(WIFI_DPP, "%s:%d: Creating device context\n", __func__, __LINE__);

    // create context and push in queue
    ctx = (wifi_device_dpp_context_t *)malloc(sizeof(wifi_device_dpp_context_t));
    if (ctx == NULL) {
        wifi_util_error_print(WIFI_DPP, "%s:%d: Exit. Allocation was unsuccessful.\n", __func__, __LINE__);
        return;
    }
    memset(ctx, 0, sizeof(wifi_device_dpp_context_t));

    ctx->ap_index = apIndex;

    // set the reconfig ctx
    ctx->config.reconfigCtx = g_easy_connect.reconfig[ctx->ap_index].reconf_ctx;

    // set the csign instance
    ctx->config.cSignInstance = g_easy_connect.csign[ctx->ap_index].csign_inst;

    wifi_util_error_print(WIFI_DPP, "%s:%d: ap index: %d recfg ctx:%p csign instance:%p\n", __func__, __LINE__, ctx->ap_index,
            ctx->config.reconfigCtx, ctx->config.cSignInstance);

    ctx->configurator_version = pWifiDppCfg.version;//ONE_WIFI
    memcpy(ctx->session_data.sta_mac, sta, sizeof(mac_address_t));
    ctx->max_retries = pWifiDppSta.MaxRetryCount;//ONE_WIFI

    ctx->session_data.session = wifi_dpp_session_type_reconfig;
    ctx->session_data.state = STATE_DPP_PROVISIONED;
    ctx->type = dpp_context_type_received_frame_recfg_announce;

    wifi_getRadioChannel(getRadioIndexFromAp(ctx->ap_index), (ULONG *)&ctx->session_data.channel);
    memset(ctx->session_data.u.reconfig_data.iPubKey, 0, 256);
    strcpy(ctx->session_data.u.reconfig_data.iPubKey, g_easy_connect.reconfig[ctx->ap_index].reconf_pub_key);

    if (strcmp(pWifiDppSta.Cred.KeyManagement, "Common-PSK") == 0) {                 
        ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSK;
    } else if (strcmp(pWifiDppSta.Cred.KeyManagement, "DPP") == 0) {
        ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_DPP;
    }else if (strcmp(pWifiDppSta.Cred.KeyManagement, "DPPSAE") == 0) {
        ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_SAE;
    }else if (strcmp(pWifiDppSta.Cred.KeyManagement, "PSKSAE") == 0) {
        ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSKSAE;
    }else if (strcmp(pWifiDppSta.Cred.KeyManagement, "DPPPSKSAE") == 0) {
        ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_DPPPSKSAE;
    }


    wifi_util_error_print(WIFI_DPP, "%s:%d: Pushing event for processing\n", __func__, __LINE__);
    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, TRUE));
}

void dppReconfigAuthResponse_callback(UINT apIndex, mac_address_t sta, unsigned char *frame, unsigned int len)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 9 ... \n", __func__, __LINE__);
    
    wifi_device_dpp_context_t *ctx = NULL;
    wifi_easy_connect_event_match_criteria_t criteria;

    criteria.apIndex = apIndex;
    memcpy(criteria.sta_mac, sta, sizeof(mac_address_t));
    criteria.state = STATE_DPP_RECFG_AUTH_RSP_PENDING;

    wifi_util_error_print(WIFI_DPP, "%s:%d apIndex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x len=%d\n", __func__, __LINE__, apIndex, sta[0], sta[1], sta[2], sta[3], sta[4], sta[5], len);
    ctx = (wifi_device_dpp_context_t *)data_plane_queue_remove_event(wifi_data_plane_event_type_dpp, &criteria);

    if (ctx == NULL) {
        wifi_util_error_print(WIFI_DPP, "%s:%d ctx NULL\n", __func__, __LINE__);
        return;
    }

    wifi_util_error_print(WIFI_DPP, "%s:%d setting up context\n", __func__, __LINE__);

    ctx->type = dpp_context_type_received_frame_recfg_auth_rsp;
    ctx->received_frame.frame = malloc(len);
    memcpy(ctx->received_frame.frame, frame, len);

    ctx->received_frame.length = len;

    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, TRUE));
}

int find_best_dpp_channel(wifi_device_dpp_context_t *ctx)
{
    wifi_util_error_print(WIFI_DPP, "%s:%d: Test DPP 10 ... \n", __func__, __LINE__);
    
    unsigned int ch;

    wifi_util_error_print(WIFI_DPP, "%s: ctx->current_attempts = %d, ctx->num_channels=%d, %d\n", __func__, ctx->current_attempts, ctx->num_channels, __LINE__);    
    if (ctx->current_attempts >= ctx->num_channels) {
        wifi_util_error_print(WIFI_DPP, "%s:%d: Exit\n", __func__, __LINE__);
        return -1;
    } 
    ch = ctx->channels_list[ctx->current_attempts];
    ctx->current_attempts++;

    return ch;
}

int start_device_provisioning (wifi_vap_info_t *pWiFiAP, ULONG staIndex)
{
    wifi_device_dpp_context_t *ctx = NULL;
    unsigned int i;

    wifi_util_error_print(WIFI_DPP, "%s:%d: Enter\n", __func__, __LINE__);
    if(pWiFiAP == NULL)
    {
        wifi_util_error_print(WIFI_DPP, "%s:%d: PCOSA_DML_WIFI_AP is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
// #if 0
    wifi_vap_dpp_sta_t *pWifiDppSta = &pWiFiAP->vap_dpp.sta_array[staIndex-1]; 
    ULONG apIndex = pWiFiAP->vap_index;
    UCHAR dppVersion = pWiFiAP->vap_dpp.version;
    wifi_util_error_print(WIFI_DPP, "%s:%d: Enter  version %d \n", __func__, __LINE__, dppVersion);

    if(pWifiDppSta == NULL)
    {
        wifi_util_error_print(WIFI_DPP, "%s:%d: PCOSA_DML_WIFI_DPP_STA_CFG is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
// #endif//ONE_WIFI
    // create context and push in queue
    ctx = (wifi_device_dpp_context_t *)malloc(sizeof(wifi_device_dpp_context_t));
    if(ctx == NULL)
    {
        wifi_util_error_print(WIFI_DPP, "%s:%d: Exit. Allocation was unsuccessful.\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(ctx, 0, sizeof(wifi_device_dpp_context_t));

    ctx->ap_index = apIndex;
    ctx->configurator_version = dppVersion;

    // set the reconfig ctx
    ctx->config.reconfigCtx = g_easy_connect.reconfig[ctx->ap_index].reconf_ctx;

    // set the csign instance
    ctx->config.cSignInstance = g_easy_connect.csign[ctx->ap_index].csign_inst;

    ctx->session_data.session = wifi_dpp_session_type_config;
    
    memset(ctx->config.discovery, 0x0, sizeof(char)*32);
    memset(ctx->config.credentials.creds.passPhrase, 0x0, sizeof(char)*64);
    strncpy(ctx->config.discovery, pWiFiAP->u.sta_info.ssid, sizeof(ctx->config.discovery)-1);
    strncpy(ctx->config.credentials.creds.passPhrase, pWiFiAP->u.bss_info.security.u.key.key, sizeof(ctx->config.credentials.creds.passPhrase));
    memset(ctx->session_data.u.config_data.iPubKey, 0x0, sizeof(char)*256);
    memset(ctx->session_data.u.config_data.rPubKey, 0x0, sizeof(char)*256);
// #if 0
    to_mac_bytes(pWifiDppSta->ClientMac, ctx->session_data.sta_mac);
    strcpy(ctx->session_data.u.config_data.iPubKey, pWifiDppSta->InitiatorBootstrapSubjectPublicKeyInfo);
    strcpy(ctx->session_data.u.config_data.rPubKey, pWifiDppSta->ResponderBootstrapSubjectPublicKeyInfo);

    for (i = 0; i < pWifiDppSta->NumChannels; i++) {
        ctx->channels_list[i] = pWifiDppSta->Channels[i];
        wifi_util_error_print(WIFI_DPP, "%s:%d: ctx->channels_list[%d] = %d\n", __func__, __LINE__, i, ctx->channels_list[i]);
    }

    ctx->num_channels = pWifiDppSta->NumChannels;
    wifi_util_error_print(WIFI_DPP, "%s:%d: ctx->num_channels = %d pWifiDppSta.NumChannels = %d\n", __func__, __LINE__, ctx->num_channels, pWifiDppSta->NumChannels);
// #else
    //This implementation part is remaining
// #endif//ONE_WIFI
    ctx->session_data.state = STATE_DPP_UNPROVISIONED;
    ctx->max_retries = pWifiDppSta->MaxRetryCount;//ONE_WIFI
    ctx->session_data.channel = find_best_dpp_channel(ctx);
    wifi_util_error_print(WIFI_DPP, "%s:%d: After find_best_dpp_channel\n", __func__, __LINE__);
 
// #if 0 
    if (strcmp(pWifiDppSta->Cred.KeyManagement, "Common-PSK") == 0) {                 
        ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSK;
    } else if (strcmp(pWifiDppSta->Cred.KeyManagement, "DPPPSKSAE") == 0) {
        ctx->config.credentials.keyManagement = WIFI_DPP_KEY_MGMT_DPPPSKSAE;
    }
// #else
    //This implementation part is remaininsg
// #endif

    wifi_util_error_print(WIFI_DPP, "%s:%d: Before data_plane_queue_push\n", __func__, __LINE__);
 
    data_plane_queue_push(data_plane_queue_create_event(ctx,wifi_data_plane_event_type_dpp, TRUE));

    wifi_util_error_print(WIFI_DPP, "%s:%d: DPP Activate started thread and Exit\n", __func__, __LINE__);

    return RETURN_OK;
}

void destroy_easy_connect (void)
{
}

wifi_vap_dpp_t find_dpp_dml_wifi_ap(unsigned int apIndex)
{
    wifi_vap_info_t *vapInfo = getVapInfo(apIndex);
    return vapInfo->vap_dpp;

}

wifi_vap_dpp_sta_t find_dpp_sta_dml_wifi_ap(unsigned int ap_index, mac_address_t sta_mac) 
{
    wifi_vap_dpp_sta_t pWifiDppSta;
    mac_address_t bmac;
    unsigned int i;
    // wifi_vap_info_t *vapInfo = (wifi_vap_info_t *) get_dml_cache_vap_info(ap_index);
    wifi_vap_info_t *vapInfo = getVapInfo(ap_index);
    for (i = 0; i < vapInfo->vap_dpp.staIndex; i++) {
        pWifiDppSta = vapInfo->vap_dpp.sta_array[i];
        wifi_util_error_print(WIFI_DPP, "%s:%d: DPP config for STA:%s\n", __func__, __LINE__, pWifiDppSta);
        to_mac_bytes (pWifiDppSta.ClientMac, bmac);
        if (memcmp(bmac, sta_mac, sizeof(mac_address_t)) == 0) {
            break;
        }
    }
    
    return pWifiDppSta;
}

//int init_easy_connect (PCOSA_DATAMODEL_WIFI pWifiDataModel)
int init_easy_connect (wifi_vap_dpp_t pWifiApDPP)
{
    int i = 0;

    wifi_util_error_print(WIFI_DPP, "%s:%d: Enter\n", __func__, __LINE__);


    g_easy_connect.channels_on_ap[0].num = 5;
    g_easy_connect.channels_on_ap[0].channels[0] = 1;
    g_easy_connect.channels_on_ap[0].channels[1] = 6;
    g_easy_connect.channels_on_ap[0].channels[2] = 11;
    g_easy_connect.channels_on_ap[0].channels[3] = 3;
    g_easy_connect.channels_on_ap[0].channels[4] = 9;

    g_easy_connect.channels_on_ap[1].num = 12;
    g_easy_connect.channels_on_ap[1].channels[0] = 36;
    g_easy_connect.channels_on_ap[1].channels[1] = 40;
    g_easy_connect.channels_on_ap[1].channels[2] = 44;
    g_easy_connect.channels_on_ap[1].channels[3] = 48;

    g_easy_connect.channels_on_ap[1].channels[4] = 136;
    g_easy_connect.channels_on_ap[1].channels[5] = 140;
    g_easy_connect.channels_on_ap[1].channels[6] = 144;

    g_easy_connect.channels_on_ap[1].channels[7] = 149;
    g_easy_connect.channels_on_ap[1].channels[8] = 153;
    g_easy_connect.channels_on_ap[1].channels[9] = 157;
    g_easy_connect.channels_on_ap[1].channels[10] = 161;
    g_easy_connect.channels_on_ap[1].channels[11] = 165;

			wifi_dppCreateCSignIntance(i, pWifiApDPP.reconfig.PrivateSigningKey, (void*)&g_easy_connect.csign[i].csign_inst, 
                    g_easy_connect.csign[i].sign_key_hash);
            wifi_dppCreateReconfigContext(i, pWifiApDPP.reconfig.PrivateReconfigAccessKey, (void*)&g_easy_connect.reconfig[i].reconf_ctx,
                    g_easy_connect.reconfig[i].reconf_pub_key);
            

            wifi_util_error_print(WIFI_DPP, "%s:%d: ap:%d reconfig context:%p csign instance: %p\n", __func__, __LINE__, i,
                    g_easy_connect.reconfig[i].reconf_ctx, g_easy_connect.csign[i].csign_inst);
    wifi_dpp_frame_received_callbacks_register(dppAuthResponse_callback, dppConfigRequest_callback, 
            dppConfigResult_callback, dppReconfigAnnounce_callback, dppReconfigAuthResponse_callback);

    wifi_dppStartReceivingTestFrame(g_easy_connect.csign[0].sign_key_hash, g_easy_connect.csign[1].sign_key_hash);
    return 0;
}

    wifi_easy_connect_best_enrollee_channels_t *
get_easy_connect_best_enrollee_channels	(unsigned int ap_index)
{
    return &g_easy_connect.channels_on_ap[ap_index];
}
