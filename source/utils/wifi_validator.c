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

#if DML_SUPPORT
#include "cosa_apis.h"
#include "cosa_dbus_api.h"
#include "cosa_wifi_apis.h"
#include "cosa_wifi_internal.h"
#endif // DML_SUPPORT
#include "wifi_webconfig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "platform-logger.h"
#include "wifi_hal.h"
#include "cJSON.h"
#include "wifi_passpoint.h"
#include "ctype.h"
#include "webconfig_framework.h"

#include "wifi_ctrl.h"
#include "wifi_util.h"

bool g_interworking_RFC;
bool g_passpoint_RFC;

//This Macro ONE_WIFI_CHANGES, used to modify the validator changes. Re-check is required where the macro is used
#define ONE_WIFI_CHANGES

#define validate_param_string(json, key, value) \
{	\
    value = cJSON_GetObjectItem(json, key); 	\
    if ((value == NULL) || (cJSON_IsString(value) == false) ||	\
            (value->valuestring == NULL) || (strcmp(value->valuestring, "") == 0)) {	\
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);	\
        if (execRetVal) { \
            snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg)-1, "Missing or Invalid Value for key: %s",key); \
        } \
        return RETURN_ERR;	\
    }	\
}	\

#define validate_param_integer(json, key, value) \
{	\
    value = cJSON_GetObjectItem(json, key); 	\
    if ((value == NULL) || (cJSON_IsNumber(value) == false)) {	\
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);	\
        if (execRetVal) { \
            snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg)-1, "Missing or Invalid Value for key: %s",key); \
        } \
        return RETURN_ERR;	\
    }	\
}	\

#define validate_param_bool(json, key, value) \
{	\
    value = cJSON_GetObjectItem(json, key); 	\
    if ((value == NULL) || (cJSON_IsBool(value) == false)) {	\
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);	\
        if (execRetVal) { \
            snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg)-1, "Missing or Invalid Value for key: %s",key); \
        } \
        return RETURN_ERR;	\
    }	\
}	\


#define validate_param_array(json, key, value) \
{	\
    value = cJSON_GetObjectItem(json, key); 	\
    if ((value == NULL) || (cJSON_IsArray(value) == false)) {	\
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);	\
        if (execRetVal) { \
            snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg)-1, "Missing or Invalid Value for key: %s",key); \
        } \
        return RETURN_ERR;	\
    }	\
}	\


#define validate_param_object(json, key, value) \
{	\
    value = cJSON_GetObjectItem(json, key); 	\
    if ((value == NULL) || (cJSON_IsObject(value) == false)) {	\
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);	\
        if (execRetVal) { \
            snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg)-1, "Missing or Invalid Value for key: %s",key); \
        } \
        return RETURN_ERR;	\
    }	\
}	\

int validate_ipv4_address(char *ip) {
    struct sockaddr_in sa;

    if (inet_pton(AF_INET,ip, &(sa.sin_addr)) != 1 ) {
        platform_trace_error(WIFI_PASSPOINT, "%s: Invalid IPv4 address: %s\n",__FUNCTION__,ip);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int validate_ipv6_address(char *ip) {
    struct sockaddr_in6 sa;

    if (inet_pton(AF_INET6,ip,(&sa.sin6_addr)) != 1 ) {
        platform_trace_error(WIFI_PASSPOINT, "%s:Invalid IPv6 address: %s\n",__FUNCTION__,ip);
        return RETURN_ERR;
    }
    return RETURN_OK;

}

int validate_anqp(const cJSON *anqp, wifi_interworking_t *vap_info, pErr execRetVal)
{
    cJSON *mainEntry = NULL;
    cJSON *anqpElement = NULL;
    cJSON *anqpList = NULL;
    cJSON *anqpEntry = NULL;
    cJSON *anqpParam = NULL;
    cJSON *subList = NULL;
    cJSON *subEntry = NULL;
    cJSON *subParam = NULL;
    UCHAR *next_pos = NULL;

    
    cJSON *passPointStats = cJSON_CreateObject();//root object for Passpoint Stats
    cJSON *statsMainEntry = cJSON_AddObjectToObject(passPointStats,"PassPointStats");
    cJSON *statsList = cJSON_AddArrayToObject(statsMainEntry, "ANQPResponse");
    
    if(!anqp || !vap_info || !execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"ANQP entry is NULL\n");
        if(execRetVal) {
            strncpy(execRetVal->ErrorMsg, "Empty ANQP Entry",sizeof(execRetVal->ErrorMsg)-1);
        }
        cJSON_Delete(passPointStats);
        return RETURN_ERR;
    }
    mainEntry = (cJSON *) anqp;
    //CapabilityListANQPElement
    vap_info->anqp.capabilityInfoLength = 0;
    vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_query_list;
    vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_capability_list;
    
    //VenueNameANQPElement
    validate_param_object(mainEntry,"VenueNameANQPElement",anqpElement);
 
    next_pos = (UCHAR *)&vap_info->anqp.venueInfo;

    validate_param_array(anqpElement,"VenueInfo",anqpList);
    if(cJSON_GetArraySize(anqpList) > 16){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Venue entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Exceeded Max number of Venue entries",sizeof(execRetVal->ErrorMsg)-1); 
        cJSON_Delete(passPointStats);
        return RETURN_ERR;
    } else if (cJSON_GetArraySize(anqpList)) {
        //Venue List is non-empty. Update capability List
        vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_venue_name;

        //Fill in Venue Group and Type from Interworking Config
        wifi_venueNameElement_t *venueElem = (wifi_venueNameElement_t *)next_pos;
        venueElem->venueGroup = vap_info->interworking.venueGroup;
        next_pos += sizeof(venueElem->venueGroup);
        venueElem->venueType = vap_info->interworking.venueType;
        next_pos += sizeof(venueElem->venueType);
    }

    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_venueName_t *venueBuf = (wifi_venueName_t *)next_pos;
        next_pos += sizeof(venueBuf->length); //Will be filled at the end
        validate_param_string(anqpEntry,"Language",anqpParam);
        copy_string(anqpParam->valuestring,(char*)next_pos);
        next_pos += strlen(anqpParam->valuestring);
        anqpParam = cJSON_GetObjectItem(anqpEntry,"Name");
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Venue name cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid size for Venue name",sizeof(execRetVal->ErrorMsg)-1);
            cJSON_Delete(passPointStats);
            return RETURN_ERR;
        }
        copy_string((char*)next_pos, anqpParam->valuestring);
        next_pos += strlen(anqpParam->valuestring);
        venueBuf->length = next_pos - &venueBuf->language[0];
    }
    vap_info->anqp.venueInfoLength = next_pos - (UCHAR *)&vap_info->anqp.venueInfo;

    //RoamingConsortiumANQPElement
    validate_param_object(mainEntry,"RoamingConsortiumANQPElement", anqpElement);
    next_pos = (UCHAR *)&vap_info->anqp.roamInfo;

    validate_param_array(anqpElement,"OI",anqpList);
    if(cJSON_GetArraySize(anqpList) > 32){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Only 32 OUI supported in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__); 
        strncpy(execRetVal->ErrorMsg, "Invalid number of OUIs",sizeof(execRetVal->ErrorMsg)-1);
        cJSON_Delete(passPointStats);
        return RETURN_ERR;
    }
    int ouiCount = 0;
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_ouiDuple_t *ouiBuf = (wifi_ouiDuple_t *)next_pos;
        UCHAR ouiStr[30+1];
        int i, ouiStrLen = 0;
        memset(ouiStr,0,sizeof(ouiStr));
        anqpParam = cJSON_GetObjectItem(anqpEntry,"OI");
        if(anqpParam){
            ouiStrLen = strlen(anqpParam->valuestring);
            if((ouiStrLen < 6) || (ouiStrLen > 30) || (ouiStrLen % 2)){
                wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid OUI Length in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
                strncpy(execRetVal->ErrorMsg, "Invalid OUI Length",sizeof(execRetVal->ErrorMsg)-1);
                cJSON_Delete(passPointStats);
                return RETURN_ERR;
            }
            copy_string((char*)ouiStr, anqpParam->valuestring);
        }
        //Covert the incoming string to HEX
        for(i = 0; i < ouiStrLen; i++){
            if((ouiStr[i] >= '0') && (ouiStr[i] <= '9')){
                ouiStr[i] -= '0';
            }else if((ouiStr[i] >= 'a') && (ouiStr[i] <= 'f')){
                ouiStr[i] -= ('a' - 10);//a=10
            }else if((ouiStr[i] >= 'A') && (ouiStr[i] <= 'F')){
                ouiStr[i] -= ('A' - 10);//A=10
            }else{
                wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid OUI in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
                strncpy(execRetVal->ErrorMsg, "Invalid  character in OUI",sizeof(execRetVal->ErrorMsg)-1);
                cJSON_Delete(passPointStats);
                return RETURN_ERR;
            }
            if(i%2){
                ouiBuf->oui[(i/2)] = ouiStr[i] | (ouiStr[i-1] << 4);
            }
        }
        ouiBuf->length = i/2;
        next_pos += sizeof(ouiBuf->length);
        next_pos += ouiBuf->length;
        if(ouiCount < 3){
            memcpy(&vap_info->roamingConsortium.wifiRoamingConsortiumOui[ouiCount][0],&ouiBuf->oui[0],ouiBuf->length);
            vap_info->roamingConsortium.wifiRoamingConsortiumLen[ouiCount] = ouiBuf->length;
        }
        ouiCount++;
    }
    vap_info->roamingConsortium.wifiRoamingConsortiumCount = ouiCount;

    if(ouiCount) {
        vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_roaming_consortium;
    }

    vap_info->anqp.roamInfoLength = next_pos - (UCHAR *)&vap_info->anqp.roamInfo;

    //IPAddressTypeAvailabilityANQPElement
    validate_param_object(mainEntry,"IPAddressTypeAvailabilityANQPElement",anqpElement);
    vap_info->anqp.ipAddressInfo.field_format = 0;

    validate_param_integer(anqpElement,"IPv6AddressType",anqpParam);
    if((0 > anqpParam->valuedouble) || (2 < anqpParam->valuedouble)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid IPAddressTypeAvailabilityANQPElement. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Invalid IPAddressTypeAvailabilityANQPElement",sizeof(execRetVal->ErrorMsg)-1);
        cJSON_Delete(passPointStats);
        return RETURN_ERR;
    }
    vap_info->anqp.ipAddressInfo.field_format = (UCHAR)anqpParam->valuedouble;

    validate_param_integer(anqpElement,"IPv4AddressType",anqpParam);
    if((0 > anqpParam->valuedouble) || (7 < anqpParam->valuedouble)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid IPAddressTypeAvailabilityANQPElement. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Invalid IPAddressTypeAvailabilityANQPElement",sizeof(execRetVal->ErrorMsg)-1);
        cJSON_Delete(passPointStats);
        return RETURN_ERR;
    }
    vap_info->anqp.ipAddressInfo.field_format |= ((UCHAR)anqpParam->valuedouble << 2);
    vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_ip_address_availabality;

    //NAIRealmANQPElement
    validate_param_object(mainEntry, "NAIRealmANQPElement", anqpElement);

    validate_param_array(anqpElement, "Realm", anqpList);

    wifi_naiRealmElement_t *naiElem = &vap_info->anqp.realmInfo;
    naiElem->nai_realm_count = cJSON_GetArraySize(anqpList);
    if(naiElem->nai_realm_count > 20) {
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Only 20 Realm Entries are supported. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Exceeded max number of Realm entries",sizeof(execRetVal->ErrorMsg)-1);
        cJSON_Delete(passPointStats);
        return RETURN_ERR;
    }
    next_pos = (UCHAR *)naiElem;
    next_pos += sizeof(naiElem->nai_realm_count);

    if(naiElem->nai_realm_count) {
        vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_nai_realm;
    }

    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_naiRealm_t *realmInfoBuf = (wifi_naiRealm_t *)next_pos;
        next_pos += sizeof(realmInfoBuf->data_field_length);

        validate_param_integer(anqpEntry,"RealmEncoding",anqpParam);
        realmInfoBuf->encoding = anqpParam->valuedouble;
        next_pos += sizeof(realmInfoBuf->encoding);

        validate_param_string(anqpEntry,"Realms",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Realm Length cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid Realm Length",sizeof(execRetVal->ErrorMsg)-1);
            cJSON_Delete(passPointStats);
            return RETURN_ERR;
        }
        realmInfoBuf->realm_length = strlen(anqpParam->valuestring);
        next_pos += sizeof(realmInfoBuf->realm_length);
        copy_string((char*)next_pos, anqpParam->valuestring);
        next_pos += realmInfoBuf->realm_length;

        cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", anqpParam->valuestring);
        cJSON_AddNumberToObject(realmStats, "EntryType", 1);//1-NAI Realm
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);
        cJSON_AddItemToArray(statsList, realmStats);

        validate_param_array(anqpEntry,"EAP",subList);
        realmInfoBuf->eap_method_count = cJSON_GetArraySize(subList);
        if(realmInfoBuf->eap_method_count > 16){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: EAP entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid number of EAP entries in realm",sizeof(execRetVal->ErrorMsg)-1);
            cJSON_Delete(passPointStats);
            return RETURN_ERR;
        }
        next_pos += sizeof(realmInfoBuf->eap_method_count);

        cJSON_ArrayForEach(subEntry, subList){
            wifi_eapMethod_t *eapBuf = (wifi_eapMethod_t *)next_pos;
            validate_param_integer(subEntry,"Method",subParam);
            eapBuf->method = subParam->valuedouble;
            next_pos += sizeof(eapBuf->method);
            cJSON *subList_1  = NULL;
            cJSON *subEntry_1 = NULL;
            cJSON *subParam_1 = NULL;
            
            validate_param_array(subEntry,"AuthenticationParameter",subList_1);
            eapBuf->auth_param_count = cJSON_GetArraySize(subList_1);
            if(eapBuf->auth_param_count > 16){
                wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Auth entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
                strncpy(execRetVal->ErrorMsg, "Invalid number of Auth entries in EAP Method",sizeof(execRetVal->ErrorMsg)-1);
                cJSON_Delete(passPointStats);
                return RETURN_ERR;
            }
            next_pos += sizeof(eapBuf->auth_param_count);
            cJSON_ArrayForEach(subEntry_1, subList_1){
                int i,authStrLen;
                UCHAR authStr[14+1];
                wifi_authMethod_t *authBuf = (wifi_authMethod_t *)next_pos;

                validate_param_integer(subEntry_1,"ID",subParam_1);
                authBuf->id = subParam_1->valuedouble;
                next_pos += sizeof(authBuf->id);

                subParam_1 = cJSON_GetObjectItem(subEntry_1,"Value");
                if(!subParam_1){
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Auth Parameter Value not prensent in NAIRealmANQPElement EAP Data. Discarding Configuration\n", __func__, __LINE__);
                    strncpy(execRetVal->ErrorMsg, "Auth param missing in RealANQP EAP Data",sizeof(execRetVal->ErrorMsg)-1);  
                    cJSON_Delete(passPointStats);
                    return RETURN_ERR;
                } else if (subParam_1->valuedouble) {
                    authBuf->length = 1;
                    authBuf->val[0] = subParam_1->valuedouble;
                } else {
                    authStrLen = strlen(subParam_1->valuestring);
                    if((authStrLen != 2) && (authStrLen != 14)){
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid EAP Value Length in NAIRealmANQPElement Data. Has to be 1 to 7 bytes Long. Discarding Configuration\n", __func__, __LINE__);
                        strncpy(execRetVal->ErrorMsg, "Invalid EAP Length in NAIRealmANQPElement Data",sizeof(execRetVal->ErrorMsg)-1);
                        cJSON_Delete(passPointStats);
                        return RETURN_ERR;
                    }
                    copy_string((char*)authStr,subParam_1->valuestring);
                                
                    //Covert the incoming string to HEX
                    for(i = 0; i < authStrLen; i++){ 
                        if((authStr[i] >= '0') && (authStr[i] <= '9')){
                            authStr[i] -= '0';  
                        }else if((authStr[i] >= 'a') && (authStr[i] <= 'f')){
                            authStr[i] -= ('a' - 10);//a=10
                        }else if((authStr[i] >= 'A') && (authStr[i] <= 'F')){
                            authStr[i] -= ('A' - 10);//A=10
                        }else{
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid EAP val in NAIRealmANQPElement Data. Discarding Configuration\n", __func__, __LINE__); 
                            strncpy(execRetVal->ErrorMsg, "Invalid EAP value in NAIRealmANQPElement Data",sizeof(execRetVal->ErrorMsg)-1);
                            cJSON_Delete(passPointStats);
                            return RETURN_ERR;
                        }
                        if(i%2){
                            authBuf->val[(i/2)] = authStr[i] | (authStr[i-1] << 4);
                        }
                    }
                    authBuf->length = i/2;
                }
                next_pos += sizeof(authBuf->length);
                next_pos += authBuf->length;
            }
            eapBuf->length = next_pos - &eapBuf->method;
        }
        realmInfoBuf->data_field_length = next_pos - &realmInfoBuf->encoding;
    }
    vap_info->anqp.realmInfoLength = next_pos - (UCHAR *)&vap_info->anqp.realmInfo;

    //3GPPCellularANQPElement
    validate_param_object(mainEntry, "3GPPCellularANQPElement", anqpElement);
    wifi_3gppCellularNetwork_t *gppBuf = &vap_info->anqp.gppInfo;
    next_pos = (UCHAR *)gppBuf;

    validate_param_integer(anqpElement,"GUD",anqpParam);
    gppBuf->gud = anqpParam->valuedouble;
    next_pos += sizeof(gppBuf->gud);

    next_pos += sizeof(gppBuf->uhdLength);//Skip over UHD length to be filled at the end
    UCHAR *uhd_pos = next_pos;//Beginning of UHD data

    wifi_3gpp_plmn_list_information_element_t *plmnInfoBuf = (wifi_3gpp_plmn_list_information_element_t *)next_pos;
    plmnInfoBuf->iei = 0;
    next_pos += sizeof(plmnInfoBuf->iei);
    next_pos += sizeof(plmnInfoBuf->plmn_length);//skip through the length field that will be filled at the end
    UCHAR *plmn_pos = next_pos;//beginnig of PLMN data

    validate_param_array(anqpElement,"PLMN",anqpList);
    plmnInfoBuf->number_of_plmns = cJSON_GetArraySize(anqpList);
    next_pos += sizeof(plmnInfoBuf->number_of_plmns);  
    if(plmnInfoBuf->number_of_plmns > 16){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: 3GPP entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Exceeded max number of 3GPP entries",sizeof(execRetVal->ErrorMsg)-1);
        cJSON_Delete(passPointStats);
        return RETURN_ERR; 
     }

    cJSON_ArrayForEach(anqpEntry, anqpList){
        UCHAR mccStr[3+1];
        UCHAR mncStr[3+1];
        memset(mccStr,0,sizeof(mccStr));
        memset(mncStr,0,sizeof(mncStr));

        validate_param_string(anqpEntry,"MCC",anqpParam);
        if(strlen(anqpParam->valuestring) == (sizeof(mccStr) -1)){
            copy_string((char*)mccStr,anqpParam->valuestring);
        }else if(strlen(anqpParam->valuestring) == (sizeof(mccStr) -2)){
            mccStr[0] = '0';
            copy_string((char*)&mccStr[1], anqpParam->valuestring);
        }else{
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid MCC in 3GPPCellularANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid MCC in 3GPP Element",sizeof(execRetVal->ErrorMsg)-1);
            cJSON_Delete(passPointStats);
            return RETURN_ERR;
        }

        validate_param_string(anqpEntry,"MNC",anqpParam);
        if(strlen(anqpParam->valuestring) == (sizeof(mccStr) -1)){
            copy_string((char*)mncStr, anqpParam->valuestring);
        }else if(strlen(anqpParam->valuestring) ==  (sizeof(mccStr) -2)){
            mncStr[0] = '0';
            copy_string((char*)&mncStr[1], anqpParam->valuestring);
        }else{
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid MNC in 3GPPCellularANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid MNC in 3GPP Element",sizeof(execRetVal->ErrorMsg)-1); 
            cJSON_Delete(passPointStats);
            return RETURN_ERR;
        }
        wifi_plmn_t *plmnBuf = (wifi_plmn_t *)next_pos;
        plmnBuf->PLMN[0] = (UCHAR)((mccStr[0] - '0') | ((mccStr[1] - '0') << 4));
        plmnBuf->PLMN[1] = (UCHAR)((mccStr[2] - '0') | ((mncStr[2] - '0') << 4));
        plmnBuf->PLMN[2] = (UCHAR)((mncStr[0] - '0') | ((mncStr[1] - '0') << 4));
        next_pos += sizeof(wifi_plmn_t);

        char  nameStr[8];
        snprintf(nameStr, sizeof(nameStr), "%s:%s", mccStr, mncStr);
        cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", nameStr);
        cJSON_AddNumberToObject(realmStats, "EntryType", 3);//3-3GPP
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);
        cJSON_AddItemToArray(statsList, realmStats);
    }
    gppBuf->uhdLength = next_pos - uhd_pos;
    plmnInfoBuf->plmn_length = next_pos - plmn_pos;
    vap_info->anqp.gppInfoLength = next_pos - (UCHAR *)&vap_info->anqp.gppInfo;
    vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_3gpp_cellular_network;            
    
    //DomainANQPElement
    validate_param_object(mainEntry, "DomainANQPElement", anqpElement);
    validate_param_array(anqpElement, "DomainName", anqpList);

    if(cJSON_GetArraySize(anqpList) > 4){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Only 4 Entries supported in DomainNameANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Exceeded max no of entries in DomainNameANQPElement Data",sizeof(execRetVal->ErrorMsg)-1);
        cJSON_Delete(passPointStats);
        return RETURN_ERR;
    }
    next_pos = (UCHAR *)&vap_info->anqp.domainNameInfo;

    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_domainNameTuple_t *nameBuf = (wifi_domainNameTuple_t *)next_pos;
        validate_param_string(anqpEntry,"Name",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){ 
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Domain name length cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid Domain name length",sizeof(execRetVal->ErrorMsg)-1);
            cJSON_Delete(passPointStats);
            return RETURN_ERR;
        }
        nameBuf->length = strlen(anqpParam->valuestring);
        next_pos += sizeof(nameBuf->length);
        copy_string((char*)next_pos, anqpParam->valuestring);
        next_pos += nameBuf->length;

        cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", anqpParam->valuestring);
        cJSON_AddNumberToObject(realmStats, "EntryType", 2);//2-Domain
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);
        cJSON_AddItemToArray(statsList, realmStats);
    }
    
    vap_info->anqp.domainInfoLength = next_pos - (UCHAR *)&vap_info->anqp.domainNameInfo;
    if (vap_info->anqp.domainInfoLength) {
        vap_info->anqp.capabilityInfo.capabilityList[vap_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_domain_name;
    }

    //Update the stats JSON
    cJSON_PrintPreallocated(passPointStats,(char *)&vap_info->anqp.passpointStats, sizeof(vap_info->anqp.passpointStats), false);
    cJSON_Delete(passPointStats);

    return RETURN_OK;
}

int validate_passpoint(const cJSON *passpoint, wifi_interworking_t *vap_info, pErr execRetVal) 
{
    cJSON *mainEntry = NULL;
    cJSON *anqpElement = NULL;
    cJSON *anqpList = NULL;
    cJSON *anqpEntry = NULL;
    cJSON *anqpParam = NULL;
    UCHAR *next_pos = NULL;

    if(!passpoint || !vap_info || !execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Passpoint entry is NULL\n");
        return RETURN_ERR;
    }
    mainEntry = (cJSON *)passpoint;

    validate_param_bool(mainEntry, "PasspointEnable", anqpParam);
    vap_info->passpoint.enable = (anqpParam->type & cJSON_True) ? true:false;

    if(vap_info->passpoint.enable) {
        if(!g_passpoint_RFC) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Passpoint cannot be enable when RFC is disabled\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "PasspointEnable: Cannot Enable Passpoint. RFC Disabled",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        } else if(vap_info->interworking.interworkingEnabled == FALSE) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Passpoint cannot be enable when Interworking is disabled\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Cannot Enable Passpoint. Interworking Disabled",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
    }	
    validate_param_bool(mainEntry, "GroupAddressedForwardingDisable", anqpParam);
    vap_info->passpoint.gafDisable = (anqpParam->type & cJSON_True) ? true:false;

    validate_param_bool(mainEntry, "P2pCrossConnectionDisable", anqpParam);
    vap_info->passpoint.p2pDisable = (anqpParam->type & cJSON_True) ? true:false;

    if((vap_info->interworking.accessNetworkType == 2) || (vap_info->interworking.accessNetworkType == 3)) {
        vap_info->passpoint.l2tif = true;
    }

    if(vap_info->passpoint.enable) {
        vap_info->passpoint.bssLoad = true;
        vap_info->passpoint.countryIE = true;
        vap_info->passpoint.proxyArp = true;
    }

    //HS2CapabilityListANQPElement
    vap_info->passpoint.capabilityInfoLength = 0;
    vap_info->passpoint.capabilityInfo.capabilityList[vap_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_hs_query_list;
    vap_info->passpoint.capabilityInfo.capabilityList[vap_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_hs_capability_list;
    
    //OperatorFriendlyNameANQPElement
    validate_param_object(mainEntry,"OperatorFriendlyNameANQPElement",anqpElement);
    validate_param_array(anqpElement,"Name",anqpList);

    if(cJSON_GetArraySize(anqpList) > 16){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: OperatorFriendlyName cannot have more than 16 entiries. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Invalid no of entries in OperatorFriendlyName",sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }

    next_pos = (UCHAR *)&vap_info->passpoint.opFriendlyNameInfo;
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_HS2_OperatorNameDuple_t *opNameBuf = (wifi_HS2_OperatorNameDuple_t *)next_pos;
        next_pos += sizeof(opNameBuf->length);//Fill length after reading the remaining fields

        validate_param_string(anqpEntry,"LanguageCode",anqpParam);
        if(strlen(anqpParam->valuestring) > 3){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid Language Code. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid Language Code",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
        copy_string((char*)next_pos, anqpParam->valuestring);
        next_pos += sizeof(opNameBuf->languageCode);

        validate_param_string(anqpEntry,"OperatorName",anqpParam);
        if(strlen(anqpParam->valuestring) > 252){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid OperatorFriendlyName. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid OperatorFriendlyName",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
        copy_string((char*)next_pos, anqpParam->valuestring);
        next_pos += strlen(anqpParam->valuestring);
        opNameBuf->length = strlen(anqpParam->valuestring) +  sizeof(opNameBuf->languageCode);
    }
    vap_info->passpoint.opFriendlyNameInfoLength = next_pos - (UCHAR *)&vap_info->passpoint.opFriendlyNameInfo;
    if(vap_info->passpoint.opFriendlyNameInfoLength) {
        vap_info->passpoint.capabilityInfo.capabilityList[vap_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_operator_friendly_name;
    }

    //ConnectionCapabilityListANQPElement
    validate_param_object(mainEntry,"ConnectionCapabilityListANQPElement",anqpElement);
    validate_param_array(anqpElement,"ProtoPort",anqpList);
    if(cJSON_GetArraySize(anqpList) > 16){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Connection Capability count cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Exceeded max count of Connection Capability", sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }
    next_pos = (UCHAR *)&vap_info->passpoint.connCapabilityInfo;
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_HS2_Proto_Port_Tuple_t *connCapBuf = (wifi_HS2_Proto_Port_Tuple_t *)next_pos;
        validate_param_integer(anqpEntry,"IPProtocol",anqpParam);
        connCapBuf->ipProtocol = anqpParam->valuedouble;
        next_pos += sizeof(connCapBuf->ipProtocol);
        validate_param_integer(anqpEntry,"PortNumber",anqpParam);
        connCapBuf->portNumber = anqpParam->valuedouble;
        next_pos += sizeof(connCapBuf->portNumber);
        validate_param_integer(anqpEntry,"Status",anqpParam);
        connCapBuf->status = anqpParam->valuedouble;
        next_pos += sizeof(connCapBuf->status);
    }
    vap_info->passpoint.connCapabilityLength = next_pos - (UCHAR *)&vap_info->passpoint.connCapabilityInfo;
    if(vap_info->passpoint.connCapabilityLength) {
        vap_info->passpoint.capabilityInfo.capabilityList[vap_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_conn_capability;
    }

    //NAIHomeRealmANQPElement
    validate_param_object(mainEntry,"NAIHomeRealmANQPElement",anqpElement);
    validate_param_array(anqpElement,"Realms",anqpList);
    if(cJSON_GetArraySize(anqpList) > 20){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: NAI Realm count cannot be more than 20. Discarding Configuration\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Exceeded max count of NAI Realm",sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }
    next_pos = (UCHAR *)&vap_info->passpoint.realmInfo;
    wifi_HS2_NAI_Home_Realm_Query_t *naiElem = (wifi_HS2_NAI_Home_Realm_Query_t *)next_pos;
    naiElem->realmCount = cJSON_GetArraySize(anqpList);
    next_pos += sizeof(naiElem->realmCount);
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_HS2_NAI_Home_Realm_Data_t *realmInfoBuf = (wifi_HS2_NAI_Home_Realm_Data_t *)next_pos;
        validate_param_integer(anqpEntry,"Encoding",anqpParam);
        realmInfoBuf->encoding = anqpParam->valuedouble;
        next_pos += sizeof(realmInfoBuf->encoding);
        validate_param_string(anqpEntry,"Name",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid NAI Home Realm Name. Discarding Configuration\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid NAI Home Realm Name", sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
        realmInfoBuf->length = strlen(anqpParam->valuestring);
        next_pos += sizeof(realmInfoBuf->length);
        copy_string((char*)next_pos, anqpParam->valuestring);
        next_pos += realmInfoBuf->length;
    }
    vap_info->passpoint.realmInfoLength = next_pos - (UCHAR *)&vap_info->passpoint.realmInfo;
    if(vap_info->passpoint.realmInfoLength) {
        vap_info->passpoint.capabilityInfo.capabilityList[vap_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_nai_home_realm_query;
    }
   
    //WANMetricsANQPElement
    //wifi_getHS2WanMetrics(&g_hs2_data[apIns].wanMetricsInfo);
    vap_info->passpoint.wanMetricsInfo.wanInfo = 0b00000001;
    vap_info->passpoint.wanMetricsInfo.downLinkSpeed = 25000;
    vap_info->passpoint.wanMetricsInfo.upLinkSpeed = 5000;
    vap_info->passpoint.wanMetricsInfo.downLinkLoad = 0;
    vap_info->passpoint.wanMetricsInfo.upLinkLoad = 0;
    vap_info->passpoint.wanMetricsInfo.lmd = 0;
    vap_info->passpoint.capabilityInfo.capabilityList[vap_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_wan_metrics;
 
    return RETURN_OK;
}

static void validation_error_msg(const uint8_t group, const uint8_t type, pErr execRetVal)
{
    wifi_util_error_print(WIFI_PASSPOINT,"%s:%d: Validation failed for VenueGroup=%d and VenueType=%d\n",
        __func__, __LINE__, group, type);
    strncpy(execRetVal->ErrorMsg, "Invalid Venue Group and type combination", sizeof(execRetVal->ErrorMsg) - 1);
}

static int checkVenueParams(const uint8_t venueGroup, const uint8_t venueType, pErr execRetVal)
{
    if (venueType > 15) {
        validation_error_msg(venueGroup, venueType, execRetVal);
        return RETURN_ERR;
    }

    switch (venueGroup) {
    case 0:
       if (venueType > 0) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
       }
       break;
    case 1:
        if (venueType > 15) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 2:
        if (venueType > 9) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 3:
        if (venueType > 3) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 4:
        if (venueType > 1) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 5:
        if (venueType > 5) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 6:
        if (venueType > 5) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 7:
        if (venueType > 4) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 8:
        if (venueType > 0) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 9:
        if (venueType > 0) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 10:
        if (venueType > 7) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    case 11:
        if (venueType > 6) {
            validation_error_msg(venueGroup, venueType, execRetVal);
            return RETURN_ERR;
        }
        break;
    default:
        validation_error_msg(venueGroup, venueType, execRetVal);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int validate_interworking(const cJSON *interworking, wifi_vap_info_t *vap_info, pErr execRetVal)
{
    const cJSON *param, *venue;
    const cJSON *passpoint, *anqp;

    if(!interworking || !vap_info || !execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Interworking entry is NULL\n");
        return RETURN_ERR;
    }
    validate_param_bool(interworking, "InterworkingEnable", param);
    vap_info->u.bss_info.interworking.interworking.interworkingEnabled = (param->type & cJSON_True) ? true:false;

    if((!g_interworking_RFC) && (vap_info->u.bss_info.interworking.interworking.interworkingEnabled)) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Interworking cannot be enable when RFC is disabled\n", __func__, __LINE__);	
        strncpy(execRetVal->ErrorMsg, "InterworkingEnable: Cannot Enable Interworking. RFC Disabled",sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }
	
    validate_param_integer(interworking, "AccessNetworkType", param);
    vap_info->u.bss_info.interworking.interworking.accessNetworkType = param->valuedouble;
    if (vap_info->u.bss_info.interworking.interworking.accessNetworkType > 5) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for AccessNetworkType\n", __func__, __LINE__);	
        strncpy(execRetVal->ErrorMsg, "Invalid Access Network type",sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }
	
    validate_param_bool(interworking, "Internet", param);
    vap_info->u.bss_info.interworking.interworking.internetAvailable = (param->type & cJSON_True) ? true:false;

    validate_param_bool(interworking, "ASRA", param);
    vap_info->u.bss_info.interworking.interworking.asra = (param->type & cJSON_True) ? true:false;

    validate_param_bool(interworking, "ESR", param);
    vap_info->u.bss_info.interworking.interworking.esr = (param->type & cJSON_True) ? true:false;

    validate_param_bool(interworking, "UESA", param);
    vap_info->u.bss_info.interworking.interworking.uesa = (param->type & cJSON_True) ? true:false;

    validate_param_bool(interworking, "HESSOptionPresent", param);
    vap_info->u.bss_info.interworking.interworking.hessOptionPresent = (param->type & cJSON_True) ? true:false;

    validate_param_string(interworking, "HESSID", param);
    copy_string(vap_info->u.bss_info.interworking.interworking.hessid,param->valuestring);
    if (WiFi_IsValidMacAddr(vap_info->u.bss_info.interworking.interworking.hessid) != TRUE) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for HESSID\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Invalid HESSID",sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }

    validate_param_object(interworking, "Venue", venue);
    validate_param_integer(venue, "VenueType", param);
    uint8_t VenueType = param->valuedouble;
    validate_param_integer(venue, "VenueGroup", param);
    uint8_t VenueGroup = param->valuedouble;

    if (checkVenueParams(VenueGroup, VenueType, execRetVal) != RETURN_OK)
    {
        return RETURN_ERR;
    }

    vap_info->u.bss_info.interworking.interworking.venueGroup = VenueGroup;
    vap_info->u.bss_info.interworking.interworking.venueType = VenueType;

    validate_param_object(interworking, "ANQP",anqp);

    if (validate_anqp(anqp, &vap_info->u.bss_info.interworking, execRetVal) != 0) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed\n", __func__, __LINE__);
        return RETURN_ERR;
    } else {
        cJSON *anqpString = cJSON_CreateObject();
        cJSON_AddItemReferenceToObject(anqpString, "ANQP", (cJSON *)anqp);
        cJSON_PrintPreallocated(anqpString, (char *)&vap_info->u.bss_info.interworking.anqp.anqpParameters, sizeof(vap_info->u.bss_info.interworking.anqp.anqpParameters),false);
        cJSON_Delete(anqpString);
    }

    validate_param_object(interworking, "Passpoint",passpoint);

    if (validate_passpoint(passpoint, &vap_info->u.bss_info.interworking, execRetVal) != 0) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed\n", __func__, __LINE__);
        return RETURN_ERR;
    } else {
        cJSON *hs2String = cJSON_CreateObject();
        cJSON_AddItemReferenceToObject(hs2String, "Passpoint", (cJSON *)passpoint);
        cJSON_PrintPreallocated(hs2String, (char *)&vap_info->u.bss_info.interworking.passpoint.hs2Parameters, sizeof(vap_info->u.bss_info.interworking.passpoint.hs2Parameters),false);
        cJSON_Delete(hs2String);
    }

    return RETURN_OK;
}

int early_validate_interworking(const cJSON *interworking, pErr execRetVal)
{
    const cJSON *param, *venue;
    const cJSON *passpoint, *anqp;

    if(!interworking || !execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Interworking entry is NULL\n");
        return RETURN_ERR;
    }

    validate_param_bool(interworking, "InterworkingEnable", param);
    validate_param_integer(interworking, "AccessNetworkType", param);
    if (param->valuedouble > 5) {
        wifi_util_error_print(WIFI_PASSPOINT,"%s:%d: Validation failed for AccessNetworkType=%d\n",
            __func__, __LINE__, param->valuedouble);
        strncpy(execRetVal->ErrorMsg, "Invalid Access Network type",sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }

    validate_param_bool(interworking, "Internet", param);
    validate_param_bool(interworking, "ASRA", param);
    validate_param_bool(interworking, "ESR", param);
    validate_param_bool(interworking, "UESA", param);
    validate_param_bool(interworking, "HESSOptionPresent", param);
    validate_param_string(interworking, "HESSID", param);
    if (WiFi_IsValidMacAddr(param->valuestring) != TRUE) {
        wifi_util_error_print(WIFI_PASSPOINT,"%s:%d: Validation failed for HESSID=%s\n",
            __func__, __LINE__, param->valuestring);
        strncpy(execRetVal->ErrorMsg, "Invalid HESSID",sizeof(execRetVal->ErrorMsg)-1);
        return RETURN_ERR;
    }

    validate_param_object(interworking, "Venue", venue);
    validate_param_integer(venue, "VenueType", param);
    uint8_t venueType = param->valuedouble;
    validate_param_integer(venue, "VenueGroup", param);
    uint8_t venueGroup = param->valuedouble;

    if (checkVenueParams(venueGroup, venueType, execRetVal) != RETURN_OK)
    {
        return RETURN_ERR;
    }

    validate_param_object(interworking, "ANQP",anqp);
    validate_param_object(interworking, "Passpoint",passpoint);

    return RETURN_OK;
}

int validate_radius_settings(const cJSON *radius, wifi_vap_info_t *vap_info, pErr execRetVal)
{
	const cJSON *param;

        if(!radius || !vap_info || !execRetVal){
            wifi_util_dbg_print(WIFI_PASSPOINT,"Radius entry is NULL\n");
            return RETURN_ERR;
        }

	validate_param_string(radius, "RadiusServerIPAddr", param);
	if (validate_ipv4_address(param->valuestring) == RETURN_OK || validate_ipv6_address(param->valuestring) == RETURN_OK) {
#ifndef WIFI_HAL_VERSION_3_PHASE2
	    copy_string((char *)vap_info->u.bss_info.security.u.radius.ip,param->valuestring);
	}
    else {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for RadiusServerIPAddr\n", __func__, __LINE__);	
        strncpy(execRetVal->ErrorMsg, "Invalid Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
		return RETURN_ERR;
    }
#else
    /* check the INET family and update the radius ip address */
    if(inet_pton(AF_INET, param->valuestring, &(vap_info->u.bss_info.security.u.radius.ip.u.IPv4addr)) > 0) {
       vap_info->u.bss_info.security.u.radius.ip.family = wifi_ip_family_ipv4;
    } else if(inet_pton(AF_INET6, param->valuestring, &(vap_info->u.bss_info.security.u.radius.ip.u.IPv6addr)) > 0) {
       vap_info->u.bss_info.security.u.radius.ip.family = wifi_ip_family_ipv6;
    } else {
       platform_trace_error(WIFI_PASSPOINT, "<%s> <%d> : inet_pton falied for primary radius IP\n", __FUNCTION__, __LINE__);
       return RETURN_ERR;
    }
#endif

	validate_param_integer(radius, "RadiusServerPort", param);
	vap_info->u.bss_info.security.u.radius.port = param->valuedouble;

	validate_param_string(radius, "RadiusSecret", param);
	copy_string(vap_info->u.bss_info.security.u.radius.key, param->valuestring);

	validate_param_string(radius, "SecondaryRadiusServerIPAddr", param);
	if (validate_ipv4_address(param->valuestring) == RETURN_OK || validate_ipv6_address(param->valuestring) == RETURN_OK) {
#ifndef WIFI_HAL_VERSION_3_PHASE2
        copy_string((char *)vap_info->u.bss_info.security.u.radius.s_ip,param->valuestring);
	}
    else {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for SecondaryRadiusServerIPAddr\n", __func__, __LINE__);
        strncpy(execRetVal->ErrorMsg, "Invalid Secondary Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
		return RETURN_ERR;
    }
#else
        /* check the INET family and update the radius ip address */
        if(inet_pton(AF_INET, param->valuestring, &(vap_info->u.bss_info.security.u.radius.s_ip.u.IPv4addr)) > 0) {
           vap_info->u.bss_info.security.u.radius.s_ip.family = wifi_ip_family_ipv4;
        } else if(inet_pton(AF_INET6, param->valuestring, &(vap_info->u.bss_info.security.u.radius.s_ip.u.IPv6addr)) > 0) {
           vap_info->u.bss_info.security.u.radius.s_ip.family = wifi_ip_family_ipv6;
        } else {
          platform_trace_error(WIFI_PASSPOINT, "<%s> <%d> : inet_pton falied for primary radius IP\n", __FUNCTION__, __LINE__);
          return RETURN_ERR;
        }
#endif

	validate_param_integer(radius, "SecondaryRadiusServerPort", param);
	vap_info->u.bss_info.security.u.radius.s_port = param->valuedouble;
	validate_param_string(radius, "SecondaryRadiusSecret", param);
	copy_string(vap_info->u.bss_info.security.u.radius.s_key, param->valuestring);

        validate_param_string(radius, "DasServerIPAddr", param);
        if (validate_ipv4_address(param->valuestring) == RETURN_OK || validate_ipv6_address(param->valuestring) == RETURN_OK) {
            getIpAddressFromString(param->valuestring, &vap_info->u.bss_info.security.u.radius.dasip);
        }
        else {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed for DasServerIPAddr\n", __func__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "Invalid Das Server IP Addr",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }
	
        validate_param_integer(radius, "DasServerPort", param);
        vap_info->u.bss_info.security.u.radius.dasport = param->valuedouble;

        validate_param_string(radius, "DasSecret", param);
        copy_string(vap_info->u.bss_info.security.u.radius.daskey, param->valuestring);

        //max_auth_attempts
        validate_param_integer(radius, "MaxAuthAttempts", param);
        vap_info->u.bss_info.security.u.radius.max_auth_attempts = param->valuedouble;

        //blacklist_table_timeout
        validate_param_integer(radius, "BlacklistTableTimeout", param);
        vap_info->u.bss_info.security.u.radius.blacklist_table_timeout = param->valuedouble;

        //identity_req_retry_interval
        validate_param_integer(radius, "IdentityReqRetryInterval", param);
        vap_info->u.bss_info.security.u.radius.identity_req_retry_interval = param->valuedouble;

        //server_retries
        validate_param_integer(radius, "ServerRetries", param);
        vap_info->u.bss_info.security.u.radius.server_retries = param->valuedouble;

        //Wpa3_transition_disable
	validate_param_bool(radius, "Wpa3_transition_disable", param);
        vap_info->u.bss_info.security.wpa3_transition_disable =  (param->type & cJSON_True) ? true:false;

        validate_param_bool(radius, "StrictRekey", param);
        vap_info->u.bss_info.security.strict_rekey =  (param->type & cJSON_True) ? true:false;

        validate_param_integer(radius, "EapolKeyTimeout", param);
        vap_info->u.bss_info.security.eapol_key_retries = param->valuedouble;

        validate_param_integer(radius, "EapolKeyRetries", param);
        vap_info->u.bss_info.security.eapol_key_retries = param->valuedouble;

        validate_param_integer(radius, "EapIdentityReqTimeout", param);
        vap_info->u.bss_info.security.eap_identity_req_timeout = param->valuedouble;

        validate_param_integer(radius, "EapIdentityReqRetries", param);
        vap_info->u.bss_info.security.eap_identity_req_retries = param->valuedouble;

        validate_param_integer(radius, "EapReqTimeout", param);
        vap_info->u.bss_info.security.eap_req_timeout = param->valuedouble;

        validate_param_integer(radius, "EapReqRetries", param);
        vap_info->u.bss_info.security.eap_req_retries = param->valuedouble;

        validate_param_bool(radius, "DisablePmksaCaching", param);
        vap_info->u.bss_info.security.disable_pmksa_caching = (param->type & cJSON_True) ? true:false;
	return RETURN_OK;

}

int validate_enterprise_security(const cJSON *security, wifi_vap_info_t *vap_info, pErr execRetVal)
{
	const cJSON *param;

        if(!security || !vap_info || !execRetVal){
            wifi_util_dbg_print(WIFI_PASSPOINT,"Interworking entry is NULL\n");
            return RETURN_ERR;
        }

	validate_param_string(security, "Mode", param);
	if ((strcmp(param->valuestring, "WPA2-Enterprise") != 0) && (strcmp(param->valuestring, "WPA-WPA2-Enterprise") != 0) && (strcmp(param->valuestring, "WPA3-Enterprise") != 0)) {
		wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Xfinity WiFi VAP security is not WPA2 Eneterprise, value:%s\n", 
			__func__, __LINE__, param->valuestring);
                strncpy(execRetVal->ErrorMsg, "Invalid sec mode for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1); 
		return RETURN_ERR;
	}
    if (strcmp(param->valuestring, "WPA2-Enterprise") == 0) { 
        vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    } else if (strcmp(param->valuestring, "WPA3-Enterprise") == 0) { 
        vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_enterprise;
    } else {
        vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_wpa2_enterprise;
    }

        validate_param_string(security, "EncryptionMethod", param);
        if ((strcmp(param->valuestring, "AES") != 0) && (strcmp(param->valuestring, "AES+TKIP") != 0)) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Xfinity WiFi VAP Encrytpion mode is Invalid:%s\n", 
                    __func__, __LINE__, param->valuestring);
            strncpy(execRetVal->ErrorMsg, "Invalid enc mode for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);  
            return RETURN_ERR;
        }
        if (strcmp(param->valuestring, "AES") == 0) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes;	
        } else {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        }

        // MFPConfig
        validate_param_string(security, "MFPConfig", param);
        if ((strcmp(param->valuestring, "Disabled") != 0) 
             && (strcmp(param->valuestring, "Required") != 0) 
             && (strcmp(param->valuestring, "Optional") != 0)) {
                wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%s\n",
                        __func__, __LINE__, param->valuestring);
                strncpy(execRetVal->ErrorMsg, "Invalid  MFPConfig for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }
        if ( vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise && (strcmp(param->valuestring, "Required") != 0)) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: MFPConfig not valid, value:%s\n",
                        __func__, __LINE__, param->valuestring);
                return RETURN_ERR;
        }
#if defined(WIFI_HAL_VERSION_3)
        if (strstr(param->valuestring, "Disabled")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        } else if (strstr(param->valuestring, "Required")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
        } else if (strstr(param->valuestring, "Optional")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
        }
#else
        copy_string(vap_info->u.bss_info.security.mfpConfig, param->valuestring);
#endif

        validate_param_integer(security, "RekeyInterval", param);
        vap_info->u.bss_info.security.rekey_interval = param->valuedouble;

	validate_param_object(security, "RadiusSettings",param);
	if (validate_radius_settings(param, vap_info, execRetVal) != 0) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed\n", __func__, __LINE__);
		return RETURN_ERR;
	}
	return RETURN_OK;
}

int validate_personal_security(const cJSON *security, wifi_vap_info_t *vap_info, pErr execRetVal)
{
        if(!security || !vap_info || !execRetVal){
            wifi_util_dbg_print(WIFI_PASSPOINT,"Interworking entry is NULL\n");
            return RETURN_ERR;
        }
        
        const cJSON *param;

        validate_param_string(security, "EncryptionMethod", param);

        if (strcmp(param->valuestring, "TKIP") == 0) {
            vap_info->u.bss_info.security.encr = wifi_encryption_tkip;
        } else if(strcmp(param->valuestring, "AES") == 0) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes;
        } else if(strcmp(param->valuestring, "AES+TKIP") == 0) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        } else {
            platform_trace_error(WIFI_PASSPOINT, "%s: Invalid Encryption method for private vap\n", __FUNCTION__);
            strncpy(execRetVal->ErrorMsg, "Invalid Encryption method",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }

        if ((vap_info->u.bss_info.security.mode == wifi_security_mode_wpa_wpa2_personal) &&
            (vap_info->u.bss_info.security.encr == wifi_encryption_tkip)) {
            platform_trace_error(WIFI_PASSPOINT, "%s: Invalid Encryption method combination for private vap\n",__FUNCTION__);
            strncpy(execRetVal->ErrorMsg, "Invalid Encryption method combinaiton",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }


        validate_param_string(security, "Passphrase", param);

        if ((strlen(param->valuestring) < MIN_PWD_LEN) || (strlen(param->valuestring) > MAX_PWD_LEN)) {
            strncpy(execRetVal->ErrorMsg, "Invalid Key passphrase length",sizeof(execRetVal->ErrorMsg)-1);
            platform_trace_error(WIFI_PASSPOINT, "%s: Invalid Key passphrase length\n",__FUNCTION__);
            return RETURN_ERR;
        }
        strncpy(vap_info->u.bss_info.security.u.key.key, param->valuestring,
                sizeof(vap_info->u.bss_info.security.u.key.key) - 1);	

        return RETURN_OK;
}

int validate_ssid_name(char *ssid_name, pErr execRetVal) 
{
    int i =0, ssid_len;

    if(!ssid_name ||!execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Interworking entry is NULL\n");
        return RETURN_ERR;
    }
        
    ssid_len = strlen(ssid_name);
    if ((ssid_len == 0) || (ssid_len > WIFI_MAX_SSID_NAME_LEN)) {
        platform_trace_error(WIFI_PASSPOINT, "%s: Invalid SSID size \n",__FUNCTION__);
        strncpy(execRetVal->ErrorMsg, "Invalid SSID Size",sizeof(execRetVal->ErrorMsg)-1); 
        return RETURN_ERR;
    }


    for (i = 0; i < ssid_len; i++) {
        if (!((ssid_name[i] >= ' ') && (ssid_name[i] <= '~'))) {
            platform_trace_error(WIFI_PASSPOINT, "%s: Invalid character present in SSID Name \n",__FUNCTION__);
            strncpy(execRetVal->ErrorMsg, "Invalid character in SSID",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
    }
    return RETURN_OK;
}

int validate_xfinity_secure_vap(const cJSON *vap, wifi_vap_info_t *vap_info, pErr execRetVal)
{
        if(!vap || !vap_info || !execRetVal){
            wifi_util_dbg_print(WIFI_PASSPOINT,"VAP entry is NULL\n");
            return RETURN_ERR;
        }
        
	const cJSON *security, *interworking;

	validate_param_object(vap, "Security",security);

	if (validate_enterprise_security(security, vap_info, execRetVal) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed\n", __func__, __LINE__);
		return RETURN_ERR;
	}

	validate_param_object(vap, "Interworking",interworking);

	if (validate_interworking(interworking, vap_info, execRetVal) != RETURN_OK) {
            return RETURN_ERR;
	}

	return RETURN_OK;
}

int validate_xfinity_open_vap(const cJSON *vap, wifi_vap_info_t *vap_info, pErr execRetVal)
{
        const cJSON *security, *param, *interworking;
        
        validate_param_object(vap, "Security",security);

        validate_param_string(security, "Mode", param);
        if ((strcmp(param->valuestring, "None") != 0) && (strcmp(param->valuestring, "Enhanced-Open") != 0)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "[%s] Passed Xfinity open security %s is invalid \n", __FUNCTION__,param->valuestring);
            strncpy(execRetVal->ErrorMsg, "Invalid security for hotspot open vap",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }

        if (strcmp(param->valuestring, "None") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_none;
        }
        if (strcmp(param->valuestring, "Enhanced-Open") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_enhanced_open;
            vap_info->u.bss_info.security.encr = wifi_encryption_aes;
        }
        
        // MFPConfig
        validate_param_string(security, "MFPConfig", param);
        if ((strcmp(param->valuestring, "Disabled") != 0) 
             && (strcmp(param->valuestring, "Required") != 0) 
             && (strcmp(param->valuestring, "Optional") != 0)) {
                wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%s\n",
                        __func__, __LINE__, param->valuestring);
                strncpy(execRetVal->ErrorMsg, "Invalid  MFPConfig for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }

        if (vap_info->u.bss_info.security.mode == wifi_security_mode_enhanced_open && (strcmp(param->valuestring, "Required") != 0)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: MFPConfig not valid for Enhanced-Open, value:%s\n",
                        __func__, __LINE__, param->valuestring);
            return RETURN_ERR;
        }
#if defined(WIFI_HAL_VERSION_3)
        if (strstr(param->valuestring, "Disabled")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        } else if (strstr(param->valuestring, "Required")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
        } else if (strstr(param->valuestring, "Optional")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
        }
#else
        copy_string(vap_info->u.bss_info.security.mfpConfig, param->valuestring);
#endif

        validate_param_integer(security, "RekeyInterval", param);
        vap_info->u.bss_info.security.rekey_interval = param->valuedouble;

        validate_param_object(vap, "Interworking",interworking);

        if (validate_interworking(interworking, vap_info, execRetVal) != RETURN_OK) {
            return RETURN_ERR;
        }

        if (vap_info->u.bss_info.interworking.passpoint.enable) {
            platform_trace_error(WIFI_PASSPOINT, "[%s] Passpoint cannot be enabled on hotspot open vap\n", __FUNCTION__);
            strncpy(execRetVal->ErrorMsg, "Passpoint cannot be enabled on hotspot open vap",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }

	return RETURN_OK;
}

int validate_private_vap(const cJSON *vap, wifi_vap_info_t *vap_info, pErr execRetVal)
{
        const cJSON *security, *param, *interworking;

        validate_param_object(vap, "Security",security);
        validate_param_string(security, "Mode", param);

        if (strcmp(param->valuestring, "None") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_none;
        } else if (strcmp(param->valuestring, "WPA-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_personal;
        } else if (strcmp(param->valuestring, "WPA2-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
        } else if (strcmp(param->valuestring, "WPA-WPA2-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_wpa2_personal;
#ifdef WIFI_HAL_VERSION_3
        } else if (strcmp(param->valuestring, "WPA3-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_sae;
        } else if (strcmp(param->valuestring, "WPA3-Personal-Transition") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
#endif
        } else {
            platform_trace_error(WIFI_PASSPOINT, "%s: Invalid Authentication mode for private vap", __FUNCTION__);
            strncpy(execRetVal->ErrorMsg, "Invalid Authentication mode for private vap",sizeof(execRetVal->ErrorMsg)-1);  
            return RETURN_ERR;
        }


        // MFPConfig
        validate_param_string(security, "MFPConfig", param);
        if ((strcmp(param->valuestring, "Disabled") != 0) 
             && (strcmp(param->valuestring, "Required") != 0) 
             && (strcmp(param->valuestring, "Optional") != 0)) {
                wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%s\n",
                        __func__, __LINE__, param->valuestring);
                strncpy(execRetVal->ErrorMsg, "Invalid  MFPConfig for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }
#if defined(WIFI_HAL_VERSION_3)
        if (strstr(param->valuestring, "Disabled")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        } else if (strstr(param->valuestring, "Required")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
        } else if (strstr(param->valuestring, "Optional")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
        }
#else
        copy_string(vap_info->u.bss_info.security.mfpConfig, param->valuestring);
#endif

        if ((vap_info->u.bss_info.security.mode != wifi_security_mode_none) &&
            (validate_personal_security(security, vap_info, execRetVal) != RETURN_OK)) {
            platform_trace_error(WIFI_PASSPOINT, "%s: Failed to validate security for vap %s", __FUNCTION__, vap_info->vap_name);
            return RETURN_ERR;
        } 

        validate_param_integer(security, "RekeyInterval", param);
        vap_info->u.bss_info.security.rekey_interval = param->valuedouble;

        validate_param_object(vap, "Interworking",interworking);

        if (validate_interworking(interworking, vap_info, execRetVal) != RETURN_OK) {
            return RETURN_ERR;
        }

        if (vap_info->u.bss_info.interworking.passpoint.enable) {
            platform_trace_error(WIFI_PASSPOINT, "[%s] Passpoint cannot be enabled on private vap\n", __FUNCTION__);
            strncpy(execRetVal->ErrorMsg, "Passpoint cannot be enabled on private vap",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }

	return RETURN_OK;
}

int validate_xhome_vap(const cJSON *vap, wifi_vap_info_t *vap_info, pErr execRetVal)
{
        const cJSON *security, *param, *interworking;

        validate_param_object(vap, "Security",security);

        validate_param_string(security, "Mode", param);

        if (strcmp(param->valuestring, "None") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_none;
        } else if (strcmp(param->valuestring, "WPA-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_personal;
        } else if (strcmp(param->valuestring, "WPA2-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
        } else if (strcmp(param->valuestring, "WPA-WPA2-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_wpa2_personal;
#if defined(WIFI_HAL_VERSION_3)
        } else if (strcmp(param->valuestring, "WPA3-Personal") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_sae;
        } else if (strcmp(param->valuestring, "WPA3-Personal-Transition") == 0) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
#endif
        } else {
            platform_trace_error(WIFI_PASSPOINT, "%s: Invalid Authentication mode for vap %s", __FUNCTION__, vap_info->vap_name);
            strncpy(execRetVal->ErrorMsg,"Invalid Authentication mode for xhome vap",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }

        // MFPConfig
        validate_param_string(security, "MFPConfig", param);
        if ((strcmp(param->valuestring, "Disabled") != 0)
             && (strcmp(param->valuestring, "Required") != 0)
             && (strcmp(param->valuestring, "Optional") != 0)) {
                wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%s\n",
                        __func__, __LINE__, param->valuestring);
                strncpy(execRetVal->ErrorMsg, "Invalid  MFPConfig for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }
#if defined(WIFI_HAL_VERSION_3)
        if (strstr(param->valuestring, "Disabled")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        } else if (strstr(param->valuestring, "Required")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
        } else if (strstr(param->valuestring, "Optional")) {
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
        }
#else
        copy_string(vap_info->u.bss_info.security.mfpConfig, param->valuestring);
#endif

        if ((vap_info->u.bss_info.security.mode != wifi_security_mode_none) &&
            (validate_personal_security(security, vap_info, execRetVal) != RETURN_OK)) {
            platform_trace_error(WIFI_PASSPOINT, "%s: Failed to validate security for vap %s", __FUNCTION__, vap_info->vap_name);
            return RETURN_ERR;
        }

        validate_param_integer(security, "RekeyInterval", param);
        vap_info->u.bss_info.security.rekey_interval = param->valuedouble;

        validate_param_object(vap, "Interworking",interworking);

        if (validate_interworking(interworking, vap_info, execRetVal) != RETURN_OK) {
            return RETURN_ERR;
        }

        if (vap_info->u.bss_info.interworking.passpoint.enable) {
            platform_trace_error(WIFI_PASSPOINT, "[%s] Passpoint cannot be enabled on private vap\n", __FUNCTION__);
            strncpy(execRetVal->ErrorMsg, "Passpoint cannot be enabled on private vap",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }

	return RETURN_OK;
}

int validate_contry_code(wifi_countrycode_type_t *contry_code, char *contry)
{
    int i;
    for (i = 0 ; i < MAX_WIFI_COUNTRYCODE; ++i)
    {
        if(strcasecmp(contry,wifiCountryMapMembers[i].countryStr) == 0)
        {
            *contry_code = wifiCountryMapMembers[i].countryCode;
            return RETURN_OK;
        }
    }

    if(i == MAX_WIFI_COUNTRYCODE)
    {
        platform_trace_error(WIFI_PASSPOINT, "RDK_LOG_ERROR, %s Invalid Country code %s\n", __func__,contry);
    }
    return RETURN_ERR;
}

int validate_vap(const cJSON *vap, wifi_vap_info_t *vap_info, wifi_platform_property_t *wifi_prop, pErr execRetVal)
{
	const cJSON  *param;
	int ret=RETURN_OK;

        //VAP Name
	validate_param_string(vap, "VapName",param);
	strcpy(vap_info->vap_name, param->valuestring);

        //Bridge Name
        validate_param_string(vap, "BridgeName", param);
        strncpy(vap_info->bridge_name, param->valuestring,WIFI_BRIDGE_NAME_LEN-1);

	// SSID
	validate_param_string(vap, "SSID", param);
	strcpy(vap_info->u.bss_info.ssid, param->valuestring);

        if (validate_ssid_name(vap_info->u.bss_info.ssid, execRetVal) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s %d : Ssid name validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
            return RETURN_ERR;
        } 
	// Enabled
	validate_param_bool(vap, "Enabled", param);
	vap_info->u.bss_info.enabled = (param->type & cJSON_True) ? true:false;

	// Broadcast SSID
	validate_param_bool(vap, "SSIDAdvertisementEnabled", param);
	vap_info->u.bss_info.showSsid = (param->type & cJSON_True) ? true:false;

	// Isolation
	validate_param_bool(vap, "IsolationEnable", param);
	vap_info->u.bss_info.isolation = (param->type & cJSON_True) ? true:false;

	// ManagementFramePowerControl
	validate_param_integer(vap, "ManagementFramePowerControl", param);
	vap_info->u.bss_info.mgmtPowerControl = param->valuedouble;

	// BssMaxNumSta
	validate_param_integer(vap, "BssMaxNumSta", param);
	vap_info->u.bss_info.bssMaxSta = param->valuedouble;

        // BSSTransitionActivated
        validate_param_bool(vap, "BSSTransitionActivated", param);
        vap_info->u.bss_info.bssTransitionActivated = (param->type & cJSON_True) ? true:false;

        // NeighborReportActivated
        validate_param_bool(vap, "NeighborReportActivated", param);
        vap_info->u.bss_info.nbrReportActivated = (param->type & cJSON_True) ? true:false;

        // RapidReconnCountEnable
        validate_param_bool(vap, "RapidReconnCountEnable", param);
        vap_info->u.bss_info.rapidReconnectEnable = (param->type & cJSON_True) ? true:false;

	// RapidReconnThreshold
	validate_param_integer(vap, "RapidReconnThreshold", param);
	vap_info->u.bss_info.rapidReconnThreshold = param->valuedouble;

        // VapStatsEnable
        validate_param_bool(vap, "VapStatsEnable", param);
        vap_info->u.bss_info.vapStatsEnable = (param->type & cJSON_True) ? true:false;

        // MacFilterEnable
        validate_param_bool(vap, "MacFilterEnable", param);
        vap_info->u.bss_info.mac_filter_enable = (param->type & cJSON_True) ? true:false;

        // MacFilterMode
        validate_param_integer(vap, "MacFilterMode", param);
        vap_info->u.bss_info.mac_filter_mode = param->valuedouble;
	if ((vap_info->u.bss_info.mac_filter_mode < 0) || (vap_info->u.bss_info.mac_filter_mode > 1)) {
                wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid wifi vap mac filter mode, should be between 0 and 1\n");
                strncpy(execRetVal->ErrorMsg, "Invalid wifi vap mac filter mode: 0..1",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }
/*
        // MacAddrAclEnabled
        validate_param_bool(vap, "MacAddrAclEnabled", param);
        vap_info->u.bss_info.mac_addr_acl_enabled = (param->type & cJSON_True) ? true:false;
*/        
	// WmmEnabled
        validate_param_bool(vap, "WmmEnabled", param);
        vap_info->u.bss_info.wmm_enabled = (param->type & cJSON_True) ? true:false;

        validate_param_bool(vap, "UapsdEnabled", param);
        vap_info->u.bss_info.UAPSDEnabled = (param->type & cJSON_True) ? true:false;

        validate_param_integer(vap, "BeaconRate", param);
        vap_info->u.bss_info.beaconRate = param->valuedouble;

        // WmmNoAck
        validate_param_integer(vap, "WmmNoAck", param);
        vap_info->u.bss_info.wmmNoAck = param->valuedouble;

        // WepKeyLength
        validate_param_integer(vap, "WepKeyLength", param);
        vap_info->u.bss_info.wepKeyLength = param->valuedouble;

        // BssHotspot
        validate_param_bool(vap, "BssHotspot", param);
        vap_info->u.bss_info.bssHotspot = (param->type & cJSON_True) ? true:false;

        // wpsPushButton
        validate_param_integer(vap, "WpsPushButton", param);
        vap_info->u.bss_info.wpsPushButton = param->valuedouble;

        // BeaconRateCtl
        validate_param_string(vap, "BeaconRateCtl", param);
        strcpy(vap_info->u.bss_info.beaconRateCtl, param->valuestring);
        INT apIndex = 0;
        apIndex = convert_vap_name_to_index(wifi_prop, vap_info->vap_name);
        if (apIndex != -1)
        {
            vap_info->vap_index = apIndex;
            vap_info->radio_index = getRadioIndexFromAp(apIndex);
            if (isVapHotspot(apIndex)) {
                if (isVapHotspotSecure(apIndex)) {
                    ret = validate_xfinity_secure_vap(vap, vap_info, execRetVal);
                } else {
                    ret = validate_xfinity_open_vap(vap, vap_info, execRetVal);
                }
            } else if(isVapPrivate(apIndex)) {
                ret = validate_private_vap(vap, vap_info, execRetVal);
            } else if (isVapXhs(apIndex)) {
                ret = validate_xhome_vap(vap, vap_info, execRetVal);
            } else if (isVapLnfSecure(apIndex)) {
                ret = validate_xfinity_secure_vap(vap, vap_info, execRetVal);
            } else {
                //Work-Around : need to add seperate validation functions for isVapLnf(),isVapLnfPsk(), isVapMesh() and isVapLnfSecure()
                ret = validate_xhome_vap(vap, vap_info, execRetVal);
            }
        }

    else {
                wifi_util_dbg_print(WIFI_PASSPOINT,"%s %d Validation failed: Invalid vap name",__FUNCTION__, __LINE__);
                strncpy(execRetVal->ErrorMsg, "Invalid vap name",sizeof(execRetVal->ErrorMsg)-1);
		return RETURN_ERR;
	}

        if (ret != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s %d Validation of %s vap failed\n", __FUNCTION__,__LINE__ , vap_info->vap_name);
        } 
	return ret;
}

int validate_wifi_global_config(const cJSON *global_cfg, wifi_global_param_t *global_info, pErr execRetVal)
{
    if(!global_cfg || !execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"wifi global entry is NULL\n");
        return RETURN_ERR;
    }

    const cJSON  *param;
	
    // NotifyWifiChanges
    validate_param_bool(global_cfg, "NotifyWifiChanges", param);
    global_info->notify_wifi_changes = (param->type & cJSON_True) ? true:false;

    // PreferPrivate
    validate_param_bool(global_cfg, "PreferPrivate", param);
    global_info->prefer_private = (param->type & cJSON_True) ? true:false;

    // PreferPrivateConfigure
    validate_param_bool(global_cfg, "PreferPrivateConfigure", param);
    global_info->prefer_private_configure = (param->type & cJSON_True) ? true:false;

    // FactoryReset
    validate_param_bool(global_cfg, "FactoryReset", param);
    global_info->factory_reset = (param->type & cJSON_True) ? true:false;

    // TxOverflowSelfheal
    validate_param_bool(global_cfg, "TxOverflowSelfheal", param);
    global_info->tx_overflow_selfheal = (param->type & cJSON_True) ? true:false;

    // InstWifiClientEnabled
    validate_param_bool(global_cfg, "InstWifiClientEnabled", param);
    global_info->inst_wifi_client_enabled = (param->type & cJSON_True) ? true:false;

    //InstWifiClientReportingPeriod
    validate_param_integer(global_cfg, "InstWifiClientReportingPeriod", param);
    global_info->inst_wifi_client_reporting_period = param->valuedouble;

    //InstWifiClientMac
    validate_param_string(global_cfg, "InstWifiClientMac", param);
    //copy_string((unsigned char *)global_info->inst_wifi_client_mac, param->valuestring);
    string_mac_to_uint8_mac((uint8_t *)&global_info->inst_wifi_client_mac, param->valuestring);

    //InstWifiClientDefReportingPeriod
    validate_param_integer(global_cfg, "InstWifiClientDefReportingPeriod", param);
    global_info->inst_wifi_client_def_reporting_period = param->valuedouble;

    // WifiActiveMsmtEnabled
    validate_param_bool(global_cfg, "WifiActiveMsmtEnabled", param);
    global_info->wifi_active_msmt_enabled = (param->type & cJSON_True) ? true:false;

    //WifiActiveMsmtPktsize
    validate_param_integer(global_cfg, "WifiActiveMsmtPktsize", param);
    global_info->wifi_active_msmt_pktsize = param->valuedouble;

    //WifiActiveMsmtNumSamples
    validate_param_integer(global_cfg, "WifiActiveMsmtNumSamples", param);
    global_info->wifi_active_msmt_num_samples = param->valuedouble;

    //WifiActiveMsmtSampleDuration
    validate_param_integer(global_cfg, "WifiActiveMsmtSampleDuration", param);
    global_info->wifi_active_msmt_sample_duration = param->valuedouble;

    //VlanCfgVersion
    validate_param_integer(global_cfg, "VlanCfgVersion", param);
    global_info->vlan_cfg_version = param->valuedouble;

    //WpsPin
    validate_param_string(global_cfg, "WpsPin", param);
    copy_string(global_info->wps_pin, param->valuestring);

    // BandsteeringEnable
    validate_param_bool(global_cfg, "BandsteeringEnable", param);
    global_info->bandsteering_enable = (param->type & cJSON_True) ? true:false;

    //GoodRssiThreshold
    validate_param_integer(global_cfg, "GoodRssiThreshold", param);
    global_info->good_rssi_threshold = param->valuedouble;

    //AssocCountThreshold
    validate_param_integer(global_cfg, "AssocCountThreshold", param);
    global_info->assoc_count_threshold = param->valuedouble;

    //AssocGateTime
    validate_param_integer(global_cfg, "AssocGateTime", param);
    global_info->assoc_gate_time = param->valuedouble;

    //WhixLoginterval
    validate_param_integer(global_cfg, "WhixLoginterval", param);
    global_info->whix_log_interval = param->valuedouble;

    //Whix_ChUtility_Loginterval
    validate_param_integer(global_cfg, "whix_chutility_loginterval", param);
    global_info->whix_chutility_loginterval = param->valuedouble;

    //AssocMonitorDuration
    validate_param_integer(global_cfg, "AssocMonitorDuration", param);
    global_info->assoc_monitor_duration = param->valuedouble;

    // RapidReconnectEnable
    validate_param_bool(global_cfg, "RapidReconnectEnable", param);
    global_info->rapid_reconnect_enable = (param->type & cJSON_True) ? true:false;

    // VapStatsFeature
    validate_param_bool(global_cfg, "VapStatsFeature", param);
    global_info->vap_stats_feature = (param->type & cJSON_True) ? true:false;

    // MfpConfigFeature
    validate_param_bool(global_cfg, "MfpConfigFeature", param);
    global_info->mfp_config_feature = (param->type & cJSON_True) ? true:false;

    // ForceDisableRadioFeature
    validate_param_bool(global_cfg, "ForceDisableRadioFeature", param);
    global_info->force_disable_radio_feature = (param->type & cJSON_True) ? true:false;

    // ForceDisableRadioStatus
    validate_param_bool(global_cfg, "ForceDisableRadioStatus", param);
    global_info->force_disable_radio_status = (param->type & cJSON_True) ? true:false;

    //FixedWmmParams
    validate_param_integer(global_cfg, "FixedWmmParams", param);
    global_info->fixed_wmm_params = param->valuedouble;

    //WifiRegionCode
    validate_param_string(global_cfg, "WifiRegionCode", param);
    copy_string(global_info->wifi_region_code, param->valuestring);

    // DiagnosticEnable
    validate_param_bool(global_cfg, "DiagnosticEnable", param);
    global_info->diagnostic_enable = (param->type & cJSON_True) ? true:false;

    // ValidateSsid
    validate_param_bool(global_cfg, "ValidateSsid", param);
    global_info->validate_ssid = (param->type & cJSON_True) ? true:false;

    // DeviceNetworkMode
    validate_param_integer(global_cfg, "DeviceNetworkMode", param);
    global_info->device_network_mode = param->valuedouble;

    //NormalizedRssiList
    validate_param_string(global_cfg, "NormalizedRssiList", param);
    copy_string(global_info->normalized_rssi_list, param->valuestring);

    //SNRList
    validate_param_string(global_cfg, "SNRList", param);
    copy_string(global_info->snr_list, param->valuestring);

    //CliStatList
    validate_param_string(global_cfg, "CliStatList", param);
    copy_string(global_info->cli_stat_list, param->valuestring);

    //TxRxRateList
    validate_param_string(global_cfg, "TxRxRatetList", param);
    copy_string(global_info->txrx_rate_list, param->valuestring);

    wifi_util_dbg_print(WIFI_PASSPOINT,"wifi global Parameters validate successfully\n");
    return RETURN_OK;
}

int validate_gas_config(const cJSON *gas, wifi_GASConfiguration_t *gas_info, pErr execRetVal)
{
        if(!gas || !gas_info || !execRetVal){
            wifi_util_dbg_print(WIFI_PASSPOINT,"GAS entry is NULL\n");
            return RETURN_ERR;
        }
        
        const cJSON  *param;
        //AdvertisementId
        validate_param_integer(gas, "AdvertisementId", param);
        gas_info->AdvertisementID = param->valuedouble;
        if (gas_info->AdvertisementID != 0) { //ANQP
            wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid Configuration. Only Advertisement ID 0 - ANQP is Supported\n");
            strncpy(execRetVal->ErrorMsg, "Invalid AdvertisementId. Only ANQP(0) Supported",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
        
        // PauseForServerResp
        validate_param_bool(gas, "PauseForServerResp", param);
        gas_info->PauseForServerResponse = (param->type & cJSON_True) ? true:false;

        //ResponseTimeout
        validate_param_integer(gas, "RespTimeout", param);
        gas_info->ResponseTimeout = param->valuedouble;
        if ((gas_info->ResponseTimeout < 1000) || (gas_info->ResponseTimeout > 65535)) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid Configuration. ResponseTimeout should be between 1000 and 65535\n");
            strncpy(execRetVal->ErrorMsg, "Invalid RespTimeout 1000..65535",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
        
        //ComebackDelay
        validate_param_integer(gas, "ComebackDelay", param);
        gas_info->ComeBackDelay = param->valuedouble;
        if (gas_info->ComeBackDelay > 65535) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid Configuration. ComeBackDelay should be between 0 and 65535\n");
            strncpy(execRetVal->ErrorMsg, "Invalid ComebackDelay 0..65535",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
        
        //ResponseBufferingTime
        validate_param_integer(gas, "RespBufferTime", param);
        gas_info->ResponseBufferingTime = param->valuedouble;
        
        //QueryResponseLengthLimit
        validate_param_integer(gas, "QueryRespLengthLimit", param);
        gas_info->QueryResponseLengthLimit = param->valuedouble;
        if ((gas_info->QueryResponseLengthLimit < 1) || (gas_info->QueryResponseLengthLimit > 127)) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid Configuration. QueryResponseLengthLimit should be between 1 and 127\n");
            strncpy(execRetVal->ErrorMsg, "Invalid QueryRespLengthLimit 1..127",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }

        return RETURN_OK;
}

int validate_wifi_channel(wifi_freq_bands_t wifi_band, UINT *wifi_radio_channel, UINT wifi_channel)
{
    if(wifi_band == WIFI_FREQUENCY_2_4_BAND)
    {
        if((wifi_channel >= MIN_CHANNEL_2G) && (wifi_channel <= MAX_CHANNEL_2G))
        {
            *wifi_radio_channel = wifi_channel;
        }
        else
        {
            platform_trace_error(WIFI_PASSPOINT, "%s 2.4 Ghz wrong wifi channel\n",__FUNCTION__);
            return RETURN_ERR; 
        }
    }
    else if(wifi_band == WIFI_FREQUENCY_5_BAND)
    {
        if((wifi_channel >= MIN_CHANNEL_5G) && (wifi_channel <= MAX_CHANNEL_5G))
        {
            *wifi_radio_channel = wifi_channel;
        }
        else
        {
            platform_trace_error(WIFI_PASSPOINT, "%s 5 Ghz wrong wifi channel\n",__FUNCTION__);
            return RETURN_ERR;
        }
    }
    else if(wifi_band == WIFI_FREQUENCY_5L_BAND)
    {
        if((wifi_channel >= MIN_CHANNEL_5GL) && (wifi_channel <= MAX_CHANNEL_5GL))
        {
            *wifi_radio_channel = wifi_channel;
        }
        else
        {
            platform_trace_error(WIFI_PASSPOINT, "%s 5 Ghz Low wrong wifi channel\n",__FUNCTION__);
            return RETURN_ERR;
        }
    }
    else if(wifi_band == WIFI_FREQUENCY_5H_BAND)
    {
        if((wifi_channel >= MIN_CHANNEL_5GH) && (wifi_channel <= MAX_CHANNEL_5GH))
        {
            *wifi_radio_channel = wifi_channel;
        }
        else
        {
            platform_trace_error(WIFI_PASSPOINT, "%s 5 Ghz High wrong wifi channel\n",__FUNCTION__);
            return RETURN_ERR;
        }
    }
    else if(wifi_band == WIFI_FREQUENCY_6_BAND)
    {
        if((wifi_channel >= MIN_CHANNEL_6G) && (wifi_channel <= MAX_CHANNEL_6G))
        {   
            *wifi_radio_channel = wifi_channel;
        }
        else
        {
            platform_trace_error(WIFI_PASSPOINT, "%s 6 Ghz wrong wifi channel\n",__FUNCTION__);
            return RETURN_ERR;
        }
    }
    else if(wifi_band == WIFI_FREQUENCY_60_BAND)
    {

    }
    else
    {
        platform_trace_error(WIFI_PASSPOINT, "%s wrong supported wifi band\n",__FUNCTION__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int validate_radio_vap(const cJSON *wifi, wifi_radio_operationParam_t *wifi_radio_info, wifi_vap_info_map_t *vap_map,  wifi_radio_feature_param_t *wifi_radio_feat_info, pErr execRetVal)
{
    static const unsigned int channelWidthFirst = WIFI_CHANNELBANDWIDTH_20MHZ;
#ifdef CONFIG_IEEE80211BE
    static const unsigned int channelWidthLast = WIFI_CHANNELBANDWIDTH_320MHZ;
#else
    static const unsigned int channelWidthLast = WIFI_CHANNELBANDWIDTH_80_80MHZ;
#endif /* CONFIG_IEEE80211BE */
    const cJSON  *param;
    char *ptr, *tmp;
    unsigned int num_of_channel = 0;
    int ret;
    int radio_index = 0;
    UINT wifi_radio_channel;
    wifi_countrycode_type_t contry_code;

    if(!wifi || !wifi_radio_info || !execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"WiFi Global entry is NULL\n");
        return RETURN_ERR;
    }

        // FreqBand
        validate_param_integer(wifi, "FreqBand", param);
        wifi_radio_info->band = param->valuedouble;
                if ((wifi_radio_info->band < 0) || (wifi_radio_info->band > 0x20)) {
                wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid wifi radio band configuration, should be between 0 and 0x20\n");
                strncpy(execRetVal->ErrorMsg, "Invalid wifi radio band config 0..0x20",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }
        
        if(convert_freq_band_to_radio_index(wifi_radio_info->band, &radio_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s %d failed for convert_freq_band_to_radio_index for %d\n", __FUNCTION__, __LINE__, wifi_radio_info->band);
            return RETURN_ERR;
        }

        get_wifi_radio_config(radio_index,wifi_radio_info,wifi_radio_feat_info);
 
	// Enabled
	validate_param_bool(wifi, "Enabled", param);
	wifi_radio_info->enable = (param->type & cJSON_True) ? true:false;
	
	
	// AutoChannelEnabled
	validate_param_bool(wifi, "AutoChannelEnabled", param);
	wifi_radio_info->autoChannelEnabled = (param->type & cJSON_True) ? true:false;

	// Channel
	validate_param_integer(wifi, "Channel", param);
	ret = validate_wifi_channel(wifi_radio_info->band, &wifi_radio_channel, param->valuedouble);
		if (ret != RETURN_OK) {
		wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid wifi radio channel configuration\n");
		strncpy(execRetVal->ErrorMsg, "Invalid wifi radio channel config",sizeof(execRetVal->ErrorMsg)-1);
		return RETURN_ERR;
	}
    wifi_radio_info->channel = wifi_radio_channel;
	// NumSecondaryChannels
	validate_param_integer(wifi, "NumSecondaryChannels", param);
	wifi_radio_info->numSecondaryChannels = param->valuedouble;

        if(wifi_radio_info->numSecondaryChannels>0)
        {
            //SecondaryChannelsList
            validate_param_string(wifi, "SecondaryChannelsList",param);
            ptr = param->valuestring;
            tmp = param->valuestring;
            
            while ((ptr = strchr(tmp, ',')) != NULL) {
                    ptr++;
                    wifi_radio_info->channelSecondary[num_of_channel] = atoi(tmp);
                    tmp = ptr;
                    num_of_channel++;
            }
            // Last channel
            wifi_radio_info->channelSecondary[num_of_channel++] = atoi(tmp);
            
            if(num_of_channel != wifi_radio_info->numSecondaryChannels) {
                    wifi_util_dbg_print(WIFI_PASSPOINT,"number of secondary channels and secondary chaneel list not match\n");
                    strncpy(execRetVal->ErrorMsg, "Invalid Secondary channel list",sizeof(execRetVal->ErrorMsg)-1);
                    return RETURN_ERR;
            }
        }

	// ChannelWidth
	validate_param_integer(wifi, "ChannelWidth", param);
	wifi_radio_info->channelWidth = param->valuedouble;

    if ((wifi_radio_info->channelWidth < channelWidthFirst) || (wifi_radio_info->channelWidth > channelWidthLast)) {
		wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid wifi radio channelWidth configuration, should be between 0 and 4\n");
		snprintf(execRetVal->ErrorMsg, sizeof(execRetVal->ErrorMsg), "Invalid wifi radio channelWidth config %d..%d", channelWidthFirst, channelWidthLast);
		return RETURN_ERR;
	}
	
	// HwMode
	validate_param_integer(wifi, "HwMode", param);
        if (validate_wifi_hw_variant(wifi_radio_info->band, param->valuedouble) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid wifi radio hardware mode [%d] configuration\n", param->valuedouble);
            strncpy(execRetVal->ErrorMsg, "Invalid wifi radio hardware mode config",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
	wifi_radio_info->variant = param->valuedouble;
	
	// CsaBeaconCount
	validate_param_integer(wifi, "CsaBeaconCount", param);
	wifi_radio_info->csa_beacon_count = param->valuedouble;

	// Country
	validate_param_string(wifi, "Country", param);
        ret = validate_contry_code(&contry_code, param->valuestring);
	if (ret != RETURN_OK) {
                wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid wifi radio contry code\n");
                strncpy(execRetVal->ErrorMsg, "Invalid wifi radio code",sizeof(execRetVal->ErrorMsg)-1);
                return RETURN_ERR;
        }
    wifi_radio_info->countryCode = contry_code;
	// DcsEnabled
	validate_param_bool(wifi, "DcsEnabled", param);
	wifi_radio_info->DCSEnabled = (param->type & cJSON_True) ? true:false;

        // DtimPeriod
        validate_param_integer(wifi, "DtimPeriod", param);
        wifi_radio_info->dtimPeriod = param->valuedouble;

        // BeaconInterval
        validate_param_integer(wifi, "BeaconInterval", param);
        wifi_radio_info->beaconInterval = param->valuedouble;

        // OperatingClass
        validate_param_integer(wifi, "OperatingClass", param);
        wifi_radio_info->operatingClass = param->valuedouble;

        // BasicDataTransmitRates
        validate_param_integer(wifi, "BasicDataTransmitRates", param);
        wifi_radio_info->basicDataTransmitRates = param->valuedouble;

        // OperationalDataTransmitRates
        validate_param_integer(wifi, "OperationalDataTransmitRates", param);
        wifi_radio_info->operationalDataTransmitRates = param->valuedouble;

        // FragmentationThreshold
        validate_param_integer(wifi, "FragmentationThreshold", param);
        wifi_radio_info->fragmentationThreshold = param->valuedouble;

        // GuardInterval
        validate_param_integer(wifi, "GuardInterval", param);
        wifi_radio_info->guardInterval = param->valuedouble;

        // TransmitPower
        validate_param_integer(wifi, "TransmitPower", param);
        wifi_radio_info->transmitPower = param->valuedouble;

        // RtsThreshold
        validate_param_integer(wifi, "RtsThreshold", param);
        wifi_radio_info->rtsThreshold = param->valuedouble;

        // FactoryResetSsid
        validate_param_bool(wifi, "FactoryResetSsid", param);
        wifi_radio_info->factoryResetSsid = (param->type & cJSON_True) ? true:false;

        // RadioStatsMeasuringRate
        validate_param_integer(wifi, "RadioStatsMeasuringRate", param);
        wifi_radio_info->radioStatsMeasuringRate = param->valuedouble;

        // RadioStatsMeasuringInterval
        validate_param_integer(wifi, "RadioStatsMeasuringInterval", param);
        wifi_radio_info->radioStatsMeasuringInterval = param->valuedouble;

        // CtsProtection
        validate_param_bool(wifi, "CtsProtection", param);
        wifi_radio_info->ctsProtection = (param->type & cJSON_True) ? true:false;

        // ObssCoex
        validate_param_bool(wifi, "ObssCoex", param);
        wifi_radio_info->obssCoex = (param->type & cJSON_True) ? true:false;

        // StbcEnable
        validate_param_bool(wifi, "StbcEnable", param);
        wifi_radio_info->stbcEnable = (param->type & cJSON_True) ? true:false;

        // GreenFieldEnable
        validate_param_bool(wifi, "GreenFieldEnable", param);
        wifi_radio_info->greenFieldEnable = (param->type & cJSON_True) ? true:false;

        // UserControl
        validate_param_integer(wifi, "UserControl", param);
        wifi_radio_info->userControl = param->valuedouble;

        // AdminControl
        validate_param_integer(wifi, "AdminControl", param);
        wifi_radio_info->adminControl = param->valuedouble;

        // ChanUtilThreshold
        validate_param_integer(wifi, "ChanUtilThreshold", param);
        wifi_radio_info->chanUtilThreshold = param->valuedouble;

        // ChanUtilSelfHealEnable
        validate_param_bool(wifi, "ChanUtilSelfHealEnable", param);
        wifi_radio_info->chanUtilSelfHealEnable = (param->type & cJSON_True) ? true:false;

        // EcoPowerDown
        validate_param_bool(wifi, "EcoPowerDown", param);
        wifi_radio_info->EcoPowerDown = (param->type & cJSON_True) ? true:false;

        //Tscan
        validate_param_integer(wifi, "Tscan", param);
        wifi_radio_feat_info->OffChanTscanInMsec = param->valuedouble;

        //Nscan
        validate_param_integer(wifi, "Nscan", param);
        wifi_radio_feat_info->OffChanNscanInSec = (param->valuedouble != 0) ? (24*3600)/(param->valuedouble) : 0;

        //Tidle
        validate_param_integer(wifi, "Tidle", param);
        wifi_radio_feat_info->OffChanTidleInSec = param->valuedouble;

    return RETURN_OK;
}

int validate_wifi_config(const cJSON *wifi, wifi_global_config_t *wifi_info, pErr execRetVal)
{
    const cJSON  *param,*gas_entry;
    int ret;

    if(!wifi || !wifi_info || !execRetVal){
        wifi_util_dbg_print(WIFI_PASSPOINT,"WiFi Global entry is NULL\n");
        return RETURN_ERR;
    }
                
    validate_param_array(wifi, "GASConfig", param);
    cJSON_ArrayForEach(gas_entry, param) {
        ret = validate_gas_config(gas_entry,&wifi_info->gas_config,execRetVal);
        if (ret != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s %d Validation of GAS Configuration Failed\n",__FUNCTION__, __LINE__);
            return RETURN_ERR;
        }
    }

    ret = validate_wifi_global_config(wifi, &wifi_info->global_parameters,execRetVal);
    if(ret != RETURN_OK)
    {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s %d  Validation of wifi global Configuration Failed\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int wifi_validate_config(const cJSON *root_json, wifi_global_config_t *wifi_config, wifi_vap_info_map_t *vap_map, wifi_radio_operationParam_t *radio_vap_map, wifi_radio_feature_param_t *radio_feat_map, char *num_of_radio, wifi_platform_property_t *wifi_prop, pErr execRetVal)
{
    const cJSON *wifi, *radio_vaps, *radio_vap, *param_vap, *param_radio;
    int num_radio;
    const char *err = NULL;
    const cJSON   *vap, *param;
//    unsigned int i = 0;
    unsigned int vap_index = 0;
    uint8_t vap_array_index = 0;
    uint8_t radio_index = 0;

    if (!root_json || !vap_map || !radio_vap_map || !execRetVal) {
        return RETURN_ERR;
    }

    //Parse Wifi Global Config
    wifi = cJSON_GetObjectItem(root_json, "WifiConfig");
    if (wifi == NULL) {
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s %d Getting WifiConfig json objet fail\n",__FUNCTION__, __LINE__);
        strncpy(execRetVal->ErrorMsg,"WifiConfig object get fail",sizeof(execRetVal->ErrorMsg)-1);
	//cJSON_Delete(root_json);
        err = cJSON_GetErrorPtr();
        if (err) {
            platform_trace_error(WIFI_PASSPOINT, "%s: Json delete error %s\n",__FUNCTION__,err);
        }
	return RETURN_ERR;
    }

    if (validate_wifi_config(wifi, wifi_config, execRetVal) != RETURN_OK) {
        //cJSON_Delete(root_json);
        return RETURN_ERR;
    }

     //Parse wifi Radio Config
     radio_vaps = cJSON_GetObjectItem(root_json, "WifiRadioConfig");
     if (radio_vaps == NULL) {
           	platform_trace_error(WIFI_PASSPOINT, "%s: Getting WifiRadioConfig json objet fail\n",__FUNCTION__);
                strncpy(execRetVal->ErrorMsg,"WifiRadioConfig object get fail",sizeof(execRetVal->ErrorMsg)-1);
//                cJSON_Delete(root_json);
                err = cJSON_GetErrorPtr();
                if (err) {
                platform_trace_error(WIFI_PASSPOINT, "%s: Json delete error %s\n",__FUNCTION__,err);
                }
                return RETURN_ERR;
        }

    num_radio = 0;

    //Filling the global cache, Need to be optimized.
    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        get_wifi_radio_config(radio_index, &radio_vap_map[radio_index], &radio_feat_map);
        get_wifi_vap_config(radio_index, &vap_map[radio_index]);
    }

    cJSON_ArrayForEach(radio_vap, radio_vaps) {
        validate_param_integer(radio_vap, "FreqBand", param_radio);
        if(convert_freq_band_to_radio_index(param_radio->valuedouble, &num_radio) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s %d convert_freq_band_to_radio_index failed\n",__FUNCTION__, __LINE__);
            return RETURN_ERR;
        }

        if (validate_radio_vap(radio_vap, &radio_vap_map[num_radio], &vap_map[num_radio], radio_feat_map, execRetVal) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s %d validate_wifi_config Failed\n",__FUNCTION__, __LINE__);
            return RETURN_ERR;
        }
    }
    *num_of_radio = getNumberRadios();
    //Parse VAP Config
    param = cJSON_GetObjectItem(root_json, "WifiVapConfig");
    if (param == NULL) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s %d  Getting WifiVapConfig json objet fail\n",__FUNCTION__, __LINE__);
        strncpy(execRetVal->ErrorMsg,"WifiVapConfig object get fail",sizeof(execRetVal->ErrorMsg)-1);
        err = cJSON_GetErrorPtr();
        if (err) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s %d  JSON Delete Error\n",__FUNCTION__, __LINE__);
        }
        return RETURN_ERR;
    }

    cJSON_ArrayForEach(vap, param) {
        validate_param_string(vap, "VapName",param_vap);

        if(getVAPIndexFromName(param_vap->valuestring, &vap_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s %d getVAPIndexFromName failure for %s\n",__FUNCTION__, __LINE__, param_vap->valuestring);
            return RETURN_ERR;
        }
        get_vap_and_radio_index_from_vap_instance(wifi_prop, vap_index, &radio_index, &vap_array_index);

        if (validate_vap(vap, &vap_map[radio_index].vap_array[vap_array_index], wifi_prop, execRetVal) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"%s %d validate vap failure \n",__FUNCTION__, __LINE__);
            strncpy(execRetVal->ErrorMsg, "validate vap failure",sizeof(execRetVal->ErrorMsg)-1);
            return RETURN_ERR;
        }
    }
    return RETURN_OK;
}
