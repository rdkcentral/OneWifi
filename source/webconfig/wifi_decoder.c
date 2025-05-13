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
#include <cjson/cJSON.h>
#include "wifi_webconfig.h"
#include "ctype.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"

#define TCM_EXPWEIGHT "0.6"
#define TCM_GRADTHRESHOLD "0.18"
//This Macro ONE_WIFI_CHANGES, used to modify the validator changes. Re-check is required where the macro is used
#define ONE_WIFI_CHANGES

#define  ARRAY_SZ(x)    (sizeof(x) / sizeof((x)[0]))
#define decode_param_string(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) || (strcmp(value->valuestring, "") == 0)) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_allow_empty_string(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) ) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_allow_optional_string(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) != true) ||  \
            (value->valuestring == NULL) ) {    \
        value = NULL;\
    }   \
}   \

#define decode_param_integer(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsNumber(value) == false)) {  \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_bool(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsBool(value) == false)) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_allow_empty_bool(json, key, value, connected_building) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsBool(value) == false)) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation has emptyfor key:%s\n", __func__, __LINE__, key);   \
        connected_building = false; \
    }   \
    else { \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation for key:%s\n", __func__, __LINE__, key);   \
        connected_building = true; \
    }  \
}   \

#define decode_param_allow_empty_integer(json, key, value, intval) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsNumber(value) == false)) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation has emptyfor key:%s\n", __func__, __LINE__, key);   \
        intval = false; \
    }   \
    else { \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation for key:%s\n", __func__, __LINE__, key);   \
        intval = true; \
    }  \
}   \

#define decode_param_array(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsArray(value) == false)) {   \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \


#define decode_param_object(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsObject(value) == false)) {  \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_blaster_mqtt_topic(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d\n", __func__, __LINE__);    \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) ) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \


#define decode_param_blaster_mac(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) ) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_blaster_trace_info(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d\n", __func__, __LINE__);    \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) ) {    \
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \


webconfig_error_t decode_cac_object(wifi_vap_info_t *vap_info, cJSON *obj_array );
bool is_valid_channel(unsigned int channel, bool dfs)
{
    if (channel >= 50 && channel <= 144) {
        if (dfs == true) {
            return true;
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid channel=%d  dfc = %d\r\n",__func__, __LINE__, channel, dfs);
        }
    } else {
        return true;
    }

    return false;
}

webconfig_error_t decode_ipv4_address(char *ip) {
    struct sockaddr_in sa;

    if (inet_pton(AF_INET,ip, &(sa.sin_addr)) != 1 ) {
        return webconfig_error_decode;
    }
    return webconfig_error_none;
}

webconfig_error_t decode_ipv6_address(char *ip) {
    struct sockaddr_in6 sa;

    if (inet_pton(AF_INET6,ip, &(sa.sin6_addr)) != 1 ) {
        return webconfig_error_decode;
    }
    return webconfig_error_none;
}

webconfig_error_t decode_anqp_object(const cJSON *anqp, wifi_interworking_t *interworking_info)
{
    cJSON *anqpElement = NULL;
    cJSON *anqpList = NULL;
    cJSON *anqpEntry = NULL;
    cJSON *anqpParam = NULL;
    cJSON *subList = NULL;
    cJSON *subEntry = NULL;
    cJSON *subParam = NULL;
    UCHAR *next_pos = NULL;

    if(!anqp || !interworking_info){
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Anqp entry is NULL\n");
        return webconfig_error_decode;
    }

    //VenueNameANQPElement
    decode_param_object(anqp, "VenueNameANQPElement", anqpElement);

    next_pos = (UCHAR *)&interworking_info->anqp.venueInfo;
    decode_param_array(anqpElement, "VenueInfo", anqpList);
    if(cJSON_GetArraySize(anqpList) > 16){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Venue entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_venue_entries;
    } else if (cJSON_GetArraySize(anqpList)) {
        //Venue List is non-empty. Update capability List
        interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_venue_name;

        //Fill in Venue Group and Type from Interworking Config
        wifi_venueNameElement_t *venueElem = (wifi_venueNameElement_t *)next_pos;
        venueElem->venueGroup = interworking_info->interworking.venueGroup;
        next_pos += sizeof(venueElem->venueGroup);
        venueElem->venueType = interworking_info->interworking.venueType;
        next_pos += sizeof(venueElem->venueType);
    }

    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_venueName_t *venueBuf = (wifi_venueName_t *)next_pos;
        next_pos += sizeof(venueBuf->length); //Will be filled at the end
        decode_param_string(anqpEntry,"Language",anqpParam);
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += strlen(anqpParam->valuestring);
        anqpParam = cJSON_GetObjectItem(anqpEntry,"Name");
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Venue name cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            return webconfig_error_venue_name_size;
        }
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += strlen(anqpParam->valuestring);
        venueBuf->length = next_pos - &venueBuf->language[0];
    }
    interworking_info->anqp.venueInfoLength = next_pos - (UCHAR *)&interworking_info->anqp.venueInfo;

    //RoamingConsortiumANQPElement
    decode_param_object(anqp,"RoamingConsortiumANQPElement", anqpElement);
    next_pos = (UCHAR *)&interworking_info->anqp.roamInfo;

    decode_param_array(anqpElement,"OI",anqpList);
    if(cJSON_GetArraySize(anqpList) > 32){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Only 32 OUI supported in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_oui_entries;
    }
    int ouiCount = 0;
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_ouiDuple_t *ouiBuf = (wifi_ouiDuple_t *)next_pos;
        UCHAR ouiStr[64];
        int i, ouiStrLen = 0;
        memset(ouiStr,0,sizeof(ouiStr));
        anqpParam = cJSON_GetObjectItem(anqpEntry,"OI");
        if(anqpParam){
            ouiStrLen = strlen(anqpParam->valuestring);
            if((ouiStrLen < 6) || (ouiStrLen > 30) || (ouiStrLen % 2)){
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid OUI Length in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
                return webconfig_error_oui_length;
            }
            strcpy((char*)ouiStr, anqpParam->valuestring);
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
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid OUI in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
                return webconfig_error_oui_char;
            }
            if(i%2){
                ouiBuf->oui[(i/2)] = ouiStr[i] | (ouiStr[i-1] << 4);
            }
        }
        ouiBuf->length = i/2;
        next_pos += sizeof(ouiBuf->length);
        next_pos += ouiBuf->length;
        if(ouiCount < 3){
            memcpy(&interworking_info->roamingConsortium.wifiRoamingConsortiumOui[ouiCount][0],&ouiBuf->oui[0],ouiBuf->length);
            interworking_info->roamingConsortium.wifiRoamingConsortiumLen[ouiCount] = ouiBuf->length;
        }
        ouiCount++;
    }
    interworking_info->roamingConsortium.wifiRoamingConsortiumCount = ouiCount;

    if(ouiCount) {
        interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_roaming_consortium;
    }

    interworking_info->anqp.roamInfoLength = next_pos - (UCHAR *)&interworking_info->anqp.roamInfo;

    //IPAddressTypeAvailabilityANQPElement
    decode_param_object(anqp,"IPAddressTypeAvailabilityANQPElement",anqpElement);
    interworking_info->anqp.ipAddressInfo.field_format = 0;

    decode_param_integer(anqpElement,"IPv6AddressType",anqpParam);
    if((0 > anqpParam->valuedouble) || (2 < anqpParam->valuedouble)){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid IPAddressTypeAvailabilityANQPElement. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_ipaddress;
    }
    interworking_info->anqp.ipAddressInfo.field_format = (UCHAR)anqpParam->valuedouble;

    decode_param_integer(anqpElement,"IPv4AddressType",anqpParam);
    if((0 > anqpParam->valuedouble) || (7 < anqpParam->valuedouble)){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid IPAddressTypeAvailabilityANQPElement. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_ipaddress;
    }
    interworking_info->anqp.ipAddressInfo.field_format |= ((UCHAR)anqpParam->valuedouble << 2);
    interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_ip_address_availabality;

    //NAIRealmANQPElement
    decode_param_object(anqp, "NAIRealmANQPElement", anqpElement);

    decode_param_array(anqpElement, "Realm", anqpList);

    wifi_naiRealmElement_t *naiElem = &interworking_info->anqp.realmInfo;
    naiElem->nai_realm_count = cJSON_GetArraySize(anqpList);
    if(naiElem->nai_realm_count > 20) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Only 20 Realm Entries are supported. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_realm_entries;
    }
    next_pos = (UCHAR *)naiElem;
    next_pos += sizeof(naiElem->nai_realm_count);

    if(naiElem->nai_realm_count) {
        interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_nai_realm;
    }

    cJSON_ArrayForEach(anqpEntry, anqpList){
        UCHAR eap_method_count = 0;
        wifi_naiRealm_t *realmInfoBuf = (wifi_naiRealm_t *)next_pos;
        next_pos += sizeof(realmInfoBuf->data_field_length);

        decode_param_integer(anqpEntry,"RealmEncoding",anqpParam);
        realmInfoBuf->encoding = anqpParam->valuedouble;
        next_pos += sizeof(realmInfoBuf->encoding);

        decode_param_string(anqpEntry,"Realms",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Realm Length cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            return webconfig_error_realm_length;
        }
        realmInfoBuf->realm_length = strlen(anqpParam->valuestring);
        next_pos += sizeof(realmInfoBuf->realm_length);
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += realmInfoBuf->realm_length;

/**        cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", anqpParam->valuestring);
        cJSON_AddNumberToObject(realmStats, "EntryType", 1);//1-NAI Realm
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);**/

        decode_param_array(anqpEntry,"EAP",subList);
        eap_method_count = cJSON_GetArraySize(subList);
        if(eap_method_count > 16){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: EAP entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
            return webconfig_error_eap_entries;
        }
        *next_pos = eap_method_count;
        next_pos += sizeof(realmInfoBuf->eap_method_count);

        cJSON_ArrayForEach(subEntry, subList){
            wifi_eapMethod_t *eapBuf = (wifi_eapMethod_t *)next_pos;
            next_pos += sizeof(eapBuf->length);

            decode_param_integer(subEntry,"Method",subParam);
            eapBuf->method = subParam->valuedouble;
            next_pos += sizeof(eapBuf->method);
            cJSON *subList_1  = NULL;
            cJSON *subEntry_1 = NULL;
            cJSON *subParam_1 = NULL;

            decode_param_array(subEntry,"AuthenticationParameter",subList_1);
            eapBuf->auth_param_count = cJSON_GetArraySize(subList_1);
            if(eapBuf->auth_param_count > 16){
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Auth entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
                return webconfig_error_auth_entries;
            }
            next_pos += sizeof(eapBuf->auth_param_count);
            cJSON_ArrayForEach(subEntry_1, subList_1){
                int i,authStrLen;
                UCHAR authStr[14+1];
                wifi_authMethod_t *authBuf = (wifi_authMethod_t *)next_pos;

                decode_param_integer(subEntry_1,"ID",subParam_1);
                authBuf->id = subParam_1->valuedouble;
                next_pos += sizeof(authBuf->id);

                subParam_1 = cJSON_GetObjectItem(subEntry_1,"Value");
                if(!subParam_1){
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Auth Parameter Value not prensent in NAIRealmANQPElement EAP Data. Discarding Configuration\n", __func__, __LINE__);
                    return webconfig_error_auth_param;
                } else if (subParam_1->valuedouble) {
                    authBuf->length = 1;
                    authBuf->val[0] = subParam_1->valuedouble;
                } else {
                    authStrLen = strlen(subParam_1->valuestring);
                    if((authStrLen != 2) && (authStrLen != 14)){
                        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid EAP Value Length in NAIRealmANQPElement Data. Has to be 1 to 7 bytes Long. Discarding Configuration\n", __func__, __LINE__);
                        return webconfig_error_eap_length;
                    }
                    strcpy((char*)authStr,subParam_1->valuestring);

                    //Covert the incoming string to HEX
                    for(i = 0; i < authStrLen; i++){
                        if((authStr[i] >= '0') && (authStr[i] <= '9')){
                            authStr[i] -= '0';
                        }else if((authStr[i] >= 'a') && (authStr[i] <= 'f')){
                            authStr[i] -= ('a' - 10);//a=10
                        }else if((authStr[i] >= 'A') && (authStr[i] <= 'F')){
                            authStr[i] -= ('A' - 10);//A=10
                        }else{
                            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid EAP val in NAIRealmANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
                            return webconfig_error_eap_value;
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
    interworking_info->anqp.realmInfoLength = next_pos - (UCHAR *)&interworking_info->anqp.realmInfo;

    //3GPPCellularANQPElement
    decode_param_object(anqp, "3GPPCellularANQPElement", anqpElement);
    wifi_3gppCellularNetwork_t *gppBuf = &interworking_info->anqp.gppInfo;
    next_pos = (UCHAR *)gppBuf;

    decode_param_integer(anqpElement,"GUD",anqpParam);
    gppBuf->gud = anqpParam->valuedouble;
    next_pos += sizeof(gppBuf->gud);

    next_pos += sizeof(gppBuf->uhdLength);//Skip over UHD length to be filled at the end
    UCHAR *uhd_pos = next_pos;//Beginning of UHD data

    wifi_3gpp_plmn_list_information_element_t *plmnInfoBuf = (wifi_3gpp_plmn_list_information_element_t *)next_pos;
    plmnInfoBuf->iei = 0;
    next_pos += sizeof(plmnInfoBuf->iei);
    next_pos += sizeof(plmnInfoBuf->plmn_length);//skip through the length field that will be filled at the end
    UCHAR *plmn_pos = next_pos;//beginnig of PLMN data

    decode_param_array(anqpElement,"PLMN",anqpList);
    plmnInfoBuf->number_of_plmns = cJSON_GetArraySize(anqpList);
    next_pos += sizeof(plmnInfoBuf->number_of_plmns);
    if(plmnInfoBuf->number_of_plmns > 16){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: 3GPP entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Exceeded max number of 3GPP entries",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
     }

    cJSON_ArrayForEach(anqpEntry, anqpList){
        UCHAR mccStr[3+1];
        UCHAR mncStr[3+1];
        memset(mccStr,0,sizeof(mccStr));
        memset(mncStr,0,sizeof(mncStr));

        decode_param_string(anqpEntry,"MCC",anqpParam);
        if(strlen(anqpParam->valuestring) == (sizeof(mccStr) -1)){
            strcpy((char*)mccStr,anqpParam->valuestring);
        }else if(strlen(anqpParam->valuestring) == (sizeof(mccStr) -2)){
            mccStr[0] = '0';
            strcpy((char*)&mccStr[1], anqpParam->valuestring);
        }else{
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid MCC in 3GPPCellularANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid MCC in 3GPP Element",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }

        decode_param_string(anqpEntry,"MNC",anqpParam);
        if(strlen(anqpParam->valuestring) == (sizeof(mccStr) -1)){
            strcpy((char*)mncStr, anqpParam->valuestring);
        }else if(strlen(anqpParam->valuestring) ==  (sizeof(mccStr) -2)){
            mncStr[0] = '0';
            strcpy((char*)&mncStr[1], anqpParam->valuestring);
        }else{
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid MNC in 3GPPCellularANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid MNC in 3GPP Element",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
        wifi_plmn_t *plmnBuf = (wifi_plmn_t *)next_pos;
        plmnBuf->PLMN[0] = (UCHAR)((mccStr[0] - '0') | ((mccStr[1] - '0') << 4));
        plmnBuf->PLMN[1] = (UCHAR)((mccStr[2] - '0') | ((mncStr[2] - '0') << 4));
        plmnBuf->PLMN[2] = (UCHAR)((mncStr[0] - '0') | ((mncStr[1] - '0') << 4));
        next_pos += sizeof(wifi_plmn_t);

        /*char  nameStr[8];
        snprintf(nameStr, sizeof(nameStr), "%s:%s", mccStr, mncStr);
        cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", nameStr);
        cJSON_AddNumberToObject(realmStats, "EntryType", 3);//3-3GPP
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);*/
    }
    gppBuf->uhdLength = next_pos - uhd_pos;
    plmnInfoBuf->plmn_length = next_pos - plmn_pos;
    interworking_info->anqp.gppInfoLength = next_pos - (UCHAR *)&interworking_info->anqp.gppInfo;
    interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_3gpp_cellular_network;

    //DomainANQPElement
    decode_param_object(anqp, "DomainANQPElement", anqpElement);
    decode_param_array(anqpElement, "DomainName", anqpList);

    if(cJSON_GetArraySize(anqpList) > 4){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Only 4 Entries supported in DomainNameANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Exceeded max no of entries in DomainNameANQPElement Data",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    next_pos = (UCHAR *)&interworking_info->anqp.domainNameInfo;

    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_domainNameTuple_t *nameBuf = (wifi_domainNameTuple_t *)next_pos;
        decode_param_string(anqpEntry,"Name",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Domain name length cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Domain name length",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
        nameBuf->length = strlen(anqpParam->valuestring);
        next_pos += sizeof(nameBuf->length);
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += nameBuf->length;

        /*cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", anqpParam->valuestring);
        cJSON_AddNumberToObject(realmStats, "EntryType", 2);//2-Domain
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);*/
    }

    interworking_info->anqp.domainInfoLength = next_pos - (UCHAR *)&interworking_info->anqp.domainNameInfo;
    if (interworking_info->anqp.domainInfoLength) {
        interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_domain_name;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_passpoint_object(const cJSON *passpoint, wifi_interworking_t *interworking_info)
{
    cJSON *mainEntry = NULL;
    cJSON *anqpElement = NULL;
    cJSON *anqpList = NULL;
    cJSON *anqpEntry = NULL;
    cJSON *anqpParam = NULL;
    UCHAR *next_pos = NULL;

    if(!passpoint || !interworking_info){
        wifi_util_error_print(WIFI_WEBCONFIG,"Passpoint entry is NULL\n");
        return webconfig_error_decode;
    }
    mainEntry = (cJSON *)passpoint;

    decode_param_bool(mainEntry, "PasspointEnable", anqpParam);
    interworking_info->passpoint.enable = (anqpParam->type & cJSON_True) ? true:false;

    if((interworking_info->passpoint.enable == true) && (interworking_info->interworking.interworkingEnabled == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Passpoint cannot be enable when Interworking is disabled\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Cannot Enable Passpoint. Interworking Disabled",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    decode_param_bool(mainEntry, "GroupAddressedForwardingDisable", anqpParam);
    interworking_info->passpoint.gafDisable = (anqpParam->type & cJSON_True) ? true:false;

    decode_param_bool(mainEntry, "P2pCrossConnectionDisable", anqpParam);
    interworking_info->passpoint.p2pDisable = (anqpParam->type & cJSON_True) ? true:false;

    if((interworking_info->interworking.accessNetworkType == 2) || (interworking_info->interworking.accessNetworkType == 3)) {
        interworking_info->passpoint.l2tif = true;
    }

    if(interworking_info->passpoint.enable) {
        interworking_info->passpoint.bssLoad = true;
        interworking_info->passpoint.countryIE = true;
        interworking_info->passpoint.proxyArp = true;
    }

    //HS2CapabilityListANQPElement
    interworking_info->passpoint.capabilityInfoLength = 0;
    interworking_info->passpoint.capabilityInfo.capabilityList[interworking_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_hs_query_list;
    interworking_info->passpoint.capabilityInfo.capabilityList[interworking_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_hs_capability_list;

    //OperatorFriendlyNameANQPElement
    decode_param_object(mainEntry,"OperatorFriendlyNameANQPElement",anqpElement);
    decode_param_array(anqpElement,"Name",anqpList);

    if(cJSON_GetArraySize(anqpList) > 16){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: OperatorFriendlyName cannot have more than 16 entiries. Discarding Configuration\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid no of entries in OperatorFriendlyName",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    next_pos = (UCHAR *)&interworking_info->passpoint.opFriendlyNameInfo;
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_HS2_OperatorNameDuple_t *opNameBuf = (wifi_HS2_OperatorNameDuple_t *)next_pos;
        next_pos += sizeof(opNameBuf->length);//Fill length after reading the remaining fields

        decode_param_string(anqpEntry,"LanguageCode",anqpParam);
        if(strlen(anqpParam->valuestring) > 3){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid Language Code. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Language Code",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += sizeof(opNameBuf->languageCode);

        decode_param_string(anqpEntry,"OperatorName",anqpParam);
        if(strlen(anqpParam->valuestring) > 252){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid OperatorFriendlyName. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid OperatorFriendlyName",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += strlen(anqpParam->valuestring);
        opNameBuf->length = strlen(anqpParam->valuestring) +  sizeof(opNameBuf->languageCode);
    }
    interworking_info->passpoint.opFriendlyNameInfoLength = next_pos - (UCHAR *)&interworking_info->passpoint.opFriendlyNameInfo;
    if(interworking_info->passpoint.opFriendlyNameInfoLength) {
        interworking_info->passpoint.capabilityInfo.capabilityList[interworking_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_operator_friendly_name;
    }

    //ConnectionCapabilityListANQPElement
    decode_param_object(mainEntry,"ConnectionCapabilityListANQPElement",anqpElement);
    decode_param_array(anqpElement,"ProtoPort",anqpList);
    if(cJSON_GetArraySize(anqpList) > 16){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Connection Capability count cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Exceeded max count of Connection Capability", sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    next_pos = (UCHAR *)&interworking_info->passpoint.connCapabilityInfo;
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_HS2_Proto_Port_Tuple_t *connCapBuf = (wifi_HS2_Proto_Port_Tuple_t *)next_pos;
        decode_param_integer(anqpEntry,"IPProtocol",anqpParam);
        connCapBuf->ipProtocol = anqpParam->valuedouble;
        next_pos += sizeof(connCapBuf->ipProtocol);
        decode_param_integer(anqpEntry,"PortNumber",anqpParam);
        connCapBuf->portNumber = anqpParam->valuedouble;
        next_pos += sizeof(connCapBuf->portNumber);
        decode_param_integer(anqpEntry,"Status",anqpParam);
        connCapBuf->status = anqpParam->valuedouble;
        next_pos += sizeof(connCapBuf->status);
    }
    interworking_info->passpoint.connCapabilityLength = next_pos - (UCHAR *)&interworking_info->passpoint.connCapabilityInfo;
    if(interworking_info->passpoint.connCapabilityLength) {
        interworking_info->passpoint.capabilityInfo.capabilityList[interworking_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_conn_capability;
    }

    //NAIHomeRealmANQPElement
    decode_param_object(mainEntry,"NAIHomeRealmANQPElement",anqpElement);
    decode_param_array(anqpElement,"Realms",anqpList);
    if(cJSON_GetArraySize(anqpList) > 20){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NAI Realm count cannot be more than 20. Discarding Configuration\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Exceeded max count of NAI Realm",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    next_pos = (UCHAR *)&interworking_info->passpoint.realmInfo;
    wifi_HS2_NAI_Home_Realm_Query_t *naiElem = (wifi_HS2_NAI_Home_Realm_Query_t *)next_pos;
    naiElem->realmCount = cJSON_GetArraySize(anqpList);
    next_pos += sizeof(naiElem->realmCount);
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_HS2_NAI_Home_Realm_Data_t *realmInfoBuf = (wifi_HS2_NAI_Home_Realm_Data_t *)next_pos;
        decode_param_integer(anqpEntry,"Encoding",anqpParam);
        realmInfoBuf->encoding = anqpParam->valuedouble;
        next_pos += sizeof(realmInfoBuf->encoding);
        decode_param_string(anqpEntry,"Name",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid NAI Home Realm Name. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid NAI Home Realm Name", sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
        realmInfoBuf->length = strlen(anqpParam->valuestring);
        next_pos += sizeof(realmInfoBuf->length);
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += realmInfoBuf->length;
    }
    interworking_info->passpoint.realmInfoLength = next_pos - (UCHAR *)&interworking_info->passpoint.realmInfo;
    if(interworking_info->passpoint.realmInfoLength) {
        interworking_info->passpoint.capabilityInfo.capabilityList[interworking_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_nai_home_realm_query;
    }

    //WANMetricsANQPElement
    //wifi_getHS2WanMetrics(&g_hs2_data[apIns].wanMetricsInfo);
    interworking_info->passpoint.wanMetricsInfo.wanInfo = 0b00000001;
    interworking_info->passpoint.wanMetricsInfo.downLinkSpeed = 25000;
    interworking_info->passpoint.wanMetricsInfo.upLinkSpeed = 5000;
    interworking_info->passpoint.wanMetricsInfo.downLinkLoad = 0;
    interworking_info->passpoint.wanMetricsInfo.upLinkLoad = 0;
    interworking_info->passpoint.wanMetricsInfo.lmd = 0;
    interworking_info->passpoint.capabilityInfo.capabilityList[interworking_info->passpoint.capabilityInfoLength++] = wifi_anqp_element_hs_subtype_wan_metrics;

    return webconfig_error_none;
}

webconfig_error_t decode_interworking_common_object(const cJSON *interworking, wifi_interworking_t *interworking_info)
{
    const cJSON *param, *venue;
    bool invalid_venue_group_type = false;

    decode_param_bool(interworking, "InterworkingEnable", param);
    interworking_info->interworking.interworkingEnabled = (param->type & cJSON_True) ? true:false;
/*
    if((interworking_info->interworking.interworkingEnabled)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Interworking cannot be enable when RFC is disabled\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "InterworkingEnable: Cannot Enable Interworking. RFC Disabled",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
*/

    decode_param_integer(interworking, "AccessNetworkType", param);
    interworking_info->interworking.accessNetworkType = param->valuedouble;
    if (interworking_info->interworking.accessNetworkType > 5) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for AccessNetworkType\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Access Network type",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    decode_param_bool(interworking, "Internet", param);
    interworking_info->interworking.internetAvailable = (param->type & cJSON_True) ? true:false;

    decode_param_bool(interworking, "ASRA", param);
    interworking_info->interworking.asra = (param->type & cJSON_True) ? true:false;

    decode_param_bool(interworking, "ESR", param);
    interworking_info->interworking.esr = (param->type & cJSON_True) ? true:false;

    decode_param_bool(interworking, "UESA", param);
    interworking_info->interworking.uesa = (param->type & cJSON_True) ? true:false;

    decode_param_bool(interworking, "HESSOptionPresent", param);
    interworking_info->interworking.hessOptionPresent = (param->type & cJSON_True) ? true:false;

    decode_param_string(interworking, "HESSID", param);
    strcpy(interworking_info->interworking.hessid, param->valuestring);
    if (WiFi_IsValidMacAddr(interworking_info->interworking.hessid) != TRUE) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for HESSID\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid HESSID",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    decode_param_object(interworking, "Venue", venue);

    decode_param_bool(venue, "VenueOptionPresent", param);
    interworking_info->interworking.venueOptionPresent = (param->type & cJSON_True) ? true : false;

    decode_param_integer(venue, "VenueType", param);
    interworking_info->interworking.venueType = param->valuedouble;
    if (interworking_info->interworking.venueType > 15) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for VenueGroup\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Venue Group",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    decode_param_integer(venue, "VenueGroup", param);
    interworking_info->interworking.venueGroup = param->valuedouble;
    if (interworking_info->interworking.venueGroup > 11) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for VenueGroup\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Venue Group",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    switch (interworking_info->interworking.venueGroup) {
        case 0:
            if (interworking_info->interworking.venueType > 0) {
                invalid_venue_group_type = true;
            }
            break;

        case 1:
            if (interworking_info->interworking.venueType > 15) {
                invalid_venue_group_type = true;
            }
            break;

        case 2:
            if (interworking_info->interworking.venueType > 9) {
                invalid_venue_group_type = true;
            }
            break;

        case 3:
            if (interworking_info->interworking.venueType > 3) {
                invalid_venue_group_type = true;
            }
            break;

        case 4:
            if (interworking_info->interworking.venueType > 1) {
                invalid_venue_group_type = true;
            }
            break;

        case 5:
            if (interworking_info->interworking.venueType > 5) {
                invalid_venue_group_type = true;
            }
            break;

        case 6:
            if (interworking_info->interworking.venueType > 5) {
                invalid_venue_group_type = true;
            }
            break;

        case 7:
            if (interworking_info->interworking.venueType > 4) {
                invalid_venue_group_type = true;
            }
            break;

        case 8:
            if (interworking_info->interworking.venueType > 0) {
                invalid_venue_group_type = true;
            }
            break;

        case 9:
            if (interworking_info->interworking.venueType > 0) {
                invalid_venue_group_type = true;
            }
            break;

        case 10:
            if (interworking_info->interworking.venueType > 7) {
                invalid_venue_group_type = true;
            }
            break;

        case 11:
            if (interworking_info->interworking.venueType > 6) {
                invalid_venue_group_type = true;
            }
            break;
    }

    if (invalid_venue_group_type == true) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid venue group and type, encode failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_interworking_object(const cJSON *interworking, wifi_interworking_t *interworking_info)
{
    const cJSON *passpoint, *anqp;

    if (decode_interworking_common_object(interworking, interworking_info) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }


    if(cJSON_HasObjectItem(interworking, "ANQP") == true) {
        decode_param_object(interworking, "ANQP", anqp);

/*
        if (decode_anqp_object(anqp, interworking_info) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        } else {

            cJSON *anqpString = cJSON_CreateObject();
            cJSON_AddItemReferenceToObject(anqpString, "ANQP", (cJSON *)anqp);
            cJSON_PrintPreallocated(anqpString, (char *)&interworking_info->anqp.anqpParameters, sizeof(interworking_info->anqp.anqpParameters),false);
            cJSON_Delete(anqpString);
        }
*/
        if (decode_anqp_object(anqp, interworking_info) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
            //Not returning error since anqp is optional configuration
        }
        cJSON *anqpString = cJSON_CreateObject();
        cJSON_AddItemReferenceToObject(anqpString, "ANQP", (cJSON *)anqp);
        cJSON_PrintPreallocated(anqpString, (char *)&interworking_info->anqp.anqpParameters, sizeof(interworking_info->anqp.anqpParameters),false);
        cJSON_Delete(anqpString);
    }

    if(cJSON_HasObjectItem(interworking, "Passpoint") == true) {
        decode_param_object(interworking, "Passpoint", passpoint);

/*
        if (decode_passpoint_object(passpoint, interworking_info) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        } else {
 
            cJSON *hs2String = cJSON_CreateObject();
            cJSON_AddItemReferenceToObject(hs2String, "Passpoint", (cJSON *)passpoint);
            cJSON_PrintPreallocated(hs2String, (char *)&interworking_info->passpoint.hs2Parameters, sizeof(interworking_info->passpoint.hs2Parameters),false);
            cJSON_Delete(hs2String);
        }
*/
        if (decode_passpoint_object(passpoint, interworking_info) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
            // Not returning error since Passpoint is optional configuration
        }
        cJSON *hs2String = cJSON_CreateObject();
        cJSON_AddItemReferenceToObject(hs2String, "Passpoint", (cJSON *)passpoint);
        cJSON_PrintPreallocated(hs2String, (char *)&interworking_info->passpoint.hs2Parameters, sizeof(interworking_info->passpoint.hs2Parameters),false);
        cJSON_Delete(hs2String);
    }

    return webconfig_error_none;
}


webconfig_error_t decode_radius_object(const cJSON *radius, wifi_radius_settings_t *radius_info)
{
    const cJSON *param;

    decode_param_allow_empty_string(radius, "RadiusServerIPAddr", param);
    if (strlen(param->valuestring) == 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: RadiusServerIPAddr is NULL\n", __func__, __LINE__);
            strcpy(param->valuestring,"0.0.0.0");
    }
    if (decode_ipv4_address(param->valuestring) == webconfig_error_none || decode_ipv6_address(param->valuestring) == webconfig_error_none) {
#ifndef WIFI_HAL_VERSION_3_PHASE2
        strncpy((char *)radius_info->ip,param->valuestring,sizeof(radius_info->ip)-1);
    }
    else {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for RadiusServerIPAddr\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
#else
    /* check the INET family and update the radius ip address */
    if(inet_pton(AF_INET, param->valuestring, &(radius_info->ip.u.IPv4addr)) > 0) {
       radius_info->ip.family = wifi_ip_family_ipv4;
    } else if(inet_pton(AF_INET6, param->valuestring, &(radius_info->ip.u.IPv6addr)) > 0) {
       radius_info->ip.family = wifi_ip_family_ipv6;
    } else {
       return webconfig_error_decode;
    }
#endif
    decode_param_integer(radius, "RadiusServerPort", param);
    radius_info->port = param->valuedouble;

    decode_param_string(radius, "RadiusSecret", param);
    strcpy(radius_info->key, param->valuestring);

    decode_param_allow_empty_string(radius, "SecondaryRadiusServerIPAddr", param);
    if (strlen(param->valuestring) == 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: SecondaryRadiusServerIPAddr is NULL\n", __func__, __LINE__);
            strcpy(param->valuestring,"0.0.0.0");
    }
    if (decode_ipv4_address(param->valuestring) == webconfig_error_none || decode_ipv6_address(param->valuestring) == webconfig_error_none) {
#ifndef WIFI_HAL_VERSION_3_PHASE2
        strncpy((char *)radius_info->s_ip,param->valuestring,sizeof(radius_info->s_ip)-1);
    }
    else {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for SecondaryRadiusServerIPAddr\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Secondary Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
#else
    /* check the INET family and update the radius ip address */
    if (inet_pton(AF_INET, param->valuestring, &(radius_info->s_ip.u.IPv4addr)) > 0) {
        radius_info->s_ip.family = wifi_ip_family_ipv4;
    } else if(inet_pton(AF_INET6, param->valuestring, &(radius_info->s_ip.u.IPv6addr)) > 0) {
        radius_info->s_ip.family = wifi_ip_family_ipv6;
    } else {
        return webconfig_error_decode;
    }
#endif

    decode_param_integer(radius, "SecondaryRadiusServerPort", param);
    radius_info->s_port = param->valuedouble;
    decode_param_string(radius, "SecondaryRadiusSecret", param);
    strcpy(radius_info->s_key, param->valuestring);

    decode_param_allow_empty_string(radius, "DasServerIPAddr", param);
    if (strlen(param->valuestring) == 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: DasServerIPAddr is NULL\n", __func__, __LINE__);
            strcpy(param->valuestring,"0.0.0.0");
    }
    if (inet_pton(AF_INET, param->valuestring, &(radius_info->dasip.u.IPv4addr)) > 0) {
        radius_info->dasip.family = wifi_ip_family_ipv4;
    } else if (inet_pton(AF_INET6, param->valuestring, &(radius_info->dasip.u.IPv6addr)) > 0) {
        radius_info->dasip.family = wifi_ip_family_ipv6;
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for DasServerIPAddr\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Das Server IP Addr",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    decode_param_integer(radius, "DasServerPort", param);
    radius_info->dasport = param->valuedouble;

    decode_param_string(radius, "DasSecret", param);
    strcpy(radius_info->daskey, param->valuestring);

    //max_auth_attempts
    decode_param_integer(radius, "MaxAuthAttempts", param);
    radius_info->max_auth_attempts = param->valuedouble;

    //blacklist_table_timeout
    decode_param_integer(radius, "BlacklistTableTimeout", param);
    radius_info->blacklist_table_timeout = param->valuedouble;

    //identity_req_retry_interval
    decode_param_integer(radius, "IdentityReqRetryInterval", param);
    radius_info->identity_req_retry_interval = param->valuedouble;

    //server_retries
    decode_param_integer(radius, "ServerRetries", param);
    radius_info->server_retries = param->valuedouble;

    return webconfig_error_none;
}


webconfig_error_t decode_open_radius_object(const cJSON *radius, wifi_radius_settings_t *radius_info)
{
    const cJSON *param;
    cJSON *object = NULL;
    char temp_ip[46] = {0};

    object = cJSON_GetObjectItem(radius, "RadiusServerIPAddr");

    if (object != NULL) {
        decode_param_allow_empty_string(radius, "RadiusServerIPAddr", param);
        if(strlen(param->valuestring) == 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: open_radius_object RadiusServerIPAddr is NULL \n", __func__, __LINE__);
            strcpy(temp_ip,"0.0.0.0");
        } else {
            strcpy(temp_ip,param->valuestring);
        }
        if (decode_ipv4_address(temp_ip) == webconfig_error_none || decode_ipv6_address(temp_ip) == webconfig_error_none) {
#ifndef WIFI_HAL_VERSION_3_PHASE2
            strncpy((char *)radius_info->ip,temp_ip,sizeof(radius_info->ip)-1);    
        }
        else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for RadiusServerIPAddr\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
#else
        /* check the INET family and update the radius ip address */
        if(inet_pton(AF_INET, temp_ip, &(radius_info->ip.u.IPv4addr)) > 0) {
            radius_info->ip.family = wifi_ip_family_ipv4;
        } else if(inet_pton(AF_INET6, temp_ip, &(radius_info->ip.u.IPv6addr)) > 0) {
            radius_info->ip.family = wifi_ip_family_ipv6;
        } else {
            return webconfig_error_decode;
        }
#endif
        memset(temp_ip, 0, sizeof(temp_ip));
    }

    object = cJSON_GetObjectItem(radius, "RadiusServerPort");

    if (object != NULL) {
        decode_param_integer(radius, "RadiusServerPort", param);
        radius_info->port = param->valuedouble;
    }

    object = cJSON_GetObjectItem(radius, "RadiusSecret");

    if (object != NULL) {
        decode_param_allow_empty_string(radius, "RadiusSecret", param);
        strcpy(radius_info->key, param->valuestring);
    }
    object = cJSON_GetObjectItem(radius, "SecondaryRadiusServerIPAddr");

    if (object != NULL) {
        decode_param_allow_empty_string(radius, "SecondaryRadiusServerIPAddr", param);
        if (strlen(param->valuestring) == 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: In open_radius SecondaryRadiusServerIPAddr is NULL\n", __func__, __LINE__);
            strcpy(temp_ip,"0.0.0.0");
        } else {
            strcpy(temp_ip,param->valuestring);
        }
        if (decode_ipv4_address(temp_ip) == webconfig_error_none || decode_ipv6_address(temp_ip) == webconfig_error_none) {
#ifndef WIFI_HAL_VERSION_3_PHASE2
            strncpy((char *)radius_info->s_ip,temp_ip,sizeof(radius_info->s_ip)-1);
        }
        else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for SecondaryRadiusServerIPAddr\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Secondary Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
#else
        /* check the INET family and update the radius ip address */
        if (inet_pton(AF_INET, temp_ip, &(radius_info->s_ip.u.IPv4addr)) > 0) {
            radius_info->s_ip.family = wifi_ip_family_ipv4;
        } else if(inet_pton(AF_INET6, temp_ip, &(radius_info->s_ip.u.IPv6addr)) > 0) {
            radius_info->s_ip.family = wifi_ip_family_ipv6;
        } else {
            return webconfig_error_decode;
        }
#endif
        memset(temp_ip, 0, sizeof(temp_ip));
    }

    object = cJSON_GetObjectItem(radius, "SecondaryRadiusServerPort");

    if (object != NULL) {
        decode_param_integer(radius, "SecondaryRadiusServerPort", param);
        radius_info->s_port = param->valuedouble;
    }

    object = cJSON_GetObjectItem(radius, "SecondaryRadiusSecret");

    if (object != NULL) {
        decode_param_allow_empty_string(radius, "SecondaryRadiusSecret", param);
        strcpy(radius_info->s_key, param->valuestring);
    }

    object = cJSON_GetObjectItem(radius, "DasServerIPAddr");

    if (object != NULL) {
        decode_param_allow_empty_string(radius, "DasServerIPAddr", param);
        if (strlen(param->valuestring) == 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: In open_radius DasServerIPAddr is NULL\n", __func__, __LINE__);
            strcpy(temp_ip,"0.0.0.0");
        } else {
            strcpy(temp_ip,param->valuestring);
        }
        if (inet_pton(AF_INET, temp_ip, &(radius_info->dasip.u.IPv4addr)) > 0) {
            radius_info->dasip.family = wifi_ip_family_ipv4;
        } else if (inet_pton(AF_INET6, temp_ip, &(radius_info->dasip.u.IPv6addr)) > 0) {
            radius_info->dasip.family = wifi_ip_family_ipv6;
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for DasServerIPAddr\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        memset(temp_ip, 0, sizeof(temp_ip));
    }

    object = cJSON_GetObjectItem(radius, "DasServerPort");

    if (object != NULL) {
        decode_param_integer(radius, "DasServerPort", param);
        radius_info->dasport = param->valuedouble;
    }

    object = cJSON_GetObjectItem(radius, "DasSecret");

    if (object != NULL) {
        decode_param_allow_empty_string(radius, "DasSecret", param);
        strcpy(radius_info->daskey, param->valuestring);
    }

    object = cJSON_GetObjectItem(radius, "MaxAuthAttempts");
    if (object != NULL) {
        //max_auth_attempts
        decode_param_integer(radius, "MaxAuthAttempts", param);
        radius_info->max_auth_attempts = param->valuedouble;
    }

    //blacklist_table_timeout
    object = cJSON_GetObjectItem(radius, "BlacklistTableTimeout");

    if (object != NULL) {
        decode_param_integer(radius, "BlacklistTableTimeout", param);
        radius_info->blacklist_table_timeout = param->valuedouble;
    }
    //identity_req_retry_interval
    object = cJSON_GetObjectItem(radius, "IdentityReqRetryInterval");

    if (object != NULL) {
        decode_param_integer(radius, "IdentityReqRetryInterval", param);
        radius_info->identity_req_retry_interval = param->valuedouble;
    }

    //server_retries
    object = cJSON_GetObjectItem(radius, "ServerRetries");

    if (object != NULL) {
        decode_param_integer(radius, "ServerRetries", param);
        radius_info->server_retries = param->valuedouble;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_security_object(const cJSON *security, wifi_vap_security_t *security_info,
    int band)
{
    const cJSON *param, *object;

    decode_param_string(security, "Mode", param);

    if (strcmp(param->valuestring, "None") == 0) {
        security_info->mode = wifi_security_mode_none;
    } else if (strcmp(param->valuestring, "Enhanced-Open") == 0) {
        security_info->mode = wifi_security_mode_enhanced_open;
    } else if (strcmp(param->valuestring, "WPA-Personal") == 0) {
        security_info->mode = wifi_security_mode_wpa_personal;
    } else if (strcmp(param->valuestring, "WPA2-Personal") == 0) {
        security_info->mode = wifi_security_mode_wpa2_personal;
    } else if (strcmp(param->valuestring, "WPA-WPA2-Personal") == 0) {
        security_info->mode = wifi_security_mode_wpa_wpa2_personal;
    } else if (strcmp(param->valuestring, "WPA3-Personal") == 0) {
        security_info->mode = wifi_security_mode_wpa3_personal;
        security_info->u.key.type = wifi_security_key_type_sae;
    } else if (strcmp(param->valuestring, "WPA3-Personal-Transition") == 0) {
        security_info->mode = wifi_security_mode_wpa3_transition;
        security_info->u.key.type = wifi_security_key_type_psk_sae;
    } else if (strcmp(param->valuestring, "WPA-Enterprise") == 0) {
        security_info->mode = wifi_security_mode_wpa_enterprise;
    } else if (strcmp(param->valuestring, "WPA2-Enterprise") == 0) {
        security_info->mode = wifi_security_mode_wpa2_enterprise;
    } else if (strcmp(param->valuestring, "WPA-WPA2-Enterprise") == 0) {
        security_info->mode = wifi_security_mode_wpa_wpa2_enterprise;
    } else if (strcmp(param->valuestring, "WPA3-Enterprise") == 0) {
        security_info->mode = wifi_security_mode_wpa3_enterprise;
    } else if (strcmp(param->valuestring, "WPA3-Personal-Compatibility") == 0) {
        security_info->mode = wifi_security_mode_wpa3_compatibility;
        security_info->u.key.type = wifi_security_key_type_psk_sae;    
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to decode security mode: %s\n",
            __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }

    if (band == WIFI_FREQUENCY_6_BAND &&
        security_info->mode != wifi_security_mode_wpa3_personal &&
        security_info->mode != wifi_security_mode_wpa3_compatibility &&
        security_info->mode != wifi_security_mode_wpa3_enterprise &&
        security_info->mode != wifi_security_mode_enhanced_open) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid security mode for 6G interface: %d\n",
            __func__, __LINE__, security_info->mode);
        return webconfig_error_decode;
    }

    if (security_info->mode == wifi_security_mode_none ||
        security_info->mode == wifi_security_mode_enhanced_open) {
        object = cJSON_GetObjectItem(security, "RadiusSettings");
        if (object != NULL) {
            decode_param_object(security, "RadiusSettings", param);
            if (decode_open_radius_object(param, &security_info->u.radius) != 0) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to decode radius settings\n",
                    __func__, __LINE__);
                return webconfig_error_decode;
            }
        }
    }

    if (security_info->mode == wifi_security_mode_none) {
        return webconfig_error_none;
    }

    decode_param_string(security, "MFPConfig", param);

    if (strstr(param->valuestring, "Disabled")) {
        security_info->mfp = wifi_mfp_cfg_disabled;
    } else if (strstr(param->valuestring, "Required")) {
        security_info->mfp = wifi_mfp_cfg_required;
    } else if (strstr(param->valuestring, "Optional")) {
        security_info->mfp = wifi_mfp_cfg_optional;
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to decode MFP value: %s",
            __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }

    if (security_info->mfp != wifi_mfp_cfg_optional &&
        security_info->mode == wifi_security_mode_wpa3_transition) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid MFP value %d for %d mode\n", __func__,
            __LINE__, security_info->mfp, security_info->mode);
        return webconfig_error_encode;
    }

#ifndef CONFIG_IEEE80211BE
    if (security_info->mfp != wifi_mfp_cfg_required &&
        (security_info->mode == wifi_security_mode_enhanced_open ||
        security_info->mode == wifi_security_mode_wpa3_enterprise ||
        security_info->mode == wifi_security_mode_wpa3_personal)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid MFP value for %d mode: %d\n",
            __func__, __LINE__, security_info->mfp, security_info->mode);
        return webconfig_error_decode;
    }
#endif // CONFIG_IEEE80211BE

    if(security_info->mode == wifi_security_mode_wpa3_compatibility &&
       security_info->mfp != wifi_mfp_cfg_disabled) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Invalid MFP Config %d for %d mode \n",
            __func__, __LINE__, security_info->mfp, security_info->mode);
        return webconfig_error_decode;
    }

    decode_param_string(security, "EncryptionMethod", param);

    if (strcmp(param->valuestring, "TKIP") == 0) {
        security_info->encr = wifi_encryption_tkip;
    } else if(strcmp(param->valuestring, "AES") == 0) {
        security_info->encr = wifi_encryption_aes;
    } else if(strcmp(param->valuestring, "AES+TKIP") == 0) {
        security_info->encr = wifi_encryption_aes_tkip;
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to decode encryption method: %s\n",
            __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }

    if (security_info->encr != wifi_encryption_aes &&
        (security_info->mode == wifi_security_mode_enhanced_open ||
        security_info->mode == wifi_security_mode_wpa3_enterprise ||
        security_info->mode == wifi_security_mode_wpa3_personal)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid encryption method for %d mode: %d\n",
            __func__, __LINE__, security_info->encr, security_info->mode);
        return webconfig_error_decode;
    }

    if (security_info->encr == wifi_encryption_tkip &&
        security_info->mode == wifi_security_mode_wpa_wpa2_personal) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid encryption method TKIP with "
            "WPA/WPA2 mode\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (security_info->mode == wifi_security_mode_enhanced_open) {
        return webconfig_error_none;
    }

    if (security_info->mode == wifi_security_mode_wpa_enterprise ||
        security_info->mode == wifi_security_mode_wpa2_enterprise ||
        security_info->mode == wifi_security_mode_wpa_wpa2_enterprise ||
        security_info->mode == wifi_security_mode_wpa3_enterprise) {

        decode_param_integer(security, "RekeyInterval", param);
        security_info->rekey_interval = param->valuedouble;

        decode_param_bool(security, "StrictRekey", param);
        security_info->strict_rekey = (param->type & cJSON_True) ? true : false;

        decode_param_integer(security, "EapolKeyTimeout", param);
        security_info->eapol_key_timeout = param->valuedouble;

        decode_param_integer(security, "EapolKeyRetries", param);
        security_info->eapol_key_retries = param->valuedouble;

        decode_param_integer(security, "EapIdentityReqTimeout", param);
        security_info->eap_identity_req_timeout = param->valuedouble;

        decode_param_integer(security, "EapIdentityReqRetries", param);
        security_info->eap_identity_req_retries = param->valuedouble;

        decode_param_integer(security, "EapReqTimeout", param);
        security_info->eap_req_timeout = param->valuedouble;

        decode_param_integer(security, "EapReqRetries", param);
        security_info->eap_req_retries = param->valuedouble;

        decode_param_bool(security, "DisablePmksaCaching", param);
        security_info->disable_pmksa_caching = (param->type & cJSON_True) ? true : false;

        decode_param_object(security, "RadiusSettings", param);
        if (decode_radius_object(param, &security_info->u.radius) != 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to decode radius settings\n",
                __func__, __LINE__);
            return webconfig_error_decode;
        }

        return webconfig_error_none;
    }

    decode_param_string(security, "Passphrase", param);

    if (security_info->mode != wifi_security_mode_none &&
        (strlen(param->valuestring) < MIN_PWD_LEN || strlen(param->valuestring) > MAX_PWD_LEN)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d invalid password length: %d\n", __func__,
            __LINE__, strlen(param->valuestring));
        return webconfig_error_decode;
    }

    strncpy(security_info->u.key.key, param->valuestring, sizeof(security_info->u.key.key) - 1);

    decode_param_bool(security, "Wpa3_transition_disable", param);
    security_info->wpa3_transition_disable = (param->type & cJSON_True) ? true : false;

    decode_param_integer(security, "RekeyInterval", param);
    security_info->rekey_interval = param->valuedouble;

    decode_param_allow_optional_string(security, "KeyId", param);
    if (param != NULL) {
        strncpy(security_info->key_id, param->valuestring, sizeof(security_info->key_id) - 1);
    }

    return webconfig_error_none;
}

webconfig_error_t decode_ssid_name(char *ssid_name)
{
    int i = 0, ssid_len;

    if(!ssid_name){
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: SSID is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    ssid_len = strlen(ssid_name);
    if ((ssid_len == 0) || (ssid_len > WIFI_MAX_SSID_NAME_LEN)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: SSID length %d exceeds max SSID length %d\n", __func__, __LINE__, ssid_len, WIFI_MAX_SSID_NAME_LEN);
        //strncpy(execRetVal->ErrorMsg, "Invalid SSID Size",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }


    for (i = 0; i < ssid_len; i++) {
        if (!((ssid_name[i] >= ' ') && (ssid_name[i] <= '~'))) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid character %c in SSID\n", __func__, __LINE__, ssid_name[i]);
            //strncpy(execRetVal->ErrorMsg, "Invalid character in SSID",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
    }

    return webconfig_error_none;
}

webconfig_error_t decode_contry_code(wifi_countrycode_type_t *contry_code, char *contry)
{
    int i;

    for (i = 0 ; i < MAX_WIFI_COUNTRYCODE; ++i) {
        if(strcasecmp(contry,wifiCountryMapMembers[i].countryStr) == 0) {
            *contry_code = wifiCountryMapMembers[i].countryCode;
            return webconfig_error_none;
        }
    }

    if(i == MAX_WIFI_COUNTRYCODE) {
        ;
    }
    return webconfig_error_decode;
}

webconfig_error_t decode_operating_environment(wifi_operating_env_t *operating_env, char *environment)
{
    int i, arr_size = 0;
    bool valid_env =  FALSE;
    
    arr_size = ((int)(sizeof(wifiEnviromentMap)/sizeof(wifiEnviromentMap[0])));
    for(i = 0; i < arr_size; i++) {
        if (strcasecmp(environment, wifiEnviromentMap[i].environment) == 0) {
            *operating_env = wifiEnviromentMap[i].operatingEnvironment;
            valid_env  = TRUE;
            break;
        }
    }

    if (!valid_env) {
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_vap_common_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    const cJSON *param;
    cJSON *object = NULL;
    bool connected_value = false;
    bool mdu_value = false, intval = false;

    // VAP Name
    decode_param_string(vap, "VapName", param);
    strcpy(vap_info->vap_name, param->valuestring);

    vap_info->vap_index = convert_vap_name_to_index(wifi_prop, vap_info->vap_name);
    if ((int)vap_info->vap_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s %d :Invalid vapname %s\n", __FUNCTION__, __LINE__,
            vap_info->vap_name);
        return webconfig_error_decode;
    }
    // Radio Index
    decode_param_integer(vap, "RadioIndex", param);
    vap_info->radio_index = param->valuedouble;

    // VAP Mode
    decode_param_integer(vap, "VapMode", param);
    vap_info->vap_mode = param->valuedouble;

    // Exists
    decode_param_bool(vap, "Exists", param);
    rdk_vap_info->exists = (param->type & cJSON_True) ? true : false;

    // Bridge Name
    decode_param_allow_empty_string(vap, "BridgeName", param);
    strncpy(vap_info->bridge_name, param->valuestring, WIFI_BRIDGE_NAME_LEN - 1);

    //Repurposed Bridge Name
    decode_param_allow_optional_string(vap, "RepurposedBridgeName", param);
    if (param != NULL && param->valuestring != NULL) {
        strncpy(vap_info->repurposed_bridge_name, param->valuestring, WIFI_BRIDGE_NAME_LEN - 1);
        vap_info->repurposed_bridge_name[WIFI_BRIDGE_NAME_LEN - 1] = '\0';
    } else {
        vap_info->repurposed_bridge_name[0] = '\0';
    }

    // repurposed vap_name
    decode_param_allow_empty_string(vap, "RepurposedVapName", param);
    strncpy(vap_info->repurposed_vap_name, param->valuestring,
        sizeof(vap_info->repurposed_vap_name) - 1);

    // SSID
    decode_param_string(vap, "SSID", param);

    if (decode_ssid_name(param->valuestring) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s %d : Ssid name validation failed for %s\n",
            __FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }
    strncpy(vap_info->u.bss_info.ssid, param->valuestring, sizeof(vap_info->u.bss_info.ssid) - 1);

    // BSSID
    decode_param_string(vap, "BSSID", param);
    string_mac_to_uint8_mac(vap_info->u.bss_info.bssid, param->valuestring);

    // Enabled
    decode_param_bool(vap, "Enabled", param);
    vap_info->u.bss_info.enabled = (param->type & cJSON_True) ? true : false;

    // Broadcast SSID
    decode_param_bool(vap, "SSIDAdvertisementEnabled", param);
    vap_info->u.bss_info.showSsid = (param->type & cJSON_True) ? true : false;
    decode_param_allow_empty_integer(vap, "SpeedTier", param, intval);
    if (!intval) {
        vap_info->u.bss_info.am_config.npc.speed_tier = intval;
    } else {
        decode_param_integer(vap, "SpeedTier", param);
        vap_info->u.bss_info.am_config.npc.speed_tier = param->valuedouble;
    }

    decode_param_allow_empty_bool(vap, "MDUEnabled", param, mdu_value);
    if (!mdu_value) {
        vap_info->u.bss_info.mdu_enabled = false;
    } else {
        decode_param_bool(vap, "MDUEnabled", param);
        vap_info->u.bss_info.mdu_enabled = (param->type & cJSON_True) ? true : false;
    }

    // MLD Enable
    decode_param_bool(vap, "MLD_Enable", param);
    vap_info->u.bss_info.mld_info.common_info.mld_enable = (param->type & cJSON_True) ? true:false;

    // MLD Apply
    decode_param_bool(vap, "MLD_Apply", param);
    vap_info->u.bss_info.mld_info.common_info.mld_apply = (param->type & cJSON_True) ? true:false;

    // MLD_ID
    decode_param_integer(vap, "MLD_ID", param);
    vap_info->u.bss_info.mld_info.common_info.mld_id = param->valuedouble;

    // MLD_Link_ID
    decode_param_integer(vap, "MLD_Link_ID", param);
    vap_info->u.bss_info.mld_info.common_info.mld_link_id = param->valuedouble;

    // MLD_Addr
    decode_param_string(vap, "MLD_Addr", param);
    string_mac_to_uint8_mac(vap_info->u.bss_info.mld_info.common_info.mld_addr, param->valuestring);

    // Isolation
    decode_param_bool(vap, "IsolationEnable", param);
    vap_info->u.bss_info.isolation = (param->type & cJSON_True) ? true : false;

    // ManagementFramePowerControl
    decode_param_integer(vap, "ManagementFramePowerControl", param);
    vap_info->u.bss_info.mgmtPowerControl = param->valuedouble;

    decode_param_integer(vap, "InteropNumSta", param);
    vap_info->u.bss_info.inum_sta = param->valuedouble;

    // BssMaxNumSta
    decode_param_integer(vap, "BssMaxNumSta", param);
    vap_info->u.bss_info.bssMaxSta = param->valuedouble;

    // BSSTransitionActivated
    decode_param_bool(vap, "BSSTransitionActivated", param);
    vap_info->u.bss_info.bssTransitionActivated = (param->type & cJSON_True) ? true : false;

    // NeighborReportActivated
    decode_param_bool(vap, "NeighborReportActivated", param);
    vap_info->u.bss_info.nbrReportActivated = (param->type & cJSON_True) ? true : false;

    // NetworkGreyList since this is not mandatory field we need
    // check for its existence before decode
    object = cJSON_GetObjectItem(vap, "NetworkGreyList");
    if (object != NULL) {
        decode_param_bool(vap, "NetworkGreyList", param);
        vap_info->u.bss_info.network_initiated_greylist = (param->type & cJSON_True) ? true : false;
    }

    // force_apply is not mandatory
    object = cJSON_GetObjectItem(vap, "ForceApply");
    if (object != NULL) {
        decode_param_bool(vap, "ForceApply", param);
        rdk_vap_info->force_apply = (param->type & cJSON_True) ? true : false;
    } else {
        // update the force_apply flag to false if force_apply not present
        rdk_vap_info->force_apply = false;
    }

    // RapidReconnCountEnable
    decode_param_bool(vap, "RapidReconnCountEnable", param);
    vap_info->u.bss_info.rapidReconnectEnable = (param->type & cJSON_True) ? true : false;

    // RapidReconnThreshold
    decode_param_integer(vap, "RapidReconnThreshold", param);
    vap_info->u.bss_info.rapidReconnThreshold = param->valuedouble;

    // VapStatsEnable
    decode_param_bool(vap, "VapStatsEnable", param);
    vap_info->u.bss_info.vapStatsEnable = (param->type & cJSON_True) ? true : false;

    // MacFilterEnable
    decode_param_bool(vap, "MacFilterEnable", param);
    vap_info->u.bss_info.mac_filter_enable = (param->type & cJSON_True) ? true : false;

    // MacFilterMode
    decode_param_integer(vap, "MacFilterMode", param);
    vap_info->u.bss_info.mac_filter_mode = param->valuedouble;
    if ((vap_info->u.bss_info.mac_filter_mode < 0) || (vap_info->u.bss_info.mac_filter_mode > 1)) {
        wifi_util_error_print(WIFI_WEBCONFIG,
            "Invalid wifi vap mac filter mode %d, should be between 0 and 1\n",
            vap_info->u.bss_info.mac_filter_mode);
        // strncpy(execRetVal->ErrorMsg, "Invalid wifi vap mac filter mode:
        // 0..1",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    // WmmEnabled
    decode_param_bool(vap, "WmmEnabled", param);
    vap_info->u.bss_info.wmm_enabled = (param->type & cJSON_True) ? true : false;

    decode_param_bool(vap, "UapsdEnabled", param);
    vap_info->u.bss_info.UAPSDEnabled = (param->type & cJSON_True) ? true : false;

    decode_param_integer(vap, "BeaconRate", param);
    vap_info->u.bss_info.beaconRate = param->valuedouble;

    // WmmNoAck
    decode_param_integer(vap, "WmmNoAck", param);
    vap_info->u.bss_info.wmmNoAck = param->valuedouble;

    // WepKeyLength
    decode_param_integer(vap, "WepKeyLength", param);
    vap_info->u.bss_info.wepKeyLength = param->valuedouble;

    // BssHotspot
    decode_param_bool(vap, "BssHotspot", param);
    vap_info->u.bss_info.bssHotspot = (param->type & cJSON_True) ? true : false;

    // wpsPushButton
    decode_param_integer(vap, "WpsPushButton", param);
    vap_info->u.bss_info.wpsPushButton = param->valuedouble;

    // wpsEnable
    decode_param_bool(vap, "WpsEnable", param);
    vap_info->u.bss_info.wps.enable = (param->type & cJSON_True) ? true : false;

    // wpsConfigMethodsEnabled
    if (strstr(vap_info->vap_name, "private") != NULL) {
        decode_param_integer(vap, "WpsConfigMethodsEnabled", param);
        vap_info->u.bss_info.wps.methods = param->valuedouble;
        // WpsConfigPin
        decode_param_allow_empty_string(vap, "WpsConfigPin", param);
        strcpy(vap_info->u.bss_info.wps.pin, param->valuestring);
    }
    // BeaconRateCtl
    decode_param_string(vap, "BeaconRateCtl", param);
    strcpy(vap_info->u.bss_info.beaconRateCtl, param->valuestring);

    // connected_building_enabled params
    decode_param_allow_empty_bool(vap, "Connected_building_enabled", param, connected_value);
    if (!connected_value) {
        vap_info->u.bss_info.connected_building_enabled = false;
    } else {
        decode_param_bool(vap, "Connected_building_enabled", param);
        vap_info->u.bss_info.connected_building_enabled = (param->type & cJSON_True) ? true : false;
    }

    // HostapMgtFrameCtrl
    decode_param_bool(vap, "HostapMgtFrameCtrl", param);
    vap_info->u.bss_info.hostap_mgt_frame_ctrl = (param->type & cJSON_True) ? true : false;

    decode_param_bool(vap, "InteropCtrl", param);
    vap_info->u.bss_info.interop_ctrl = (param->type & cJSON_True) ? true : false;

    decode_param_bool(vap, "MboEnabled", param);
    vap_info->u.bss_info.mbo_enabled = (param->type & cJSON_True) ? true : false;

    return webconfig_error_none;
}

webconfig_error_t decode_hotspot_open_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    int radio_index, band;
    const cJSON *security, *interworking;
    cJSON *cac_obj;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }
    cac_obj = cJSON_GetObjectItem(vap, "VapConnectionControl");
    if (decode_cac_object(vap_info,cac_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: CACobjects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }
    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_hotspot_secure_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    int radio_index, band;
    const cJSON *security, *interworking;
    cJSON *cac_obj;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }
    cac_obj = cJSON_GetObjectItem(vap, "VapConnectionControl");
    if (decode_cac_object(vap_info,cac_obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: CACobjects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_lnf_psk_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;
    int radio_index = -1;
    int band = -1;


    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_lnf_radius_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    int radio_index, band;
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_iot_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    const cJSON *security, *interworking;
    int radio_index = -1;
    int band = -1;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }
    
    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }
    
    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_mesh_backhaul_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    const cJSON *security, *interworking;
    int radio_index = -1;
    int band = -1;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_private_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    const cJSON *security, *interworking;
    int radio_index = -1;
    int band = -1;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }


    return webconfig_error_none;
}

webconfig_error_t decode_mesh_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    return decode_private_vap_object(vap, vap_info, rdk_vap_info, wifi_prop);
}

webconfig_error_t decode_wifiapi_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;
    int radio_index = -1;
    int band = -1;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info, rdk_vap_info, wifi_prop)) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }


    return webconfig_error_none;
}

webconfig_error_t decode_scan_params_object(const cJSON *scan_obj, wifi_scan_params_t *scan_info)
{
    const cJSON  *param;

    // period
    decode_param_integer(scan_obj, "Period", param);
    scan_info->period = param->valuedouble;

    // channel
    decode_param_integer(scan_obj, "Channel", param);
    scan_info->channel.channel = param->valuedouble;

    return webconfig_error_none;
}

webconfig_error_t decode_mesh_sta_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop)
{
    const cJSON  *param, *security, *scan;
    int radio_index = -1;
    int band = -1;
    //VAP Name
    decode_param_string(vap, "VapName", param);
    strcpy(vap_info->vap_name, param->valuestring);

    vap_info->vap_index = convert_vap_name_to_index(wifi_prop, vap_info->vap_name);
    if ((int)vap_info->vap_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s %d :Invalid vapname %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    // Radio Index
    decode_param_integer(vap, "RadioIndex", param);
    vap_info->radio_index = param->valuedouble;

    // VAP Mode
    decode_param_integer(vap, "VapMode", param);
    vap_info->vap_mode = param->valuedouble;

    // Exists
    decode_param_bool(vap, "Exists", param);
    rdk_vap_info->exists = (param->type & cJSON_True) ? true : false;

    //Bridge Name
    param = cJSON_GetObjectItem(vap, "BridgeName");
    if ((param != NULL) && (cJSON_IsString(param) == true) && (param->valuestring != NULL)) {
        strncpy(vap_info->bridge_name, param->valuestring,WIFI_BRIDGE_NAME_LEN-1);
    } else {
        vap_info->bridge_name[0] = '\0';
    }

    // SSID
    decode_param_string(vap, "SSID", param);
    strcpy(vap_info->u.sta_info.ssid, param->valuestring);

    // BSSID
    decode_param_string(vap, "BSSID", param);
    string_mac_to_uint8_mac(vap_info->u.sta_info.bssid, param->valuestring);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: vapname : %s bssid : %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",__FUNCTION__, __LINE__, vap_info->vap_name,
            vap_info->u.sta_info.bssid[0], vap_info->u.sta_info.bssid[1], vap_info->u.sta_info.bssid[2],
            vap_info->u.sta_info.bssid[3], vap_info->u.sta_info.bssid[4], vap_info->u.sta_info.bssid[5]);

    // MAC
    decode_param_string(vap, "MAC", param);
    string_mac_to_uint8_mac(vap_info->u.sta_info.mac, param->valuestring);

    // Enabled
    decode_param_bool(vap, "Enabled", param);
    vap_info->u.sta_info.enabled = (param->type & cJSON_True) ? true:false;

    // ConnectStatus
    decode_param_bool(vap, "ConnectStatus", param);
    vap_info->u.sta_info.conn_status = (param->type & cJSON_True) ? wifi_connection_status_connected:wifi_connection_status_disconnected;

    radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vap_info->vap_name);
    if (radio_index < 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio Index\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to fetch proper band\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.sta_info.security, band) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "ScanParameters", scan);
    if (decode_scan_params_object(scan, &vap_info->u.sta_info.scan_params) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Scan parameters objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_wifi_global_config(const cJSON *global_cfg, wifi_global_param_t *global_info)
{
    const cJSON  *param;

    // NotifyWifiChanges
    decode_param_bool(global_cfg, "NotifyWifiChanges", param);
    global_info->notify_wifi_changes = (param->type & cJSON_True) ? true:false;

    // PreferPrivate
    decode_param_bool(global_cfg, "PreferPrivate", param);
    global_info->prefer_private = (param->type & cJSON_True) ? true:false;

    // PreferPrivateConfigure
    decode_param_bool(global_cfg, "PreferPrivateConfigure", param);
    global_info->prefer_private_configure = (param->type & cJSON_True) ? true:false;

    // FactoryReset
    decode_param_bool(global_cfg, "FactoryReset", param);
    global_info->factory_reset = (param->type & cJSON_True) ? true:false;

    // TxOverflowSelfheal
    decode_param_bool(global_cfg, "TxOverflowSelfheal", param);
    global_info->tx_overflow_selfheal = (param->type & cJSON_True) ? true:false;

    // InstWifiClientEnabled
    decode_param_bool(global_cfg, "InstWifiClientEnabled", param);
    global_info->inst_wifi_client_enabled = (param->type & cJSON_True) ? true:false;

    //InstWifiClientReportingPeriod
    decode_param_integer(global_cfg, "InstWifiClientReportingPeriod", param);
    global_info->inst_wifi_client_reporting_period = param->valuedouble;

    //InstWifiClientMac
    decode_param_string(global_cfg, "InstWifiClientMac", param);
    //strcpy((unsigned char *)global_info->inst_wifi_client_mac, param->valuestring);
    string_mac_to_uint8_mac((uint8_t *)&global_info->inst_wifi_client_mac, param->valuestring);

    //InstWifiClientDefReportingPeriod
    decode_param_integer(global_cfg, "InstWifiClientDefReportingPeriod", param);
    global_info->inst_wifi_client_def_reporting_period = param->valuedouble;

    // WifiActiveMsmtEnabled
    decode_param_bool(global_cfg, "WifiActiveMsmtEnabled", param);
    global_info->wifi_active_msmt_enabled = (param->type & cJSON_True) ? true:false;

    //WifiActiveMsmtPktsize
    decode_param_integer(global_cfg, "WifiActiveMsmtPktsize", param);
    global_info->wifi_active_msmt_pktsize = param->valuedouble;

    //WifiActiveMsmtNumSamples
    decode_param_integer(global_cfg, "WifiActiveMsmtNumSamples", param);
    global_info->wifi_active_msmt_num_samples = param->valuedouble;

    //WifiActiveMsmtSampleDuration
    decode_param_integer(global_cfg, "WifiActiveMsmtSampleDuration", param);
    global_info->wifi_active_msmt_sample_duration = param->valuedouble;

    //VlanCfgVersion
    decode_param_integer(global_cfg, "VlanCfgVersion", param);
    global_info->vlan_cfg_version = param->valuedouble;

 #ifndef EASY_MESH_NODE
    // WpsPin
    decode_param_string(global_cfg, "WpsPin", param);
    strcpy(global_info->wps_pin, param->valuestring);
#endif

    // BandsteeringEnable
    decode_param_bool(global_cfg, "BandsteeringEnable", param);
    global_info->bandsteering_enable = (param->type & cJSON_True) ? true:false;

    //GoodRssiThreshold
    decode_param_integer(global_cfg, "GoodRssiThreshold", param);
    global_info->good_rssi_threshold = param->valuedouble;

    //AssocCountThreshold
    decode_param_integer(global_cfg, "AssocCountThreshold", param);
    global_info->assoc_count_threshold = param->valuedouble;

    //AssocGateTime
    decode_param_integer(global_cfg, "AssocGateTime", param);
    global_info->assoc_gate_time = param->valuedouble;

    //WhixLoginterval
    decode_param_integer(global_cfg, "WhixLoginterval", param);
    global_info->whix_log_interval = param->valuedouble;

    //Whix_ChUtility_Loginterval
    decode_param_integer(global_cfg, "whix_chutility_loginterval", param);
    global_info->whix_chutility_loginterval = param->valuedouble;

    //Rss threshold
    decode_param_integer(global_cfg, "rss_memory_restart_threshold_low", param);
    global_info->rss_memory_restart_threshold_low = param->valuedouble;

    decode_param_integer(global_cfg, "rss_memory_restart_threshold_high", param);
    global_info->rss_memory_restart_threshold_high = param->valuedouble;

    //AssocMonitorDuration
    decode_param_integer(global_cfg, "AssocMonitorDuration", param);
    global_info->assoc_monitor_duration = param->valuedouble;

    // RapidReconnectEnable
    decode_param_bool(global_cfg, "RapidReconnectEnable", param);
    global_info->rapid_reconnect_enable = (param->type & cJSON_True) ? true:false;

    // VapStatsFeature
    decode_param_bool(global_cfg, "VapStatsFeature", param);
    global_info->vap_stats_feature = (param->type & cJSON_True) ? true:false;

    // MfpConfigFeature
    decode_param_bool(global_cfg, "MfpConfigFeature", param);
    global_info->mfp_config_feature = (param->type & cJSON_True) ? true:false;

    // ForceDisableRadioFeature
    decode_param_bool(global_cfg, "ForceDisableRadioFeature", param);
    global_info->force_disable_radio_feature = (param->type & cJSON_True) ? true:false;

    // ForceDisableRadioStatus
    decode_param_bool(global_cfg, "ForceDisableRadioStatus", param);
    global_info->force_disable_radio_status = (param->type & cJSON_True) ? true:false;

    //FixedWmmParams
    decode_param_integer(global_cfg, "FixedWmmParams", param);
    global_info->fixed_wmm_params = param->valuedouble;

    // MgtFrameRateLimitEnable
    decode_param_bool(global_cfg, "MgtFrameRateLimitEnable", param);
    global_info->mgt_frame_rate_limit_enable = (param->type & cJSON_True) ? true : false;

    // MgtFrameRateLimit
    decode_param_integer(global_cfg, "MgtFrameRateLimit", param);
    global_info->mgt_frame_rate_limit = param->valuedouble;

    // MgtFrameRateLimitWindowSize
    decode_param_integer(global_cfg, "MgtFrameRateLimitWindowSize", param);
    global_info->mgt_frame_rate_limit_window_size = param->valuedouble;

    // MgtFrameRateLimitCooldownTime
    decode_param_integer(global_cfg, "MgtFrameRateLimitCooldownTime", param);
    global_info->mgt_frame_rate_limit_cooldown_time = param->valuedouble;

    decode_param_bool(global_cfg, "MemwrapToolEnable", param);
    global_info->memwraptool.enable = (param->type & cJSON_True) ? true : false;

    decode_param_integer(global_cfg, "rss_check_interval", param);
    global_info->memwraptool.rss_check_interval = param->valuedouble;

    decode_param_integer(global_cfg, "rss_threshold", param);
    global_info->memwraptool.rss_threshold = param->valuedouble;

    decode_param_integer(global_cfg, "rss_maxlimit", param);
    global_info->memwraptool.rss_maxlimit = param->valuedouble;

    decode_param_integer(global_cfg, "heapwalk_duration", param);
    global_info->memwraptool.heapwalk_duration = param->valuedouble;

    decode_param_integer(global_cfg, "heapwalk_interval", param);
    global_info->memwraptool.heapwalk_interval = param->valuedouble;

    //WifiRegionCode
    decode_param_string(global_cfg, "WifiRegionCode", param);
    strcpy(global_info->wifi_region_code, param->valuestring);

    // DiagnosticEnable
    decode_param_bool(global_cfg, "DiagnosticEnable", param);
    global_info->diagnostic_enable = (param->type & cJSON_True) ? true:false;

    // ValidateSsid
    decode_param_bool(global_cfg, "ValidateSsid", param);
    global_info->validate_ssid = (param->type & cJSON_True) ? true:false;

    // DeviceNetworkMode
    decode_param_integer(global_cfg, "DeviceNetworkMode", param);
    global_info->device_network_mode = param->valuedouble;

    //NormalizedRssiList
    decode_param_string(global_cfg, "NormalizedRssiList", param);
    strncpy(global_info->normalized_rssi_list, param->valuestring, sizeof(global_info->normalized_rssi_list));

    //SNRList
    decode_param_string(global_cfg, "SNRList", param);
    strncpy(global_info->snr_list, param->valuestring, sizeof(global_info->snr_list));


    //CliStatList
    decode_param_string(global_cfg, "CliStatList", param);
    strncpy(global_info->cli_stat_list, param->valuestring, sizeof(global_info->cli_stat_list));


    //TxRxRateList
    decode_param_string(global_cfg, "TxRxRateList", param);
    strncpy(global_info->txrx_rate_list, param->valuestring, sizeof(global_info->txrx_rate_list));

    wifi_util_dbg_print(WIFI_WEBCONFIG,"wifi global Parameters decode successfully\n");
    return webconfig_error_none;
}

webconfig_error_t decode_gas_config(const cJSON *gas, wifi_GASConfiguration_t *gas_info)
{
    const cJSON  *param;

    //AdvertisementId
    decode_param_integer(gas, "AdvertisementId", param);
    gas_info->AdvertisementID = param->valuedouble;
    if (gas_info->AdvertisementID != 0) { //ANQP
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid Configuration. Only Advertisement ID 0 - ANQP is Supported\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid AdvertisementId. Only ANQP(0) Supported",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    // PauseForServerResp
    decode_param_bool(gas, "PauseForServerResp", param);
    gas_info->PauseForServerResponse = (param->type & cJSON_True) ? true:false;

    //ResponseTimeout
    decode_param_integer(gas, "RespTimeout", param);
    gas_info->ResponseTimeout = param->valuedouble;
    if ((gas_info->ResponseTimeout < 1000) || (gas_info->ResponseTimeout > 65535)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid Configuration. ResponseTimeout should be between 1000 and 65535\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid RespTimeout 1000..65535",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    //ComebackDelay
    decode_param_integer(gas, "ComebackDelay", param);
    gas_info->ComeBackDelay = param->valuedouble;
    if (gas_info->ComeBackDelay > 65535) {
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid Configuration. ComeBackDelay should be between 0 and 65535\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid ComebackDelay 0..65535",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    //ResponseBufferingTime
    decode_param_integer(gas, "RespBufferTime", param);
    gas_info->ResponseBufferingTime = param->valuedouble;

    //QueryResponseLengthLimit
    decode_param_integer(gas, "QueryRespLengthLimit", param);
    gas_info->QueryResponseLengthLimit = param->valuedouble;
    if ((gas_info->QueryResponseLengthLimit < 1) || (gas_info->QueryResponseLengthLimit > 127)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid Configuration. QueryResponseLengthLimit should be between 1 and 127\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid QueryRespLengthLimit 1..127",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_wifi_channel(wifi_freq_bands_t wifi_band, UINT *wifi_radio_channel, BOOL dfs_enable, UINT wifi_channel)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s-%d Channel %d Band %d\n", __func__, __LINE__, wifi_channel, wifi_band);

    if (wifi_band == WIFI_FREQUENCY_2_4_BAND) {
        if ((wifi_channel >= MIN_CHANNEL_2G) && (wifi_channel <= MAX_CHANNEL_2G)) {
            *wifi_radio_channel = wifi_channel;
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s-%d Invalid channel %d\n", __func__, __LINE__, wifi_channel);
            return webconfig_error_decode;
        }
    } else if (wifi_band == WIFI_FREQUENCY_5_BAND) {
        if (is_valid_channel(wifi_channel, dfs_enable)) {
            *wifi_radio_channel = wifi_channel;
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s-%d Invalid channel %d\n", __func__, __LINE__, wifi_channel);
            return webconfig_error_decode;
        }
    } else if (wifi_band == WIFI_FREQUENCY_5L_BAND) {
        if ((wifi_channel >= MIN_CHANNEL_5GL) && (wifi_channel <= MAX_CHANNEL_5GL)) {
            *wifi_radio_channel = wifi_channel;
        } else {
            return webconfig_error_decode;
        }
    } else if (wifi_band == WIFI_FREQUENCY_5H_BAND) {
        if ((wifi_channel >= MIN_CHANNEL_5GH) && (wifi_channel <= MAX_CHANNEL_5GH)) {
            *wifi_radio_channel = wifi_channel;
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s-%d Invalid channel %d\n", __func__, __LINE__, wifi_channel);
            return webconfig_error_decode;
        }
    } else if (wifi_band == WIFI_FREQUENCY_6_BAND) {
        if ((wifi_channel >= MIN_CHANNEL_6G) && (wifi_channel <= MAX_CHANNEL_6G)) {
            *wifi_radio_channel = wifi_channel;
        } else {
            return webconfig_error_decode;
        }
    } else if (wifi_band == WIFI_FREQUENCY_60_BAND) {

    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s-%d Invalid channel %d\n", __func__, __LINE__, wifi_channel);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

int validate_wifi_hw_variant(wifi_freq_bands_t radio_band, wifi_ieee80211Variant_t wifi_hw_mode)
{
    if (wifi_hw_mode == 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s() %d Error wifi_hw_mode %d\n", __FUNCTION__, __LINE__, wifi_hw_mode);
        return RETURN_ERR;
    }

    // see wifi_hal_generic.h in halinterface pkg for bit sets
    #define MASK_BITSET(x, bit) ((x) &= ~(bit))

    if (radio_band == WIFI_FREQUENCY_2_4_BAND) {
        // Mask hw variant b,g,n,ax bit
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_B);
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_G);
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_N);
#if !defined (_PP203X_PRODUCT_REQ_)
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_AX);
#endif
#ifdef CONFIG_IEEE80211BE
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_BE);
#endif /* CONFIG_IEEE80211BE */
        if(wifi_hw_mode != 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s() %d Error wifi_hw_mode %d\n", __FUNCTION__, __LINE__, wifi_hw_mode);
            return RETURN_ERR;
        }
    } else if ((radio_band == WIFI_FREQUENCY_5_BAND) || (radio_band == WIFI_FREQUENCY_5L_BAND) || (radio_band == WIFI_FREQUENCY_5H_BAND)) {
        // Mask hw variant a,n,h,ac,ax,be bits
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_A);
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_N);
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_H);
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_AC);
#if !defined (_PP203X_PRODUCT_REQ_)
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_AX);
#endif
#ifdef CONFIG_IEEE80211BE
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_BE);
#endif /* CONFIG_IEEE80211BE */
        if (wifi_hw_mode != 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s() %d Error wifi_hw_mode %d\n", __FUNCTION__, __LINE__, wifi_hw_mode);
            return RETURN_ERR;
        }
    } else if (radio_band == WIFI_FREQUENCY_6_BAND) {
        // Mask hw variant ax, be bits
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_AX);
#ifdef CONFIG_IEEE80211BE
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_BE);
#endif /* CONFIG_IEEE80211BE */
        if (wifi_hw_mode != 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s() %d Error wifi_hw_mode %d\n", __FUNCTION__, __LINE__, wifi_hw_mode);
            return RETURN_ERR;
        }
    } else if (radio_band == WIFI_FREQUENCY_60_BAND) {
        // Mask hw variant ad bit
        MASK_BITSET(wifi_hw_mode, WIFI_80211_VARIANT_AD);

        if (wifi_hw_mode != 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s() %d Error wifi_hw_mode %d\n", __FUNCTION__, __LINE__, wifi_hw_mode);
            return RETURN_ERR;
        }
    }
    return RETURN_OK;
}

webconfig_error_t decode_radio_setup_object(const cJSON *obj_radio_setup, rdk_wifi_vap_map_t *vap_map)
{
    const cJSON  *param, *obj, *obj_array;
    unsigned int i;

    decode_param_integer(obj_radio_setup, "RadioIndex", param);
    vap_map->radio_index = param->valuedouble;

    decode_param_array(obj_radio_setup, "VapMap", obj_array);

    vap_map->num_vaps = cJSON_GetArraySize(obj_array);
    for (i = 0; i < vap_map->num_vaps; i++) {
        obj = cJSON_GetArrayItem(obj_array, i);

        // VapName
        memset(vap_map->rdk_vap_array[i].vap_name, 0, sizeof(vap_map->rdk_vap_array[i].vap_name));
        decode_param_string(obj, "VapName", param);
        strcpy((char *)vap_map->rdk_vap_array[i].vap_name, param->valuestring);

        // VapIndex
        decode_param_integer(obj, "VapIndex", param);
        vap_map->rdk_vap_array[i].vap_index = param->valuedouble;
    }

    return webconfig_error_none;
}

int remove_chanlist_entries(wifi_channels_list_per_bandwidth_t *chanlist)
{
    for (int i = 0; i < chanlist->num_channels_list; i++) {
        memset(chanlist->channels_list[i].channels_list, 0,
            sizeof(chanlist->channels_list[i].channels_list));
        chanlist->channels_list[i].num_channels = 0;
    }
    if (chanlist->num_channels_list > 0) {
        chanlist->num_channels_list = 0;
        chanlist->chanwidth = 0;
    }
    return 0;
}

webconfig_error_t process_bandwidth(cJSON *radioParams, const char *bandwidth_str,
    wifi_freq_bands_t band, wifi_channels_list_per_bandwidth_t *chanlist,
    wifi_channelBandwidth_t bandwidth_type)
{
    cJSON *bandwidth = cJSON_GetObjectItem(radioParams, bandwidth_str);
    if (bandwidth != NULL) {
        int channels_list[MAX_CHANNELS];
        int num_channels = 0;
        cJSON *channel;
        cJSON_ArrayForEach(channel, bandwidth) {
            if (get_on_channel_scan_list(band, bandwidth_type, channel->valueint, channels_list,
                    &num_channels) == 0) {
                memcpy(chanlist->channels_list[chanlist->num_channels_list].channels_list,
                    channels_list, sizeof(channels_list));
                chanlist->channels_list[chanlist->num_channels_list].num_channels = num_channels;
                chanlist->num_channels_list++;
            } else {
                wifi_util_error_print(WIFI_CTRL,
                    "%s:%d get_on_channel_scan_list failed for bandwidth %s channel %d \n",
                    __FUNCTION__, __LINE__, bandwidth_str, channel->valueint);
                return webconfig_error_decode;
            }
        }
        chanlist->chanwidth = bandwidth_type;
    } else {
        remove_chanlist_entries(chanlist);
    }
    return webconfig_error_none;
}

webconfig_error_t decode_bandwidth_from_json(cJSON *radioParams, wifi_freq_bands_t band,
    wifi_radio_operationParam_t *radioOperParams)
{
    const char *bandwidths[] = { "20", "40", "80", "160",
#ifdef CONFIG_IEEE80211BE
        "8080", "320"
#endif
    };
    const int arr_size = sizeof(bandwidths) / sizeof(bandwidths[0]);
    for (int i = 0; i < arr_size; i++) {
        wifi_channelBandwidth_t bw_type = string_to_channel_width_convert(bandwidths[i]);
        if (process_bandwidth(radioParams, bandwidths[i], band,
                &radioOperParams->channels_per_bandwidth[i], bw_type) != webconfig_error_none) {
            return webconfig_error_decode;
        }
    }
    radioOperParams->acs_keep_out_reset = false; // 5GH and 6G treated as RadioIndex 2
    return webconfig_error_none;
}

// Optimize in PHASE 2
void decode_acs_keep_out_json(const char *json_string, unsigned int num_of_radios,
    webconfig_subdoc_data_t *data)
{
    cJSON *json = cJSON_Parse(json_string);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Error before: %s\n", __FUNCTION__, __LINE__,
                error_ptr);
        }
        return;
    }
    wifi_radio_operationParam_t *radio_oper = NULL;
    cJSON *item = NULL;
    const char *radioNames[] = { "radio2G", "radio5G", "radio5GL", "radio5GH", "radio6G" };
    wifi_freq_bands_t freq_band;
    int radioIndex;
    int numRadios = ARRAY_SZ(radioNames);
    cJSON *channelExclusion = cJSON_GetObjectItem(json, "ChannelExclusion");
    if (!channelExclusion) {
        for (unsigned int i = 0; i < num_of_radios; i++) {
            radio_oper = &data->u.decoded.radios[i].oper;
            radio_oper->acs_keep_out_reset = true;
            for (int k = 0; k < MAX_NUM_CHANNELBANDWIDTH_SUPPORTED; k++) {
                remove_chanlist_entries(&radio_oper->channels_per_bandwidth[k]);
            }
        }
        cJSON_Delete(json);
        return;
    }
    cJSON_ArrayForEach(item, channelExclusion) {
        for (int i = 0, j = WIFI_FREQUENCY_2_4_BAND; i < numRadios; i++, j *= 2) {
            freq_band = (wifi_freq_bands_t)j;
            if (convert_freq_band_to_radio_index(freq_band, &radioIndex) != RETURN_OK) {
                continue;
            }
            radio_oper = &data->u.decoded.radios[radioIndex].oper;
            if (!radio_oper) {
                wifi_util_error_print(WIFI_CTRL,
                    "%s:%d Could not retrieve values for radio_operationparam for radioIndex= "
                    "%d\n",
                    __FUNCTION__, __LINE__, radioIndex);
                continue;
            }
            cJSON *radioParams = cJSON_GetObjectItem(item, radioNames[i]);
            if (radioParams != NULL) {
                if (decode_bandwidth_from_json(radioParams, freq_band, radio_oper) !=
                    webconfig_error_none) {
                    wifi_util_error_print(WIFI_CTRL,
                        "%s:%d decode_bandwidth_from_json returned error\n", __FUNCTION__,
                        __LINE__);
                    return;
                }
            } else {
                radio_oper->acs_keep_out_reset = true; // Optimize in Phase 2
                for (int k = 0; k < MAX_NUM_CHANNELBANDWIDTH_SUPPORTED; k++) {
                    remove_chanlist_entries(&radio_oper->channels_per_bandwidth[k]);
                }
            }
        }
    }
    cJSON_Delete(json);
}

webconfig_error_t decode_radio_operating_classes(const cJSON *obj_radio_setup,
    wifi_radio_operationParam_t *oper)
{
    const cJSON *param, *obj_array, *obj, *non_operable_channels, *iterator;
    unsigned int i, j;
    wifi_operating_classes_t *oper_classes;

    // NumberofOpClass
    decode_param_integer(obj_radio_setup, "NumberOfOpClass", param);
    oper->numOperatingClasses = param->valuedouble;

    decode_param_array(obj_radio_setup, "OperatingClasses", obj_array);
    for (i = 0; i < oper->numOperatingClasses; i++) {
        oper_classes = &oper->operatingClasses[i];
        memset(oper_classes, 0, sizeof(wifi_operating_classes_t));

        obj = cJSON_GetArrayItem(obj_array, i);
        decode_param_integer(obj, "NumberOfNonOperChan", param);
        oper_classes->numberOfNonOperChan = param->valuedouble;
        decode_param_integer(obj, "Class", param);
        oper_classes->opClass = param->valuedouble;
        decode_param_integer(obj, "MaxTxPower", param);
        oper_classes->maxTxPower = param->valuedouble;

        /* NonOperable Array */
        if (oper_classes->numberOfNonOperChan != 0) {
            non_operable_channels = cJSON_GetObjectItem(obj, "NonOperable");
            if (non_operable_channels == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s %d: NonOperable is NULL for opClass:%d NumberofNonOperChan:%d\n",
                    __FUNCTION__, __LINE__, oper_classes->opClass,
                    oper_classes->numberOfNonOperChan);
                return webconfig_error_decode;
            }

            j = 0;
            cJSON_ArrayForEach(iterator, non_operable_channels) {
                if ((cJSON_IsNumber(iterator)) && (j < MAXNUMNONOPERABLECHANNELS)) {
                    oper_classes->nonOperable[j] = iterator->valuedouble;
                    j++;
                }
            }
        }
    }
    return webconfig_error_none;
}

webconfig_error_t decode_radio_curr_operating_classes(const cJSON *obj_radio_setup,
    wifi_radio_operationParam_t *oper)
{
    const cJSON *param, *obj_array, *obj;

    decode_param_array(obj_radio_setup, "CurrentOperatingClasses", obj_array);
    // Update with the first element of the array.
    obj = cJSON_GetArrayItem(obj_array, 0);
    decode_param_integer(obj, "Class", param);
    oper->operatingClass = param->valuedouble;
    decode_param_integer(obj, "Channel", param);
    // update the channel only if oper->channel is not configured
    // if oper->channel is already populated then don't overwrite.
    if (oper->channel == 0) {
        oper->channel = param->valuedouble;
    } else {
        wifi_util_info_print(WIFI_WEBCONFIG,
            "%s:%d Not updating channel:%u from CurrentOperatingClasses as oper->channel:%u is "
            "already populated.\n",
            __FUNCTION__, __LINE__, param->valuedouble, oper->channel);
    }
    return webconfig_error_none;
}

webconfig_error_t decode_radio_object(const cJSON *obj_radio, rdk_wifi_radio_t *radio)
{
    const cJSON  *param;
    char *ptr, *tmp;
    unsigned int num_of_channel = 0;
    int ret;
    int radio_index = 0;
    char* ctx = NULL;
    int idx = 0;
    char tmp_buf[512];
    wifi_radio_operationParam_t *radio_info = &radio->oper;
    wifi_radio_feature_param_t *radio_feat = &radio->feature;
    wifi_countrycode_type_t country_code;
    wifi_operating_env_t operating_environment;
    UINT wifi_radio_channel;

    // WifiRadioSetup
    decode_param_object(obj_radio, "WifiRadioSetup", param);
    if (decode_radio_setup_object(param, &radio->vaps) != webconfig_error_none) {
        wifi_util_error_print(WIFI_LIB,"%s:%d Radio setup decode failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    memset(radio_info, 0, sizeof(wifi_radio_operationParam_t));
    memset(radio_feat, 0, sizeof(wifi_radio_feature_param_t));

    // RadioName
    decode_param_string(obj_radio, "RadioName", param);
    strcpy(radio->name, param->valuestring);

    // FreqBand
    decode_param_integer(obj_radio, "FreqBand", param);
    radio_info->band = param->valuedouble;
    switch(radio_info->band) {
        case WIFI_FREQUENCY_2_4_BAND:
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
        case WIFI_FREQUENCY_6_BAND:
        case WIFI_FREQUENCY_60_BAND:
            break;

        default:
            wifi_util_error_print(WIFI_WEBCONFIG,"Invalid wifi radio band 0x%x\n", radio_info->band);
            return webconfig_error_decode;
    }

    if (convert_freq_band_to_radio_index(radio_info->band, &radio_index) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s %d failed for convert_freq_band_to_radio_index for band 0x%x\n", __FUNCTION__, __LINE__, radio_info->band);
        return webconfig_error_decode;
    }
    radio_feat->radio_index = radio_index; //Required for decoded radio_feat value

    // Enabled
    decode_param_bool(obj_radio, "Enabled", param);
    radio_info->enable = (param->type & cJSON_True) ? true:false;


    // AutoChannelEnabled
    decode_param_bool(obj_radio, "AutoChannelEnabled", param);
    radio_info->autoChannelEnabled = (param->type & cJSON_True) ? true:false;

    // DFSEnable
    decode_param_bool(obj_radio, "DFSEnable", param);
    radio_info->DfsEnabled = (param->type & cJSON_True) ? true:false;

    // DfsEnabledBootup
    decode_param_bool(obj_radio, "DfsEnabledBootup", param);
    radio_info->DfsEnabledBootup = (param->type & cJSON_True) ? true:false;

    // ChannelAvailability
    decode_param_string(obj_radio, "ChannelAvailability", param);
    memset(tmp_buf, 0, sizeof(tmp_buf));
    snprintf(tmp_buf,sizeof(tmp_buf),"%s",param->valuestring);
    char* token = strtok_r(tmp_buf, ",", &ctx);
    while (token != NULL){
        sscanf( token, "%3d:%1d", &radio_info->channel_map[idx].ch_number, (int*)&radio_info->channel_map[idx].ch_state );
        idx++;
        token = strtok_r(NULL, ",", &ctx);
    }

    //radarInfo
    decode_param_string(obj_radio, "radarInfo", param);
    sscanf(param->valuestring, "last_channel:%d,num_detected:%d,time:%lld",
           &radio->radarInfo.last_channel,&radio->radarInfo.num_detected,&radio->radarInfo.timestamp );

    // Channel
    decode_param_integer(obj_radio, "Channel", param);
    ret = decode_wifi_channel(radio_info->band, &wifi_radio_channel, radio_info->DfsEnabled, param->valuedouble);
    if (ret != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid wifi radio channel configuration. channel %d %d\n",
            radio_info->channel, param->valuedouble);
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio channel config",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    radio_info->channel = wifi_radio_channel;

    // NumSecondaryChannels
    decode_param_integer(obj_radio, "NumSecondaryChannels", param);
    radio_info->numSecondaryChannels = param->valuedouble;

    if  (radio_info->numSecondaryChannels > 0) {
        //SecondaryChannelsList
        decode_param_string(obj_radio, "SecondaryChannelsList",param);
        ptr = param->valuestring;
        tmp = param->valuestring;

        while ((ptr = strchr(tmp, ',')) != NULL) {
            ptr++;
            radio_info->channelSecondary[num_of_channel] = atoi(tmp);
            tmp = ptr;
            num_of_channel++;
        }
        // Last channel
        radio_info->channelSecondary[num_of_channel++] = atoi(tmp);

        if(num_of_channel != radio_info->numSecondaryChannels) {
            wifi_util_error_print(WIFI_WEBCONFIG,"number of secondary channels and secondary chaneel list not match\n");
            //strncpy(execRetVal->ErrorMsg, "Invalid Secondary channel list",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
    }

    // ChannelWidth
    decode_param_integer(obj_radio, "ChannelWidth", param);
    radio_info->channelWidth = param->valuedouble;
    if ((radio_info->channelWidth < WIFI_CHANNELBANDWIDTH_20MHZ)
        || (radio_info->channelWidth > WIFI_CHANNELBANDWIDTH_320MHZ)) {
        //TODO: Do we need to check fot the 320MHZ ?
        if ( (radio_info->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) && (radio_info->band == WIFI_FREQUENCY_5_BAND || radio_info->band == WIFI_FREQUENCY_5L_BAND || radio_info->band == WIFI_FREQUENCY_5H_BAND) && (radio_info->DfsEnabled != true) )
        {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: DFS Disabled!! Cannot set to ChanWidth = %d  \n",__func__, __LINE__,radio_info->channelWidth);
            return webconfig_error_decode;
        }
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid wifi radio channelWidth[%d] configuration, should be between %d and %d\n", radio_info->channelWidth, WIFI_CHANNELBANDWIDTH_20MHZ,
                                            WIFI_CHANNELBANDWIDTH_80_80MHZ);
        return webconfig_error_decode;
    }

    // HwMode
    decode_param_integer(obj_radio, "HwMode", param);
    if (validate_wifi_hw_variant(radio_info->band, param->valuedouble) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid wifi radio hardware mode [%d] configuration\n", param->valuedouble);
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio hardware mode config",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    radio_info->variant = param->valuedouble;

    // CsaBeaconCount
    decode_param_integer(obj_radio, "CsaBeaconCount", param);
    radio_info->csa_beacon_count = param->valuedouble;

    // Country
    decode_param_string(obj_radio, "Country", param);
    ret = decode_contry_code(&country_code, param->valuestring);
    if (ret != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid wifi radio contry code '%s'\n", param->valuestring);
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio code",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    radio_info->countryCode = country_code;

    // RegDomain
    decode_param_integer(obj_radio, "RegDomain", param);
    radio_info->regDomain = param->valuedouble;
    
    //OperatingEnvironment
    decode_param_string(obj_radio, "OperatingEnvironment", param);
    ret = decode_operating_environment(&operating_environment, param->valuestring);
    if (ret != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"Invalid wifi Operating Environment '%s'\n", param->valuestring);
        return webconfig_error_decode;
    }
    radio_info->operatingEnvironment = operating_environment;

    // DcsEnabled
    decode_param_bool(obj_radio, "DcsEnabled", param);
    radio_info->DCSEnabled = (param->type & cJSON_True) ? true:false;

    // DtimPeriod
    decode_param_integer(obj_radio, "DtimPeriod", param);
    radio_info->dtimPeriod = param->valuedouble;

    // BeaconInterval
    decode_param_integer(obj_radio, "BeaconInterval", param);
    radio_info->beaconInterval = param->valuedouble;

    // OperatingClass
    decode_param_integer(obj_radio, "OperatingClass", param);
    radio_info->operatingClass = param->valuedouble;

    // BasicDataTransmitRates
    decode_param_integer(obj_radio, "BasicDataTransmitRates", param);
    radio_info->basicDataTransmitRates = param->valuedouble;

    // OperationalDataTransmitRates
    decode_param_integer(obj_radio, "OperationalDataTransmitRates", param);
    radio_info->operationalDataTransmitRates = param->valuedouble;

    // FragmentationThreshold
    decode_param_integer(obj_radio, "FragmentationThreshold", param);
    radio_info->fragmentationThreshold = param->valuedouble;

    // GuardInterval
    decode_param_integer(obj_radio, "GuardInterval", param);
    radio_info->guardInterval = param->valuedouble;

    // TransmitPower
    decode_param_integer(obj_radio, "TransmitPower", param);
    radio_info->transmitPower = param->valuedouble;
    if (radio_info->transmitPower == 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "Invalid TransmitPower value 0, set to 100\n");
        radio_info->transmitPower = 100;
    }

    // RtsThreshold
    decode_param_integer(obj_radio, "RtsThreshold", param);
    radio_info->rtsThreshold = param->valuedouble;

    // FactoryResetSsid
    decode_param_bool(obj_radio, "FactoryResetSsid", param);
    radio_info->factoryResetSsid = (param->type & cJSON_True) ? true:false;

    // RadioStatsMeasuringRate
    decode_param_integer(obj_radio, "RadioStatsMeasuringRate", param);
    radio_info->radioStatsMeasuringRate = param->valuedouble;

    // RadioStatsMeasuringInterval
    decode_param_integer(obj_radio, "RadioStatsMeasuringInterval", param);
    radio_info->radioStatsMeasuringInterval = param->valuedouble;

    // CtsProtection
    decode_param_bool(obj_radio, "CtsProtection", param);
    radio_info->ctsProtection = (param->type & cJSON_True) ? true:false;

    // ObssCoex
    decode_param_bool(obj_radio, "ObssCoex", param);
    radio_info->obssCoex = (param->type & cJSON_True) ? true:false;

    // StbcEnable
    decode_param_bool(obj_radio, "StbcEnable", param);
    radio_info->stbcEnable = (param->type & cJSON_True) ? true:false;

    // GreenFieldEnable
    decode_param_bool(obj_radio, "GreenFieldEnable", param);
    radio_info->greenFieldEnable = (param->type & cJSON_True) ? true:false;

    // UserControl
    decode_param_integer(obj_radio, "UserControl", param);
    radio_info->userControl = param->valuedouble;

    // AdminControl
    decode_param_integer(obj_radio, "AdminControl", param);
    radio_info->adminControl = param->valuedouble;

    // ChanUtilThreshold
    decode_param_integer(obj_radio, "ChanUtilThreshold", param);
    radio_info->chanUtilThreshold = param->valuedouble;

    // ChanUtilSelfHealEnable
    decode_param_bool(obj_radio, "ChanUtilSelfHealEnable", param);
    radio_info->chanUtilSelfHealEnable = (param->type & cJSON_True) ? true:false;

    // EcoPowerDown
    decode_param_bool(obj_radio, "EcoPowerDown", param);
    radio_info->EcoPowerDown = (param->type & cJSON_True) ? true:false;
#ifdef FEATURE_SUPPORT_ECOPOWERDOWN
    if (radio_info->EcoPowerDown && radio_info->enable ) {
        wifi_util_error_print(WIFI_WEBCONFIG," Radio is in eco mode, so not allowed to radio in enable state\n");
        return webconfig_error_decode;
    }
#endif // FEATURE_SUPPORT_ECOPOWERDOWN

    // Tscan
    decode_param_integer(obj_radio, "Tscan", param);
    radio_feat->OffChanTscanInMsec = param->valuedouble;

    // Nscan
    decode_param_integer(obj_radio, "Nscan", param);
    radio_feat->OffChanNscanInSec = (param->valuedouble != 0) ? (24*3600)/(param->valuedouble) : 0; //Converting to seconds

    // Tidle
    decode_param_integer(obj_radio, "Tidle", param);
    radio_feat->OffChanTidleInSec = param->valuedouble;

    // DfsTimer
    decode_param_integer(obj_radio, "DfsTimer", param);
    radio_info->DFSTimer = param->valuedouble;

    //RadarDetected
    decode_param_string(obj_radio, "RadarDetected", param);
    strncpy(radio_info->radarDetected, param->valuestring, sizeof(radio_info->radarDetected));

    // AmsduTid
    unsigned int amsdu_tid_idx = 0;
    decode_param_string(obj_radio, "Amsdu_Tid", param);
    ptr = param->valuestring;
    tmp = param->valuestring;

    while ((ptr = strchr(tmp, ',')) != NULL) {
        ptr++;
        radio_info->amsduTid[amsdu_tid_idx] = (BOOL)atoi(tmp);
        tmp = ptr;
        amsdu_tid_idx++;
    }
    // Last AMSDU TID
    radio_info->amsduTid[amsdu_tid_idx++] = atoi(tmp);

    if (amsdu_tid_idx != MAX_AMSDU_TID) {
        wifi_util_error_print(WIFI_WEBCONFIG,
            "number of AMSDU TIDs decoded - %d does not match required amount - %d!\n", amsdu_tid_idx, MAX_AMSDU_TID);
        return webconfig_error_decode;
    }

    if (decode_radio_operating_classes(obj_radio, radio_info) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Radio operation classes decode failed\n",
            __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (decode_radio_curr_operating_classes(obj_radio, radio_info) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Radio current operation class decoding failed\n",
            __func__, __LINE__);
    }
    return webconfig_error_none;
}

webconfig_error_t decode_config_object(const cJSON *wifi, wifi_global_config_t *wifi_info)
{
    const cJSON  *param;
    webconfig_error_t ret;

    decode_param_object(wifi, "GASConfig", param);
    ret = decode_gas_config(param, &wifi_info->gas_config);
    if (ret != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s %d Validation of GAS Configuration Failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    ret = decode_wifi_global_config(wifi, &wifi_info->global_parameters);
    if(ret != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s %d  Validation of wifi global Configuration Failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_device_info(const cJSON *device_cfg, wifi_platform_property_t *info)
{
    const cJSON  *param;

    decode_param_string(device_cfg, "Manufacturer", param);
    strcpy(info->manufacturer, param->valuestring);

    decode_param_string(device_cfg, "Model", param);
    strcpy(info->manufacturerModel, param->valuestring);

    decode_param_string(device_cfg, "SerialNo", param);
    strcpy(info->serialNo, param->valuestring);

    decode_param_string(device_cfg, "Software_version", param);
    strcpy(info->software_version, param->valuestring);

    decode_param_string(device_cfg, "CMMAC", param);
    str_to_mac_bytes(param->valuestring,info->cm_mac);

    decode_param_string(device_cfg, "AL1905-MAC", param);
    str_to_mac_bytes(param->valuestring,info->al_1905_mac);

    return webconfig_error_none;
}

unsigned char *stringtohex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out)
{
    unsigned int i;
    unsigned char tmp1, tmp2;

    if (out_len < in_len / 2) {
        return NULL;
    }

    for (i = 0; i < in_len / 2; i++) {
        if (in[2 * i] <= '9') {
            tmp1 = (unsigned char)in[2 * i] - 0x30;
        } else {
            tmp1 = (unsigned char)in[2 * i] - 0x61 + 0xa;
        }

        tmp1 = tmp1 << 4;

        if (in[2 * i + 1] <= '9') {
            tmp2 = (unsigned char)in[2 * i + 1] - 0x30;
        } else {
            tmp2 = (unsigned char)in[2 * i + 1] - 0x61 + 0xa;
        }

        tmp2 &= 0xf;

        out[i] = tmp1 | tmp2;
    }

    return out;
}

webconfig_error_t decode_frame_data(cJSON *obj_assoc_client, frame_data_t *frame)
{
    char *tmp_assoc_frame_string;
    unsigned char *out_ptr;
    cJSON *value_object;

    value_object = cJSON_GetObjectItem(obj_assoc_client, "FrameData");
    if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: FrameData Invalid or not present\n", __func__,
            __LINE__);
        return webconfig_error_none;
    }

    tmp_assoc_frame_string = cJSON_GetStringValue(value_object);
    if (tmp_assoc_frame_string == NULL || strlen(tmp_assoc_frame_string) == 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: FrameData empty\n", __func__, __LINE__);
        return webconfig_error_none;
    }

    memset(frame, 0, sizeof(frame_data_t));
    out_ptr = stringtohex(strlen(tmp_assoc_frame_string), tmp_assoc_frame_string,
        sizeof(frame->data), frame->data);
    if (out_ptr == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed converting Framedata to hex\n",
            __func__, __LINE__);
        return webconfig_error_decode;
    }
    frame->frame.len = strlen(tmp_assoc_frame_string) / 2;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Frame Length:%u\n", __func__, __LINE__,
        frame->frame.len);
    return webconfig_error_none;
}

webconfig_error_t decode_associated_clients_object(webconfig_subdoc_data_t *data, cJSON *obj_vaps, assoclist_type_t assoclist_type)
{

    mac_address_t mac;
    cJSON *obj_vap;
    cJSON *obj_array, *assoc_client, *value_object;
    char *tmp_string;
    mac_addr_str_t tmp_mac_key;
    assoc_dev_data_t  assoc_dev_data, *tmp_assoc_dev_data = NULL;
    webconfig_subdoc_decoded_data_t *params;
    hash_map_t *associated_devices_map = NULL;
    char *name;
    rdk_wifi_vap_info_t *rdk_vap_info;
    int vap_array_index, radio_index;

    unsigned int size = 0, i = 0, n = 0, vaps_size = 0;

    params = &data->u.decoded;

    vaps_size = cJSON_GetArraySize(obj_vaps);
    if (vaps_size == 0) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid schema\n", __func__, __LINE__);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_decode;
    }

    for (n = 0; n < vaps_size; n++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, n);
        if (obj_vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        if (name == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        radio_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, name);
        if (radio_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio_index\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        vap_array_index = convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, name);
        if (vap_array_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  vap_array_index\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        if (rdk_vap_info == NULL ) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        rdk_vap_info->vap_index = convert_vap_name_to_index(&params->hal_cap.wifi_prop, name);
        if ((int)rdk_vap_info->vap_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  vap_index\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        obj_array = cJSON_GetObjectItem(obj_vap, "associatedClients");
        if (obj_array == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Json pointer\n", __func__, __LINE__);
        }

        if (cJSON_IsArray(obj_array) == false) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: associated clients object not present\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        size = cJSON_GetArraySize(obj_array);
        if (size == 0) {
            continue;
        }

        if (rdk_vap_info->associated_devices_map == NULL) {
            rdk_vap_info->associated_devices_map = hash_map_create();
        }
        if (assoclist_type == assoclist_type_full) {
            associated_devices_map = rdk_vap_info->associated_devices_map;
        } else if ((assoclist_type == assoclist_type_add) || (assoclist_type == assoclist_type_remove)) {
            if (rdk_vap_info->associated_devices_diff_map == NULL) {
                rdk_vap_info->associated_devices_diff_map = hash_map_create();
            }
            associated_devices_map = rdk_vap_info->associated_devices_diff_map;
        }

        for (i=0; i<size; i++) {
            assoc_client  = cJSON_GetArrayItem(obj_array, i);
            if (assoc_client == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Json pointer\n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            value_object = cJSON_GetObjectItem(assoc_client, "MACAddress");
            if ((value_object == NULL) || (cJSON_IsString(value_object) == false)){
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            tmp_string = cJSON_GetStringValue(value_object);
            if (tmp_string == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            memset(tmp_mac_key, 0, sizeof(tmp_mac_key));
            memset(&assoc_dev_data, 0, sizeof(assoc_dev_data));
            snprintf(tmp_mac_key, sizeof(tmp_mac_key), "%s", tmp_string);
            str_to_mac_bytes(tmp_string, mac);
            memcpy(assoc_dev_data.dev_stats.cli_MACAddress, mac, 6);

            if (assoclist_type == assoclist_type_remove) {
                assoc_dev_data.client_state = client_state_disconnected;
            } else {
                assoc_dev_data.client_state = client_state_connected;
            }

            value_object = cJSON_GetObjectItem(assoc_client, "WpaKeyMgmt");
            if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            tmp_string  = cJSON_GetStringValue(value_object);
            if (tmp_string == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            strncpy(assoc_dev_data.conn_security.wpa_key_mgmt, tmp_string, sizeof(assoc_dev_data.conn_security.wpa_key_mgmt));


            value_object = cJSON_GetObjectItem(assoc_client, "PairwiseCipher");
            if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            tmp_string  = cJSON_GetStringValue(value_object);
            if (tmp_string == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            strncpy(assoc_dev_data.conn_security.pairwise_cipher, tmp_string, sizeof(assoc_dev_data.conn_security.pairwise_cipher));


            value_object = cJSON_GetObjectItem(assoc_client, "AuthenticationState");
            if ((value_object == NULL) || (cJSON_IsBool(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_AuthenticationState = (value_object->type & cJSON_True) ? true:false;

            value_object = cJSON_GetObjectItem(assoc_client, "LastDataDownlinkRate");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_LastDataDownlinkRate = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "LastDataUplinkRate");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_LastDataUplinkRate = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "SignalStrength");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_SignalStrength = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "Retransmissions");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_Retransmissions = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "Active");
            if ((value_object == NULL) || (cJSON_IsBool(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_Active = (value_object->type & cJSON_True) ? true:false;

            value_object = cJSON_GetObjectItem(assoc_client, "OperatingStandard");
            if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            tmp_string  = cJSON_GetStringValue(value_object);
            if (tmp_string == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            memcpy(assoc_dev_data.dev_stats.cli_OperatingStandard, tmp_string, strlen(tmp_string)+1);

            value_object = cJSON_GetObjectItem(assoc_client, "OperatingChannelBandwidth");
            if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            tmp_string  = cJSON_GetStringValue(value_object);
            if (tmp_string == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            memcpy(assoc_dev_data.dev_stats.cli_OperatingChannelBandwidth, tmp_string, strlen(tmp_string)+1);

            value_object = cJSON_GetObjectItem(assoc_client, "SNR");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_SNR = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "InterferenceSources");
            if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }

            tmp_string  = cJSON_GetStringValue(value_object);
            if (tmp_string == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            memcpy(assoc_dev_data.dev_stats.cli_InterferenceSources, tmp_string, strlen(tmp_string)+1);

            value_object = cJSON_GetObjectItem(assoc_client, "DataFramesSentAck");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_DataFramesSentAck = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "DataFramesSentNoAck");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_DataFramesSentNoAck = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "BytesSent");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_BytesSent = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "BytesReceived");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_BytesReceived = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "RSSI");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_RSSI = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "MinRSSI");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_MinRSSI = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "MaxRSSI");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_MaxRSSI = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "Disassociations");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_Disassociations = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "AuthenticationFailures");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_AuthenticationFailures = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "PacketsSent");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_PacketsSent = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "PacketsReceived");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_PacketsReceived = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "ErrorsSent");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_ErrorsSent = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "RetransCount");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_RetransCount = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "FailedRetransCount");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_FailedRetransCount = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "RetryCount");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_RetryCount = value_object->valuedouble;

            value_object = cJSON_GetObjectItem(assoc_client, "MultipleRetryCount");
            if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            assoc_dev_data.dev_stats.cli_MultipleRetryCount = value_object->valuedouble;

            if (decode_frame_data(assoc_client, &assoc_dev_data.sta_data.msg_data) !=
                webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Decode frame data failed for client %s\n",
                    __func__, __LINE__, tmp_mac_key);
            }

            if (associated_devices_map != NULL) {
                str_tolower(tmp_mac_key);
                tmp_assoc_dev_data = hash_map_get(associated_devices_map, tmp_mac_key);
                if (tmp_assoc_dev_data == NULL) {
                    tmp_assoc_dev_data = (assoc_dev_data_t *)malloc(sizeof(assoc_dev_data_t));
                    if (tmp_assoc_dev_data == NULL) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: tmp_assoc_dev_data is NULL for %d\n", __func__, __LINE__, i);
                        return webconfig_error_decode;
                    }
                    memcpy(tmp_assoc_dev_data, &assoc_dev_data, sizeof(assoc_dev_data_t));
                    hash_map_put(associated_devices_map, strdup(tmp_mac_key), tmp_assoc_dev_data);
                } else {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mac %s is already present for %d\n", __func__, __LINE__, tmp_mac_key, rdk_vap_info->vap_index);
                }
            }
        }
    }

    return webconfig_error_none;
}

webconfig_error_t decode_mac_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *obj_array )
{
    if ((rdk_vap_info == NULL) || (obj_array == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d MAC OBJECT decode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    mac_address_t mac;
    cJSON *client, *obj_acl, *mac_object, *device_name;
    const cJSON  *param;
    unsigned int size = 0, i = 0;
    acl_entry_t *acl_entry, *tmp_acl_entry;

    obj_acl =  cJSON_GetObjectItem(obj_array, "MACFilterList");

    size = cJSON_GetArraySize(obj_acl);

    rdk_vap_info->acl_map = NULL;

    for (i=0; i<size; i++) {
        mac_object  = cJSON_GetArrayItem(obj_acl, i);
        client = cJSON_GetObjectItem(mac_object, "MAC");
        char *tmp_mac = cJSON_GetStringValue(client);

        str_to_mac_bytes(tmp_mac, mac);

        acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
        if (acl_entry == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        memset(acl_entry, 0, (sizeof(acl_entry_t)));

        if(!rdk_vap_info->acl_map) {
            rdk_vap_info->acl_map = hash_map_create();
        }
        memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
        device_name = cJSON_GetObjectItem(mac_object, "DeviceName");
        if ((device_name == NULL) || (cJSON_IsString(device_name) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(acl_entry);
            return webconfig_error_decode;
        }
        char *tmp_device_name = cJSON_GetStringValue(device_name);
        if (tmp_device_name == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(acl_entry);
            return webconfig_error_decode;
        }
        strncpy(acl_entry->device_name, tmp_device_name, sizeof(acl_entry->device_name)-1);
        decode_param_integer(mac_object, "reason", param);
        acl_entry->reason = param->valuedouble;
        decode_param_integer(mac_object, "expiry_time", param);
        acl_entry->expiry_time = param->valuedouble;

        str_tolower(tmp_mac);
        tmp_acl_entry = hash_map_get(rdk_vap_info->acl_map, tmp_mac);
        if (tmp_acl_entry == NULL) {
            hash_map_put(rdk_vap_info->acl_map, strdup(tmp_mac), acl_entry);
        } else {
            memcpy(tmp_acl_entry, acl_entry, sizeof(acl_entry_t));
            free(acl_entry);
            acl_entry = NULL;
        }
    }

    return webconfig_error_none;
}

webconfig_error_t decode_levl_object(const cJSON *levl_cfg, levl_config_t *levl_config)
{
    const cJSON  *param;

    //clientMac
    decode_param_string(levl_cfg, "clientMac", param);
    str_to_mac_bytes(param->valuestring, levl_config->clientMac);

    //maxNumberCSIClients
    decode_param_integer(levl_cfg, "maxNumberCSIClients", param);
    levl_config->max_num_csi_clients = param->valuedouble;

    //Duration
    decode_param_integer(levl_cfg, "Duration", param);
    levl_config->levl_sounding_duration = param->valuedouble;

    //Interval
    decode_param_integer(levl_cfg, "Interval", param);
    levl_config->levl_publish_interval = param->valuedouble;

    return webconfig_error_none;
}

webconfig_error_t decode_memwraptool_object(const cJSON *memwraptool_cfg,
    memwraptool_config_t *memwrap_info)
{
    const cJSON *param;

    decode_param_bool(memwraptool_cfg, "enable", param);
    memwrap_info->enable = (param->type & cJSON_True) ? true : false;

    decode_param_integer(memwraptool_cfg, "rss_check_interval", param);
    memwrap_info->rss_check_interval = param->valuedouble;

    decode_param_integer(memwraptool_cfg, "rss_threshold", param);
    memwrap_info->rss_threshold = param->valuedouble;

    decode_param_integer(memwraptool_cfg, "rss_maxlimit", param);
    memwrap_info->rss_maxlimit = param->valuedouble;

    decode_param_integer(memwraptool_cfg, "heapwalk_duration", param);
    memwrap_info->heapwalk_duration = param->valuedouble;

    decode_param_integer(memwraptool_cfg, "heapwalk_interval", param);
    memwrap_info->heapwalk_interval = param->valuedouble;
    return webconfig_error_none;
}

webconfig_error_t decode_preassoc_cac_object(const cJSON *preassoc, wifi_preassoc_control_t *preassoc_info)
{
    const cJSON *param;
    int val, ret;
    // RssiUpThreshold
    decode_param_allow_empty_string(preassoc, "RssiUpThreshold", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->rssi_up_threshold, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: -90 to -50\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val > -50 || val < -95) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)preassoc_info->rssi_up_threshold, param->valuestring);
    }

    // SnrThreshold
    decode_param_allow_empty_string(preassoc, "SnrThreshold", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->snr_threshold, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val < 1 || val > 100) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)preassoc_info->snr_threshold, param->valuestring);
    }

     // CuThreshold
    decode_param_allow_empty_string(preassoc, "CuThreshold", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->cu_threshold, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val < 0 || val > 100) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)preassoc_info->cu_threshold, param->valuestring);
    }

    // basic_data_transmit_rate
    decode_param_allow_empty_string(preassoc, "BasicDataTransmitRates", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->basic_data_transmit_rates, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)preassoc_info->basic_data_transmit_rates, param->valuestring);
    }

     // operational_data_transmit_rate
    decode_param_allow_empty_string(preassoc, "OperationalDataTransmitRates", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->operational_data_transmit_rates, "disabled");
    } else {
        strcpy((char *)preassoc_info->operational_data_transmit_rates, param->valuestring);
    }

     // supported_data_transmit_rate
    decode_param_allow_empty_string(preassoc, "SupportedDataTransmitRates", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->supported_data_transmit_rates, "disabled");
    } else {
        strcpy((char *)preassoc_info->supported_data_transmit_rates, param->valuestring);
    }

     // minimum_advertised_mcs
    decode_param_allow_empty_string(preassoc, "MinimumAdvertisedMCS", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->minimum_advertised_mcs, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Incorrect format\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }
        if ( val < 0 || val > 7) {
          wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Incorrect value, value should be withing 0 to 7\n", __FUNCTION__,__LINE__);
          return webconfig_error_decode;
        }
        strcpy((char *)preassoc_info->minimum_advertised_mcs, param->valuestring);
    }

     //6GOpInfoMinRate
    if (cJSON_GetObjectItem(preassoc,"6GOpInfoMinRate")) {
        decode_param_allow_empty_string(preassoc, "6GOpInfoMinRate", param);

        if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
            strcpy((char *)preassoc_info->sixGOpInfoMinRate, "disabled");
        } else {
            strcpy((char *)preassoc_info->sixGOpInfoMinRate, param->valuestring);
        }
   }
   else {
            strcpy((char *)preassoc_info->sixGOpInfoMinRate, "disabled");
   }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoding preassoc settings passed\n", __func__, __LINE__);

    return webconfig_error_none;
}

webconfig_error_t decode_tcm_preassoc_object(const cJSON *preassoc, wifi_preassoc_control_t *preassoc_info)
{
    const cJSON *param;
    int ret;
    float fval;

    decode_param_integer(preassoc, "TcmWaitTime", param);
    preassoc_info->time_ms = param->valuedouble;

    decode_param_integer(preassoc, "TcmMinMgmtFrames", param);
    preassoc_info->min_num_mgmt_frames = param->valuedouble;

    decode_param_allow_empty_string(preassoc, "TcmExpWeightage", param);
    if ((strcmp(param->valuestring, TCM_EXPWEIGHT) == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->tcm_exp_weightage, TCM_EXPWEIGHT);
    } else {
        ret = sscanf(param->valuestring, "%f", &fval);

        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Incorrect format.\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)preassoc_info->tcm_exp_weightage, param->valuestring);
    }

    decode_param_allow_empty_string(preassoc, "TcmGradientThreshold", param);
    if ((strcmp(param->valuestring, TCM_GRADTHRESHOLD) == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)preassoc_info->tcm_gradient_threshold, TCM_GRADTHRESHOLD);
    } else {
        ret = sscanf(param->valuestring, "%f", &fval);

        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Incorrect format \n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)preassoc_info->tcm_gradient_threshold, param->valuestring);
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoding tcm preassoc settings passed\n", __func__, __LINE__);

    return webconfig_error_none;
}


webconfig_error_t decode_postassoc_cac_object(const cJSON *postassoc, wifi_postassoc_control_t *postassoc_info)
{
    const cJSON *param;
    int val, ret;

     // RssiUpThreshold
    decode_param_allow_empty_string(postassoc, "RssiUpThreshold", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)postassoc_info->rssi_up_threshold, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val > -50 || val < -95) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)postassoc_info->rssi_up_threshold, param->valuestring);
    }

    // SamplingInterval
    decode_param_allow_empty_string(postassoc, "SamplingInterval", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)postassoc_info->sampling_interval, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val < 1 || val > 10) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)postassoc_info->sampling_interval, param->valuestring);
    }

    // SnrThreshold
    decode_param_allow_empty_string(postassoc, "SnrThreshold", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)postassoc_info->snr_threshold, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val < 1 || val > 100) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)postassoc_info->snr_threshold, param->valuestring);
    }

    // SamplingCount
    decode_param_allow_empty_string(postassoc, "SamplingCount", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)postassoc_info->sampling_count, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val < 1 || val > 10) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)postassoc_info->sampling_count, param->valuestring);
    }

     // CuThreshold
    decode_param_allow_empty_string(postassoc, "CuThreshold", param);

    if ((strcmp(param->valuestring, "disabled") == 0) || (strlen(param->valuestring) == 0)) {
        strcpy((char *)postassoc_info->cu_threshold, "disabled");
    } else {
        ret = sscanf(param->valuestring, "%d", &val);

        /*String should be in format of range between two integers*/
        if (ret != 1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Incorrect format. Example: 10 to 100\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        if (val < 10 || val > 100) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d %s Value is out of supported range\n", __FUNCTION__,__LINE__);
            return webconfig_error_decode;
        }

        strcpy((char *)postassoc_info->cu_threshold, param->valuestring);
    }

    return webconfig_error_none;
}

webconfig_error_t decode_cac_object(wifi_vap_info_t *vap_info, cJSON *obj_array )
{
    const cJSON *preassoc, *postassoc;

    decode_param_object(obj_array, "PreAssociationDeny", preassoc);
    if (decode_preassoc_cac_object(preassoc, &vap_info->u.bss_info.preassoc) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: preassoc cac objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(obj_array, "TcmPreAssociationDeny", preassoc);
    if (decode_tcm_preassoc_object(preassoc, &vap_info->u.bss_info.preassoc) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: tcm preassoc  objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(obj_array, "PostAssociationDeny", postassoc);
    if (decode_postassoc_cac_object(postassoc, &vap_info->u.bss_info.postassoc) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: postassoc cac objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_blaster_object(const cJSON *blaster_cfg, active_msmt_t *blaster_info)
{
    const cJSON  *param;
    cJSON *stepobj;
    const cJSON  *obj_array;
    int length = 0, i = 0;

    // ActiveMsmtEnabled
    decode_param_bool(blaster_cfg, "ActiveMsmtEnable", param);
    blaster_info->ActiveMsmtEnable = (param->type & cJSON_True) ? true:false;

    //ActiveMsmtPktsize
    decode_param_integer(blaster_cfg, "ActiveMsmtPktsize", param);
    blaster_info->ActiveMsmtPktSize = param->valuedouble;

    //ActiveMsmtNumSamples
    decode_param_integer(blaster_cfg, "ActiveMsmtNumberOfSamples", param);
    blaster_info->ActiveMsmtNumberOfSamples = param->valuedouble;

    //ActiveMsmtSampleDuration
    decode_param_integer(blaster_cfg, "ActiveMsmtSampleDuration", param);
    blaster_info->ActiveMsmtSampleDuration = param->valuedouble;

    decode_param_string(blaster_cfg, "PlanId", param);
    strncpy((char *)blaster_info->PlanId, param->valuestring, sizeof(blaster_info->PlanId) - 1);

    decode_param_array(blaster_cfg, "Step", obj_array);
    length = cJSON_GetArraySize(obj_array);

    for (i = 0; i < length; i++) {
        stepobj = cJSON_GetArrayItem(obj_array, i);
        decode_param_integer(stepobj, "StepId", param);
        blaster_info->Step[i].StepId = param->valuedouble;

        decode_param_blaster_mac(stepobj, "SrcMac", param);
        strcpy((char *)blaster_info->Step[i].SrcMac, param->valuestring);

        decode_param_blaster_mac(stepobj, "DestMac", param);
        strcpy((char *)blaster_info->Step[i].DestMac, param->valuestring);
    }

    decode_param_integer(blaster_cfg, "Status", param);
    blaster_info->Status = param->valuedouble;

    decode_param_blaster_mqtt_topic(blaster_cfg, "MQTT Topic", param);
    strcpy((char *)blaster_info->blaster_mqtt_topic, param->valuestring);

    decode_param_blaster_trace_info(blaster_cfg, "traceParent", param);
    strcpy((char *)blaster_info->t_header.traceParent, param->valuestring);

    decode_param_blaster_trace_info(blaster_cfg, "traceState", param);
    strcpy((char *)blaster_info->t_header.traceState, param->valuestring);

    return webconfig_error_none;
}

webconfig_error_t decode_harvester_object(const cJSON *obj, instant_measurement_config_t *harvester)
{
    const cJSON  *param;

    decode_param_bool(obj, "Enabled", param);
    harvester->b_inst_client_enabled = (param->type & cJSON_True) ? true:false;
    decode_param_string(obj, "MacAddress", param);
    strcpy(harvester->mac_address, param->valuestring);
    decode_param_integer(obj, "ReportingPeriod", param);
    harvester->u_inst_client_reporting_period = param->valuedouble;
    decode_param_integer(obj, "DefReportingPeriod", param);
    harvester->u_inst_client_def_reporting_period = param->valuedouble;
    decode_param_integer(obj, "DefOverrideTTL", param);
    harvester->u_inst_client_def_override_ttl = param->valuedouble;

    return webconfig_error_none;
}

webconfig_error_t decode_wifivapcap(wifi_interface_name_idex_map_t *interface_map, cJSON *object)
{
    cJSON *value_object;
    char *tmp_string;

        value_object = cJSON_GetObjectItem(object, "VapName");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        tmp_string = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        strncpy(interface_map->vap_name, tmp_string, sizeof(interface_map->vap_name)-1);

        value_object = cJSON_GetObjectItem(object, "PhyIndex");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        interface_map->phy_index = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(object, "RadioIndex");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        interface_map->rdk_radio_index = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(object, "InterfaceName");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        tmp_string = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        strncpy(interface_map->interface_name, tmp_string, sizeof(interface_map->interface_name) - 1);

        value_object = cJSON_GetObjectItem(object, "BridgeName");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        tmp_string = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        strncpy(interface_map->bridge_name, tmp_string, sizeof(interface_map->bridge_name) - 1);

        value_object = cJSON_GetObjectItem(object, "VLANID");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        interface_map->vlan_id = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(object, "Index");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        interface_map->index = value_object->valuedouble;

        return webconfig_error_none;
}

webconfig_error_t decode_wifiradiointerfacecap(radio_interface_mapping_t *radio_interface_map, cJSON *object)
{
    cJSON *value_object;
    char *tmp_string;

    value_object = cJSON_GetObjectItem(object, "PhyIndex");
    if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    radio_interface_map->phy_index = value_object->valuedouble;

    value_object = cJSON_GetObjectItem(object, "RadioIndex");
    if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    radio_interface_map->radio_index = value_object->valuedouble;

    value_object = cJSON_GetObjectItem(object, "InterfaceName");
    if ((value_object == NULL) || (cJSON_IsString(value_object) == false)){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    tmp_string = cJSON_GetStringValue(value_object);
    if (tmp_string == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    strncpy(radio_interface_map->interface_name, tmp_string, sizeof(radio_interface_map->interface_name) - 1);

    return webconfig_error_none;
}

webconfig_error_t decode_csi_object(queue_t** csi_queue, cJSON *object)
{
    unsigned int size, itr, count=0;
    char *tmp_string;
    cJSON *obj_mac, *value_object, *obj_array;

    csi_data_t *csi_data  = (csi_data_t *)malloc(sizeof(csi_data_t));
    if (csi_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Data Pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }
    memset(csi_data, 0, sizeof(csi_data_t));

    obj_array = cJSON_GetObjectItem(object, "MACArray");
    if ((obj_array == NULL) && (cJSON_IsArray(obj_array) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
        free(csi_data);
        return webconfig_error_decode;
    }
    size = cJSON_GetArraySize(obj_array);
    if ((size > CSI_CLIENT_PER_SESSION)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid Array size %d\n", __func__, __LINE__, size);
        free(csi_data);
        return webconfig_error_decode;
    }
    for (itr=0; itr<size; itr++) {
        obj_mac = cJSON_GetArrayItem(obj_array, itr);
        if (obj_mac == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer \n", __func__, __LINE__);
            free(csi_data);
            return webconfig_error_decode;
        }

        value_object = cJSON_GetObjectItem(obj_mac, "macaddress");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(csi_data);
            return webconfig_error_decode;
        }

        tmp_string = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            free(csi_data);
            return webconfig_error_decode;
        }
        str_to_mac_bytes(tmp_string, csi_data->csi_client_list[itr]);
        count++;
    }
    csi_data->csi_client_count = count;

    value_object = cJSON_GetObjectItem(object, "SessionID");
    if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
        free(csi_data);
        return webconfig_error_decode;
    }

    csi_data->csi_session_num = value_object->valuedouble;

    value_object = cJSON_GetObjectItem(object, "Enabled");
    if ((value_object == NULL) || (cJSON_IsBool(value_object) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
        free(csi_data);
        return webconfig_error_decode;
    }

    csi_data->enabled = (value_object->type & cJSON_True) ? true:false;
    if (*csi_queue == NULL) {
        *csi_queue = queue_create();
    }
    queue_push(*csi_queue, csi_data);
    return webconfig_error_none;
}

webconfig_error_t decode_wifiradiocap(wifi_platform_property_t *wifi_prop, cJSON *obj_wificap)
{
    cJSON *allowed_channels, *iterator, *allowed_channelwidths;
    int count = 0, i, size = 0, chanwidth = 0;
    cJSON *value_object, *object;
    wifi_radio_capabilities_t *radio_cap;

    if (wifi_prop == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s %d: Input arguements is NULL\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    size = cJSON_GetArraySize(obj_wificap);

    for (i = 0; i < size; i++) {
         object  = cJSON_GetArrayItem(obj_wificap, i);
         radio_cap = &wifi_prop->radiocap[i];
         value_object = cJSON_GetObjectItem(object, "RadioIndex");
         if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
             wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
             return webconfig_error_decode;
         }

         radio_cap->index = value_object->valuedouble;

         /*allowed_channels*/
         allowed_channels = cJSON_GetObjectItem(object, "PossibleChannels");
         if (allowed_channels == NULL) {
             wifi_util_error_print(WIFI_WEBCONFIG,"%s %d: allowed_channels is NULL for index : %d radio_cap->ifaceName : %s\n",__FUNCTION__, __LINE__, radio_cap->index, radio_cap->ifaceName);
             return webconfig_error_decode;
         }

         count = 0;
         cJSON_ArrayForEach(iterator, allowed_channels) {
             if (cJSON_IsNumber(iterator)) {
                 radio_cap->channel_list[0].channels_list[count] = iterator->valuedouble;
                 count++;
             }
         }
         radio_cap->channel_list[0].num_channels = count;

         /*allowed_channelwidths*/
         allowed_channelwidths = cJSON_GetObjectItem(object, "PossibleChannelWidths");
         if (allowed_channelwidths == NULL) {
             wifi_util_error_print(WIFI_WEBCONFIG,"%s %d: PossibleChannelWidths is NULL for index : %d radio_cap->ifaceName : %s\n",__FUNCTION__, __LINE__, radio_cap->index, radio_cap->ifaceName);
             return webconfig_error_decode;
         }

         chanwidth = 0 ;
         cJSON_ArrayForEach(iterator, allowed_channelwidths) {
             if (cJSON_IsNumber(iterator)) {
                 chanwidth = iterator->valuedouble;
                 radio_cap->channelWidth[0] |= chanwidth;
             }
         }
         radio_cap->numSupportedFreqBand = 1;

         value_object = cJSON_GetObjectItem(object, "RadioPresence");
         if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
             wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
             return webconfig_error_decode;
         }
         wifi_prop->radio_presence[i] = value_object->valuedouble;
    }
    return webconfig_error_none;
}

webconfig_error_t decode_stats_config_object(hash_map_t **stats_map, cJSON *st_arr_obj)
{
    char key[32] = {0};
    unsigned char id[32] = {0};
    stats_config_t temp_sta_cfg;
    stats_config_t *sta_cfg;
    cJSON *st_obj, *iterator, *channel_list;
    unsigned int size = 0, i = 0;
    int count = 0;

    if (st_arr_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: cjson st_arr_obj is NULL \n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    size = cJSON_GetArraySize(st_arr_obj);
    if (*stats_map == NULL) {
        *stats_map = hash_map_create();
    }

    for (i = 0; i < size; i++) {
        st_obj = cJSON_GetArrayItem(st_arr_obj, i);
        if (st_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer for : %d \n", __func__, __LINE__, i);
            return webconfig_error_decode;
        }


        memset(&temp_sta_cfg, 0, sizeof(stats_config_t));

        cJSON *param;
        decode_param_integer(st_obj, "StatsType", param);
        temp_sta_cfg.stats_type = param->valuedouble;
        decode_param_integer(st_obj, "ReportType", param);
        temp_sta_cfg.report_type = param->valuedouble;
        decode_param_integer(st_obj, "RadioType", param);
        temp_sta_cfg.radio_type = param->valuedouble;
        decode_param_integer(st_obj, "SurveyType", param);
        temp_sta_cfg.survey_type = param->valuedouble;
        decode_param_integer(st_obj, "ReportingInterval", param);
        temp_sta_cfg.reporting_interval = param->valuedouble;
        decode_param_integer(st_obj, "ReportingCount", param);
        temp_sta_cfg.reporting_count = param->valuedouble;
        decode_param_integer(st_obj, "SamplingInterval", param);
        temp_sta_cfg.sampling_interval = param->valuedouble;
        decode_param_integer(st_obj, "SurveyInterval", param);
        temp_sta_cfg.survey_interval = param->valuedouble;
        decode_param_integer(st_obj, "ThresholdUtil", param);
        temp_sta_cfg.threshold_util = param->valuedouble;
        decode_param_integer(st_obj, "ThresholdMaxDelay", param);
        temp_sta_cfg.threshold_max_delay = param->valuedouble;

        channel_list = cJSON_GetObjectItem(st_obj, "ChannelList");
        if (channel_list != NULL) {
            count = 0;
            cJSON_ArrayForEach(iterator, channel_list) {
                if (cJSON_IsNumber(iterator)) {
                    temp_sta_cfg.channels_list.channels_list[count] = iterator->valuedouble;
                    count++;
                }
            }
            temp_sta_cfg.channels_list.num_channels = count;
        }

        memset(key, 0, sizeof(key));
        memset(id, 0, sizeof(id));
        if (get_stats_cfg_id(key, sizeof(key), id, sizeof(id), temp_sta_cfg.stats_type, temp_sta_cfg.report_type,
                    temp_sta_cfg.radio_type, temp_sta_cfg.survey_type) == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_stats_cfg_id failed %d\n", __func__, __LINE__, i);
            return webconfig_error_decode;
        }

        snprintf(temp_sta_cfg.stats_cfg_id, sizeof(temp_sta_cfg.stats_cfg_id), "%s", key);
        if (*stats_map != NULL) {
            sta_cfg = hash_map_get(*stats_map, key);
            if (sta_cfg == NULL) {
                sta_cfg = (stats_config_t *)malloc(sizeof(stats_config_t));
                if (sta_cfg == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stat_config is NULL for %d\n", __func__, __LINE__, i);
                    return webconfig_error_decode;
                }
                memset(sta_cfg, 0, sizeof(stats_config_t));
                memcpy(sta_cfg, &temp_sta_cfg, sizeof(stats_config_t));
                hash_map_put(*stats_map, strdup(key), sta_cfg);
            } else {
                memcpy(sta_cfg, &temp_sta_cfg, sizeof(stats_config_t));
            }
        }
    }
    return webconfig_error_none;
}

webconfig_error_t decode_steering_config_object(hash_map_t **steer_map, cJSON *st_arr_obj)
{
    const cJSON  *param;
    cJSON *st_obj, *vap_name_array, *vap_name_obj;
    steering_config_t temp_st_cfg, *st_cfg;
    char key[64] = {0};
    unsigned char id[64] = {0};
    unsigned int size = 0, i = 0, vap_name_array_size = 0, j = 0, vap_name_list_count = 0;

    if (st_arr_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: cjson st_arr_obj is NULL \n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    size = cJSON_GetArraySize(st_arr_obj);

    if (*steer_map == NULL) {
        *steer_map = hash_map_create();
    }


    for (i = 0; i < size; i++) {
        st_obj = cJSON_GetArrayItem(st_arr_obj, i);
        if (st_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        memset(&temp_st_cfg, 0, sizeof(steering_config_t));

        vap_name_array = cJSON_GetObjectItem(st_obj, "VapNames");
        if ((vap_name_array == NULL) && (cJSON_IsObject(vap_name_array) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_name_array object not present\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        vap_name_array_size = cJSON_GetArraySize(vap_name_array);

        for (j = 0; j<vap_name_array_size; j++) {
            vap_name_obj = cJSON_GetArrayItem(vap_name_array, j);
            if (vap_name_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            decode_param_string(vap_name_obj, "VapName", param);
            strcpy((char *)temp_st_cfg.vap_name_list[vap_name_list_count], param->valuestring);
            vap_name_list_count++;
        }
        temp_st_cfg.vap_name_list_len = vap_name_list_count;
        if (vap_name_list_count < 2) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_name list count : %d \n", __func__, __LINE__, vap_name_list_count);
            return webconfig_error_decode;
        }

        decode_param_integer(st_obj, "ChanUtilAvgCount", param);
        temp_st_cfg.chan_util_avg_count = param->valuedouble;
        decode_param_integer(st_obj, "ChanUtilCheckSec", param);
        temp_st_cfg.chan_util_check_sec = param->valuedouble;
        decode_param_integer(st_obj, "ChanUtilHWM", param);
        temp_st_cfg.chan_util_hwm = param->valuedouble;
        decode_param_integer(st_obj, "ChanUtilLWM", param);
        temp_st_cfg.chan_util_lwm = param->valuedouble;
        decode_param_bool(st_obj, "Dbg2gRawChUtil", param);
        temp_st_cfg.dbg_2g_raw_chan_util = (param->type & cJSON_True) ? true:false;
        decode_param_bool(st_obj, "Dbg2gRawRSSI", param);
        temp_st_cfg.dbg_2g_raw_rssi = (param->type & cJSON_True) ? true:false;
        decode_param_bool(st_obj, "Dbg5gRawChUtil", param);
        temp_st_cfg.dbg_5g_raw_chan_util = (param->type & cJSON_True) ? true:false;
        decode_param_bool(st_obj, "Dbg5gRawChRSSI", param);
        temp_st_cfg.dbg_5g_raw_rssi = (param->type & cJSON_True) ? true:false;
        decode_param_integer(st_obj, "DbgLevel", param);
        temp_st_cfg.debug_level = param->valuedouble;
        decode_param_integer(st_obj, "DefRssiInactXing", param);
        temp_st_cfg.def_rssi_inact_xing = param->valuedouble;
        decode_param_integer(st_obj, "DefRssiLowXing", param);
        temp_st_cfg.def_rssi_low_xing = param->valuedouble;
        decode_param_integer(st_obj, "DefRssiXing", param);
        temp_st_cfg.def_rssi_xing = param->valuedouble;
        decode_param_bool(st_obj, "GwOnly", param);
        temp_st_cfg.gw_only = (param->type & cJSON_True) ? true:false;
        decode_param_integer(st_obj, "InactChkSec", param);
        temp_st_cfg.inact_check_sec = param->valuedouble;
        decode_param_integer(st_obj, "InactToutSecNormal", param);
        temp_st_cfg.inact_tmout_sec_normal = param->valuedouble;
        decode_param_integer(st_obj, "InactToutSecOverload", param);
        temp_st_cfg.inact_tmout_sec_overload = param->valuedouble;
        decode_param_integer(st_obj, "KickDebouncePeriod", param);
        temp_st_cfg.kick_debounce_period = param->valuedouble;
        decode_param_integer(st_obj, "KickDebounceThresh", param);
        temp_st_cfg.kick_debounce_thresh = param->valuedouble;
        decode_param_integer(st_obj, "StatsReportInterval", param);
        temp_st_cfg.stats_report_interval = param->valuedouble;
        decode_param_integer(st_obj, "SuccesssThreshSecs", param);
        temp_st_cfg.success_threshold_secs = param->valuedouble;

        memset(key, 0, sizeof(key));
        memset(id, 0, sizeof(id));
        if (get_steering_cfg_id(key, sizeof(key), id, sizeof(id), &temp_st_cfg) == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_steering_cfg_id failed %d\n", __func__, __LINE__, i);
            return webconfig_error_decode;
        }
        snprintf(temp_st_cfg.steering_cfg_id, sizeof(temp_st_cfg.steering_cfg_id), "%s", key);

        if (*steer_map != NULL) {
            st_cfg = hash_map_get(*steer_map, key);
            if (st_cfg == NULL) {
                st_cfg = (steering_config_t *)malloc(sizeof(steering_config_t));
                if (st_cfg == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: st_config is NULL for %d\n", __func__, __LINE__, i);
                    return webconfig_error_decode;
                }
                memset(st_cfg, 0, sizeof(steering_config_t));
                memcpy(st_cfg, &temp_st_cfg, sizeof(steering_config_t));
                hash_map_put(*steer_map, strdup(key), st_cfg);
            } else {
                memcpy(st_cfg, &temp_st_cfg, sizeof(steering_config_t));
            }
        }
    }

    return webconfig_error_none;
}

webconfig_error_t decode_steering_clients_object(hash_map_t **steering_client_map, cJSON *st_arr_obj)
{
    const cJSON  *param;
    cJSON *st_obj, *param_arr, *param_obj;
    band_steering_clients_t temp_st_cfg, *st_cfg;
    char key[64] = {0};
    unsigned char id[64] = {0};
    unsigned int size = 0, i = 0, j = 0, param_arr_size;

    if (st_arr_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: cjson st_arr_obj is NULL \n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    size = cJSON_GetArraySize(st_arr_obj);

    if (*steering_client_map == NULL) {
        *steering_client_map = hash_map_create();
    }


    for (i = 0; i < size; i++) {
        st_obj = cJSON_GetArrayItem(st_arr_obj, i);
        if (st_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        memset(&temp_st_cfg, 0, sizeof(band_steering_clients_t));
        decode_param_string(st_obj, "Mac", param);
        strcpy((char *)temp_st_cfg.mac, param->valuestring);
        decode_param_integer(st_obj, "BackoffExpBase", param);
        temp_st_cfg.backoff_exp_base = param->valuedouble;
        decode_param_integer(st_obj, "BackoffSecs", param);
        temp_st_cfg.backoff_secs = param->valuedouble;
        decode_param_integer(st_obj, "Hwm", param);
        temp_st_cfg.hwm = param->valuedouble;
        decode_param_integer(st_obj, "Lwm", param);
        temp_st_cfg.lwm = param->valuedouble;
        decode_param_integer(st_obj, "KickDebouncePeriod", param);
        temp_st_cfg.kick_debounce_period = param->valuedouble;
        decode_param_integer(st_obj, "KickReason", param);
        temp_st_cfg.kick_reason = param->valuedouble;
        decode_param_bool(st_obj, "KickUponIdle", param);
        temp_st_cfg.kick_upon_idle = param->valuedouble;
        decode_param_integer(st_obj, "MaxRejects", param);
        temp_st_cfg.max_rejects = param->valuedouble;
        decode_param_bool(st_obj, "PreAssocAuthBlock", param);
        temp_st_cfg.pre_assoc_auth_block = param->valuedouble;
        decode_param_integer(st_obj, "RejectsTmoutSecs", param);
        temp_st_cfg.rejects_tmout_secs = param->valuedouble;
        decode_param_integer(st_obj, "ScKickDebouncePeriod", param);
        temp_st_cfg.sc_kick_debounce_period = param->valuedouble;
        decode_param_integer(st_obj, "ScKickReason", param);
        temp_st_cfg.sc_kick_reason = param->valuedouble;
        decode_param_bool(st_obj, "SteerDuringBackoff", param);
        temp_st_cfg.steer_during_backoff = param->valuedouble;
        decode_param_integer(st_obj, "SteeringFailCnt", param);
        temp_st_cfg.steering_fail_cnt = param->valuedouble;
        decode_param_integer(st_obj, "SteeringKickCnt", param);
        temp_st_cfg.steering_kick_cnt = param->valuedouble;
        decode_param_integer(st_obj, "SteeringSuccessCnt", param);
        temp_st_cfg.steering_success_cnt = param->valuedouble;
        decode_param_integer(st_obj, "StickyKickCnt", param);
        temp_st_cfg.sticky_kick_cnt = param->valuedouble;
        decode_param_integer(st_obj, "StickyKickDebouncePeriod", param);
        temp_st_cfg.sticky_kick_debounce_period = param->valuedouble;
        decode_param_integer(st_obj, "StickyKickReason", param);
        temp_st_cfg.sticky_kick_reason = param->valuedouble;
        decode_param_integer(st_obj, "CsMode", param);
        temp_st_cfg.cs_mode = param->valuedouble;
        decode_param_integer(st_obj, "ForceKick", param);
        temp_st_cfg.force_kick = param->valuedouble;
        decode_param_integer(st_obj, "KickType", param);
        temp_st_cfg.kick_type = param->valuedouble;
        decode_param_integer(st_obj, "Pref5g", param);
        temp_st_cfg.pref_5g = param->valuedouble;
        decode_param_integer(st_obj, "RejectDetection", param);
        temp_st_cfg.reject_detection = param->valuedouble;
        decode_param_integer(st_obj, "ScKickType", param);
        temp_st_cfg.sc_kick_type = param->valuedouble;
        decode_param_integer(st_obj, "StickyKickType", param);
        temp_st_cfg.sticky_kick_type = param->valuedouble;

        //CsParams
        param_arr = cJSON_GetObjectItem(st_obj, "CsParams");
        if ((param_arr == NULL) && (cJSON_IsObject(param_arr) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: param_arr object not present\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        param_arr_size = cJSON_GetArraySize(param_arr);

        for (j = 0; j<param_arr_size; j++) {
            param_obj = cJSON_GetArrayItem(param_arr, j);
            if (param_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            decode_param_string(param_obj, "Key", param);
            strcpy((char *)temp_st_cfg.cs_params[j].key, param->valuestring);
            decode_param_string(param_obj, "Value", param);
            strcpy((char *)temp_st_cfg.cs_params[j].value, param->valuestring);
        }
        temp_st_cfg.cs_params_len = j;

        //steering_btm_params
        param_arr = cJSON_GetObjectItem(st_obj, "SteeringBtmParams");
        if ((param_arr == NULL) && (cJSON_IsObject(param_arr) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: param_arr object not present\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        param_arr_size = cJSON_GetArraySize(param_arr);

        for (j = 0; j<param_arr_size; j++) {
            param_obj = cJSON_GetArrayItem(param_arr, j);
            if (param_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            decode_param_string(param_obj, "Key", param);
            strcpy((char *)temp_st_cfg.steering_btm_params[j].key, param->valuestring);
            decode_param_string(param_obj, "Value", param);
            strcpy((char *)temp_st_cfg.steering_btm_params[j].value, param->valuestring);
        }
        temp_st_cfg.steering_btm_params_len = j;

        //rrm_bcn_rpt_params
        param_arr = cJSON_GetObjectItem(st_obj, "RrmBcnRptParams");
        if ((param_arr == NULL) && (cJSON_IsObject(param_arr) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: param_arr object not present\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        param_arr_size = cJSON_GetArraySize(param_arr);

        for (j = 0; j<param_arr_size; j++) {
            param_obj = cJSON_GetArrayItem(param_arr, j);
            if (param_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            decode_param_string(param_obj, "Key", param);
            strcpy((char *)temp_st_cfg.rrm_bcn_rpt_params[j].key, param->valuestring);
            decode_param_string(param_obj, "Value", param);
            strcpy((char *)temp_st_cfg.rrm_bcn_rpt_params[j].value, param->valuestring);
        }
        temp_st_cfg.rrm_bcn_rpt_params_len = j;

        //sc_btm_params
        param_arr = cJSON_GetObjectItem(st_obj, "ScBtmParams");
        if ((param_arr == NULL) && (cJSON_IsObject(param_arr) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: param_arr object not present\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        param_arr_size = cJSON_GetArraySize(param_arr);

        for (j = 0; j<param_arr_size; j++) {
            param_obj = cJSON_GetArrayItem(param_arr, j);
            if (param_obj == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer \n", __func__, __LINE__);
                return webconfig_error_decode;
            }
            decode_param_string(param_obj, "Key", param);
            strcpy((char *)temp_st_cfg.sc_btm_params[j].key, param->valuestring);
            decode_param_string(param_obj, "Value", param);
            strcpy((char *)temp_st_cfg.sc_btm_params[j].value, param->valuestring);
        }
        temp_st_cfg.sc_btm_params_len = j;

        memset(key, 0, sizeof(key));
        memset(id, 0, sizeof(id));

        if (get_steering_clients_id(key, sizeof(key), id, sizeof(id), temp_st_cfg.mac) == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_steering_cfg_id failed %d\n", __func__, __LINE__, i);
            return webconfig_error_decode;
        }
        snprintf(temp_st_cfg.steering_client_id, sizeof(temp_st_cfg.steering_client_id), "%s", key);

        if (*steering_client_map != NULL) {
            st_cfg = hash_map_get(*steering_client_map, key);
            if (st_cfg == NULL) {
                st_cfg = (band_steering_clients_t *)malloc(sizeof(band_steering_clients_t));
                if (st_cfg == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: st_config is NULL for %d\n", __func__, __LINE__, i);
                    return webconfig_error_decode;
                }
                memset(st_cfg, 0, sizeof(band_steering_clients_t));
                memcpy(st_cfg, &temp_st_cfg, sizeof(band_steering_clients_t));
                hash_map_put(*steering_client_map, strdup(key), st_cfg);
            } else {
                memcpy(st_cfg, &temp_st_cfg, sizeof(band_steering_clients_t));
            }
        }
    }

    return webconfig_error_none;
}

webconfig_error_t decode_vif_neighbors_object(hash_map_t **neighbors_map, cJSON *neighbors_arr_obj)
{
    char key[32] = {0};
    vif_neighbors_t temp_neighbors_cfg;
    vif_neighbors_t *neighbors_cfg;
    cJSON *neighbors_obj;
    unsigned int size = 0, i = 0;
    unsigned char id[64] = {0};

    if (neighbors_arr_obj == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: cjson neighbors_arr_obj is NULL \n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    size = cJSON_GetArraySize(neighbors_arr_obj);
    if (*neighbors_map == NULL) {
        *neighbors_map = hash_map_create();
    }

    for (i = 0; i < size; i++) {
        neighbors_obj = cJSON_GetArrayItem(neighbors_arr_obj, i);
        if (neighbors_obj == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer for : %d \n", __func__, __LINE__, i);
            return webconfig_error_decode;
        }


        memset(&temp_neighbors_cfg, 0, sizeof(vif_neighbors_t));

        cJSON *param;

        decode_param_string(neighbors_obj, "Bssid", param);
        strcpy((char *)temp_neighbors_cfg.bssid, param->valuestring);
        decode_param_string(neighbors_obj, "IfName", param);
        strcpy((char *)temp_neighbors_cfg.if_name, param->valuestring);
        decode_param_integer(neighbors_obj, "Channel", param);
        temp_neighbors_cfg.channel = param->valuedouble;
        decode_param_integer(neighbors_obj, "HTMode", param);
        temp_neighbors_cfg.ht_mode = param->valuedouble;
        decode_param_integer(neighbors_obj, "Priority", param);
        temp_neighbors_cfg.priority = param->valuedouble;

        memset(key, 0, sizeof(key));
        memset(id, 0, sizeof(id));

        if (get_vif_neighbor_id(key, sizeof(key), id, sizeof(id), temp_neighbors_cfg.bssid) == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_vif_neighbor_id failed %d\n", __func__, __LINE__, i);
            return webconfig_error_decode;
        }

        snprintf(temp_neighbors_cfg.neighbor_id, sizeof(temp_neighbors_cfg.neighbor_id), "%s", key);
        if (*neighbors_map != NULL) {
            neighbors_cfg = hash_map_get(*neighbors_map, key);
            if (neighbors_cfg == NULL) {
                neighbors_cfg = (vif_neighbors_t *)malloc(sizeof(vif_neighbors_t));
                if (neighbors_cfg == NULL) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: neighbors_cfg is NULL for %d\n", __func__, __LINE__, i);
                    return webconfig_error_decode;
                }
                memset(neighbors_cfg, 0, sizeof(vif_neighbors_t));
                memcpy(neighbors_cfg, &temp_neighbors_cfg, sizeof(vif_neighbors_t));
                hash_map_put(*neighbors_map, strdup(key), neighbors_cfg);
            } else {
                memcpy(neighbors_cfg, &temp_neighbors_cfg, sizeof(vif_neighbors_t));
            }
        }
    }
    return webconfig_error_none;
}

webconfig_error_t decode_radio_channel_radio_stats_object(wifi_provider_response_t **chan_stats, cJSON *json)
{
    cJSON *radio_stats_arr;
    cJSON *radio_stats;
    const cJSON  *param;
    int size = 0;
    radio_chan_data_t *chan_data = NULL;
    wifi_neighborScanMode_t scan_mode;

    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: cjson object is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    radio_stats_arr = cJSON_GetObjectItem(json, "RadioChannelStats");
    if ((radio_stats_arr == NULL) && (cJSON_IsObject(radio_stats_arr) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Stats config object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    size = cJSON_GetArraySize(radio_stats_arr);

    *chan_stats = (wifi_provider_response_t*) calloc(1, sizeof(wifi_provider_response_t));
    if (*chan_stats == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_integer(json, "RadioIndex", param);
    (*chan_stats)->args.radio_index = param->valuedouble;

    decode_param_string(json, "ScanMode", param);
    if (scan_mode_type_conversion(&scan_mode, param->valuestring, MAX_SCAN_MODE_LEN, STRING_TO_ENUM) != RETURN_OK)  {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: scan_mode_type_conversion failed for %s\n", __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }
    (*chan_stats)->args.scan_mode = scan_mode;

    chan_data = (radio_chan_data_t*) malloc(sizeof(radio_chan_data_t) * size);
    if (chan_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    for (int count = 0; count < size; count++) {
        radio_stats = cJSON_GetArrayItem(radio_stats_arr, count);
        if (radio_stats == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer for : %d \n", __func__, __LINE__, count);
            return webconfig_error_decode;
        }

        decode_param_integer(radio_stats, "ChannelNumber", param);
        chan_data[count].ch_number = param->valuedouble;

        decode_param_integer(radio_stats, "ChannelNoise", param);
        chan_data[count].ch_noise = param->valuedouble;

        decode_param_bool(radio_stats, "RadarNoise", param);
        chan_data[count].ch_radar_noise = (param->type & cJSON_True) ? true:false;

        decode_param_integer(radio_stats, "RSSI", param);
        chan_data[count].ch_max_80211_rssi = param->valuedouble;

        decode_param_integer(radio_stats, "Non80211Noise", param);
        chan_data[count].ch_non_80211_noise = param->valuedouble;

        decode_param_integer(radio_stats, "ChannelUtilization", param);
        chan_data[count].ch_utilization = param->valuedouble;

        decode_param_integer(radio_stats,"TotalUtilization", param);
        chan_data[count].ch_utilization_total = param->valuedouble;

        decode_param_integer(radio_stats, "UtilizationBusy", param);
        chan_data[count].ch_utilization_busy = param->valuedouble;

        decode_param_integer(radio_stats, "UtilizationBusyTx", param);
        chan_data[count].ch_utilization_busy_tx = param->valuedouble;

        decode_param_integer(radio_stats, "UtilizationBusyRx", param);
        chan_data[count].ch_utilization_busy_rx = param->valuedouble;

        decode_param_integer(radio_stats, "UtilizationBusySelf",  param);
        chan_data[count].ch_utilization_busy_self = param->valuedouble;

        decode_param_integer(radio_stats, "UtilizationBusyExt", param);
        chan_data[count].ch_utilization_busy_ext = param->valuedouble;
    }
    (*chan_stats)->stat_pointer = chan_data;
    (*chan_stats)->stat_array_size = size;

    return webconfig_error_none;
}

webconfig_error_t decode_radio_neighbor_stats_object(wifi_provider_response_t **chan_stats, cJSON *json)
{
    cJSON *neighbor_stats_arr;
    cJSON *neighbor_stats;
    const cJSON  *param;
    int size = 0;
    wifi_neighbor_ap2_t *neighbor_stats_data = NULL;
    wifi_neighborScanMode_t scan_mode;

    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: cjson object is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    neighbor_stats_arr = cJSON_GetObjectItem(json, "NeighborStats");
    if ((neighbor_stats_arr == NULL) && (cJSON_IsObject(neighbor_stats_arr) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Stats config object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    size = cJSON_GetArraySize(neighbor_stats_arr);

    *chan_stats = (wifi_provider_response_t*) calloc(1, sizeof(wifi_provider_response_t));
    if (*chan_stats == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_integer(json, "RadioIndex", param);
    (*chan_stats)->args.radio_index = param->valuedouble;

    decode_param_string(json, "ScanMode", param);
    if (scan_mode_type_conversion(&scan_mode, param->valuestring, MAX_SCAN_MODE_LEN, STRING_TO_ENUM) != RETURN_OK)  {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: scan_mode_type_conversion failed for %s\n", __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }
    (*chan_stats)->args.scan_mode = scan_mode;

    if (size == 0) {
        (*chan_stats)->stat_pointer = NULL;
        (*chan_stats)->stat_array_size = 0;
        wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: Neighbor stats array size is %d\n", __func__, __LINE__, (*chan_stats)->stat_array_size);
        return webconfig_error_none;
    } else {
        neighbor_stats_data = (wifi_neighbor_ap2_t*) malloc(sizeof(wifi_neighbor_ap2_t) * size);
        if (neighbor_stats_data == NULL) {
            free(*chan_stats);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
            return webconfig_error_decode;
        }
    }

    for (int count = 0; count < size; count++) {
        neighbor_stats = cJSON_GetArrayItem(neighbor_stats_arr, count);
        if (neighbor_stats == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer for : %d \n", __func__, __LINE__, count);
            return webconfig_error_decode;
        }

        param = cJSON_GetObjectItem(neighbor_stats, "ap_SSID");
        if ((param != NULL) && (param->valuestring != NULL)) {
            strncpy(neighbor_stats_data[count].ap_SSID, param->valuestring, sizeof(neighbor_stats_data[count].ap_SSID) - 1);
        }

        decode_param_string(neighbor_stats, "ap_BSSID", param);
        strncpy(neighbor_stats_data[count].ap_BSSID, param->valuestring, sizeof(neighbor_stats_data[count].ap_BSSID) - 1);

        decode_param_string(neighbor_stats, "ap_Mode", param);
        strncpy(neighbor_stats_data[count].ap_Mode, param->valuestring, sizeof(neighbor_stats_data[count].ap_Mode) - 1);

        decode_param_integer(neighbor_stats, "ap_Channel", param);
        neighbor_stats_data[count].ap_Channel = param->valuedouble;

        decode_param_integer(neighbor_stats, "ap_SignalStrength", param);
        neighbor_stats_data[count].ap_SignalStrength = param->valuedouble;

        decode_param_string(neighbor_stats, "ap_SecurityModeEnabled", param);
        strncpy(neighbor_stats_data[count].ap_SecurityModeEnabled, param->valuestring, sizeof(neighbor_stats_data[count].ap_SecurityModeEnabled) - 1);

        decode_param_string(neighbor_stats, "ap_EncryptionMode", param);
        strncpy(neighbor_stats_data[count].ap_EncryptionMode, param->valuestring, sizeof(neighbor_stats_data[count].ap_EncryptionMode) - 1);

        decode_param_string(neighbor_stats, "ap_OperatingFrequencyBand", param);
        strncpy(neighbor_stats_data[count].ap_OperatingFrequencyBand, param->valuestring, sizeof(neighbor_stats_data[count].ap_OperatingFrequencyBand) - 1);

        decode_param_string(neighbor_stats, "ap_SupportedStandards", param);
        strncpy(neighbor_stats_data[count].ap_SupportedStandards, param->valuestring, sizeof(neighbor_stats_data[count].ap_SupportedStandards) - 1);

        decode_param_string(neighbor_stats, "ap_OperatingStandards", param);
        strncpy(neighbor_stats_data[count].ap_OperatingStandards, param->valuestring, sizeof(neighbor_stats_data[count].ap_OperatingStandards) - 1);

        decode_param_string(neighbor_stats, "ap_OperatingChannelBandwidth", param);
        strncpy(neighbor_stats_data[count].ap_OperatingChannelBandwidth, param->valuestring, sizeof(neighbor_stats_data[count].ap_OperatingChannelBandwidth) - 1);

        decode_param_integer(neighbor_stats, "ap_BeaconPeriod", param);
        neighbor_stats_data[count].ap_BeaconPeriod = param->valuedouble;

        decode_param_integer(neighbor_stats, "ap_Noise", param);
        neighbor_stats_data[count].ap_Noise = param->valuedouble;

        decode_param_string(neighbor_stats, "ap_BasicDataTransferRates", param);
        strncpy(neighbor_stats_data[count].ap_BasicDataTransferRates, param->valuestring, sizeof(neighbor_stats_data[count].ap_BasicDataTransferRates) - 1);

        decode_param_string(neighbor_stats, "ap_SupportedDataTransferRates", param);
        strncpy(neighbor_stats_data[count].ap_SupportedDataTransferRates, param->valuestring, sizeof(neighbor_stats_data[count].ap_SupportedDataTransferRates) - 1);

        decode_param_integer(neighbor_stats, "ap_DTIMPeriod", param);
        neighbor_stats_data[count].ap_DTIMPeriod = param->valuedouble;

        decode_param_integer(neighbor_stats, "ap_ChannelUtilization", param);
        neighbor_stats_data[count].ap_ChannelUtilization = param->valuedouble;

    }
    (*chan_stats)->stat_pointer = neighbor_stats_data;
    (*chan_stats)->stat_array_size = size;

    return webconfig_error_none;
}

webconfig_error_t decode_assocdev_stats_object(wifi_provider_response_t **assoc_stats, cJSON *json)
{
    cJSON *assoc_stats_arr;
    cJSON *assoc_data;
    const cJSON *param;
    int size = 0;
    wifi_associated_dev3_t *client_stats_data = NULL;

    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: cjson object is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    assoc_stats_arr = cJSON_GetObjectItem(json, "AssociatedDeviceStats");
    if ((assoc_stats_arr == NULL) && (cJSON_IsObject(assoc_stats_arr) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Stats config object not present\n", __func__,
            __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    size = cJSON_GetArraySize(assoc_stats_arr);

    *assoc_stats = (wifi_provider_response_t*) calloc(1, sizeof(wifi_provider_response_t));
    if (*assoc_stats == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__,
            __LINE__);
        return webconfig_error_decode;
    }

    decode_param_integer(json, "VapIndex", param);
    (*assoc_stats)->args.vap_index = param->valuedouble;

    if (size == 0) {
        (*assoc_stats)->stat_pointer = NULL;
        (*assoc_stats)->stat_array_size = 0;
        wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: Associated Device stats array size is %d\n",
            __func__, __LINE__, (*assoc_stats)->stat_array_size);
        return webconfig_error_none;
    } else {
        client_stats_data = (wifi_associated_dev3_t *)malloc(sizeof(wifi_associated_dev3_t) * size);
        if (client_stats_data == NULL) {
            free(*assoc_stats);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__,
                __LINE__);
            return webconfig_error_decode;
        }
    }

    for (int count = 0; count < size; count++) {
        assoc_data = cJSON_GetArrayItem(assoc_stats_arr, count);
        if (assoc_data == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer for : %d \n", __func__,
                __LINE__, count);
            return webconfig_error_decode;
        }

        decode_param_string(assoc_data, "cli_MACAddress", param);
        string_mac_to_uint8_mac(client_stats_data[count].cli_MACAddress, param->valuestring);

        decode_param_bool(assoc_data, "cli_AuthenticationState", param);
        client_stats_data[count].cli_AuthenticationState = (param->type & cJSON_True) ? true :
                                                                                        false;

        decode_param_integer(assoc_data, "cli_LastDataDownlinkRate", param);
        client_stats_data[count].cli_LastDataDownlinkRate = param->valuedouble;

        decode_param_integer(assoc_data, "cli_LastDataUplinkRate", param);
        client_stats_data[count].cli_LastDataUplinkRate = param->valuedouble;

        decode_param_integer(assoc_data, "cli_SignalStrength", param);
        client_stats_data[count].cli_SignalStrength = param->valuedouble;

        decode_param_integer(assoc_data, "cli_Retransmissions", param);
        client_stats_data[count].cli_Retransmissions = param->valuedouble;

        decode_param_bool(assoc_data, "cli_Active", param);
        client_stats_data[count].cli_Active = (param->type & cJSON_True) ? true : false;

        decode_param_string(assoc_data, "cli_OperatingStandard", param);
        strncpy(client_stats_data[count].cli_OperatingStandard, param->valuestring,
            sizeof(client_stats_data[count].cli_OperatingStandard) - 1);

        decode_param_string(assoc_data, "cli_OperatingChannelBandwidth", param);
        strncpy(client_stats_data[count].cli_OperatingChannelBandwidth, param->valuestring,
            sizeof(client_stats_data[count].cli_OperatingChannelBandwidth) - 1);

        decode_param_integer(assoc_data, "cli_SNR", param);
        client_stats_data[count].cli_SNR = param->valuedouble;

        param = cJSON_GetObjectItem(assoc_data, "cli_InterferenceSources");
        if (param != NULL) {
            strncpy(client_stats_data[count].cli_InterferenceSources, param->valuestring,
                sizeof(client_stats_data[count].cli_InterferenceSources) - 1);
        }

        decode_param_integer(assoc_data, "cli_DataFramesSentAck", param);
        client_stats_data[count].cli_DataFramesSentAck = param->valuedouble;

        decode_param_integer(assoc_data, "cli_DataFramesSentNoAck", param);
        client_stats_data[count].cli_DataFramesSentNoAck = param->valuedouble;

        decode_param_integer(assoc_data, "cli_BytesSent", param);
        client_stats_data[count].cli_BytesSent = param->valuedouble;

        decode_param_integer(assoc_data, "cli_BytesReceived", param);
        client_stats_data[count].cli_BytesReceived = param->valuedouble;

        decode_param_integer(assoc_data, "cli_Retransmissions", param);
        client_stats_data[count].cli_Retransmissions = param->valuedouble;

        decode_param_integer(assoc_data, "cli_RSSI", param);
        client_stats_data[count].cli_RSSI = param->valuedouble;

        decode_param_integer(assoc_data, "cli_MinRSSI", param);
        client_stats_data[count].cli_MinRSSI = param->valuedouble;

        decode_param_integer(assoc_data, "cli_MaxRSSI", param);
        client_stats_data[count].cli_MaxRSSI = param->valuedouble;

        decode_param_integer(assoc_data, "cli_Disassociations", param);
        client_stats_data[count].cli_Disassociations = param->valuedouble;

        decode_param_integer(assoc_data, "cli_AuthenticationFailures", param);
        client_stats_data[count].cli_AuthenticationFailures = param->valuedouble;

        decode_param_integer(assoc_data, "cli_Associations", param);
        client_stats_data[count].cli_Associations = param->valuedouble;

        decode_param_integer(assoc_data, "cli_PacketsSent", param);
        client_stats_data[count].cli_PacketsSent = param->valuedouble;

        decode_param_integer(assoc_data, "cli_PacketsReceived", param);
        client_stats_data[count].cli_PacketsReceived = param->valuedouble;

        decode_param_integer(assoc_data, "cli_ErrorsSent", param);
        client_stats_data[count].cli_ErrorsSent = param->valuedouble;

        decode_param_integer(assoc_data, "cli_RetransCount", param);
        client_stats_data[count].cli_RetransCount = param->valuedouble;

        decode_param_integer(assoc_data, "cli_FailedRetransCount", param);
        client_stats_data[count].cli_FailedRetransCount = param->valuedouble;

        decode_param_integer(assoc_data, "cli_RetryCount", param);
        client_stats_data[count].cli_RetryCount = param->valuedouble;

        decode_param_integer(assoc_data, "cli_MultipleRetryCount", param);
        client_stats_data[count].cli_MultipleRetryCount = param->valuedouble;

        decode_param_integer(assoc_data, "cli_MaxDownlinkRate", param);
        client_stats_data[count].cli_MaxDownlinkRate = param->valuedouble;

        decode_param_integer(assoc_data, "cli_MaxUplinkRate", param);
        client_stats_data[count].cli_MaxUplinkRate = param->valuedouble;

        decode_param_integer(assoc_data, "cli_activeNumSpatialStreams", param);
        client_stats_data[count].cli_activeNumSpatialStreams = param->valuedouble;

        decode_param_integer(assoc_data, "cli_TxFrames", param);
        client_stats_data[count].cli_TxFrames = param->valuedouble;

        decode_param_integer(assoc_data, "cli_RxRetries", param);
        client_stats_data[count].cli_RxRetries = param->valuedouble;

        decode_param_integer(assoc_data, "cli_RxErrors", param);
        client_stats_data[count].cli_RxErrors = param->valuedouble;
    }
    (*assoc_stats)->stat_pointer = client_stats_data;
    (*assoc_stats)->stat_array_size = size;

    return webconfig_error_none;
}

webconfig_error_t decode_radiodiag_stats_object(wifi_provider_response_t **diag_stats, cJSON *json)
{
    cJSON *diag_stats_arr;
    cJSON *diag_data;
    const cJSON  *param;
    int size = 0;
    radio_data_t *diagnostic_data = NULL;

    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: cjson object is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    diag_stats_arr = cJSON_GetObjectItem(json, "RadioDiagnosticStats");
    if ((diag_stats_arr == NULL) && (cJSON_IsObject(diag_stats_arr) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Stats config object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    size = cJSON_GetArraySize(diag_stats_arr);

    *diag_stats = (wifi_provider_response_t*) calloc(1, sizeof(wifi_provider_response_t));
    if (*diag_stats == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_integer(json, "RadioIndex", param);
    (*diag_stats)->args.radio_index = param->valuedouble;

    diagnostic_data = (radio_data_t*) malloc(sizeof(radio_data_t) * size);
    if (diagnostic_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    for (int count = 0; count < size; count++) {
        diag_data = cJSON_GetArrayItem(diag_stats_arr, count);
        if (diag_data == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer for : %d \n", __func__, __LINE__, count);
            return webconfig_error_decode;
        }

        decode_param_integer(diag_data, "primary_radio_channel", param);
        diagnostic_data[count].primary_radio_channel = param->valuedouble;

        decode_param_integer(diag_data, "RadioActivityFactor", param);
        diagnostic_data[count].RadioActivityFactor = param->valuedouble;

        decode_param_integer(diag_data, "CarrierSenseThreshold_Exceeded", param);
        diagnostic_data[count].CarrierSenseThreshold_Exceeded = param->valuedouble;

        decode_param_integer(diag_data, "NoiseFloor", param);
        diagnostic_data[count].NoiseFloor = param->valuedouble;

        decode_param_integer(diag_data, "channelUtil", param);
        diagnostic_data[count].channelUtil = param->valuedouble;

        decode_param_integer(diag_data, "radio_BytesSent", param);
        diagnostic_data[count].radio_BytesSent = param->valuedouble;

        decode_param_integer(diag_data, "radio_BytesReceived", param);
        diagnostic_data[count].radio_BytesReceived = param->valuedouble;

        decode_param_integer(diag_data, "radio_PacketsSent", param);
        diagnostic_data[count].radio_PacketsSent = param->valuedouble;

        decode_param_integer(diag_data, "radio_PacketsReceived", param);
        diagnostic_data[count].radio_PacketsReceived = param->valuedouble;

        decode_param_integer(diag_data, "radio_ErrorsSent", param);
        diagnostic_data[count].radio_ErrorsSent = param->valuedouble;

        decode_param_integer(diag_data, "radio_ErrorsReceived", param);
        diagnostic_data[count].radio_ErrorsReceived = param->valuedouble;

        decode_param_integer(diag_data, "radio_DiscardPacketsSent", param);
        diagnostic_data[count].radio_DiscardPacketsSent = param->valuedouble;

        decode_param_integer(diag_data, "radio_DiscardPacketsReceived", param);
        diagnostic_data[count].radio_DiscardPacketsReceived = param->valuedouble;

        decode_param_integer(diag_data, "radio_InvalidMACCount", param);
        diagnostic_data[count].radio_InvalidMACCount = param->valuedouble;

        decode_param_integer(diag_data, "radio_PacketsOtherReceived", param);
        diagnostic_data[count].radio_PacketsOtherReceived = param->valuedouble;

        decode_param_integer(diag_data, "radio_RetransmissionMetirc", param);
        diagnostic_data[count].radio_RetransmissionMetirc = param->valuedouble;

        decode_param_integer(diag_data, "radio_PLCPErrorCount", param);
        diagnostic_data[count].radio_PLCPErrorCount = param->valuedouble;

        decode_param_integer(diag_data, "radio_FCSErrorCount", param);
        diagnostic_data[count].radio_FCSErrorCount = param->valuedouble;

        decode_param_integer(diag_data, "radio_MaximumNoiseFloorOnChannel", param);
        diagnostic_data[count].radio_MaximumNoiseFloorOnChannel = param->valuedouble;

        decode_param_integer(diag_data, "radio_MinimumNoiseFloorOnChannel", param);
        diagnostic_data[count].radio_MinimumNoiseFloorOnChannel = param->valuedouble;

        decode_param_integer(diag_data, "radio_MedianNoiseFloorOnChannel", param);
        diagnostic_data[count].radio_MedianNoiseFloorOnChannel = param->valuedouble;

        decode_param_integer(diag_data, "radio_StatisticsStartTime", param);
        diagnostic_data[count].radio_StatisticsStartTime = param->valuedouble;
    }
    (*diag_stats)->stat_pointer = diagnostic_data;
    (*diag_stats)->stat_array_size = size;

    return webconfig_error_none;
}

webconfig_error_t decode_radio_temperature_stats_object(wifi_provider_response_t **temp_stats, cJSON *json)
{
    cJSON *temp_stats_arr;
    cJSON *temp_data;
    const cJSON  *param;
    int size = 0;
    radio_data_t *temperature_data = NULL;

    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: cjson object is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    temp_stats_arr = cJSON_GetObjectItem(json, "RadioTemperatureStats");
    if ((temp_stats_arr == NULL) && (cJSON_IsObject(temp_stats_arr) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Stats config object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    size = cJSON_GetArraySize(temp_stats_arr);

    *temp_stats = (wifi_provider_response_t*) calloc(1, sizeof(wifi_provider_response_t));
    if (*temp_stats == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_integer(json, "RadioIndex", param);
    (*temp_stats)->args.radio_index = param->valuedouble;

    temperature_data = (radio_data_t*) malloc(sizeof(radio_data_t) * size);
    if (temperature_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    for (int count = 0; count < size; count++) {
        temp_data = cJSON_GetArrayItem(temp_stats_arr, count);
        if (temp_data == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: null Json Pointer for : %d \n", __func__, __LINE__, count);
            return webconfig_error_decode;
        }

        decode_param_integer(temp_data, "Radio_Temperature", param);
        temperature_data[count].radio_Temperature = param->valuedouble;
    }
    (*temp_stats)->stat_pointer = temperature_data;
    (*temp_stats)->stat_array_size = size;

    return webconfig_error_none;
}
