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
#include "cJSON.h"
#include "wifi_webconfig.h"
#include "ctype.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"

//This Macro ONE_WIFI_CHANGES, used to modify the validator changes. Re-check is required where the macro is used
#define ONE_WIFI_CHANGES

#define decode_param_string(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) || (strcmp(value->valuestring, "") == 0)) {    \
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_integer(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsNumber(value) == false)) {  \
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_bool(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsBool(value) == false)) {    \
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \


#define decode_param_array(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsArray(value) == false)) {   \
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \


#define decode_param_object(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsObject(value) == false)) {  \
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

#define decode_param_blaster_mac(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) ) {    \
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return webconfig_error_decode;  \
    }   \
}   \

webconfig_error_t decode_ipv4_address(char *ip) {
    struct sockaddr_in sa;

    if (inet_pton(AF_INET,ip, &(sa.sin_addr)) != 1 ) {
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

    //VenueNameANQPElement
    decode_param_object(anqp, "VenueNameANQPElement", anqpElement);

    next_pos = (UCHAR *)&interworking_info->anqp.venueInfo;
    decode_param_array(anqpElement, "VenueInfo", anqpList);
    if(cJSON_GetArraySize(anqpList) > 16){
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Venue entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
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
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Venue name cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Only 32 OUI supported in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_oui_entries;
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
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid OUI Length in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
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
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid OUI in RoamingConsortiumANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid IPAddressTypeAvailabilityANQPElement. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_ipaddress;
    }
    interworking_info->anqp.ipAddressInfo.field_format = (UCHAR)anqpParam->valuedouble;

    decode_param_integer(anqpElement,"IPv4AddressType",anqpParam);
    if((0 > anqpParam->valuedouble) || (7 < anqpParam->valuedouble)){
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid IPAddressTypeAvailabilityANQPElement. Discarding Configuration\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Only 20 Realm Entries are supported. Discarding Configuration\n", __func__, __LINE__);
        return webconfig_error_realm_entries;
    }
    next_pos = (UCHAR *)naiElem;
    next_pos += sizeof(naiElem->nai_realm_count);

    if(naiElem->nai_realm_count) {
        interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_nai_realm;
    }

    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_naiRealm_t *realmInfoBuf = (wifi_naiRealm_t *)next_pos;
        next_pos += sizeof(realmInfoBuf->data_field_length);

        decode_param_integer(anqpEntry,"RealmEncoding",anqpParam);
        realmInfoBuf->encoding = anqpParam->valuedouble;
        next_pos += sizeof(realmInfoBuf->encoding);

        decode_param_string(anqpEntry,"Realms",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Realm Length cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            return webconfig_error_realm_length;
        }
        realmInfoBuf->realm_length = strlen(anqpParam->valuestring);
        next_pos += sizeof(realmInfoBuf->realm_length);
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += realmInfoBuf->realm_length;

        cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", anqpParam->valuestring);
        cJSON_AddNumberToObject(realmStats, "EntryType", 1);//1-NAI Realm
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);

        decode_param_array(anqpEntry,"EAP",subList);
        realmInfoBuf->eap_method_count = cJSON_GetArraySize(subList);
        if(realmInfoBuf->eap_method_count > 16){
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: EAP entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
            return webconfig_error_eap_entries;
        }
        next_pos += sizeof(realmInfoBuf->eap_method_count);

        cJSON_ArrayForEach(subEntry, subList){
            wifi_eapMethod_t *eapBuf = (wifi_eapMethod_t *)next_pos;
            decode_param_integer(subEntry,"Method",subParam);
            eapBuf->method = subParam->valuedouble;
            next_pos += sizeof(eapBuf->method);
            cJSON *subList_1  = NULL;
            cJSON *subEntry_1 = NULL;
            cJSON *subParam_1 = NULL;

            decode_param_array(subEntry,"AuthenticationParameter",subList_1);
            eapBuf->auth_param_count = cJSON_GetArraySize(subList_1);
            if(eapBuf->auth_param_count > 16){
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Auth entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
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
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Auth Parameter Value not prensent in NAIRealmANQPElement EAP Data. Discarding Configuration\n", __func__, __LINE__);
                    return webconfig_error_auth_param;
                } else if (subParam_1->valuedouble) {
                    authBuf->length = 1;
                    authBuf->val[0] = subParam_1->valuedouble;
                } else {
                    authStrLen = strlen(subParam_1->valuestring);
                    if((authStrLen != 2) && (authStrLen != 14)){
                        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid EAP Value Length in NAIRealmANQPElement Data. Has to be 1 to 7 bytes Long. Discarding Configuration\n", __func__, __LINE__);
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
                            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid EAP val in NAIRealmANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: 3GPP entries cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
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
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid MCC in 3GPPCellularANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
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
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid MNC in 3GPPCellularANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid MNC in 3GPP Element",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
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
    }
    gppBuf->uhdLength = next_pos - uhd_pos;
    plmnInfoBuf->plmn_length = next_pos - plmn_pos;
    interworking_info->anqp.gppInfoLength = next_pos - (UCHAR *)&interworking_info->anqp.gppInfo;
    interworking_info->anqp.capabilityInfo.capabilityList[interworking_info->anqp.capabilityInfoLength++] = wifi_anqp_element_name_3gpp_cellular_network;

    //DomainANQPElement
    decode_param_object(anqp, "DomainANQPElement", anqpElement);
    decode_param_array(anqpElement, "DomainName", anqpList);

    if(cJSON_GetArraySize(anqpList) > 4){
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Only 4 Entries supported in DomainNameANQPElement Data. Discarding Configuration\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Exceeded max no of entries in DomainNameANQPElement Data",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    next_pos = (UCHAR *)&interworking_info->anqp.domainNameInfo;

    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_domainNameTuple_t *nameBuf = (wifi_domainNameTuple_t *)next_pos;
        decode_param_string(anqpEntry,"Name",anqpParam);
        if(strlen(anqpParam->valuestring) > 255){
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Domain name length cannot be more than 255. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Domain name length",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
        nameBuf->length = strlen(anqpParam->valuestring);
        next_pos += sizeof(nameBuf->length);
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += nameBuf->length;

        cJSON *realmStats = cJSON_CreateObject();//Create a stats Entry here for each Realm
        cJSON_AddStringToObject(realmStats, "Name", anqpParam->valuestring);
        cJSON_AddNumberToObject(realmStats, "EntryType", 2);//2-Domain
        cJSON_AddNumberToObject(realmStats, "Sent", 0);
        cJSON_AddNumberToObject(realmStats, "Failed", 0);
        cJSON_AddNumberToObject(realmStats, "Timeout", 0);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Passpoint entry is NULL\n");
        return webconfig_error_decode;
    }
    mainEntry = (cJSON *)passpoint;

    decode_param_bool(mainEntry, "PasspointEnable", anqpParam);
    interworking_info->passpoint.enable = (anqpParam->type & cJSON_True) ? true:false;

    if((interworking_info->passpoint.enable == true) && (interworking_info->interworking.interworkingEnabled == false)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Passpoint cannot be enable when Interworking is disabled\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: OperatorFriendlyName cannot have more than 16 entiries. Discarding Configuration\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid no of entries in OperatorFriendlyName",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    next_pos = (UCHAR *)&interworking_info->passpoint.opFriendlyNameInfo;
    cJSON_ArrayForEach(anqpEntry, anqpList){
        wifi_HS2_OperatorNameDuple_t *opNameBuf = (wifi_HS2_OperatorNameDuple_t *)next_pos;
        next_pos += sizeof(opNameBuf->length);//Fill length after reading the remaining fields

        decode_param_string(anqpEntry,"LanguageCode",anqpParam);
        if(strlen(anqpParam->valuestring) > 3){
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid Language Code. Discarding Configuration\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Language Code",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
        strcpy((char*)next_pos, anqpParam->valuestring);
        next_pos += sizeof(opNameBuf->languageCode);

        decode_param_string(anqpEntry,"OperatorName",anqpParam);
        if(strlen(anqpParam->valuestring) > 252){
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid OperatorFriendlyName. Discarding Configuration\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Connection Capability count cannot be more than 16. Discarding Configuration\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NAI Realm count cannot be more than 20. Discarding Configuration\n", __func__, __LINE__);
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
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid NAI Home Realm Name. Discarding Configuration\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for AccessNetworkType\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for HESSID\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid HESSID",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    decode_param_object(interworking, "Venue", venue);

    decode_param_integer(venue, "VenueType", param);
    interworking_info->interworking.venueType = param->valuedouble;
    if (interworking_info->interworking.venueType > 15) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for VenueGroup\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Venue Group",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    decode_param_integer(venue, "VenueGroup", param);
    interworking_info->interworking.venueGroup = param->valuedouble;
    if (interworking_info->interworking.venueGroup > 11) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for VenueGroup\n", __func__, __LINE__);
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid venue group and type, encode failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_interworking_object(const cJSON *interworking, wifi_interworking_t *interworking_info)
{
    const cJSON *passpoint, *anqp;

    if (decode_interworking_common_object(interworking, interworking_info) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_object(interworking, "ANQP", anqp);

    if (decode_anqp_object(anqp, interworking_info) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    } else {
        cJSON *anqpString = cJSON_CreateObject();
        cJSON_AddItemReferenceToObject(anqpString, "ANQP", (cJSON *)anqp);
        cJSON_PrintPreallocated(anqpString, (char *)&interworking_info->anqp.anqpParameters, sizeof(interworking_info->anqp.anqpParameters),false);
        cJSON_Delete(anqpString);
    }

    decode_param_object(interworking, "Passpoint", passpoint);

    if (decode_passpoint_object(passpoint, interworking_info) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    } else {
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

    decode_param_string(radius, "RadiusServerIPAddr", param);
    if (decode_ipv4_address(param->valuestring) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for RadiusServerIPAddr\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
#ifndef WIFI_HAL_VERSION_3_PHASE2
    strcpy((char *)radius_info->ip,param->valuestring);
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

    decode_param_string(radius, "SecondaryRadiusServerIPAddr", param);
    if (decode_ipv4_address(param->valuestring) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for SecondaryRadiusServerIPAddr\n", __func__, __LINE__);
            //strncpy(execRetVal->ErrorMsg, "Invalid Secondary Radius server IP",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

#ifndef WIFI_HAL_VERSION_3_PHASE2
    strcpy((char *)radius_info->s_ip,param->valuestring);
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

    decode_param_string(radius, "DasServerIPAddr", param);
    if (decode_ipv4_address(param->valuestring) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed for DasServerIPAddr\n", __func__, __LINE__);
        //strncpy(execRetVal->ErrorMsg, "Invalid Das Server IP Addr",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    getIpAddressFromString(param->valuestring, &radius_info->dasip);

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

webconfig_error_t decode_no_security_object(const cJSON *security, wifi_vap_security_t *security_info)
{
    const cJSON *param;

    decode_param_string(security, "Mode", param);
    if (strcmp(param->valuestring, "None") != 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Decode error\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    security_info->mode = wifi_security_mode_none;
    return webconfig_error_none;
}

webconfig_error_t decode_enterprise_security_object(const cJSON *security, wifi_vap_security_t *security_info)
{
    const cJSON *param;


    decode_param_string(security, "Mode", param);
    if ((strcmp(param->valuestring, "WPA2-Enterprise") != 0) && (strcmp(param->valuestring, "WPA-WPA2-Enterprise") != 0)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Xfinity WiFi VAP security is not WPA2 Eneterprise, value:%s\n",
            __func__, __LINE__, param->valuestring);
                //strncpy(execRetVal->ErrorMsg, "Invalid sec mode for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    if (strcmp(param->valuestring, "WPA2-Enterprise") == 0) {
        security_info->mode = wifi_security_mode_wpa2_enterprise;
    } else {
        security_info->mode = wifi_security_mode_wpa_wpa2_enterprise;
    }

    decode_param_string(security, "EncryptionMethod", param);
    if ((strcmp(param->valuestring, "AES") != 0) && (strcmp(param->valuestring, "AES+TKIP") != 0)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Xfinity WiFi VAP Encrytpion mode is Invalid:%s\n",
                    __func__, __LINE__, param->valuestring);
        //strncpy(execRetVal->ErrorMsg, "Invalid enc mode for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    if (strcmp(param->valuestring, "AES") == 0) {
        security_info->encr = wifi_encryption_aes;
    } else {
        security_info->encr = wifi_encryption_aes_tkip;
    }

    // MFPConfig
    decode_param_string(security, "MFPConfig", param);
    if ((strcmp(param->valuestring, "Disabled") != 0)
        && (strcmp(param->valuestring, "Required") != 0)
        && (strcmp(param->valuestring, "Optional") != 0)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: MFPConfig not valid, value:%s\n",
                        __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }

    if (strstr(param->valuestring, "Disabled")) {
        security_info->mfp = wifi_mfp_cfg_disabled;
    } else if (strstr(param->valuestring, "Required")) {
        security_info->mfp = wifi_mfp_cfg_required;
    } else if (strstr(param->valuestring, "Optional")) {
        security_info->mfp = wifi_mfp_cfg_optional;
    }

    //Wpa3_transition_disable
    decode_param_bool(security, "Wpa3_transition_disable", param);
    security_info->wpa3_transition_disable =  (param->type & cJSON_True) ? true:false;

    decode_param_integer(security, "RekeyInterval", param);
    security_info->rekey_interval = param->valuedouble;

    decode_param_bool(security, "StrictRekey", param);
    security_info->strict_rekey =  (param->type & cJSON_True) ? true:false;

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
    security_info->disable_pmksa_caching = (param->type & cJSON_True) ? true:false;

    decode_param_object(security, "RadiusSettings",param);
    if (decode_radius_object(param, &security_info->u.radius) != 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_personal_security_object(const cJSON *security, wifi_vap_security_t *security_info)
{
    const cJSON *param;

    // MFPConfig
    decode_param_string(security, "MFPConfig", param);
    if ((strcmp(param->valuestring, "Disabled") != 0)
            && (strcmp(param->valuestring, "Required") != 0)
            && (strcmp(param->valuestring, "Optional") != 0)) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%s\n",
                            __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }

    if (strstr(param->valuestring, "Disabled")) {
        security_info->mfp = wifi_mfp_cfg_disabled;
    } else if (strstr(param->valuestring, "Required")) {
        security_info->mfp = wifi_mfp_cfg_required;
    } else if (strstr(param->valuestring, "Optional")) {
        security_info->mfp = wifi_mfp_cfg_optional;
    }

    decode_param_string(security, "Mode", param);

    if (strcmp(param->valuestring, "None") == 0) {
        security_info->mode = wifi_security_mode_none;
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
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Invalid Authentication mode for private vap", __FUNCTION__);
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
        //strncpy(execRetVal->ErrorMsg, "Invalid Encryption method",sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Incorrect encryption method\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if ((security_info->mode == wifi_security_mode_wpa_wpa2_personal) &&
                (security_info->encr == wifi_encryption_tkip)) {
        //strncpy(execRetVal->ErrorMsg, "Invalid Encryption method combinaiton",sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Incorrect mode and encryption method\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    decode_param_string(security, "Passphrase", param);

    if ((strlen(param->valuestring) < MIN_PWD_LEN) || (strlen(param->valuestring) > MAX_PWD_LEN)) {
        //strncpy(execRetVal->ErrorMsg, "Invalid Key passphrase length",sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Incorrect password length\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    strncpy(security_info->u.key.key, param->valuestring,
            sizeof(security_info->u.key.key) - 1);

    return webconfig_error_none;
}

webconfig_error_t decode_security_object(const cJSON *security, wifi_vap_security_t *security_info)
{
    const cJSON *param;
    int enterprise_mode = 0;

    // MFPConfig
    decode_param_string(security, "MFPConfig", param);
    if ((strcmp(param->valuestring, "Disabled") != 0)
            && (strcmp(param->valuestring, "Required") != 0)
            && (strcmp(param->valuestring, "Optional") != 0)) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: MFPConfig not valid, value:%s\n",
                            __func__, __LINE__, param->valuestring);
        return webconfig_error_decode;
    }

    if (strstr(param->valuestring, "Disabled")) {
        security_info->mfp = wifi_mfp_cfg_disabled;
    } else if (strstr(param->valuestring, "Required")) {
        security_info->mfp = wifi_mfp_cfg_required;
    } else if (strstr(param->valuestring, "Optional")) {
        security_info->mfp = wifi_mfp_cfg_optional;
    }

    decode_param_string(security, "Mode", param);

    if (strcmp(param->valuestring, "None") == 0) {
        security_info->mode = wifi_security_mode_none;
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
    } else if (strcmp(param->valuestring, "WPA2-Enterprise") == 0) {
        security_info->mode = wifi_security_mode_wpa2_enterprise;
        enterprise_mode = 1;
    } else if (strcmp(param->valuestring, "WPA-WPA2-Enterprise") == 0) {
        security_info->mode = wifi_security_mode_wpa_wpa2_enterprise;
        enterprise_mode = 1;
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Invalid Authentication mode for private vap", __FUNCTION__);
        return webconfig_error_decode;
    }
    
    
    if (enterprise_mode == 1) {
        
        decode_param_string(security, "EncryptionMethod", param);
        if ((strcmp(param->valuestring, "AES") != 0) && (strcmp(param->valuestring, "AES+TKIP") != 0)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Xfinity WiFi VAP Encrytpion mode is Invalid:%s\n",
                        __func__, __LINE__, param->valuestring);
            //strncpy(execRetVal->ErrorMsg, "Invalid enc mode for hotspot secure vap",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }

        if (strcmp(param->valuestring, "AES") == 0) {
            security_info->encr = wifi_encryption_aes;
        } else {
            security_info->encr = wifi_encryption_aes_tkip;
        }

        //Wpa3_transition_disable
        decode_param_bool(security, "Wpa3_transition_disable", param);
        security_info->wpa3_transition_disable =  (param->type & cJSON_True) ? true:false;

        decode_param_integer(security, "RekeyInterval", param);
        security_info->rekey_interval = param->valuedouble;

        decode_param_bool(security, "StrictRekey", param);
        security_info->strict_rekey =  (param->type & cJSON_True) ? true:false;

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
        security_info->disable_pmksa_caching = (param->type & cJSON_True) ? true:false;

        decode_param_object(security, "RadiusSettings",param);
        if (decode_radius_object(param, &security_info->u.radius) != 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Validation failed\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

    } else {

        decode_param_string(security, "EncryptionMethod", param);

        if (strcmp(param->valuestring, "TKIP") == 0) {
            security_info->encr = wifi_encryption_tkip;
        } else if(strcmp(param->valuestring, "AES") == 0) {
            security_info->encr = wifi_encryption_aes;
        } else if(strcmp(param->valuestring, "AES+TKIP") == 0) {
            security_info->encr = wifi_encryption_aes_tkip;
        } else {
            //strncpy(execRetVal->ErrorMsg, "Invalid Encryption method",sizeof(execRetVal->ErrorMsg)-1);
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Incorrect encryption method\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        if ((security_info->mode == wifi_security_mode_wpa_wpa2_personal) &&
                    (security_info->encr == wifi_encryption_tkip)) {
            //strncpy(execRetVal->ErrorMsg, "Invalid Encryption method combinaiton",sizeof(execRetVal->ErrorMsg)-1);
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Incorrect mode and encryption method\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        decode_param_string(security, "Passphrase", param);

        if ((strlen(param->valuestring) < MIN_PWD_LEN) || (strlen(param->valuestring) > MAX_PWD_LEN)) {
            //strncpy(execRetVal->ErrorMsg, "Invalid Key passphrase length",sizeof(execRetVal->ErrorMsg)-1);
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Incorrect password length\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        strncpy(security_info->u.key.key, param->valuestring,
                sizeof(security_info->u.key.key) - 1);
    }
    return webconfig_error_none;
}

webconfig_error_t decode_ssid_name(char *ssid_name)
{
    int i = 0, ssid_len;

    if(!ssid_name){
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: SSID is NULL\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    ssid_len = strlen(ssid_name);
    if ((ssid_len == 0) || (ssid_len > WIFI_MAX_SSID_NAME_LEN)) {
        //strncpy(execRetVal->ErrorMsg, "Invalid SSID Size",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }


    for (i = 0; i < ssid_len; i++) {
        if (!((ssid_name[i] >= ' ') && (ssid_name[i] <= '~'))) {
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
        if(strcasecmp(contry,wifiCountryMap[i].countryStr) == 0) {
            *contry_code = wifiCountryMap[i].countryCode;
            return webconfig_error_none;
        }
    }

    if(i == MAX_WIFI_COUNTRYCODE) {
        ;
    }
    return webconfig_error_decode;
}

webconfig_error_t decode_vap_common_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON  *param;

    //VAP Name
    decode_param_string(vap, "VapName", param);
    strcpy(vap_info->vap_name, param->valuestring);

    vap_info->vap_index = convert_vap_name_to_index(vap_info->vap_name);

    // Radio Index
    decode_param_integer(vap, "RadioIndex", param);
    vap_info->radio_index = param->valuedouble;

    // VAP Mode
    decode_param_integer(vap, "VapMode", param);
    vap_info->vap_mode = param->valuedouble;

    //Bridge Name
    decode_param_string(vap, "BridgeName", param);
    strncpy(vap_info->bridge_name, param->valuestring,WIFI_BRIDGE_NAME_LEN-1);

    // SSID
    decode_param_string(vap, "SSID", param);
    strcpy(vap_info->u.bss_info.ssid, param->valuestring);

    if (decode_ssid_name(vap_info->u.bss_info.ssid) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d : Ssid name validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    // Enabled
    decode_param_bool(vap, "Enabled", param);
    vap_info->u.bss_info.enabled = (param->type & cJSON_True) ? true:false;

    // Broadcast SSID
    decode_param_bool(vap, "SSIDAdvertisementEnabled", param);
    vap_info->u.bss_info.showSsid = (param->type & cJSON_True) ? true:false;

    // Isolation
    decode_param_bool(vap, "IsolationEnable", param);
    vap_info->u.bss_info.isolation = (param->type & cJSON_True) ? true:false;

    // ManagementFramePowerControl
    decode_param_integer(vap, "ManagementFramePowerControl", param);
    vap_info->u.bss_info.mgmtPowerControl = param->valuedouble;

    // BssMaxNumSta
    decode_param_integer(vap, "BssMaxNumSta", param);
    vap_info->u.bss_info.bssMaxSta = param->valuedouble;

    // BSSTransitionActivated
    decode_param_bool(vap, "BSSTransitionActivated", param);
    vap_info->u.bss_info.bssTransitionActivated = (param->type & cJSON_True) ? true:false;

    // NeighborReportActivated
    decode_param_bool(vap, "NeighborReportActivated", param);
    vap_info->u.bss_info.nbrReportActivated = (param->type & cJSON_True) ? true:false;

    // RapidReconnCountEnable
    decode_param_bool(vap, "RapidReconnCountEnable", param);
    vap_info->u.bss_info.rapidReconnectEnable = (param->type & cJSON_True) ? true:false;

    // RapidReconnThreshold
    decode_param_integer(vap, "RapidReconnThreshold", param);
    vap_info->u.bss_info.rapidReconnThreshold = param->valuedouble;

    // VapStatsEnable
    decode_param_bool(vap, "VapStatsEnable", param);
    vap_info->u.bss_info.vapStatsEnable = (param->type & cJSON_True) ? true:false;

    // MacFilterEnable
    decode_param_bool(vap, "MacFilterEnable", param);
    vap_info->u.bss_info.mac_filter_enable = (param->type & cJSON_True) ? true:false;

    // MacFilterMode
    decode_param_integer(vap, "MacFilterMode", param);
    vap_info->u.bss_info.mac_filter_mode = param->valuedouble;
    if ((vap_info->u.bss_info.mac_filter_mode < 0) || (vap_info->u.bss_info.mac_filter_mode > 1)) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid wifi vap mac filter mode, should be between 0 and 1\n");
                //strncpy(execRetVal->ErrorMsg, "Invalid wifi vap mac filter mode: 0..1",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    // WmmEnabled
    decode_param_bool(vap, "WmmEnabled", param);
    vap_info->u.bss_info.wmm_enabled = (param->type & cJSON_True) ? true:false;

    decode_param_bool(vap, "UapsdEnabled", param);
    vap_info->u.bss_info.UAPSDEnabled = (param->type & cJSON_True) ? true:false;

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
    vap_info->u.bss_info.bssHotspot = (param->type & cJSON_True) ? true:false;

    // wpsPushButton
    decode_param_integer(vap, "WpsPushButton", param);
    vap_info->u.bss_info.wpsPushButton = param->valuedouble;

    //wpsEnable
    decode_param_bool(vap, "WpsEnable", param);
    vap_info->u.bss_info.wps.enable  = (param->type & cJSON_True) ? true:false;

    // BeaconRateCtl
    decode_param_string(vap, "BeaconRateCtl", param);
    strcpy(vap_info->u.bss_info.beaconRateCtl, param->valuestring);

    return webconfig_error_none;
}

webconfig_error_t decode_hotspot_open_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_no_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_hotspot_secure_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_enterprise_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_lnf_psk_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_personal_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_lnf_radius_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_enterprise_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_iot_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_personal_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_mesh_backhaul_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_personal_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_private_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_personal_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }


    return webconfig_error_none;
}

webconfig_error_t decode_mesh_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    return decode_private_vap_object(vap, vap_info);
}

webconfig_error_t decode_wifiapi_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON *security, *interworking;
    webconfig_error_t ret = webconfig_error_none;

    // first decode the common objects
    if ((ret = decode_vap_common_object(vap, vap_info)) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Common vap objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Security", security);
    if (decode_security_object(security, &vap_info->u.bss_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "Interworking", interworking);

    if (decode_interworking_common_object(interworking, &vap_info->u.bss_info.interworking) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Interworking objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    if (vap_info->u.bss_info.interworking.passpoint.enable) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Passpoint enabled, so decode failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
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

webconfig_error_t decode_mesh_sta_object(const cJSON *vap, wifi_vap_info_t *vap_info)
{
    const cJSON  *param, *security, *scan;

    //VAP Name
    decode_param_string(vap, "VapName", param);
    strcpy(vap_info->vap_name, param->valuestring);

    vap_info->vap_index = convert_vap_name_to_index(vap_info->vap_name);

    // Radio Index
    decode_param_integer(vap, "RadioIndex", param);
    vap_info->radio_index = param->valuedouble;

    // VAP Mode
    decode_param_integer(vap, "VapMode", param);
    vap_info->vap_mode = param->valuedouble;

    //Bridge Name
    decode_param_string(vap, "BridgeName", param);
    strncpy(vap_info->bridge_name, param->valuestring,WIFI_BRIDGE_NAME_LEN-1);

    // SSID
    decode_param_string(vap, "SSID", param);
    strcpy(vap_info->u.sta_info.ssid, param->valuestring);

    // BSSID
    decode_param_string(vap, "BSSID", param);
    string_mac_to_uint8_mac(vap_info->u.sta_info.bssid, param->valuestring);

    decode_param_object(vap, "Security", security);
    if (decode_personal_security_object(security, &vap_info->u.sta_info.security) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Security objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
        return webconfig_error_decode;
    }

    decode_param_object(vap, "ScanParameters", scan);
    if (decode_scan_params_object(scan, &vap_info->u.sta_info.scan_params) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Scan parameters objects validation failed for %s\n",__FUNCTION__, __LINE__, vap_info->vap_name);
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

    //WpsPin
    decode_param_string(global_cfg, "WpsPin", param);
    strcpy(global_info->wps_pin, param->valuestring);

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

    //WifiRegionCode
    decode_param_string(global_cfg, "WifiRegionCode", param);
    strcpy(global_info->wifi_region_code, param->valuestring);

    // DiagnosticEnable
    decode_param_bool(global_cfg, "DiagnosticEnable", param);
    global_info->diagnostic_enable = (param->type & cJSON_True) ? true:false;

    // ValidateSsid
    decode_param_bool(global_cfg, "ValidateSsid", param);
    global_info->validate_ssid = (param->type & cJSON_True) ? true:false;

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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid Configuration. Only Advertisement ID 0 - ANQP is Supported\n");
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid Configuration. ResponseTimeout should be between 1000 and 65535\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid RespTimeout 1000..65535",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    //ComebackDelay
    decode_param_integer(gas, "ComebackDelay", param);
    gas_info->ComeBackDelay = param->valuedouble;
    if (gas_info->ComeBackDelay > 65535) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid Configuration. ComeBackDelay should be between 0 and 65535\n");
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid Configuration. QueryResponseLengthLimit should be between 1 and 127\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid QueryRespLengthLimit 1..127",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_wifi_channel(wifi_freq_bands_t wifi_band, UINT *wifi_radio_channel, UINT wifi_channel)
{

    if (wifi_band == WIFI_FREQUENCY_2_4_BAND) {
        if ((wifi_channel >= 1) && (wifi_channel <= 14)) {
            *wifi_radio_channel = wifi_channel;
        } else {
            return webconfig_error_decode;
        }
    } else if (wifi_band == WIFI_FREQUENCY_5_BAND) {
        if ((wifi_channel >= 36) && (wifi_channel <= 165)) {
            *wifi_radio_channel = wifi_channel;
        } else {
            return webconfig_error_decode;
        }
    } else if (wifi_band == WIFI_FREQUENCY_5L_BAND) {

    } else if (wifi_band == WIFI_FREQUENCY_5H_BAND) {

    } else if (wifi_band == WIFI_FREQUENCY_6_BAND) {

    } else if (wifi_band == WIFI_FREQUENCY_60_BAND) {

    } else {
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

int validate_wifi_hw_variant(wifi_freq_bands_t radio_band, wifi_ieee80211Variant_t wifi_hw_mode)
{
    if (wifi_hw_mode == 0) {
        return RETURN_ERR;
    }

    if (radio_band == WIFI_FREQUENCY_2_4_BAND) {
        // Mask hw variant b,g,n,ax bit
        wifi_hw_mode &= ~(1UL << 1);
        wifi_hw_mode &= ~(1UL << 2);
        wifi_hw_mode &= ~(1UL << 3);
        wifi_hw_mode &= ~(1UL << 7);

        if(wifi_hw_mode != 0) {
            return RETURN_ERR;
        }
    } else if (radio_band == WIFI_FREQUENCY_5_BAND) {
        // Mask hw variant a,n,h,ac,ax bit
        wifi_hw_mode &= ~(1UL << 0);
        wifi_hw_mode &= ~(1UL << 3);
        wifi_hw_mode &= ~(1UL << 4);
        wifi_hw_mode &= ~(1UL << 5);
        wifi_hw_mode &= ~(1UL << 7);

        if (wifi_hw_mode != 0) {
            return RETURN_ERR;
        }
    } else if (radio_band == WIFI_FREQUENCY_6_BAND) {
        // Mask hw variant ax bit
        wifi_hw_mode &= ~(1UL << 7);

        if (wifi_hw_mode != 0) {
            return RETURN_ERR;
        }
    } else if (radio_band == WIFI_FREQUENCY_60_BAND) {
        // Mask hw variant ad bit
        wifi_hw_mode &= ~(1UL << 6);

        if (wifi_hw_mode != 0) {
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
        decode_param_string(obj, "VapName", param);
        strcpy((char *)vap_map->rdk_vap_array[i].vap_name, param->valuestring);

        // VapIndex
        decode_param_integer(obj, "VapIndex", param);
        vap_map->rdk_vap_array[i].vap_index = param->valuedouble;
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
    wifi_radio_operationParam_t *radio_info = &radio->oper;

    // WifiRadioSetup
    decode_param_object(obj_radio, "WifiRadioSetup", param);
    if (decode_radio_setup_object(param, &radio->vaps) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_LIB,"%s:%d Radio setup decode failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    // RadioName
    decode_param_string(obj_radio, "RadioName", param);
    strcpy(radio->name, param->valuestring);

    // FreqBand
    decode_param_integer(obj_radio, "FreqBand", param);
    radio_info->band = param->valuedouble;
    if ((radio_info->band < 0) || (radio_info->band > 3)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid wifi radio band configuration, should be between 0 and 3\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio band config 0..3",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    if (convert_freq_band_to_radio_index(radio_info->band, &radio_index) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d failed for convert_freq_band_to_radio_index for %d\n", __FUNCTION__, __LINE__, radio_info->band);
        return webconfig_error_decode;
    }

    // Enabled
    decode_param_bool(obj_radio, "Enabled", param);
    radio_info->enable = (param->type & cJSON_True) ? true:false;


    // AutoChannelEnabled
    decode_param_bool(obj_radio, "AutoChannelEnabled", param);
    radio_info->autoChannelEnabled = (param->type & cJSON_True) ? true:false;

    // Channel
    decode_param_integer(obj_radio, "Channel", param);
    ret = decode_wifi_channel(radio_info->band, &radio_info->channel, param->valuedouble);
    if (ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid wifi radio channel configuration\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio channel config",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

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
            wifi_util_dbg_print(WIFI_WEBCONFIG,"number of secondary channels and secondary chaneel list not match\n");
            //strncpy(execRetVal->ErrorMsg, "Invalid Secondary channel list",sizeof(execRetVal->ErrorMsg)-1);
            return webconfig_error_decode;
        }
    }

    // ChannelWidth
    decode_param_integer(obj_radio, "ChannelWidth", param);
    radio_info->channelWidth = param->valuedouble;
    if ((radio_info->channelWidth < 0) || (radio_info->channelWidth > 4)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid wifi radio channelWidth configuration, should be between 0 and 4\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio channelWidth config 0..4",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

    // HwMode
    decode_param_integer(obj_radio, "HwMode", param);
    if (validate_wifi_hw_variant(radio_info->band, param->valuedouble) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid wifi radio hardware mode [%d] configuration\n", param->valuedouble);
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio hardware mode config",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }
    radio_info->variant = param->valuedouble;

    // CsaBeaconCount
    decode_param_integer(obj_radio, "CsaBeaconCount", param);
    radio_info->csa_beacon_count = param->valuedouble;

    // Country
    decode_param_string(obj_radio, "Country", param);
    ret = decode_contry_code(&radio_info->countryCode, param->valuestring);
    if (ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"Invalid wifi radio contry code\n");
        //strncpy(execRetVal->ErrorMsg, "Invalid wifi radio code",sizeof(execRetVal->ErrorMsg)-1);
        return webconfig_error_decode;
    }

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

    return webconfig_error_none;
}

webconfig_error_t decode_config_object(const cJSON *wifi, wifi_global_config_t *wifi_info)
{
    const cJSON  *param;
    webconfig_error_t ret;

    decode_param_object(wifi, "GASConfig", param);
    ret = decode_gas_config(param, &wifi_info->gas_config);
    if (ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d Validation of GAS Configuration Failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    ret = decode_wifi_global_config(wifi, &wifi_info->global_parameters);
    if(ret != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s %d  Validation of wifi global Configuration Failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    return webconfig_error_none;
}

webconfig_error_t decode_radio_state_object(const cJSON *obj_r_state, schema_wifi_radio_state_t *r_state)
{
    const cJSON *param;

    //if_name
    decode_param_string(obj_r_state, "if_name", param);
    strcpy(r_state->if_name, param->valuestring);

    //freq_band
    decode_param_string(obj_r_state, "freq_band", param);
    strcpy(r_state->freq_band, param->valuestring);

    //enabled
    decode_param_bool(obj_r_state, "enabled", param);
    r_state->enabled = (param->type & cJSON_True) ? true:false;

    //dfs_demo
    decode_param_bool(obj_r_state, "dfs_demo", param);
    r_state->dfs_demo = (param->type & cJSON_True) ? true:false;

    //hw_type
    decode_param_string(obj_r_state, "hw_type", param);
    strcpy(r_state->hw_type, param->valuestring);

    //country
    decode_param_string(obj_r_state, "country", param);
    strcpy(r_state->country, param->valuestring);

    //channel
    decode_param_integer(obj_r_state, "channel", param);
    r_state->channel = param->valuedouble;

    //channel_mode
    decode_param_string(obj_r_state, "channel_mode", param);
    strcpy(r_state->channel_mode, param->valuestring);

    //mac
    decode_param_string(obj_r_state, "mac", param);
    strcpy(r_state->mac, param->valuestring);

    //hw_mode
    decode_param_string(obj_r_state, "hw_mode", param);
    strcpy(r_state->hw_mode, param->valuestring);

    //ht_mode
    decode_param_string(obj_r_state, "ht_mode", param);
    strcpy(r_state->ht_mode, param->valuestring);

    //thermal_shutdown
    decode_param_integer(obj_r_state, "thermal_shutdown", param);
    r_state->thermal_shutdown = param->valuedouble;


    //thermal_downgrade_temp
    decode_param_integer(obj_r_state, "thermal_downgrade_temp", param);
    r_state->thermal_downgrade_temp = param->valuedouble;

    //thermal_upgrade_temp
    decode_param_integer(obj_r_state, "thermal_upgrade_temp", param);
    r_state->thermal_upgrade_temp = param->valuedouble;

    //thermal_integration
    decode_param_integer(obj_r_state, "thermal_integration", param);
    r_state->thermal_integration = param->valuedouble;

    //thermal_downgraded
    decode_param_bool(obj_r_state, "thermal_downgraded", param);
    r_state->thermal_downgraded = (param->type & cJSON_True) ? true:false;

    //tx_power
    decode_param_integer(obj_r_state, "tx_power", param);
    r_state->tx_power = param->valuedouble;

    //bcn_int
    decode_param_integer(obj_r_state, "bcn_int", param);
    r_state->bcn_int = param->valuedouble;

    //tx_chainmask
    decode_param_integer(obj_r_state, "tx_chainmask", param);
    r_state->tx_chainmask = param->valuedouble;

    //thermal_tx_chainmask
    decode_param_integer(obj_r_state, "thermal_tx_chainmask", param);
    r_state->thermal_tx_chainmask = param->valuedouble;

    /*To do */
    //hw_config
    //radar
    return webconfig_error_none;

}


webconfig_error_t decode_vap_state_object(const cJSON *obj_v_state, schema_wifi_vap_state_t *v_state)
{
       const cJSON *param;

    if ((obj_v_state == NULL) || (v_state == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d VAP state object decode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_encode;
    }

       decode_param_string(obj_v_state, "if_name", param);
       strcpy(v_state->if_name, param->valuestring);

       //enabled
       decode_param_bool(obj_v_state, "enabled", param);
       v_state->enabled = (param->type & cJSON_True) ? true:false;

       //if_name
       decode_param_string(obj_v_state, "if_name", param);
       strcpy(v_state->if_name, param->valuestring);

       //mode
       decode_param_string(obj_v_state, "mode", param);
       strcpy(v_state->mode, param->valuestring);

       //state
       decode_param_string(obj_v_state, "state", param);
       strcpy(v_state->state, param->valuestring);

       //channel
       decode_param_integer(obj_v_state, "channel", param);
       v_state->channel = param->valuedouble;

       //mac
       decode_param_string(obj_v_state, "mac", param);
       strcpy(v_state->mac, param->valuestring);

       //vif_radio_idx
       decode_param_integer(obj_v_state, "vif_radio_idx", param);
       v_state->vif_radio_idx = param->valuedouble;

       //parent
       decode_param_string(obj_v_state, "parent", param);
       strcpy(v_state->parent, param->valuestring);

       //ssid
       decode_param_string(obj_v_state, "ssid", param);
       strcpy(v_state->ssid, param->valuestring);

       //ssid_broadcast
       decode_param_string(obj_v_state, "ssid_broadcast", param);
       strcpy(v_state->ssid_broadcast, param->valuestring);

       //bridge
       decode_param_string(obj_v_state, "bridge", param);
       strcpy(v_state->bridge, param->valuestring);

       //mac_list_type
       decode_param_string(obj_v_state, "mac_list_type", param);
       strcpy(v_state->mac_list_type, param->valuestring);

       //vlan_id
       decode_param_integer(obj_v_state, "vlan_id", param);
       v_state->vlan_id = param->valuedouble;

       //min_hw_mode
       decode_param_string(obj_v_state, "min_hw_mode", param);
       strcpy(v_state->min_hw_mode, param->valuestring);

       //uapsd_enable
       decode_param_bool(obj_v_state, "uapsd_enable", param);
       v_state->uapsd_enable = (param->type & cJSON_True) ? true:false;

       //group_rekey
       decode_param_integer(obj_v_state, "group_rekey", param);
       v_state->group_rekey = param->valuedouble;

       //ap_bridge
       decode_param_bool(obj_v_state, "ap_bridge", param);
       v_state->ap_bridge = (param->type & cJSON_True) ? true:false;

       //ft_mobility_domain
       decode_param_integer(obj_v_state, "ft_mobility_domain", param);
       v_state->ft_mobility_domain = param->valuedouble;

       //dynamic_beacon
       decode_param_bool(obj_v_state, "dynamic_beacon", param);
       v_state->dynamic_beacon = (param->type & cJSON_True) ? true:false;

       //rrm
       decode_param_integer(obj_v_state, "rrm", param);
       v_state->rrm = param->valuedouble;

       //btm
       decode_param_integer(obj_v_state, "btm", param);
       v_state->btm = param->valuedouble;

       //mcast2ucast
       decode_param_bool(obj_v_state, "mcast2ucast", param);
       v_state->mcast2ucast = (param->type & cJSON_True) ? true:false;

       //multi_ap
       decode_param_string(obj_v_state, "multi_ap", param);
       strcpy(v_state->multi_ap, param->valuestring);

       //wps
       decode_param_bool(obj_v_state, "wps", param);
       v_state->wps = (param->type & cJSON_True) ? true:false;

       //wps_pbc
       decode_param_bool(obj_v_state, "wps_pbc", param);
       v_state->wps_pbc = (param->type & cJSON_True) ? true:false;

       //wps_pbc_key_id
       decode_param_string(obj_v_state, "wps_pbc_key_id", param);
       strcpy(v_state->wps_pbc_key_id, param->valuestring);


       /*To Be Done */
       //"mac_list"
       //"wpa":
       //"wpa_key_mgmt":
       //"wpa_psks":
       //"radius_srv_addr":
       //"radius_srv_port":
       //"radius_srv_secret":
       //"dpp_connector":
       //"dpp_csign_hex":
       //"dpp_netaccesskey_hex":
       //associated_clients

       return webconfig_error_none;
}

static void to_mac_bytes   (mac_addr_str_t key, mac_address_t bmac) {
   unsigned int mac[6];
    sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
             &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
   bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
   bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

webconfig_error_t decode_associated_clients_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *assoc_array)
{
    if ((rdk_vap_info == NULL) || (assoc_array == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Associated Client decode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    mac_address_t mac;
    cJSON *obj_array, *assoc_client, *value_object;
    char *tmp_string;
    assoc_dev_data_t* assoc_dev_data;

    unsigned int size = 0, i = 0;
    obj_array = cJSON_GetObjectItem(assoc_array, "associatedClients");
    if (obj_array == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL Json pointer\n", __func__, __LINE__);
    }

    if (cJSON_IsArray(obj_array) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: associated clients object not present\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    size = cJSON_GetArraySize(obj_array);
    if (size == 0) {
        return webconfig_error_none;
    }

    for (i=0; i<size; i++) {
        assoc_client  = cJSON_GetArrayItem(obj_array, i);
        if (assoc_client == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL Json pointer\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        assoc_dev_data = (assoc_dev_data_t *)malloc(sizeof(assoc_dev_data_t));
        if (assoc_dev_data == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        value_object = cJSON_GetObjectItem(assoc_client, "MACAddress");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)){
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }

        tmp_string = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }

        to_mac_bytes(tmp_string, mac);
        memcpy(assoc_dev_data->dev_stats.cli_MACAddress, mac, 6);

        value_object = cJSON_GetObjectItem(assoc_client, "AuthenticationState");
        if ((value_object == NULL) || (cJSON_IsBool(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_AuthenticationState = (value_object->type & cJSON_True) ? true:false;

        value_object = cJSON_GetObjectItem(assoc_client, "LastDataDownlinkRate");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_LastDataDownlinkRate = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "LastDataUplinkRate");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_LastDataUplinkRate = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "SignalStrength");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_SignalStrength = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "Retransmissions");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_Retransmissions = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "Active");
        if ((value_object == NULL) || (cJSON_IsBool(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }

        value_object = cJSON_GetObjectItem(assoc_client, "OperatingStandard");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }

        tmp_string  = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        memcpy(assoc_dev_data->dev_stats.cli_OperatingStandard, tmp_string, strlen(tmp_string)+1);

        value_object = cJSON_GetObjectItem(assoc_client, "OperatingChannelBandwidth");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }

        tmp_string  = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        memcpy(assoc_dev_data->dev_stats.cli_OperatingChannelBandwidth, tmp_string, strlen(tmp_string)+1);

        value_object = cJSON_GetObjectItem(assoc_client, "SNR");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_SNR = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "InterferenceSources");
        if ((value_object == NULL) || (cJSON_IsString(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }

        tmp_string  = cJSON_GetStringValue(value_object);
        if (tmp_string == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        memcpy(assoc_dev_data->dev_stats.cli_InterferenceSources, tmp_string, strlen(tmp_string)+1);

        value_object = cJSON_GetObjectItem(assoc_client, "DataFramesSentAck");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_DataFramesSentAck = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "DataFramesSentNoAck");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_DataFramesSentNoAck = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "BytesSent");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_BytesSent = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "BytesReceived");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_BytesReceived = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "RSSI");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_RSSI = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "MinRSSI");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_MinRSSI = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "MaxRSSI");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_MaxRSSI = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "Disassociations");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_Disassociations = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "AuthenticationFailures");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_AuthenticationFailures = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "PacketsSent");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_PacketsSent = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "PacketsReceived");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_PacketsReceived = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "ErrorsSent");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_ErrorsSent = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "RetransCount");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_RetransCount = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "FailedRetransCount");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_FailedRetransCount = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "RetryCount");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_RetryCount = value_object->valuedouble;

        value_object = cJSON_GetObjectItem(assoc_client, "MultipleRetryCount");
        if ((value_object == NULL) || (cJSON_IsNumber(value_object) == false)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation Failed\n", __func__, __LINE__);
            free(assoc_dev_data);
            return webconfig_error_decode;
        }
        assoc_dev_data->dev_stats.cli_MultipleRetryCount = value_object->valuedouble;

        if (!rdk_vap_info->associated_devices_queue) {
            rdk_vap_info->associated_devices_queue = queue_create();
            if (rdk_vap_info->associated_devices_queue == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer \n", __func__, __LINE__);
                free(assoc_dev_data);
                return webconfig_error_decode;
            }
        }
        queue_push(rdk_vap_info->associated_devices_queue, assoc_dev_data);
    }

    return webconfig_error_none;
}
webconfig_error_t decode_mac_object(rdk_wifi_vap_info_t *rdk_vap_info, cJSON *obj_array )
{
    if ((rdk_vap_info == NULL) || (obj_array == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d MAC OBJECT dencode failed\n",__FUNCTION__, __LINE__);
        return webconfig_error_decode;
    }

    mac_address_t mac;
    cJSON *client, *obj_acl, *obj_acl_add, *obj_acl_del, *mac_object;
    unsigned int size = 0, i = 0;
    acl_entry_t *acl_entry;

    obj_acl =  cJSON_GetObjectItem(obj_array, "MACFilterList");
    obj_acl_add = cJSON_GetObjectItem(obj_array, "MACListToAdd");
    obj_acl_del = cJSON_GetObjectItem(obj_array, "MACListToDelete");

    size = cJSON_GetArraySize(obj_acl);

    for (i=0; i<size; i++) {
        mac_object  = cJSON_GetArrayItem(obj_acl, i);
        client = cJSON_GetObjectItem(mac_object, "MAC");
        char *tmp_mac = cJSON_GetStringValue(client);

        to_mac_bytes(tmp_mac, mac);
        acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
        if (acl_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }
        memset(acl_entry, 0, (sizeof(acl_entry_t)));

        if(!rdk_vap_info->acl_map) {
            rdk_vap_info->acl_map = hash_map_create();
        }
        memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
        acl_entry->acl_action_type = acl_action_none;
        hash_map_put(rdk_vap_info->acl_map, strdup(tmp_mac), acl_entry);
    }

    size = cJSON_GetArraySize(obj_acl_add);

    for (i=0; i<size; i++) {
        mac_object  = cJSON_GetArrayItem(obj_acl_add, i);
        client = cJSON_GetObjectItem(mac_object, "MAC");
        char *tmp_mac = cJSON_GetStringValue(client);

        to_mac_bytes(tmp_mac, mac);
        acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
        if (acl_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        memset(acl_entry, 0, (sizeof(acl_entry_t)));

        if(!rdk_vap_info->acl_map) {
            rdk_vap_info->acl_map = hash_map_create();
        }
        memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
        acl_entry->acl_action_type = acl_action_add;
        hash_map_put(rdk_vap_info->acl_map, strdup(tmp_mac), acl_entry);
    }

    size = cJSON_GetArraySize(obj_acl_del);

    for (i=0; i<size; i++) {
        mac_object  = cJSON_GetArrayItem(obj_acl_del, i);
        client = cJSON_GetObjectItem(mac_object, "MAC");
        char *tmp_mac = cJSON_GetStringValue(client);

        to_mac_bytes(tmp_mac, mac);
        acl_entry = (acl_entry_t*)malloc(sizeof(acl_entry_t));
        if (acl_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer \n", __func__, __LINE__);
            return webconfig_error_decode;
        }

        memset(acl_entry, 0, (sizeof(acl_entry_t)));

        if(!rdk_vap_info->acl_map) {
            rdk_vap_info->acl_map = hash_map_create();
        }
        memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
        acl_entry->acl_action_type = acl_action_del;
        hash_map_put(rdk_vap_info->acl_map, strdup(tmp_mac), acl_entry);
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
    strcpy((char *)blaster_info->PlanId, param->valuestring);

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
