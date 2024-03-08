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

#include "webconfig_framework.h"
#if DML_SUPPORT
#include "wifi_data_plane.h"
#include "wifi_monitor.h"
#include "plugin_main_apis.h"
#else
#include "wifi_passpoint.h"
#include "wifi_data_plane_types.h"
#endif // DML_SUPPORT
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#if DML_SUPPORT
#include <sysevent/sysevent.h>
#endif // DML_SUPPORT
#include <cJSON.h>
#include <dirent.h>
#include <errno.h>
#include "wifi_ctrl.h"
#include "wifi_util.h"//ONE_WIFI

#if !(DML_SUPPORT)
#include "log.h"
#endif // DML_SUPPORT

#define GAS_CFG_TYPE_SUPPORTED 1
#define GAS_STATS_FIXED_WINDOW_SIZE 10
#define GAS_STATS_TIME_OUT 60

static wifi_interworking_t g_interworking_data[16];
static wifi_gas_stats_t gasStats[GAS_CFG_TYPE_SUPPORTED];//ONE_WIFI

extern bool g_interworking_RFC;
extern bool g_passpoint_RFC;

void destroy_passpoint (void);

INT wifi_setGASConfiguration(UINT advertisementID, wifi_GASConfiguration_t *input_struct);

wifi_GASConfiguration_t g_gas_config;

wifi_vap_info_map_t g_vap_maps[2];

#if DML_SUPPORT
#ifndef FEATURE_SUPPORT_PASSPOINT
static long readFileToBuffer(const char *fileName, char **buffer)
{
    FILE    *infile = NULL;
    long    numbytes;
    DIR     *passPointDir = NULL;
   
    passPointDir = opendir(WIFI_PASSPOINT_DIR);
    if(passPointDir){
        closedir(passPointDir);
    }else if(ENOENT == errno){
        if(0 != mkdir(WIFI_PASSPOINT_DIR, 0777)){
            wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Create Passpoint Configuration directory.\n");
            return 0;
        }
    }else{
        wifi_util_dbg_print(WIFI_PASSPOINT,"Error opening Passpoint Configuration directory.\n");
        return 0;
    } 
 
    infile = fopen(fileName, "r");
 
    /* quit if the file does not exist */
    if(infile == NULL)
        return 0;
 
    /* Get the number of bytes */
    fseek(infile, 0L, SEEK_END);
    numbytes = ftell(infile);
    /*CID: 121788 Argument cannot be negative*/
    if (numbytes < 0) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Error in getting the num of bytes\n");
        fclose(infile);
        return 0;
    } 
    /* reset the file position indicator to 
    the beginning of the file */
    fseek(infile, 0L, SEEK_SET);	
 
    /* grab sufficient memory for the 
    buffer to hold the text */
    *buffer = (char*)calloc(numbytes+1, sizeof(char));	
 
    /* memory error */
    if(*buffer == NULL){
        fclose(infile);
        return 0;
    }
 
    /* copy all the text into the buffer */
    /*CID:121787 Ignoring number of bytes read*/
    if(1 != fread(*buffer, numbytes, 1, infile)) {
       wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to read the buffer.\n");
       fclose(infile);
       return 0;
    }
    return numbytes;
}
#endif
#endif // DML_SUPPORT


void process_passpoint_timeout()
{
//GAS Rate computation variables
    static struct timeval last_clean_time;
    static BOOL firstTime  = true;

    static UINT gas_query_rate_queue[GAS_STATS_FIXED_WINDOW_SIZE];
    static UINT gas_response_rate_queue[GAS_STATS_FIXED_WINDOW_SIZE];
    
    static UINT gas_query_rate_window_sum;
    static UINT gas_response_rate_window_sum;
  
    static UCHAR gas_rate_head;

    static UINT gas_queries_per_minute_old;
    static UINT gas_responses_per_minute_old;

    static UCHAR gas_rate_divisor;

    if (firstTime){
        firstTime = false;
        gettimeofday(&last_clean_time, NULL);
    }

    struct timeval curr_time;
    gettimeofday(&curr_time, NULL);

    if ((GAS_STATS_TIME_OUT <= (curr_time.tv_sec - last_clean_time.tv_sec)) ||
        ((curr_time.tv_sec > GAS_STATS_TIME_OUT) &&
         (last_clean_time.tv_sec > curr_time.tv_sec)))
    {
        UCHAR gas_rate_tail = (gas_rate_head + 1) % GAS_STATS_FIXED_WINDOW_SIZE;
      
        UINT gas_queries_per_minute_new = gasStats[GAS_CFG_TYPE_SUPPORTED - 1].Queries - gas_queries_per_minute_old;
        gas_queries_per_minute_old = gasStats[GAS_CFG_TYPE_SUPPORTED - 1].Queries;
      
        gas_query_rate_window_sum = gas_query_rate_window_sum - gas_query_rate_queue[gas_rate_tail] + gas_queries_per_minute_new;
            
        UINT gas_responses_per_minute_new = gasStats[GAS_CFG_TYPE_SUPPORTED - 1].Responses - gas_responses_per_minute_old;
        gas_responses_per_minute_old = gasStats[GAS_CFG_TYPE_SUPPORTED - 1].Responses;
          
        gas_response_rate_window_sum = gas_response_rate_window_sum - gas_response_rate_queue[gas_rate_tail] + gas_responses_per_minute_new;
            
        //move the head
        gas_rate_head = (gas_rate_head + 1) % GAS_STATS_FIXED_WINDOW_SIZE;
        gas_query_rate_queue[gas_rate_head] = gas_queries_per_minute_new;
        gas_response_rate_queue[gas_rate_head] = gas_responses_per_minute_new;
          
        if (gas_rate_divisor < GAS_STATS_FIXED_WINDOW_SIZE)
        {
            gas_rate_divisor++;//Increment the divisor for the first 10 minutes.
        }

        if (gas_rate_divisor)
        {
            //update stats with calculated values
            gasStats[GAS_CFG_TYPE_SUPPORTED - 1].QueryRate = gas_query_rate_window_sum / gas_rate_divisor;
            gasStats[GAS_CFG_TYPE_SUPPORTED - 1].ResponseRate = gas_response_rate_window_sum / gas_rate_divisor;
        }
      
        last_clean_time.tv_sec = curr_time.tv_sec;
    }
}

void process_passpoint_event(wifi_anqp_context_t *anqpReq)
{
    wifi_anqp_node_t *anqpList = NULL;
    int respLength = 0;
    int apIns;
    int mallocRetryCount = 0;
    int capLen;
    UCHAR wfa_oui[3] = {0x50, 0x6f, 0x9a};
    UCHAR *data_pos = NULL;
    bool rfc_status;

    respLength = 0;
    /*CID: 159997 Dereference before null check*/
    if(!anqpReq)
       return;
    apIns = anqpReq->apIndex;
    /*CID: 159998,159995  Out-of-bounds read*/
    if((apIns < 0) || (apIns > 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index: %d.\n", __func__, __LINE__,apIns);
        return;
    }
      
    //A gas query received increase the stats.
    gasStats[GAS_CFG_TYPE_SUPPORTED - 1].Queries++;

    //Check RFC value. Return NUll if not enabled
    get_wifi_rfc_parameters(RFC_WIFI_PASSPOINT, (bool *)&rfc_status);
    if (false == rfc_status){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received ANQP Request. RFC Disabled\n", __func__, __LINE__);
    }else if(g_interworking_data[apIns].passpoint.enable != true){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received ANQP Request. Passpoint is Disabled on AP: %d\n", __func__, __LINE__,apIns);
    }else{
        anqpList = anqpReq->head;
    }

#if defined (FEATURE_SUPPORT_PASSPOINT)
    UINT prevRealmCnt = g_interworking_data[apIns].anqp.realmRespCount;
    UINT prevDomainCnt = g_interworking_data[apIns].anqp.domainRespCount;
    UINT prev3gppCnt = g_interworking_data[apIns].anqp.gppRespCount;
#endif

    while(anqpList){
        anqpList->value->len = 0;
        if(anqpList->value->data){
            free(anqpList->value->data);
            anqpList->value->data = NULL;
        }
        if(anqpList->value->type == wifi_anqp_id_type_anqp){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received ANQP Request\n", __func__, __LINE__);
            switch (anqpList->value->u.anqp_elem_id){
                //CapabilityListANQPElement
                case wifi_anqp_element_name_capability_list:
                    capLen = (g_interworking_data[apIns].anqp.capabilityInfoLength * sizeof(USHORT)) + sizeof(wifi_vendor_specific_anqp_capabilities_t) + g_interworking_data[apIns].passpoint.capabilityInfoLength;
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received CapabilityListANQPElement Request\n", __func__, __LINE__);
                    anqpList->value->data = malloc(capLen);//To be freed in wifi_anqpSendResponse()
                    if(NULL == anqpList->value->data){
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                        if(mallocRetryCount > 5){
                            break;
                        }
                        mallocRetryCount++;
                        anqpList = anqpList->next;
                        continue;
                    }
                    data_pos = anqpList->value->data;
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,capLen);
                    memset(data_pos,0,capLen);
                    memcpy(data_pos,&g_interworking_data[apIns].anqp.capabilityInfo,(g_interworking_data[apIns].anqp.capabilityInfoLength * sizeof(USHORT)));
                    data_pos += (g_interworking_data[apIns].anqp.capabilityInfoLength * sizeof(USHORT));
                    wifi_vendor_specific_anqp_capabilities_t *vendorInfo = (wifi_vendor_specific_anqp_capabilities_t *)data_pos;
                    vendorInfo->info_id = wifi_anqp_element_name_vendor_specific;
                    vendorInfo->len = g_interworking_data[apIns].passpoint.capabilityInfoLength + sizeof(vendorInfo->oi) + sizeof(vendorInfo->wfa_type);
                    memcpy(vendorInfo->oi, wfa_oui, sizeof(wfa_oui));
                    vendorInfo->wfa_type = 0x11;
                    data_pos += sizeof(wifi_vendor_specific_anqp_capabilities_t);
                    memcpy(data_pos, &g_interworking_data[apIns].passpoint.capabilityInfo, g_interworking_data[apIns].passpoint.capabilityInfoLength);
                    anqpList->value->len = capLen;
                    respLength += anqpList->value->len;
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied CapabilityListANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    break;
                //IPAddressTypeAvailabilityANQPElement
                case wifi_anqp_element_name_ip_address_availabality:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received IPAddressTypeAvailabilityANQPElement Request\n", __func__, __LINE__);
                    anqpList->value->data = malloc(sizeof(wifi_ipAddressAvailabality_t));//To be freed in wifi_anqpSendResponse()
                    if(NULL == anqpList->value->data){
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                        if(mallocRetryCount > 5){
                            break;
                        }
                        mallocRetryCount++;
                        anqpList = anqpList->next;
                        continue;
                    }
                    mallocRetryCount = 0;
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,sizeof(wifi_ipAddressAvailabality_t));
                    memset(anqpList->value->data,0,sizeof(wifi_ipAddressAvailabality_t));
                    memcpy(anqpList->value->data,&g_interworking_data[apIns].anqp.ipAddressInfo,sizeof(wifi_ipAddressAvailabality_t));
                    anqpList->value->len = sizeof(wifi_ipAddressAvailabality_t);
                    respLength += anqpList->value->len;
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied IPAddressTypeAvailabilityANQPElement Data. Length: %d. Data: %02X\n", __func__, __LINE__,anqpList->value->len, ((wifi_ipAddressAvailabality_t *)anqpList->value->data)->field_format);
                    break;
                //NAIRealmANQPElement
                case wifi_anqp_element_name_nai_realm:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received NAIRealmANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].anqp.realmInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].anqp.realmInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].anqp.realmInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].anqp.realmInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].anqp.realmInfo,g_interworking_data[apIns].anqp.realmInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].anqp.realmInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied NAIRealmANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
              
                        g_interworking_data[apIns].anqp.realmRespCount++;
                    }
                    break;
                //VenueNameANQPElement
                case wifi_anqp_element_name_venue_name:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received VenueNameANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].anqp.venueInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].anqp.venueInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].anqp.venueInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].anqp.venueInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].anqp.venueInfo,g_interworking_data[apIns].anqp.venueInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].anqp.venueInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied VenueNameANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //3GPPCellularANQPElement
                case wifi_anqp_element_name_3gpp_cellular_network:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received 3GPPCellularANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].anqp.gppInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].anqp.gppInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].anqp.gppInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].anqp.gppInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].anqp.gppInfo,g_interworking_data[apIns].anqp.gppInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].anqp.gppInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied 3GPPCellularANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                        g_interworking_data[apIns].anqp.gppRespCount++;
                    }
                    break;
                //RoamingConsortiumANQPElement
                case wifi_anqp_element_name_roaming_consortium:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received RoamingConsortiumANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].anqp.roamInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].anqp.roamInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].anqp.roamInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].anqp.roamInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].anqp.roamInfo,g_interworking_data[apIns].anqp.roamInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].anqp.roamInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied RoamingConsortiumANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //DomainANQPElement
                case wifi_anqp_element_name_domain_name:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received DomainANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].anqp.domainInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].anqp.domainInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].anqp.domainInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].anqp.domainInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].anqp.domainNameInfo,g_interworking_data[apIns].anqp.domainInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].anqp.domainInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied DomainANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                        g_interworking_data[apIns].anqp.domainRespCount++;
                    }
                    break;
               default:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received Unsupported ANQPElement Request: %d\n", __func__, __LINE__,anqpList->value->u.anqp_elem_id);
                    break;
            }     
        } else if (anqpList->value->type == wifi_anqp_id_type_hs){
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received HS2 ANQP Request\n", __func__, __LINE__);
            switch (anqpList->value->u.anqp_hs_id){
                //CapabilityListANQPElement
                case wifi_anqp_element_hs_subtype_hs_capability_list:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received CapabilityListANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].passpoint.capabilityInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].passpoint.capabilityInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].passpoint.capabilityInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].passpoint.capabilityInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].passpoint.capabilityInfo,g_interworking_data[apIns].passpoint.capabilityInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].passpoint.capabilityInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied CapabilityListANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //OperatorFriendlyNameANQPElement
                case wifi_anqp_element_hs_subtype_operator_friendly_name:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received OperatorFriendlyNameANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].passpoint.opFriendlyNameInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].passpoint.opFriendlyNameInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].passpoint.opFriendlyNameInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].passpoint.opFriendlyNameInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].passpoint.opFriendlyNameInfo,g_interworking_data[apIns].passpoint.opFriendlyNameInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].passpoint.opFriendlyNameInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied OperatorFriendlyNameANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //ConnectionCapabilityListANQPElement
                case wifi_anqp_element_hs_subtype_conn_capability:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received ConnectionCapabilityListANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].passpoint.connCapabilityLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].passpoint.connCapabilityLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].passpoint.connCapabilityLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].passpoint.connCapabilityLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].passpoint.connCapabilityInfo,g_interworking_data[apIns].passpoint.connCapabilityLength);
                        anqpList->value->len = g_interworking_data[apIns].passpoint.connCapabilityLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied ConnectionCapabilityListANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //NAIHomeRealmANQPElement
                case wifi_anqp_element_hs_subtype_nai_home_realm_query:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received NAIHomeRealmANQPElement Request\n", __func__, __LINE__);
                    if(g_interworking_data[apIns].passpoint.realmInfoLength){
                        anqpList->value->data = malloc(g_interworking_data[apIns].passpoint.realmInfoLength);//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                            if(mallocRetryCount > 5){
                                break;
                            }
                            mallocRetryCount++;
                            anqpList = anqpList->next;
                            continue;
                        }
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,g_interworking_data[apIns].passpoint.realmInfoLength);
                        memset(anqpList->value->data,0,g_interworking_data[apIns].passpoint.realmInfoLength);
                        memcpy(anqpList->value->data,&g_interworking_data[apIns].passpoint.realmInfo,g_interworking_data[apIns].passpoint.realmInfoLength);
                        anqpList->value->len = g_interworking_data[apIns].passpoint.realmInfoLength;
                        respLength += anqpList->value->len;
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied NAIHomeRealmANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    }
                    break;
                //WANMetricsANQPElement
                case wifi_anqp_element_hs_subtype_wan_metrics:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received WANMetricsANQPElement Request\n", __func__, __LINE__);
                    anqpList->value->data = malloc(sizeof(wifi_HS2_WANMetrics_t));//To be freed in wifi_anqpSendResponse()
                        if(NULL == anqpList->value->data){
                        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
                        if(mallocRetryCount > 5){
                            break;
                        }
                        mallocRetryCount++;
                        anqpList = anqpList->next;
                        continue;
                    }
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Preparing to Copy Data. Length: %d\n", __func__, __LINE__,sizeof(wifi_HS2_WANMetrics_t));
                    memset(anqpList->value->data,0,sizeof(wifi_HS2_WANMetrics_t));
                    memcpy(anqpList->value->data,&g_interworking_data[apIns].passpoint.wanMetricsInfo,sizeof(wifi_HS2_WANMetrics_t));
                    anqpList->value->len = sizeof(wifi_HS2_WANMetrics_t);
                    respLength += anqpList->value->len;
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Copied WANMetricsANQPElement Data. Length: %d\n", __func__, __LINE__,anqpList->value->len);
                    break;
               default:
                    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received Unsupported HS2ANQPElement Request: %d\n", __func__, __LINE__,anqpList->value->u.anqp_hs_id);
                    break;
            }
        }else{
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid Request Type\n", __func__, __LINE__);
        }
        anqpList = anqpList->next;
    }
#if defined (FEATURE_SUPPORT_PASSPOINT)
    if(respLength == 0){
           wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Requested ANQP parameter is NULL\n", __func__, __LINE__);
    }
    if(RETURN_OK != (wifi_anqpSendResponse(anqpReq->apIndex, anqpReq->sta, anqpReq->token,  anqpReq->head))){
        //We have failed to send a gas response increase the stats
        gasStats[GAS_CFG_TYPE_SUPPORTED - 1].FailedResponses++;

        if(prevRealmCnt != g_interworking_data[apIns].anqp.realmRespCount){
            g_interworking_data[apIns].anqp.realmRespCount = prevRealmCnt;
            g_interworking_data[apIns].anqp.realmFailedCount++;
        }
        if(prevDomainCnt != g_interworking_data[apIns].anqp.domainRespCount){
            g_interworking_data[apIns].anqp.domainRespCount = prevDomainCnt;
            g_interworking_data[apIns].anqp.domainFailedCount++;
        }
        if(prev3gppCnt != g_interworking_data[apIns].anqp.gppRespCount){
            g_interworking_data[apIns].anqp.gppRespCount = prev3gppCnt;
            g_interworking_data[apIns].anqp.gppFailedCount++;
        }
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to send ANQP Response. Clear Request and Continue\n", __func__, __LINE__);
    }else{
        //We have sent a gas response increase the stats
        gasStats[GAS_CFG_TYPE_SUPPORTED - 1].Responses++;
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Successfully sent ANQP Response.\n", __func__, __LINE__);
    }
#endif 
    if(anqpReq){
        free(anqpReq);
        anqpReq = NULL;
    }
}

void anqpRequest_callback(UINT apIndex, mac_address_t sta, unsigned char token,  wifi_anqp_node_t *head)
{
    wifi_anqp_context_t *anqpReq = malloc(sizeof(wifi_anqp_context_t));
    memset(anqpReq,0,sizeof(wifi_anqp_context_t));
    anqpReq->apIndex = apIndex;
    memcpy(anqpReq->sta, sta, sizeof(mac_address_t));
    anqpReq->head = head;
    anqpReq->token = token;
    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Received ANQP Request. Pushing to Data Plane Queue.\n", __func__, __LINE__);
    data_plane_queue_push(data_plane_queue_create_event(anqpReq,wifi_data_plane_event_type_anqp, true));
}

int init_passpoint (void)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Initializing Passpoint\n", __func__, __LINE__);

    if(RETURN_OK != wifi_anqp_request_callback_register((wifi_anqp_request_callback_t)anqpRequest_callback)) {
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Failed to Initialize ANQP Callback\n", __func__, __LINE__);
        return RETURN_ERR;
    }
#endif
    return RETURN_OK;
}

INT WiFi_initPasspoint(void)
{
    if ((init_passpoint() < 0)) {
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s %d: init_passpoint Failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

INT WiFi_SaveGasCfg(char *buffer, int len)
{
    DIR     *passPointDir = NULL;
   
    passPointDir = opendir(WIFI_PASSPOINT_DIR);
    if(passPointDir){
        closedir(passPointDir);
    }else if(ENOENT == errno){
        if(0 != mkdir(WIFI_PASSPOINT_DIR, 0777)){
            wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Create Passpoint Configuration directory. Setting Default\n");
            return RETURN_ERR;;
        }
    }else{
        wifi_util_dbg_print(WIFI_PASSPOINT,"Error opening Passpoint Configuration directory. Setting Default\n");
        return RETURN_ERR;;
    } 
 
    FILE *fPasspointGasCfg = fopen(WIFI_PASSPOINT_GAS_CFG_FILE, "w");
    if(0 == fwrite(buffer, len,1, fPasspointGasCfg)){
        fclose(fPasspointGasCfg);
        return RETURN_ERR;
    }else{
        fclose(fPasspointGasCfg);
        return RETURN_OK;
    }
}

void WiFi_GetGasConfig(char *pString)
{   
    cJSON *gasCfg = NULL;
    cJSON *mainEntry = NULL;
    wifi_GASConfiguration_t gasConfig_struct;
    char JSON_STR[512] = {0};

#if defined (FEATURE_SUPPORT_PASSPOINT)
    if(RETURN_OK != wifidb_get_gas_config(0,&gasConfig_struct)){
#endif  
        copy_string(pString,WIFI_PASSPOINT_DEFAULT_GAS_CFG);
        return;
#if defined (FEATURE_SUPPORT_PASSPOINT)
    }
#endif
    
    gasCfg = cJSON_CreateObject();
    if (NULL == gasCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to create GAS JSON Object\n");
        copy_string(pString,WIFI_PASSPOINT_DEFAULT_GAS_CFG);
        return;
    }
    
    mainEntry = cJSON_AddObjectToObject(gasCfg,"GasConfig");
    
    cJSON_AddNumberToObject(mainEntry,"AdvertisementId",gasConfig_struct.AdvertisementID);
    cJSON_AddBoolToObject(mainEntry,"PauseForServerResp",gasConfig_struct.PauseForServerResponse);
    cJSON_AddNumberToObject(mainEntry,"RespTimeout",gasConfig_struct.ResponseTimeout);
    cJSON_AddNumberToObject(mainEntry,"ComebackDelay",gasConfig_struct.ComeBackDelay);
    cJSON_AddNumberToObject(mainEntry,"RespBufferTime",gasConfig_struct.ResponseBufferingTime);
    cJSON_AddNumberToObject(mainEntry,"QueryRespLengthLimit",gasConfig_struct.QueryResponseLengthLimit);
    
    cJSON_PrintPreallocated(gasCfg, JSON_STR, sizeof(JSON_STR),false);
    copy_string(pString,JSON_STR);
    cJSON_Delete(gasCfg);
    return;
}

INT WiFi_SetGasConfig(char *JSON_STR)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    wifi_GASConfiguration_t gasConfig_struct = {0, 0, 0, 0, 0, 0};
    Err execRetVal;
    wifi_GASConfiguration_t *p_gas_config = Get_wifi_gas_conf_object();

    if(!p_gas_config){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Wifi Context is NULL\n");
        return RETURN_ERR;
    }

    cJSON *gasList = NULL;
    cJSON *gasEntry = NULL;

    if(!JSON_STR){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to read JSON\n");
        return RETURN_ERR;
    }

    cJSON *passPointCfg = cJSON_Parse(JSON_STR);

    if (NULL == passPointCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to parse JSON\n");
        return RETURN_ERR;
    }

    gasList = cJSON_GetObjectItem(passPointCfg,"GASConfig");
    if(NULL == gasList){
        wifi_util_dbg_print(WIFI_PASSPOINT,"gasList is NULL\n");
        cJSON_Delete(passPointCfg);
        return RETURN_ERR;
    } 

    memset((char *)&gasConfig_struct,0,sizeof(gasConfig_struct));

   cJSON_ArrayForEach(gasEntry, gasList) {
#ifndef LINUX_VM_PORT
        if(RETURN_OK!= validate_gas_config(gasEntry, &gasConfig_struct, &execRetVal)) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"Invalid GAS Configuration. %s\n",execRetVal.ErrorMsg);
            cJSON_Delete(passPointCfg);
            return RETURN_ERR;
        }
#endif
    }


    if(RETURN_OK == wifi_setGASConfiguration(gasConfig_struct.AdvertisementID, &gasConfig_struct)){
	p_gas_config->AdvertisementID = gasConfig_struct.AdvertisementID; 
        p_gas_config->PauseForServerResponse = gasConfig_struct.PauseForServerResponse;
        p_gas_config->ResponseTimeout = gasConfig_struct.ResponseTimeout;
        p_gas_config->ComeBackDelay = gasConfig_struct.ComeBackDelay;
        p_gas_config->ResponseBufferingTime = gasConfig_struct.ResponseBufferingTime;
        p_gas_config->QueryResponseLengthLimit = gasConfig_struct.QueryResponseLengthLimit;
        cJSON_Delete(passPointCfg);

        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d GasConfig PauseForServerResponse=%d ResponseBufferingTime=%d QueryResponseLengthLimit=%d  ResponseTimeout=%d ComeBackDelay=%d\n",__func__, __LINE__,gasConfig_struct.PauseForServerResponse,gasConfig_struct.ResponseBufferingTime,gasConfig_struct.QueryResponseLengthLimit,gasConfig_struct.ResponseTimeout,gasConfig_struct.ComeBackDelay);
#if defined(ENABLE_FEATURE_MESHWIFI)        
        //Update OVSDB
        if(RETURN_OK != wifidb_update_gas_config(gasConfig_struct.AdvertisementID, &gasConfig_struct))
        {
            wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to update OVSDB with GAS Config. Adv-ID:%d\n",gasConfig_struct.AdvertisementID);
        }
#else
        if (RETURN_OK != WiFi_SaveGasCfg (JSON_STR, strlen(JSON_STR))) {
            wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to update OVSDB with GAS Config. Adv-ID:%d\n",gasConfig_struct.AdvertisementID);
        }
#endif
        return RETURN_OK;
      }
      wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to update HAL with GAS Config. Adv-ID:%d\n",gasConfig_struct.AdvertisementID);
      return RETURN_ERR;
#else
    UNREFERENCED_PARAMETER(JSON_STR);
#endif 
    return RETURN_ERR;
}

#if 1
INT WiFi_DefaultGasConfig(void)
{
    char *JSON_STR = malloc(strlen(WIFI_PASSPOINT_DEFAULT_GAS_CFG)+1);
    /*CID: 121790 Dereference before null check*/
    if (JSON_STR == NULL) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"malloc failure\n");
        return RETURN_ERR;
    }
    memset(JSON_STR,0,(strlen(WIFI_PASSPOINT_DEFAULT_GAS_CFG)+1));
    copy_string(JSON_STR, WIFI_PASSPOINT_DEFAULT_GAS_CFG);

    if(!JSON_STR || (RETURN_OK != WiFi_SetGasConfig(JSON_STR))){
        if(JSON_STR){
            free(JSON_STR);
            JSON_STR = NULL;
        }
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to update HAL with default GAS Config.\n");
        return RETURN_ERR;
    }
    if(JSON_STR){
        free(JSON_STR);
        JSON_STR = NULL;
    }
    return RETURN_OK;
}
#endif

INT WiFi_InitGasConfig(void)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)  
    char *JSON_STR = NULL;
   
#if defined(ENABLE_FEATURE_MESHWIFI)
    wifi_GASConfiguration_t gasConfig_struct = {0};
    //wifi_GASConfiguration_t *p_gas_config = Get_wifi_gas_conf_object();
    cJSON *gasCfg = NULL;
    cJSON *mainEntry = NULL;

    if(RETURN_OK != wifidb_get_gas_config(0,&gasConfig_struct)){
        return WiFi_DefaultGasConfig();
    }

    gasCfg = cJSON_CreateObject();
    if (NULL == gasCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to create GAS JSON Object\n");
        return WiFi_DefaultGasConfig();
    }

    cJSON *GASConfig = cJSON_CreateArray();
    mainEntry = cJSON_CreateObject();
    cJSON_AddNumberToObject(mainEntry,"AdvertisementId",gasConfig_struct.AdvertisementID);
    cJSON_AddBoolToObject(mainEntry,"PauseForServerResp",gasConfig_struct.PauseForServerResponse);
    cJSON_AddNumberToObject(mainEntry,"RespTimeout",gasConfig_struct.ResponseTimeout);
    cJSON_AddNumberToObject(mainEntry,"ComebackDelay",gasConfig_struct.ComeBackDelay);
    cJSON_AddNumberToObject(mainEntry,"RespBufferTime",gasConfig_struct.ResponseBufferingTime);
    cJSON_AddNumberToObject(mainEntry,"QueryRespLengthLimit",gasConfig_struct.QueryResponseLengthLimit);
    cJSON_AddItemToArray(GASConfig,mainEntry);
    cJSON_AddItemToObject(gasCfg, "GASConfig", GASConfig);
  
    JSON_STR = malloc(512);
    memset(JSON_STR, 0, 512);

    cJSON_PrintPreallocated(gasCfg, JSON_STR,512,false);
    cJSON_Delete(gasCfg);
    wifi_util_dbg_print(WIFI_PASSPOINT,"JSON_STR Is %s\n",JSON_STR);
#else
    long confSize = readFileToBuffer(WIFI_PASSPOINT_GAS_CFG_FILE,&JSON_STR);

    if(!confSize || !JSON_STR) { 
        if(JSON_STR){
            free(JSON_STR);
            JSON_STR = NULL;
        }
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Initialize GAS Configuration from memory. Setting Default\n");
        return WiFi_DefaultGasConfig();
    }
#endif

    if((RETURN_OK != WiFi_SetGasConfig(JSON_STR))){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Initialize GAS Configuration from memory. Setting Default\n");
        return WiFi_DefaultGasConfig();
    }

    if(JSON_STR){
        free(JSON_STR);
        JSON_STR = NULL;
    }
#endif
    return RETURN_OK;
}

INT WiFi_GetGasStats(wifi_gas_stats_t *pGASStats)
{
    if(!pGASStats){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Wifi GAS Context is NULL\n");
        return RETURN_ERR;
    }

    memset(pGASStats,0,sizeof(wifi_gas_stats_t));
    memcpy(pGASStats,&gasStats[GAS_CFG_TYPE_SUPPORTED - 1],sizeof(gasStats));
    return RETURN_OK;
}

INT WiFi_SetANQPConfig(uint8_t vapIndex, char *JSON_STR)
{
    Err execRetVal;
    int apIns = vapIndex - 1;

    if((apIns < 0) || (apIns > 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Setting to 1\n", __func__, __LINE__);
        apIns = 0;
    }

    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns);//ONE_WIFI
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return RETURN_ERR;
    }
    wifi_interworking_t anqpData;
    wifi_InterworkingElement_t interworking;
    cJSON *mainEntry = NULL;

    if(!JSON_STR){
        wifi_util_dbg_print(WIFI_PASSPOINT,"JSON String is NULL\n");
        return RETURN_ERR;
    }

    cJSON *passPointCfg = cJSON_Parse(JSON_STR);

    if (NULL == passPointCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to parse JSON\n");
        return RETURN_ERR;
    }

    mainEntry = cJSON_GetObjectItem(passPointCfg,"ANQP");
    if(NULL == mainEntry){
        wifi_util_dbg_print(WIFI_PASSPOINT,"ANQP entry is NULL\n");
        cJSON_Delete(passPointCfg);
        return RETURN_ERR;
    }
   
    memset((char *)&anqpData,0,sizeof(wifi_interworking_t));
    (void)memset(&interworking, 0, sizeof(interworking));
    wifi_getApInterworkingElement(apIns,&interworking);
    (void)memcpy(&anqpData.interworking, &interworking, sizeof(interworking));

#ifndef LINUX_VM_PORT
    if (validate_anqp(mainEntry, &anqpData, &execRetVal) != 0) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed. Error: %s\n", __func__, __LINE__,execRetVal.ErrorMsg);
        cJSON_Delete(passPointCfg);
        return RETURN_ERR;
    }
#endif

    if (memcmp(&g_interworking_data[apIns].roamingConsortium,
            &anqpData.roamingConsortium,
        sizeof(anqpData.roamingConsortium)) != 0) {
#if defined (FEATURE_SUPPORT_PASSPOINT)
        if (RETURN_OK != wifi_pushApRoamingConsortiumElement(apIns, 
                     &anqpData.roamingConsortium)) {
            wifi_util_dbg_print(WIFI_PASSPOINT, "%s: Failed to push Roaming Consotrium to hal for wlan %d\n",
                            __FUNCTION__, apIns);
            cJSON_Delete(passPointCfg);
            return RETURN_ERR;
        }
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s: Applied Roaming Consortium configuration successfully for wlan %d\n",
                   __FUNCTION__, apIns);
#endif
        memcpy(&g_interworking_data[apIns].roamingConsortium,&anqpData.roamingConsortium,
               sizeof(anqpData.roamingConsortium));

        //Update TR-181
	pCfg->roamingConsortium.wifiRoamingConsortiumCount = anqpData.roamingConsortium.wifiRoamingConsortiumCount;
        memcpy(&pCfg->roamingConsortium.wifiRoamingConsortiumOui,&anqpData.roamingConsortium.wifiRoamingConsortiumOui,
               sizeof(pCfg->roamingConsortium.wifiRoamingConsortiumOui));
        memcpy(&pCfg->roamingConsortium.wifiRoamingConsortiumLen,&anqpData.roamingConsortium.wifiRoamingConsortiumLen,
               sizeof(pCfg->roamingConsortium.wifiRoamingConsortiumLen));//ONE_WIFI
    }

    memcpy(&g_interworking_data[apIns].anqp, &anqpData.anqp, sizeof(wifi_anqp_settings_t));
    wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation Success. Updating ANQP Config\n", __func__, __LINE__);

    cJSON_Delete(passPointCfg);

    return RETURN_OK;
}

INT WiFi_SaveANQPCfg(uint8_t vapIndex)
{
    char cfgFile[64];
    DIR     *passPointDir = NULL;
    int apIns = 0;
    char *buffer = NULL;
    int len = 0;

    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(vapIndex - 1);//ONE_WIFI
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, vapIndex);
	return RETURN_ERR;
    }

    buffer = (char *)pCfg->anqp.anqpParameters;
    if (!buffer) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"ANQP Parameters is NULL.\n");
        return RETURN_ERR;
    }

    len = strlen((char *)pCfg->anqp.anqpParameters);
    if (!len) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"ANQP Parameters Length is 0.\n");
        return RETURN_ERR;
    }
 
    passPointDir = opendir(WIFI_PASSPOINT_DIR);
    if(passPointDir){
        closedir(passPointDir);
    }else if(ENOENT == errno){
        if(0 != mkdir(WIFI_PASSPOINT_DIR, 0777)){
            wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Create Passpoint Configuration directory.\n");
            return RETURN_ERR;
        }
    }else{
        wifi_util_dbg_print(WIFI_PASSPOINT,"Error opening Passpoint Configuration directory.\n");
        return RETURN_ERR;
    } 
 
    apIns = vapIndex;//ONE_WIFI

    sprintf(cfgFile,"%s.%d",WIFI_PASSPOINT_ANQP_CFG_FILE,apIns);
    FILE *fPasspointAnqpCfg = fopen(cfgFile, "w");
    if(0 == fwrite(buffer, len,1, fPasspointAnqpCfg)){
        fclose(fPasspointAnqpCfg);
        return RETURN_ERR;
    }else{
        fclose(fPasspointAnqpCfg);
        return RETURN_OK;
    }
}

#if 0
INT CosaDmlWiFi_InitANQPConfig(PCOSA_DML_WIFI_AP_CFG pCfg_t)
//INT WiFi_InitANQPConfig(void)
{
    char cfgFile[64];
    char *JSON_STR = NULL;
    int apIns = 0;
    long confSize = 0;
    UINT radio_index = 0;
    UINT vap_index = 0;//ONE_WIFI //This value is static temporary

    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(radio_index, vap_index);
#if 0
    if(!pCfg){
        wifi_util_dbg_print(WIFI_PASSPOINT,"AP Context is NULL\n");
        return RETURN_ERR;
    }
    pCfg->IEEE80211uCfg.PasspointCfg.ANQPConfigParameters = NULL;
    apIns = pCfg->InstanceNumber;
    if((apIns < 1) || (apIns > 16)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Return\n", __func__, __LINE__);
        return RETURN_ERR;
    }
#else 
    apIns = (radio_index * MAX_NUM_VAP_PER_RADIO) + vap_index;
#endif//ONE_WIFI

    sprintf(cfgFile,"%s.%d",WIFI_PASSPOINT_ANQP_CFG_FILE,apIns);
   
    confSize = readFileToBuffer(cfgFile,&JSON_STR);

    if(!confSize || !JSON_STR || (RETURN_OK != WiFi_SetANQPConfig(apIns, JSON_STR))){
   //if(!confSize || !JSON_STR || (RETURN_OK != CosaDmlWiFi_SetANQPConfig(pCfg_t, JSON_STR))){
        if(JSON_STR){
            free(JSON_STR);
            JSON_STR = NULL;
        }
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Initialize ANQP Configuration from memory for AP: %d.\n",apIns);
       // pCfg->IEEE80211uCfg.PasspointCfg.ANQPConfigParameters = NULL; //ONE_WIFI
    } else {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Initialized ANQP Configuration from memory for AP: %d.\n",apIns);
        strcpy(pCfg->anqp.anqpParameters, JSON_STR);
    }
    return RETURN_OK;
}
#endif//ONE_WIFI

void WiFi_UpdateANQPVenueInfo(uint8_t vapIndex)
{
    int apIns = vapIndex - 1;
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns);
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return;
    }
    if((apIns < 0) || (apIns > 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Return\n", __func__, __LINE__);
        return;
    }

    //Copy Venue Group and Type from Interworking Structure
    g_interworking_data[apIns].anqp.venueInfo.venueGroup = pCfg->anqp.venueInfo.venueGroup;
    g_interworking_data[apIns].anqp.venueInfo.venueType = pCfg->anqp.venueInfo.venueType;//ONE_WIFI

    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Updated VenueNameANQPElement from Interworking\n", __func__, __LINE__);

}

INT WiFi_SetHS2Config(uint8_t vapIndex, char *JSON_STR)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    Err execRetVal;
    BOOL apEnable = FALSE;
    int apIns = vapIndex - 1;
    if((apIns < 0) || (apIns > 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Setting to 1\n", __func__, __LINE__);
        apIns = 0;
    }
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns);
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return RETURN_ERR;
    }
    
    wifi_interworking_t passpointCfg;
    wifi_InterworkingElement_t interworking;
    cJSON *mainEntry = NULL;
    
    if(!JSON_STR){
        wifi_util_dbg_print(WIFI_PASSPOINT,"JSON String is NULL\n");
        return RETURN_ERR;
    }
    
    cJSON *passPointObj = cJSON_Parse(JSON_STR);
    
    if (NULL == passPointObj) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to parse JSON\n");
        return RETURN_ERR;
    }
    
    mainEntry = cJSON_GetObjectItem(passPointObj,"Passpoint");
    if(NULL == mainEntry){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Passpoint entry is NULL\n");
        cJSON_Delete(passPointObj);
        return RETURN_ERR;
    }

#ifndef LINUX_VM_PORT
    //Fetch RFC values for Interworking and Passpoint
    get_wifi_rfc_parameters(RFC_WIFI_INTERWORKING, (bool *)&g_interworking_RFC);
    get_wifi_rfc_parameters(RFC_WIFI_PASSPOINT, (bool *)&g_passpoint_RFC);//ONE_WIFI
#endif

    memset((char *)&passpointCfg,0,sizeof(wifi_interworking_t));
    (void)memset(&interworking, 0, sizeof(interworking));
    wifi_getApInterworkingElement(apIns,&interworking);//TBD -A
    (void)memcpy(&passpointCfg.interworking, &interworking, sizeof(interworking));
#ifndef LINUX_VM_PORT
    if (validate_passpoint(mainEntry, &passpointCfg, &execRetVal) != 0) {   
       wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation failed. Error: %s\n", __func__, __LINE__,execRetVal.ErrorMsg);
       cJSON_Delete(passPointObj);
       return RETURN_ERR;
    }
#endif
   
    wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Validation Success. Updating Passpoint Config\n", __func__, __LINE__);

    wifi_getApEnable(apIns, &apEnable);
    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Enable flag of AP Index: %d is %d \n", __func__, __LINE__,apIns, apEnable);
    if(apEnable) {
        if(RETURN_OK == enablePassPointSettings(apIns, passpointCfg.passpoint.enable,
                                                       passpointCfg.passpoint.gafDisable,
                                                       passpointCfg.passpoint.p2pDisable,
                                                       passpointCfg.passpoint.l2tif)) {
             wifi_util_dbg_print(WIFI_PASSPOINT,"%s:%d: Successfully set Passpoint Config\n", __func__, __LINE__);

	     pCfg->passpoint.enable = passpointCfg.passpoint.enable;
             pCfg->passpoint.gafDisable = passpointCfg.passpoint.gafDisable;
             pCfg->passpoint.p2pDisable = passpointCfg.passpoint.p2pDisable;
             pCfg->passpoint.l2tif = passpointCfg.passpoint.l2tif;//ONE_WIFI
         }else{
             wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Error Setting Passpoint Enable Status on AP: %d\n", __func__, __LINE__,apIns);
             cJSON_Delete(passPointObj);
             return RETURN_ERR;
        }
    } else {
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: VAP is disabled. Not Initializing Passpoint Enable Status on AP: %d\n", __func__, __LINE__,apIns);
    }
    memcpy((char *)&g_interworking_data[apIns].passpoint,&passpointCfg.passpoint,sizeof(wifi_passpoint_settings_t));

    cJSON_Delete(passPointObj);
#else
    UNREFERENCED_PARAMETER(JSON_STR);
#endif

    return RETURN_OK;
}

INT WiFi_SetHS2Status(uint8_t vapIndex, BOOL bValue, BOOL setToPSM)
{
    int apIns = vapIndex;
    if((apIns < 1) || (apIns > 16)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Return\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns - 1);//ONE_WIFI
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return RETURN_ERR;
    }

#if defined (FEATURE_SUPPORT_PASSPOINT)    
    
    if(RETURN_OK == enablePassPointSettings (apIns-1, bValue, g_interworking_data[apIns-1].passpoint.gafDisable, g_interworking_data[apIns-1].passpoint.p2pDisable, g_interworking_data[apIns-1].passpoint.l2tif)){
        pCfg->passpoint.enable = g_interworking_data[apIns-1].passpoint.enable = bValue;//ONE_WIFI
    }else{
      wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Error Setting Passpoint Enable Status on AP: %d\n", __func__, __LINE__,apIns);
      return RETURN_ERR;
    }

    if(true == bValue){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Passpoint is Enabled on AP: %d\n", __func__, __LINE__,apIns);
    }else{
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Passpoint is Disabled on AP: %d\n", __func__, __LINE__,apIns);
    }
#else
    UNREFERENCED_PARAMETER(bValue);
#endif
    UNREFERENCED_PARAMETER(setToPSM);
    return RETURN_OK;
}
    
        
INT WiFi_SaveHS2Cfg(uint8_t vapIndex)
{
    char cfgFile[64];
    DIR     *passPointDir = NULL;
    int apIns = 0;
    char *buffer = NULL;
    int len = 0;

    apIns = vapIndex;
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns - 1);//ONE_WIFI
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return RETURN_ERR;
    }

    buffer = (char *)pCfg->passpoint.hs2Parameters;
    if (!buffer) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Passpoint Parameters is NULL.\n");
        return RETURN_ERR;
    }

    len = strlen((char *)pCfg->passpoint.hs2Parameters);
    if (!len) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Passpoint Parameters Length is 0.\n");
        return RETURN_ERR;
    }//ONE_WIFI
    
    passPointDir = opendir(WIFI_PASSPOINT_DIR);
    if(passPointDir){
        closedir(passPointDir);
    }else if(ENOENT == errno){
        if(0 != mkdir(WIFI_PASSPOINT_DIR, 0777)){
            wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Create Passpoint Configuration directory.\n");
            return RETURN_ERR;
        }
    }else{
        wifi_util_dbg_print(WIFI_PASSPOINT,"Error opening Passpoint Configuration directory.\n");
        return RETURN_ERR;
    }
    
    sprintf(cfgFile,"%s.%d",WIFI_PASSPOINT_HS2_CFG_FILE,apIns);
    FILE *fPasspointCfg = fopen(cfgFile, "w");
    if(0 == fwrite(buffer, len,1, fPasspointCfg)){
        fclose(fPasspointCfg);
        return RETURN_ERR;
    }else{
        fclose(fPasspointCfg);
        return RETURN_OK;
    }
}

#if DML_SUPPORT
#if 0
//INT CosaDmlWiFi_InitHS2Config(PCOSA_DML_WIFI_AP_CFG pCfg_t)
INT WiFi_InitHS2Config(uint8_t vapIndex)
{
    char cfgFile[64];
    char *JSON_STR = NULL;
    int apIns = 0;
    long confSize = 0;
#if 0 
    if(!pCfg){
        wifi_util_dbg_print(WIFI_PASSPOINT,"AP Context is NULL\n");
        return RETURN_ERR;
    }
#else
    UINT radio_index = 0;
    UINT vap_index = 0; //ONE_WIFI //Temporary static value
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(radio_index, vap_index);
#endif//ONE_WIFI
#if 0
    pCfg->IEEE80211uCfg.PasspointCfg.HS2Parameters = NULL;
    apIns = pCfg->InstanceNumber;
    if((apIns < 1) || (apIns > 16)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Return\n", __func__, __LINE__);
        return RETURN_ERR;
    }
   
    //Set Default DGAF value to true
    pCfg->IEEE80211uCfg.PasspointCfg.gafDisable = true;
#else
    memset(pCfg->passpoint.hs2Parameters, 0, sizeof(pCfg->passpoint.hs2Parameters));
    apIns = (radio_index * MAX_NUM_VAP_PER_RADIO) + vap_index;
    if((apIns < 1) || (apIns > 16)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Return\n", __func__, __LINE__);
        return RETURN_ERR;
    }
   
    //Set Default DGAF value to true
    pCfg->passpoint.gafDisable = true;

#endif//ONE_WIFI
    sprintf(cfgFile,"%s.%d",WIFI_PASSPOINT_HS2_CFG_FILE,apIns);
    
    confSize = readFileToBuffer(cfgFile,&JSON_STR);
    
    if(!confSize || !JSON_STR || (RETURN_OK != WiFi_SetHS2Config(vapIndex, JSON_STR))){
        if(JSON_STR){
            free(JSON_STR);
            JSON_STR = NULL;
        }
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Initialize HS2.0 Configuration from memory for AP: %d. Setting Default\n",apIns);
#if 0
	pCfg->IEEE80211uCfg.PasspointCfg.HS2Parameters = NULL;
#else
        memset(pCfg->passpoint.hs2Parameters, 0, sizeof(pCfg->passpoint.hs2Parameters));
#endif//ONE_WIFI
    } else {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Initialized HS2.0 Configuration from memory for AP: %d.\n",apIns);
       // pCfg->IEEE80211uCfg.PasspointCfg.HS2Parameters = JSON_STR;
          strcpy(pCfg->passpoint.hs2Parameters, JSON_STR);//ONE_WIFI

    }

    return RETURN_OK;
}
#endif//ONE_WIFI
#endif // DML_SUPPORT

INT WiFi_GetWANMetrics(uint8_t vapIndex, char *WANMetrics, UINT WANMetrics_length)
{
    cJSON *mainEntry = NULL;
    int apIns; 

    apIns = vapIndex -1;
    if((apIns < 0) || (apIns > 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Setting to 1\n", __func__, __LINE__);
        apIns = 0;
    }

    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns);
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return RETURN_ERR;
    }
#if 0
    //memset(&pCfg->IEEE80211uCfg.PasspointCfg.WANMetrics, 0, sizeof(pCfg->IEEE80211uCfg.PasspointCfg.WANMetrics));
//    memset(&pCfg->passpoint.wanMetricsInfo, 0, sizeof(pCfg->passpoint.wanMetricsInfo));//ONE_WIFI
#else
      memset(WANMetrics, 0, WANMetrics_length);
#endif//ONE_WIFI
    cJSON *passPointCfg = cJSON_CreateObject();
    if (NULL == passPointCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to create JSON\n");
        return RETURN_ERR;
    }

    mainEntry = cJSON_AddObjectToObject(passPointCfg,"WANMetrics");

    cJSON_AddNumberToObject(mainEntry,"WANInfo",g_interworking_data[apIns].passpoint.wanMetricsInfo.wanInfo); 
    cJSON_AddNumberToObject(mainEntry,"DownlinkSpeed",g_interworking_data[apIns].passpoint.wanMetricsInfo.downLinkSpeed); 
    cJSON_AddNumberToObject(mainEntry,"UplinkSpeed",g_interworking_data[apIns].passpoint.wanMetricsInfo.upLinkSpeed);
    cJSON_AddNumberToObject(mainEntry,"DownlinkLoad",g_interworking_data[apIns].passpoint.wanMetricsInfo.downLinkLoad); 
    cJSON_AddNumberToObject(mainEntry,"UplinkLoad",g_interworking_data[apIns].passpoint.wanMetricsInfo.upLinkLoad); 
    cJSON_AddNumberToObject(mainEntry,"LMD",g_interworking_data[apIns].passpoint.wanMetricsInfo.lmd); 

#if 0
    //cJSON_PrintPreallocated(passPointCfg, (char *)&pCfg->IEEE80211uCfg.PasspointCfg.WANMetrics, sizeof(pCfg->IEEE80211uCfg.PasspointCfg.WANMetrics),false); //ONE_WIFI TBD -N
#else
    cJSON_PrintPreallocated(passPointCfg, (char *)WANMetrics, WANMetrics_length, false);
#endif//ONE_WIFI
    cJSON_Delete(passPointCfg);
    return RETURN_OK;
}

void WiFi_GetHS2Stats(uint8_t vapIndex)
{
    cJSON *mainEntry = NULL;
    cJSON *statsParam = NULL;
    cJSON *statsList = NULL;
    cJSON *statsEntry = NULL;
    int apIns; 

    apIns = vapIndex -1;
    if((apIns < 0) || (apIns > 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index.\n", __func__, __LINE__);
        return;
    }
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns);//ONE_WIFI
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return;
    }

    memset(&pCfg->anqp.passpointStats, 0, sizeof(pCfg->anqp.passpointStats));//ONE_WIFI

    cJSON *passPointStats = cJSON_Parse((char*)g_interworking_data[apIns].anqp.passpointStats);
    if (NULL == passPointStats) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to parse JSON\n");
        return;
    }

    mainEntry = cJSON_GetObjectItem(passPointStats,"PassPointStats");
    if(NULL == mainEntry){
        wifi_util_dbg_print(WIFI_PASSPOINT,"PassPointStats entry is NULL\n");
        cJSON_Delete(passPointStats);
        return;
    }
  
    //Set EAP stats to zero. TBD
    cJSON_AddNumberToObject(mainEntry, "EAPOLStartSuccess", 0);
    cJSON_AddNumberToObject(mainEntry, "EAPOLStartFailed", 0);
    cJSON_AddNumberToObject(mainEntry, "EAPOLStartTimeouts", 0);
    cJSON_AddNumberToObject(mainEntry, "EAPOLStartRetries", 0);
    cJSON_AddNumberToObject(mainEntry, "EAPOLSuccessSent", 0);
    cJSON_AddNumberToObject(mainEntry, "EAPFailedSent", 0);
  
    statsList = cJSON_GetObjectItem(mainEntry, "ANQPResponse");

    cJSON_ArrayForEach(statsEntry, statsList) {
        if(NULL != (statsParam = cJSON_GetObjectItem(statsEntry,"EntryType"))){
            switch((int)statsParam->valuedouble){
                case 1:
                    cJSON_SetIntValue(cJSON_GetObjectItem(statsEntry,"Sent"),g_interworking_data[apIns].anqp.realmRespCount);
                    cJSON_SetIntValue(cJSON_GetObjectItem(statsEntry,"Failed"),g_interworking_data[apIns].anqp.realmFailedCount);
                    break;
                case 2:
                    cJSON_SetIntValue(cJSON_GetObjectItem(statsEntry,"Sent"),g_interworking_data[apIns].anqp.domainRespCount);
                    cJSON_SetIntValue(cJSON_GetObjectItem(statsEntry,"Failed"),g_interworking_data[apIns].anqp.domainFailedCount);
                    break;
                case 3:
                    cJSON_SetIntValue(cJSON_GetObjectItem(statsEntry,"Sent"),g_interworking_data[apIns].anqp.gppRespCount);
                    cJSON_SetIntValue(cJSON_GetObjectItem(statsEntry,"Failed"),g_interworking_data[apIns].anqp.gppFailedCount);
                    break;
            }
        }
    }

    cJSON_PrintPreallocated(passPointStats, (char *)&pCfg->anqp.passpointStats, sizeof(pCfg->anqp.passpointStats),false);
    cJSON_Delete(passPointStats);
    return;
}

#if DML_SUPPORT
#if 0
//INT CosaDmlWiFi_RestoreAPInterworking (int apIndex)
INT WiFi_RestoreAPInterworking (int apIndex)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    //PCOSA_DML_WIFI_AP_CFG pCfg; 
    if((apIndex < 0) || (apIndex> 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index: %d.\n", __func__, __LINE__,apIndex);
        return RETURN_ERR;
    }

#if 0
    pCfg = find_ap_wifi_dml(apIndex);
  
    if (pCfg == NULL)
    {
        return RETURN_ERR;
    }
#else
    uint8_t radio_index = 0;
    uint8_t vap_index = 0;
    
    get_vap_and_radio_index_from_vap_instance(apIndex, &radio_index, &vap_index);
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(radio_index, vap_index);
#endif //ONE_WIFI 

#if 0
    if(!pCfg->InterworkingEnable){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Interworking is disabled on AP: %d. Returning Success\n", __func__, __LINE__, apIndex);
        return RETURN_OK;
    }
#else
    if(!pCfg->interworking.interworkingEnabled){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Interworking is disabled on AP: %d. Returning Success\n", __func__, __LINE__, apIndex);
        return RETURN_OK;
    }
#endif//ONE_WIFI

#if 0
    if ((CosaDmlWiFi_ApplyInterworkingElement(pCfg)) != RETURN_OK)
    {
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: CosaDmlWiFi_ApplyInterworkingElement Failed.\n", __func__, __LINE__);
    }
  
    if(RETURN_OK != CosaDmlWiFi_ApplyRoamingConsortiumElement(pCfg)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: CosaDmlWiFi_ApplyRoamingConsortiumElement Failed.\n", __func__, __LINE__);
    }
#else
    // this implementation is remaining
    //TBD
#endif//ONE_WIFI

    if ((g_interworking_data[apIndex].passpoint.enable) && (RETURN_OK != enablePassPointSettings (apIndex, g_interworking_data[apIndex].passpoint.enable, g_interworking_data[apIndex].passpoint.gafDisable, g_interworking_data[apIndex].passpoint.p2pDisable, g_interworking_data[apIndex].passpoint.l2tif))){
      wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Error Setting Passpoint Enable Status on AP: %d\n", __func__, __LINE__,apIndex);
      return RETURN_ERR;
    }
    //pCfg->IEEE80211uCfg.PasspointCfg.Status = g_interworking_data[apIndex].passpoint.enable;//TBD -N
    pCfg->passpoint.enable = g_interworking_data[apIndex].passpoint.enable;//ONE_WIFI
    wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Set Passpoint Enable Status on AP: %d\n", __func__, __LINE__,apIndex);
#else
    UNREFERENCED_PARAMETER(apIndex);
#endif
    return RETURN_OK;
}
#endif//ONE_WIFI TBD -N
#endif // DML_SUPPORT

INT WiFi_SaveInterworkingWebconfig( wifi_interworking_t *interworking_data, int apIns)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)

    if(!interworking_data) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"NULL Interworking Configuration\n");
        return RETURN_ERR;
    }//ONE_WIFI
    
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(apIns);
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, apIns);
	return RETURN_ERR;
    }

    //Copy ANQP Parameters.
    memset(pCfg->anqp.anqpParameters, 0, sizeof(pCfg->anqp.anqpParameters));
    copy_string((char *)pCfg->anqp.anqpParameters, (char *)interworking_data->anqp.anqpParameters);//ONE_WIFI

    if(RETURN_ERR == WiFi_SaveANQPCfg(apIns)){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Save ANQP Configuration\n");
    }//ONE_WIFI
    
    //Copy Passpoint Parameters.
    memset(pCfg->passpoint.hs2Parameters, 0, sizeof(pCfg->passpoint.hs2Parameters));
    copy_string((char *)pCfg->passpoint.hs2Parameters, (char *)interworking_data->passpoint.hs2Parameters);//ONE_WIFI

    if(RETURN_ERR == WiFi_SaveHS2Cfg(apIns)){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Save  Configuration\n");
    }//ONE_WIFI

    pCfg->passpoint.enable = interworking_data->passpoint.enable;
    pCfg->passpoint.gafDisable = interworking_data->passpoint.gafDisable;
    pCfg->passpoint.p2pDisable = interworking_data->passpoint.p2pDisable;
    pCfg->passpoint.l2tif = interworking_data->passpoint.l2tif;//ONE_WIFI
    //Copy the Data for message responses
    memcpy((char *)&g_interworking_data[apIns], interworking_data, sizeof(wifi_interworking_t));

    memcpy(pCfg->anqp.passpointStats,g_interworking_data[apIns].anqp.passpointStats, sizeof(pCfg->anqp.passpointStats)); //ONE_WIFI
#else
    UNREFERENCED_PARAMETER(apIns);
    UNREFERENCED_PARAMETER(interworking_data);
#endif

    return RETURN_OK;
}

#if DML_SUPPORT
#if 0
/***********************************************************************
Funtion     : CosaDmlWiFi_ReadInterworkingConfig
Input       : Pointer to vAP object, JSON String
Description : Parses JSON String JSON_STR, and populates the vAP object pCfg 
***********************************************************************/
INT CosaDmlWiFi_ReadInterworkingConfig (PCOSA_DML_WIFI_AP_CFG pCfg, char *JSON_STR)
{
    if(!pCfg){
        wifi_util_dbg_print(WIFI_PASSPOINT,"AP Context is NULL\n");
        return RETURN_ERR;
    }

    int apIns = pCfg->InstanceNumber -1;
    if((apIns < 0) || (apIns > 15)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Setting to 1\n", __func__, __LINE__);
        apIns = 0;
    }

    cJSON *mainEntry = NULL;
    cJSON *InterworkingElement = NULL;
    cJSON *venueParam = NULL;

    if(!JSON_STR){
        wifi_util_dbg_print(WIFI_PASSPOINT,"JSON String is NULL\n");
        return RETURN_ERR;
    }

    cJSON *interworkingCfg = cJSON_Parse(JSON_STR);

    if (NULL == interworkingCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to parse JSON\n");
        return RETURN_ERR;
    }

    mainEntry = cJSON_GetObjectItem(interworkingCfg,"Interworking");
    if(NULL == mainEntry){
        wifi_util_dbg_print(WIFI_PASSPOINT,"Interworking entry is NULL\n");
        cJSON_Delete(interworkingCfg);
        return RETURN_ERR;
    }

//Interworking Status
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"InterworkingEnable");
    pCfg->InterworkingEnable = InterworkingElement ? InterworkingElement->valuedouble : 0;

//AccessNetworkType
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"AccessNetworkType");
    if ( (pCfg->InstanceNumber == 5) || (pCfg->InstanceNumber == 6) || (pCfg->InstanceNumber == 9) || (pCfg->InstanceNumber == 10) )        //Xfinity hotspot vaps
    {
        pCfg->IEEE80211uCfg.IntwrkCfg.iAccessNetworkType = InterworkingElement ? InterworkingElement->valuedouble :2;
    } else {
        pCfg->IEEE80211uCfg.IntwrkCfg.iAccessNetworkType = InterworkingElement ? InterworkingElement->valuedouble :0;
    }

//ASRA
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"ASRA");
    pCfg->IEEE80211uCfg.IntwrkCfg.iASRA = InterworkingElement ? InterworkingElement->valuedouble : 0;

//ESR
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"ESR");
    pCfg->IEEE80211uCfg.IntwrkCfg.iESR = InterworkingElement ? InterworkingElement->valuedouble : 0;

//UESA
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"UESA");
    pCfg->IEEE80211uCfg.IntwrkCfg.iUESA = InterworkingElement ? InterworkingElement->valuedouble : 0;

//HESSOptionPresent
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"HESSOptionPresent");
    pCfg->IEEE80211uCfg.IntwrkCfg.iHESSOptionPresent = InterworkingElement ? InterworkingElement->valuedouble : 0;
        
//HESSID
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"HESSID");
    if(InterworkingElement && InterworkingElement->valuestring){
        copy_string(pCfg->IEEE80211uCfg.IntwrkCfg.iHESSID, InterworkingElement->valuestring);
    } else {
        copy_string(pCfg->IEEE80211uCfg.IntwrkCfg.iHESSID, "11:22:33:44:55:66");
    }

//VenueOptionPresent
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"VenueOptionPresent");
    pCfg->IEEE80211uCfg.IntwrkCfg.iVenueOptionPresent = InterworkingElement ? InterworkingElement->valuedouble : 0;

//Venue
    InterworkingElement = cJSON_GetObjectItem(mainEntry,"Venue");
    if (InterworkingElement){
        //VenueGroup
        venueParam = cJSON_GetObjectItem(InterworkingElement,"VenueGroup");
        pCfg->IEEE80211uCfg.IntwrkCfg.iVenueGroup = venueParam ? venueParam->valuedouble : 0;

        //VenueType
        venueParam = cJSON_GetObjectItem(InterworkingElement,"VenueType");
        pCfg->IEEE80211uCfg.IntwrkCfg.iVenueType = venueParam ? venueParam->valuedouble : 0;
    }
    cJSON_Delete(interworkingCfg);
    return RETURN_OK;
}

/***********************************************************************
Funtion     : CosaDmlWiFi_SaveInterworkingConfig
Input       : Pointer to vAP object, JSON String, length of string
Description : Saves Interworking coinfiguration as JSON String into file.
              File is saved for each vap in format InterworkingCfg_<apIns>.json
***********************************************************************/
INT CosaDmlWiFi_SaveInterworkingCfg(PCOSA_DML_WIFI_AP_CFG pCfg, char *buffer, int len)
{   
    char cfgFile[64];
    DIR     *passPointDir = NULL;
    int apIns = 0;
    
    passPointDir = opendir(WIFI_PASSPOINT_DIR);
    if(passPointDir){
        closedir(passPointDir);
    }else if(ENOENT == errno){
        if(0 != mkdir(WIFI_PASSPOINT_DIR, 0777)){ 
            wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Create Passpoint Configuration directory.\n");
            return RETURN_ERR;
        }
    }else{
        wifi_util_dbg_print(WIFI_PASSPOINT,"Error opening Passpoint Configuration directory.\n");
        return RETURN_ERR;
    }
    
    if(!pCfg){
        wifi_util_dbg_print(WIFI_PASSPOINT,"AP Context is NULL\n");
        return RETURN_ERR;
    }
    apIns = pCfg->InstanceNumber;
    sprintf(cfgFile,WIFI_INTERWORKING_CFG_FILE,apIns);
    FILE *fPasspointCfg = fopen(cfgFile, "w");
    if(0 == fwrite(buffer, len,1, fPasspointCfg)){
        fclose(fPasspointCfg);
        return RETURN_ERR;
    }else{
        fclose(fPasspointCfg);
        return RETURN_OK;
    }
}

/***********************************************************************
Funtion     : CosaDmlWiFi_WriteInterworkingConfig
Input       : Pointer to vAP object
Description : Convert Interworking parameters to JSON String JSON_STR, 
              and pass it to CosaDmlWiFi_SaveInterworkingCfg for persistent
              storage
***********************************************************************/
INT CosaDmlWiFi_WriteInterworkingConfig (PCOSA_DML_WIFI_AP_CFG pCfg)
{
    cJSON *mainEntry = NULL;
    cJSON *venueEntry = NULL;
    char JSON_STR[2048];
    int apIns;
    
    if(!pCfg){
        wifi_util_dbg_print(WIFI_PASSPOINT,"AP Context is NULL\n");
        return RETURN_ERR;
    }
    
    apIns = pCfg->InstanceNumber;
    if((apIns < 1) || (apIns > 16)){
        return RETURN_ERR;
    }
    
    cJSON *interworkingCfg = cJSON_CreateObject();
    if (NULL == interworkingCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to create JSON\n");
        return RETURN_ERR;
    }
    
    memset(JSON_STR, 0, sizeof(JSON_STR));

    mainEntry = cJSON_AddObjectToObject(interworkingCfg,"Interworking");
    
    cJSON_AddNumberToObject(mainEntry,"InterworkingEnable",pCfg->InterworkingEnable); 
    cJSON_AddNumberToObject(mainEntry,"AccessNetworkType",pCfg->IEEE80211uCfg.IntwrkCfg.iAccessNetworkType); 
    cJSON_AddNumberToObject(mainEntry,"ASRA",pCfg->IEEE80211uCfg.IntwrkCfg.iASRA); 
    cJSON_AddNumberToObject(mainEntry,"ESR",pCfg->IEEE80211uCfg.IntwrkCfg.iESR); 
    cJSON_AddNumberToObject(mainEntry,"UESA",pCfg->IEEE80211uCfg.IntwrkCfg.iUESA); 
    cJSON_AddNumberToObject(mainEntry,"HESSOptionPresent",pCfg->IEEE80211uCfg.IntwrkCfg.iHESSOptionPresent); 
    cJSON_AddStringToObject(mainEntry, "HESSID", pCfg->IEEE80211uCfg.IntwrkCfg.iHESSID);
    venueEntry = cJSON_AddObjectToObject(mainEntry,"Venue");
    cJSON_AddNumberToObject(venueEntry,"VenueGroup",pCfg->IEEE80211uCfg.IntwrkCfg.iVenueGroup); 
    cJSON_AddNumberToObject(venueEntry,"VenueType",pCfg->IEEE80211uCfg.IntwrkCfg.iVenueType); 
    
    cJSON_PrintPreallocated(interworkingCfg, JSON_STR, sizeof(JSON_STR),false);
    cJSON_Delete(interworkingCfg);
 
    return CosaDmlWiFi_SaveInterworkingCfg(pCfg, JSON_STR, sizeof(JSON_STR));
}
#endif //TBD -N
#endif // DML_SUPPORT
/***********************************************************************
Funtion     : CosaDmlWiFi_DefaultInterworkingConfig
Input       : Pointer to vAP object
Description : Populates the vAP object pCfg with default values for 
              Interworking parameters
***********************************************************************/

INT WiFi_DefaultInterworkingConfig(uint8_t vapIndex)
{      	
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(vapIndex);
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, vapIndex);
	return RETURN_ERR;
    }
    UINT InstanceNumber = vapIndex;

    pCfg->interworking.interworkingEnabled = 0;
    pCfg->interworking.asra = 0;
    pCfg->interworking.esr = 0;
    pCfg->interworking.uesa = 0;
    pCfg->interworking.hessOptionPresent = 1;
    if((InstanceNumber == 1) || (InstanceNumber == 2))
    {
        pCfg->interworking.internetAvailable = 1;
    }
    strcpy(pCfg->interworking.hessid,"11:22:33:44:55:66");

    if ( (InstanceNumber == 5) || (InstanceNumber == 6) || (InstanceNumber == 9) || (InstanceNumber == 10) )	//Xfinity hotspot vaps
    {
         pCfg->interworking.accessNetworkType = 2;
    } else {
         pCfg->interworking.accessNetworkType = 0;
    }//ONE_WIFI

    pCfg->interworking.venueOptionPresent = 1;
    pCfg->interworking.venueGroup = 0;
    pCfg->interworking.venueType = 0;//ONE_WIFI
    return RETURN_OK;
}

/***********************************************************************
Funtion     : CosaDmlWiFi_InitInterworkingElement
Input       : Pointer to vAP object
Description : Check for Saved Configuration.
              If not present, call CosaDmlWiFi_DefaultInterworkingConfig
              to populate default values
***********************************************************************/
INT WiFi_InitInterworkingElement (uint8_t vapIndex)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    wifi_interworking_t *pCfg = Get_wifi_object_interworking_parameter(vapIndex);
    if(pCfg == NULL)
    {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong vapIndex:%d \n", __FUNCTION__, vapIndex);
	return RETURN_ERR;
    }
    UINT InstanceNumber = vapIndex;

#if defined(ENABLE_FEATURE_MESHWIFI)        
    wifi_InterworkingElement_t  elem;
    memset((char *)&elem, 0, sizeof(wifi_InterworkingElement_t));
    //Update OVS DB
    if(-1 == wifidb_get_interworking_config(getVAPName(vapIndex - 1),&elem)) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Initialize Interwokring Configuration from DB for AP: %d. Setting Default\n",InstanceNumber);
        return WiFi_DefaultInterworkingConfig(vapIndex);//ONE_WIFI
    }
    
    pCfg->interworking.interworkingEnabled = elem.interworkingEnabled;
    pCfg->interworking.accessNetworkType = elem.accessNetworkType;
    pCfg->interworking.internetAvailable = elem.internetAvailable;
    pCfg->interworking.asra = elem.asra;
    pCfg->interworking.esr = elem.esr;
    pCfg->interworking.uesa = elem.uesa;
    pCfg->interworking.venueOptionPresent = elem.venueOptionPresent;
    pCfg->interworking.venueGroup = elem.venueGroup;
    pCfg->interworking.venueType = elem.venueType;
    pCfg->interworking.hessOptionPresent = elem.hessOptionPresent;
    strcpy(pCfg->interworking.hessid,elem.hessid);//ONE_WIFI

#else
    char cfgFile[64];
    char *JSON_STR = NULL;
    int apIns = 0; 
    long confSize = 0; 

    if(!pCfg){
        wifi_util_dbg_print(WIFI_PASSPOINT,"AP Context is NULL\n");
        return RETURN_ERR;
    }    

    apIns = InstanceNumber;
    if((apIns < 1) || (apIns > 16)){
        wifi_util_dbg_print(WIFI_PASSPOINT, "%s:%d: Invalid AP Index. Return\n", __func__, __LINE__);
        return RETURN_ERR;
    }    

    sprintf(cfgFile,WIFI_INTERWORKING_CFG_FILE,apIns);

    confSize = readFileToBuffer(cfgFile,&JSON_STR);

    if(!confSize || !JSON_STR || (RETURN_OK != CosaDmlWiFi_ReadInterworkingConfig(pCfg,JSON_STR))){
        if(JSON_STR){
            free(JSON_STR);
            JSON_STR = NULL;
        }    
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to Initialize Interworking Configuration from memory for AP: %d. Setting Default\n",apIns);
        return WiFi_DefaultInterworkingConfig(apIns);
    }    
    wifi_util_dbg_print(WIFI_PASSPOINT,"Initialized Interworking Configuration from memory for AP: %d.\n",apIns);

#endif
    return RETURN_OK;
#else
    return WiFi_DefaultInterworkingConfig(vapIndex);
#endif
}

void update_json_gas_config(wifi_GASConfiguration_t *gasConfig_struct) {
    cJSON *gasCfg = NULL;
    cJSON *mainEntry = NULL;
    char *JSON_STR = NULL;

    gasCfg = cJSON_CreateObject();
    if (NULL == gasCfg) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to create GAS JSON Object\n");
        return;
    }

    mainEntry = cJSON_AddObjectToObject(gasCfg,"GasConfig");    
    cJSON_AddNumberToObject(mainEntry,"AdvertisementId",gasConfig_struct->AdvertisementID);
    cJSON_AddBoolToObject(mainEntry,"PauseForServerResp",gasConfig_struct->PauseForServerResponse);
    cJSON_AddNumberToObject(mainEntry,"RespTimeout",gasConfig_struct->ResponseTimeout);
    cJSON_AddNumberToObject(mainEntry,"ComebackDelay",gasConfig_struct->ComeBackDelay);
    cJSON_AddNumberToObject(mainEntry,"RespBufferTime",gasConfig_struct->ResponseBufferingTime);
    cJSON_AddNumberToObject(mainEntry,"QueryRespLengthLimit",gasConfig_struct->QueryResponseLengthLimit);

    JSON_STR = malloc(512);
    memset(JSON_STR, 0, 512);
    cJSON_PrintPreallocated(gasCfg, JSON_STR,512,false);

    if (RETURN_OK != WiFi_SaveGasCfg(JSON_STR, strlen(JSON_STR))) {
        wifi_util_dbg_print(WIFI_PASSPOINT,"Failed to update OVSDB with GAS Config. Adv-ID:%d\n",gasConfig_struct->AdvertisementID);
    }
    cJSON_Delete(gasCfg);

    if(JSON_STR){
        free(JSON_STR);
        JSON_STR = NULL;
    }
}
