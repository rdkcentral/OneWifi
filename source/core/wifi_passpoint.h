 /*****************************************************************************
  If not stated otherwise in this file or this component's LICENSE     
  file the following copyright and licenses apply:                          
                                                                            
  Copyright 2020 RDK Management                                             
                                                                            
  Licensed under the Apache License, Version 2.0 (the "License");           
  you may not use this file except in compliance with the License.          
  You may obtain a copy of the License at                                   
                                                                            
      http://www.apache.org/licenses/LICENSE-2.0                            
                                                                            
  Unless required by applicable law or agreed to in writing, software       
  distributed under the License is distributed on an "AS IS" BASIS,         
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
  See the License for the specific language governing permissions and       
  limitations under the License.                                            
                                                                            
 *****************************************************************************/

#ifndef _WIFI_PASSPOINT_H
#define _WIFI_PASSPOINT_H

#define WIFI_PASSPOINT_DIR                  "/nvram/passpoint"
#define WIFI_PASSPOINT_GAS_CFG_FILE        "/nvram/passpoint/passpointGasCfg.json"
#define WIFI_PASSPOINT_DEFAULT_GAS_CFG     "{\"GASConfig\": [{ \"AdvertisementId\": 0, \"PauseForServerResp\": true, \"RespTimeout\": 5000, \"ComebackDelay\": 1000, \"RespBufferTime\": 1000, \"QueryRespLengthLimit\": 127 }]}"
#define WIFI_PASSPOINT_ANQP_CFG_FILE        "/nvram/passpoint/passpointAnqpCfg.json"
#define WIFI_PASSPOINT_DEFAULT_ANQP_CFG     "{\"InterworkingService\": {}}"
#define WIFI_PASSPOINT_HS2_CFG_FILE        "/nvram/passpoint/passpointHs2Cfg.json"
#define WIFI_PASSPOINT_DEFAULT_HS2_CFG     "{\"Passpoint\": {}}"

#define WIFI_INTERWORKING_CFG_FILE        "/nvram/passpoint/InterworkingCfg_%d.json"

#include "collection.h"
#if DML_SUPPORT
#include "cosa_wifi_internal.h"
#else
#include "wifi_hal.h"
#endif // DML_SUPPORT

typedef struct {
    UCHAR apIndex;
    mac_address_t sta;
    unsigned char token;
    wifi_anqp_node_t *head;
} wifi_anqp_context_t;

typedef struct {    // Values correspond to the dot11GASAdvertisementEntry field definitions; see 802.11-2016 Annex C.3.
    UINT AdvertisementID;
    UINT Queries;
    UINT QueryRate;
    UINT Responses;
    UINT ResponseRate;
    UINT NoRequestOutstanding;
    UINT ResponsesDiscarded;
    UINT FailedResponses;
} wifi_gas_stats_t;

typedef struct
{
    USHORT info_id;
    USHORT len;
    UCHAR  oi[3];
    UCHAR  wfa_type;
} __attribute__((packed)) wifi_vendor_specific_anqp_capabilities_t;

void process_passpoint_timeout();
void wifi_anqpStartReceivingTestFrame();
//void process_passpoint_event(cosa_wifi_anqp_context_t *anqpReq);
//INT CosaDmlWiFi_RestoreAPInterworking (int apIndex);
INT WiFi_initPasspoint(void);
int enablePassPointSettings(int ap_index, BOOL passpoint_enable, BOOL downstream_disable, BOOL p2p_disable, BOOL layer2TIF);
INT WiFi_InitANQPConfig(void);
INT WiFi_InitHS2Config(void);
void WiFi_UpdateANQPVenueInfo(uint8_t vapIndex);
INT WiFi_SetGasConfig(char *JSON_STR);
INT WiFi_InitGasConfig(void);
INT WiFi_SetHS2Status(uint8_t vapIndex, BOOL bValue, BOOL setToPSM);
void WiFi_GetGasConfig(char *pString);
INT WiFi_SetANQPConfig(uint8_t vapIndex, char *JSON_STR);
INT WiFi_SaveANQPCfg(uint8_t vapIndex);
INT WiFi_GetWANMetrics(uint8_t vapIndex, char *WANMetrics, UINT WANMetrics_length);
void WiFi_GetHS2Stats(uint8_t vapIndex);
INT WiFi_SetHS2Config(uint8_t vapIndex, char *JSON_STR);
INT WiFi_SaveHS2Cfg(uint8_t vapIndex);
#if defined (DUAL_CORE_XB3)
int wifi_restoreAPInterworkingElement(int apIndex);
#endif
INT WiFi_DefaultInterworkingConfig(uint8_t vapIndex);
INT WiFi_WriteInterworkingConfig (uint8_t vapIndex);
INT WiFi_InitInterworkingElement (uint8_t vapIndex);

#if DML_SUPPORT
typedef struct {
    PCOSA_DATAMODEL_WIFI    wifi_dml;
} wifi_passpoint_t;
#endif // DML_SUPPORT
        
#endif //_WIFI_PASSPOINT_H
