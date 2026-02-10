/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/**********************************************************************
    Notes:
    What is new for 2.2.0
      1. Add Country Code support
      2. Add more DCS function
      3. Move RadiusSecret from struct wifi_radius_setting_t to wifi_getApSecurityRadiusServer function
      4. Add wifi_getApSecuritySecondaryRadiusServer
    What is new for 2.2.1
      1. Add wifi_setRadioTrafficStatsMeasure, wifi_setRadioTrafficStatsRadioStatisticsEnable
    What is new for 2.2.2
      1. Add Band Steering HAL
    What is new for 2.3.0
      1. Add AP Beacon Rate control HAL
      2. Add Dynamic Channel Selection (phase 2) HAL
      3. Add Air Time Management HAL
    What is new for 2.4.0
      1. Add data structure and HAL for mesh
    What is new for 2.5.0
      1. Add the Channel switch HAL for mesh
    What is new for 2.6.0
      1. Add the Band steering HAL for mesh
    What is new for 2.7.0
      1. Add HAL for Wifi telemetry
    What is new for 2.8.0
      1. Add HAL for 11w
    What is new for 2.9.0
      1. Add HAL function definitions for 802.11r Fast Transition
    What is new for 2.10.0
      1. Add HAL function definitions for 802.11v BSS Transition Management
    What is new for 2.11.0
      1. Add HAL function definitions for 802.11k Neighbor Request and Response definitions
    What is new for 2.12.0
      1. Add HAL function definitions for 802.11k Beacon Request and Response definitions
    What is new for 2.13.0
      1. Add HAL function definitions for DPP
    What is new for 2.14.0
      1. Add HAL function definitions for steering effectiveness telemetry
    What is new for 2.15.0
      1. Add HAL function definitions for 802.11ax
      2. Add HAL definitions for dfs channel state
      3. Add HAL function definitions for EAP parameters
    What is new for 2.16.0
      1. Modified HAL structure definition for VAP Telemetry
    What is new for 2.17.0
      1. Add HAL function definition for Single Client reporting feature
    What is new for 2.18.0
      1. Add HAL Fuction Definition for Absolute TX-Power retreival
    What is new for 2.19.0
      1. Added zerowait DFS status support
      2. Modified HAL definitions for EAP parameters
      3. Updated comments for ChannelUtilization, ActivityFactor, CarrierSenseThreshold_Exceeded
         and RetransmissionMetirc radio metrics
    What is new for 2.20.0
      1. Add HAL definitions for Multi PSK support
    What is new for 3.0.0
      1. Code refactoring
      2. Add HAL definitions for tri-band and 6GHz support
**********************************************************************/
#ifndef __WIFI_HAL_H__
#define __WIFI_HAL_H__
/**
 * Wifi generic API and types definition used across multiples modules.
 * Includes wifi_init(), wifi_factoryReset(), wifi_setLED(), etc.
 */
#include "wifi_hal_generic.h"
/**
 * Wifi Radio specific APIs.
 * Includes API to configure and read configuration, factory-reset and reset of the radio. 
 */
#include "wifi_hal_radio.h"
/**
 * Wifi VAP specific APIs.
 * Includes API to create, configure and read configuration, factory-reset and reset of the VAP. 
 */
#include "wifi_hal_ap.h"
/**
* Wifi STA specific APIs.
* Includes API to create, configure and read configuration the STA VAP. 
*/
#include "wifi_hal_sta.h"
/**
 * Wifi measurement and Telemetry specific APIs.
 * 
 */
#include "wifi_hal_telemetry.h"
/**
* Wifi client management specific APIs.
 */
#include "wifi_hal_client_mgt.h"
/**
* Wifi extender specific APIs.
* Includes API's used by Plume Mesh.
 */
#include "wifi_hal_extender.h"

//TODO: This header file needs to be corrected, some API's defined in it are currently in use, and require correction or removal.
/**
* Wifi deprecated APIs.
* APIs to be deprecated. Not add new function or structure!
*/
#include "wifi_hal_deprecated.h"

#endif
